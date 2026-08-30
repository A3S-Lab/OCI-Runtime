use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use a3s_oci_agent_protocol::{AgentWaitRequest, GuestAgentService};
use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, HostPlatform, IsolationClass,
};
use a3s_oci_sdk::{
    async_trait, AttachmentCapabilities, ContainerRecord, ContainerTarget, CreateRequest,
    DeleteMode, Error, ErrorCode, ExitStatus, KillRequest, OciBundle, OperationId, Result,
    RuntimeOperation, Signal, StartRequest, RUNTIME_BUNDLE_HANDOFF_EXTENSION,
    RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION,
};
use tokio::sync::Mutex;

use super::super::handoff::BundleHandoffStore;
use super::super::layout::PreparedUtilityVmLayout;
use super::super::recovery::RecoveryStore;
use super::super::{kvm_network, UtilityVmLaunchRequest};
use crate::agent_driver::{AgentDriverClient, AGENT_DRIVER_HOOKS};
use crate::agent_session::{
    UtilityVmSession, UtilityVmSessionQualification, VerifiedLinuxUtilityVmConnectOptions,
};
use crate::driver::{
    DriverCreateRequest, DriverDeleteRequest, DriverKillRequest, DriverStartRequest, DriverState,
    DriverWaitRequest, OciHookPhase, RuntimeDriver,
};
use crate::{AgentVmSmokeReport, DriverRecovery};

mod dispatch;
mod recovery;

const QUALIFICATION_OPERATIONS: [RuntimeOperation; 6] = [
    RuntimeOperation::Create,
    RuntimeOperation::State,
    RuntimeOperation::Start,
    RuntimeOperation::Kill,
    RuntimeOperation::Delete,
    RuntimeOperation::Wait,
];
const QUALIFICATION_SCOPE: &str = "linux-kvm-operation-stage-reopen-only-v1";

#[derive(Clone)]
struct ActiveSession {
    owner: Arc<UtilityVmSession>,
    client: AgentDriverClient,
    target: ContainerTarget,
}

pub(super) struct QualificationKvmOperationDriver {
    shim: PathBuf,
    bootstrap_root: PathBuf,
    system_image_manifest: PathBuf,
    system_image_manifest_sha256: String,
    console: PathBuf,
    recovery: RecoveryStore,
    handoff: BundleHandoffStore,
    retained_create: CreateRequest,
    retained_start: Option<StartRequest>,
    retained_kill: Option<KillRequest>,
    recovery_marker: Option<PathBuf>,
    qualification: Option<UtilityVmSessionQualification>,
    session: Mutex<Option<ActiveSession>>,
    completed_report: Mutex<Option<AgentVmSmokeReport>>,
    create_identity: StdMutex<Option<(OperationId, ContainerTarget)>>,
    start_identity: StdMutex<Option<(OperationId, ContainerTarget)>>,
    kill_identity: StdMutex<Option<(OperationId, ContainerTarget, Signal, bool)>>,
    delete_identity: StdMutex<Option<(OperationId, ContainerTarget, DeleteMode)>>,
    wait_identity: StdMutex<Option<(ContainerTarget, Option<u64>)>>,
    start_calls: AtomicU32,
    kill_calls: AtomicU32,
    delete_calls: AtomicU32,
    wait_calls: AtomicU32,
    recovery_calls: AtomicU32,
    rehydrated_created_record: AtomicBool,
    rehydrated_running_record: AtomicBool,
    rehydrated_stopped_record: AtomicBool,
    rehydrated_running_pid: AtomicI32,
}

impl QualificationKvmOperationDriver {
    pub(super) fn new(
        prepared: &PreparedUtilityVmLayout,
        console: PathBuf,
        retained_create: CreateRequest,
        qualification: Option<UtilityVmSessionQualification>,
    ) -> Self {
        Self {
            shim: prepared.shim.clone(),
            bootstrap_root: prepared.bootstrap_root.clone(),
            system_image_manifest: prepared.system_image_manifest.clone(),
            system_image_manifest_sha256: prepared.system_image_manifest_sha256.clone(),
            console,
            recovery: RecoveryStore::new(prepared.recovery_directory.clone()),
            handoff: BundleHandoffStore::new(
                prepared.runtime_root.clone(),
                prepared.runtime_share_root.clone(),
            ),
            retained_create,
            retained_start: None,
            retained_kill: None,
            recovery_marker: None,
            qualification,
            session: Mutex::new(None),
            completed_report: Mutex::new(None),
            create_identity: StdMutex::new(None),
            start_identity: StdMutex::new(None),
            kill_identity: StdMutex::new(None),
            delete_identity: StdMutex::new(None),
            wait_identity: StdMutex::new(None),
            start_calls: AtomicU32::new(0),
            kill_calls: AtomicU32::new(0),
            delete_calls: AtomicU32::new(0),
            wait_calls: AtomicU32::new(0),
            recovery_calls: AtomicU32::new(0),
            rehydrated_created_record: AtomicBool::new(false),
            rehydrated_running_record: AtomicBool::new(false),
            rehydrated_stopped_record: AtomicBool::new(false),
            rehydrated_running_pid: AtomicI32::new(0),
        }
    }

    pub(super) fn with_start_recovery(
        prepared: &PreparedUtilityVmLayout,
        console: PathBuf,
        retained_create: CreateRequest,
        retained_start: StartRequest,
    ) -> Self {
        let mut driver = Self::new(prepared, console, retained_create, None);
        driver.retained_start = Some(retained_start);
        driver
    }

    pub(super) fn with_kill_recovery(
        prepared: &PreparedUtilityVmLayout,
        console: PathBuf,
        retained_create: CreateRequest,
        retained_start: StartRequest,
        retained_kill: KillRequest,
        recovery_marker: PathBuf,
    ) -> Self {
        let mut driver =
            Self::with_start_recovery(prepared, console, retained_create, retained_start);
        driver.retained_kill = Some(retained_kill);
        driver.recovery_marker = Some(recovery_marker);
        driver
    }

    pub(super) fn with_delete_recovery(
        prepared: &PreparedUtilityVmLayout,
        console: PathBuf,
        retained_create: CreateRequest,
        retained_start: StartRequest,
        retained_kill: KillRequest,
        recovery_marker: PathBuf,
    ) -> Self {
        Self::with_kill_recovery(
            prepared,
            console,
            retained_create,
            retained_start,
            retained_kill,
            recovery_marker,
        )
    }

    pub(super) fn with_wait_recovery(
        prepared: &PreparedUtilityVmLayout,
        console: PathBuf,
        retained_create: CreateRequest,
        retained_start: StartRequest,
        retained_kill: KillRequest,
        recovery_marker: PathBuf,
    ) -> Self {
        Self::with_kill_recovery(
            prepared,
            console,
            retained_create,
            retained_start,
            retained_kill,
            recovery_marker,
        )
    }

    async fn ensure_session(&self, request: &DriverCreateRequest) -> Result<ActiveSession> {
        let mut retained = self.session.lock().await;
        if let Some(active) = retained.as_ref() {
            if active.target != request.target {
                return Err(qualification_error(
                    ErrorCode::Conflict,
                    "qualification KVM owner is already bound to another generation",
                ));
            }
            return Ok(active.clone());
        }
        let mount_root = self
            .handoff
            .mount_root(&request.target, request.attachment_contract.guest_session())
            .await?;
        let guest_bundle = self
            .handoff
            .guest_bundle_path(
                &request.target,
                request.bundle.directory(),
                request.attachment_contract.guest_session(),
            )
            .await?;
        let attachment_digest = kvm_network::prepare(&UtilityVmLaunchRequest {
            target: &request.target,
            runtime_share: &mount_root,
            bundle: &request.bundle,
            guest_bundle: &guest_bundle,
            attachment_contract: &request.attachment_contract,
        })
        .await?;
        let recovery_report = self
            .recovery
            .path(&request.target, request.attachment_contract.guest_session())?;
        let options = VerifiedLinuxUtilityVmConnectOptions {
            rootfs: &self.bootstrap_root,
            system_image_manifest: &self.system_image_manifest,
            expected_system_image_manifest_sha256: &self.system_image_manifest_sha256,
            runtime_share: &mount_root,
            console: &self.console,
            recovery_report: Some(&recovery_report),
            vm_attachment_manifest_sha256: attachment_digest.as_deref(),
        };
        let result = match self.qualification.as_ref() {
            Some(qualification) => {
                UtilityVmSession::connect_with_verified_runtime_share_and_qualification(
                    &self.shim,
                    options,
                    qualification,
                )
                .await
            }
            None => {
                UtilityVmSession::connect_with_verified_runtime_share_and_vm_attachments(
                    &self.shim, options,
                )
                .await
            }
        };
        let owner = match result {
            Ok(session) => Arc::new(session),
            Err(report) => {
                let reason = report.reason.clone().unwrap_or_else(|| {
                    "authenticated qualification KVM session failed".to_string()
                });
                *self.completed_report.lock().await = Some(report);
                return Err(qualification_error(ErrorCode::Unavailable, reason).retryable(true));
            }
        };
        let service: Arc<dyn GuestAgentService> = Arc::new(owner.client());
        let active = ActiveSession {
            owner,
            client: AgentDriverClient::new(
                service,
                "qualification-only KVM guest agent",
                "qualification-kvm-operation-reopen",
            ),
            target: request.target.clone(),
        };
        *retained = Some(active.clone());
        Ok(active)
    }

    pub(super) async fn shutdown(&self) -> AgentVmSmokeReport {
        let active = self.session.lock().await.take();
        if let Some(active) = active {
            let report = active.owner.shutdown().await;
            *self.completed_report.lock().await = Some(report.clone());
            return report;
        }
        self.completed_report
            .lock()
            .await
            .clone()
            .unwrap_or_else(|| {
                let mut report = AgentVmSmokeReport::initial(HostPlatform::Linux);
                report.reason =
                    Some("qualification KVM owner never launched a session".to_string());
                report
            })
    }

    pub(super) async fn cleanup(
        &self,
        target: &ContainerTarget,
    ) -> std::result::Result<(), String> {
        self.recovery
            .remove(target, None)
            .await
            .map_err(|error| format!("failed to remove KVM recovery evidence: {error}"))?;
        self.handoff
            .cleanup(target, None, true)
            .await
            .map_err(|error| format!("failed to clean KVM runtime share: {error}"))
    }

    pub(super) async fn mount_root(
        &self,
        target: &ContainerTarget,
    ) -> std::result::Result<PathBuf, String> {
        self.handoff
            .mount_root(target, None)
            .await
            .map_err(|error| format!("failed to resolve KVM runtime share: {error}"))
    }

    pub(super) fn create_identity(
        &self,
    ) -> std::result::Result<(OperationId, ContainerTarget), String> {
        self.create_identity
            .lock()
            .map_err(|_| "KVM create identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no Create dispatch".to_string())
    }

    pub(super) fn start_identity(
        &self,
    ) -> std::result::Result<(OperationId, ContainerTarget), String> {
        self.start_identity
            .lock()
            .map_err(|_| "KVM start identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no Start dispatch".to_string())
    }

    pub(super) fn start_calls(&self) -> u32 {
        self.start_calls.load(Ordering::SeqCst)
    }

    pub(super) fn kill_identity(
        &self,
    ) -> std::result::Result<(OperationId, ContainerTarget, Signal, bool), String> {
        self.kill_identity
            .lock()
            .map_err(|_| "KVM kill identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no Kill dispatch".to_string())
    }

    pub(super) fn kill_calls(&self) -> u32 {
        self.kill_calls.load(Ordering::SeqCst)
    }

    pub(super) fn delete_identity(
        &self,
    ) -> std::result::Result<(OperationId, ContainerTarget, DeleteMode), String> {
        self.delete_identity
            .lock()
            .map_err(|_| "KVM delete identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no Delete dispatch".to_string())
    }

    pub(super) fn delete_calls(&self) -> u32 {
        self.delete_calls.load(Ordering::SeqCst)
    }

    pub(super) fn wait_identity(
        &self,
    ) -> std::result::Result<(ContainerTarget, Option<u64>), String> {
        self.wait_identity
            .lock()
            .map_err(|_| "KVM wait identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no Wait dispatch".to_string())
    }

    pub(super) fn wait_calls(&self) -> u32 {
        self.wait_calls.load(Ordering::SeqCst)
    }

    pub(super) fn recovery_calls(&self) -> u32 {
        self.recovery_calls.load(Ordering::SeqCst)
    }

    pub(super) fn rehydrated_created_record(&self) -> bool {
        self.rehydrated_created_record.load(Ordering::SeqCst)
    }

    pub(super) fn rehydrated_running_record(&self) -> bool {
        self.rehydrated_running_record.load(Ordering::SeqCst)
    }

    pub(super) fn rehydrated_stopped_record(&self) -> bool {
        self.rehydrated_stopped_record.load(Ordering::SeqCst)
    }

    pub(super) fn rehydrated_running_pid(&self) -> Option<i32> {
        match self.rehydrated_running_pid.load(Ordering::SeqCst) {
            pid if pid > 0 => Some(pid),
            _ => None,
        }
    }

    async fn live_session(&self, target: &ContainerTarget) -> Result<ActiveSession> {
        self.session
            .lock()
            .await
            .as_ref()
            .filter(|active| &active.target == target)
            .cloned()
            .ok_or_else(|| {
                qualification_error(
                    ErrorCode::NotFound,
                    "qualification KVM owner has no live exact-generation session",
                )
            })
    }

    pub(super) async fn guest_wait(&self, request: AgentWaitRequest) -> Result<ExitStatus> {
        self.live_session(&request.target)
            .await?
            .owner
            .client()
            .wait(request)
            .await
    }
}

#[async_trait]
impl RuntimeDriver for QualificationKvmOperationDriver {
    fn capability(&self) -> DriverCapability {
        DriverCapability {
            driver: DriverKind::LibkrunKvm,
            status: CapabilityStatus::Available,
            readiness: DriverReadiness::Experimental,
            isolation_classes: vec![IsolationClass::DedicatedVm],
            reason: None,
            evidence: BTreeMap::from([
                (
                    "execution_path".to_string(),
                    "real-kvm-utility-vm".to_string(),
                ),
                ("opt_in".to_string(), "qualification-only".to_string()),
                (
                    "qualification_scope".to_string(),
                    QUALIFICATION_SCOPE.to_string(),
                ),
            ]),
        }
    }

    fn linux_support(&self) -> Result<a3s_oci_sdk::OciLinuxSupport> {
        a3s_oci_sdk::OciLinuxSupport::shared_executor()
    }

    fn operations(&self) -> &[RuntimeOperation] {
        &QUALIFICATION_OPERATIONS
    }

    fn hooks(&self) -> &[OciHookPhase] {
        &AGENT_DRIVER_HOOKS
    }

    fn attachment_capabilities(&self) -> AttachmentCapabilities {
        AttachmentCapabilities::base_v1()
            .with_extension(
                RUNTIME_BUNDLE_HANDOFF_EXTENSION,
                vec![RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION],
            )
            .expect("fixed KVM handoff extension is valid")
    }

    async fn acknowledge_operation(&self, operation_id: &OperationId) -> Result<()> {
        let client = self
            .session
            .lock()
            .await
            .as_ref()
            .map(|active| active.client.clone());
        match client {
            Some(client) => client.acknowledge_operation(operation_id).await,
            None => Ok(()),
        }
    }

    async fn prepare_create_bundle(&self, request: &DriverCreateRequest) -> Result<OciBundle> {
        self.handoff.prepare(request).await
    }

    async fn recover(&self, record: &ContainerRecord) -> Result<DriverRecovery> {
        self.recover_record(record).await
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        self.dispatch_create(request).await
    }

    async fn state(&self, target: ContainerTarget) -> Result<DriverState> {
        self.live_session(&target).await?.client.state(target).await
    }

    async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        self.dispatch_start(request).await
    }

    async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        self.dispatch_kill(request).await
    }

    async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        self.dispatch_delete(request).await
    }

    async fn wait(&self, request: DriverWaitRequest) -> Result<ExitStatus> {
        self.dispatch_wait(request).await
    }
}

fn qualification_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("qualification-kvm-operation-reopen")
}
