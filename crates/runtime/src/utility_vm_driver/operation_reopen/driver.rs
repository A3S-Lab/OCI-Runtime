use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use a3s_oci_agent_protocol::GuestAgentService;
use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, HostPlatform, IsolationClass,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    async_trait, AttachmentCapabilities, ContainerRecord, ContainerTarget, CreateRequest, Error,
    ErrorCode, OciBundle, OperationId, Result, RuntimeOperation, RUNTIME_BUNDLE_HANDOFF_EXTENSION,
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
    DriverCreateAttachments, DriverCreateRequest, DriverDeleteRequest, DriverKillRequest,
    DriverStartRequest, DriverState, OciHookPhase, RuntimeDriver,
};
use crate::{AgentVmSmokeReport, DriverRecovery};

const QUALIFICATION_OPERATIONS: [RuntimeOperation; 5] = [
    RuntimeOperation::Create,
    RuntimeOperation::State,
    RuntimeOperation::Start,
    RuntimeOperation::Kill,
    RuntimeOperation::Delete,
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
    qualification: Option<UtilityVmSessionQualification>,
    session: Mutex<Option<ActiveSession>>,
    completed_report: Mutex<Option<AgentVmSmokeReport>>,
    create_identity: StdMutex<Option<(OperationId, ContainerTarget)>>,
    recovery_calls: AtomicU32,
    rehydrated_created_record: AtomicBool,
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
            qualification,
            session: Mutex::new(None),
            completed_report: Mutex::new(None),
            create_identity: StdMutex::new(None),
            recovery_calls: AtomicU32::new(0),
            rehydrated_created_record: AtomicBool::new(false),
        }
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

    async fn dispatch_create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        let identity = (request.context.operation_id.clone(), request.target.clone());
        {
            let mut retained = self.create_identity.lock().map_err(|_| {
                qualification_error(ErrorCode::Internal, "KVM create identity lock was poisoned")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed Create identity",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        let active = self.ensure_session(&request).await?;
        let guest_bundle = self
            .handoff
            .guest_bundle_path(
                &request.target,
                request.bundle.directory(),
                request.attachment_contract.guest_session(),
            )
            .await?;
        active.client.create(request, guest_bundle).await
    }

    async fn recovery_request(&self, record: &ContainerRecord) -> Result<DriverCreateRequest> {
        let attachment_digest = self.retained_create.attachments.digest()?;
        if record.driver != DriverKind::LibkrunKvm
            || record.isolation != IsolationClass::DedicatedVm
            || record.state.id() != self.retained_create.id.as_str()
            || record.config_digest != self.retained_create.bundle.config_digest()
            || record.attachments_digest.as_deref() != Some(attachment_digest.as_str())
        {
            return Err(qualification_error(
                ErrorCode::FailedPrecondition,
                "durable KVM Create record differs from the retained qualification request",
            ));
        }
        let target = ContainerTarget::exact(self.retained_create.id.clone(), record.generation);
        let mut request = DriverCreateRequest {
            context: self.retained_create.context.clone(),
            target,
            bundle: self.retained_create.bundle.clone(),
            isolation: self.retained_create.isolation.clone(),
            io: self.retained_create.attachments.process_io().clone(),
            attachment_contract: self.retained_create.attachments.clone(),
            tee_launch: None,
            attachments: DriverCreateAttachments::None,
        };
        request.bundle = self.handoff.prepare(&request).await?;
        Ok(request)
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

    pub(super) fn recovery_calls(&self) -> u32 {
        self.recovery_calls.load(Ordering::SeqCst)
    }

    pub(super) fn rehydrated_created_record(&self) -> bool {
        self.rehydrated_created_record.load(Ordering::SeqCst)
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
        if !matches!(
            record.state.status(),
            ContainerState::Creating | ContainerState::Created
        ) {
            return Err(qualification_error(
                ErrorCode::FailedPrecondition,
                "KVM operation-reopen qualification accepts only creating or created durable state",
            ));
        }
        if self.recovery_calls.fetch_add(1, Ordering::SeqCst) != 0 {
            return Err(qualification_error(
                ErrorCode::Conflict,
                "Create reopen qualification recovered more than one durable record",
            ));
        }
        let request = self.recovery_request(record).await?;
        self.recovery.recover(&request.target, record, None).await?;
        self.recovery.remove(&request.target, None).await?;
        if *record.state.status() == ContainerState::Creating {
            return Ok(DriverRecovery::none());
        }
        let observed = self.dispatch_create(request).await?;
        if observed.status() != ContainerState::Created {
            return Err(qualification_error(
                ErrorCode::Conflict,
                "replacement KVM owner did not recreate OCI created state",
            ));
        }
        self.rehydrated_created_record.store(true, Ordering::SeqCst);
        DriverRecovery::recreated_created(observed)
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        self.dispatch_create(request).await
    }

    async fn state(&self, target: ContainerTarget) -> Result<DriverState> {
        self.live_session(&target).await?.client.state(target).await
    }

    async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        self.live_session(&request.target)
            .await?
            .client
            .start(request)
            .await
    }

    async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        self.live_session(&request.target)
            .await?
            .client
            .kill(request)
            .await
    }

    async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        self.live_session(&request.target)
            .await?
            .client
            .delete(request)
            .await
    }
}

fn qualification_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("qualification-kvm-operation-reopen")
}
