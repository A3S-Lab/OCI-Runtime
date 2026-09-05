use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32};
use std::sync::{Arc, Mutex as StdMutex};

use a3s_oci_agent_protocol::GuestAgentService;
use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, HostPlatform, IsolationClass,
};
use a3s_oci_sdk::{
    async_trait, AttachmentCapabilities, CloseStdinRequest, ContainerOperationRequest,
    ContainerRecord, ContainerStats, ContainerTarget, CreateRequest, DeleteMode, Error, ErrorCode,
    ExecRequest, ExitStatus, FileRequest, FileResponse, FilesystemRequest, FilesystemResponse,
    KillRequest, OciBundle, OperationId, OutputChunk, ProcessRecord, ProcessTarget, ResizeRequest,
    Result, RuntimeOperation, Signal, SignalProcessRequest, StartRequest, UpdateRequest,
    WriteStdinRequest, RUNTIME_BUNDLE_HANDOFF_EXTENSION, RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION,
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
    DriverCloseStdinRequest, DriverContainerOperationRequest, DriverCreateRequest,
    DriverDeleteRequest, DriverExecRequest, DriverKillRequest, DriverProcess,
    DriverReadOutputRequest, DriverResizeRequest, DriverSignalProcessRequest, DriverStartRequest,
    DriverState, DriverUpdateRequest, DriverWaitProcessRequest, DriverWaitRequest,
    DriverWriteStdinRequest, OciHookPhase, RuntimeDriver,
};
use crate::{AgentVmSmokeReport, DriverRecovery};

mod dispatch;
mod evidence;
mod guest;
mod recovery;

const QUALIFICATION_OPERATIONS: [RuntimeOperation; 20] = [
    RuntimeOperation::Create,
    RuntimeOperation::State,
    RuntimeOperation::Start,
    RuntimeOperation::Kill,
    RuntimeOperation::Delete,
    RuntimeOperation::Wait,
    RuntimeOperation::Exec,
    RuntimeOperation::SignalProcess,
    RuntimeOperation::WaitProcess,
    RuntimeOperation::Pause,
    RuntimeOperation::Resume,
    RuntimeOperation::Processes,
    RuntimeOperation::Update,
    RuntimeOperation::Stats,
    RuntimeOperation::ReadOutput,
    RuntimeOperation::WriteStdin,
    RuntimeOperation::CloseStdin,
    RuntimeOperation::Resize,
    RuntimeOperation::File,
    RuntimeOperation::Filesystem,
];
const QUALIFICATION_SCOPE: &str = "linux-kvm-operation-stage-reopen-only-v1";

#[derive(Clone)]
struct ActiveSession {
    owner: Arc<UtilityVmSession>,
    client: AgentDriverClient,
    target: ContainerTarget,
}

pub(super) struct WaitProcessRecovery {
    pub(super) signal_process: SignalProcessRequest,
    pub(super) signal_ready_marker: (PathBuf, Vec<u8>),
    pub(super) exec_is_live: bool,
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
    retained_exec: Option<ExecRequest>,
    retained_signal_process: Option<SignalProcessRequest>,
    retained_signal_ready_marker: Option<(PathBuf, Vec<u8>)>,
    retained_write_stdin: Option<WriteStdinRequest>,
    retained_write_ready_marker: Option<(PathBuf, Vec<u8>)>,
    retained_close_stdin: Option<CloseStdinRequest>,
    retained_close_ready_marker: Option<(PathBuf, Vec<u8>)>,
    retained_resize: Option<ResizeRequest>,
    retained_resize_ready_marker: Option<(PathBuf, Vec<u8>)>,
    retained_file: Option<FileRequest>,
    retained_file_ready_marker: Option<(PathBuf, Vec<u8>)>,
    retained_filesystem: Option<FilesystemRequest>,
    retained_filesystem_ready_marker: Option<(PathBuf, Vec<u8>)>,
    retained_pause: Option<ContainerOperationRequest>,
    retained_pause_ready_marker: Option<(PathBuf, Vec<u8>)>,
    retained_resume: Option<ContainerOperationRequest>,
    retained_update: Option<UpdateRequest>,
    retained_update_ready_marker: Option<(PathBuf, Vec<u8>)>,
    recovery_exec_is_live: bool,
    recovery_marker: Option<PathBuf>,
    qualification: Option<UtilityVmSessionQualification>,
    session: Mutex<Option<ActiveSession>>,
    completed_report: Mutex<Option<AgentVmSmokeReport>>,
    create_identity: StdMutex<Option<(OperationId, ContainerTarget)>>,
    start_identity: StdMutex<Option<(OperationId, ContainerTarget)>>,
    kill_identity: StdMutex<Option<(OperationId, ContainerTarget, Signal, bool)>>,
    delete_identity: StdMutex<Option<(OperationId, ContainerTarget, DeleteMode)>>,
    wait_identity: StdMutex<Option<(ContainerTarget, Option<u64>)>>,
    wait_process_identity: StdMutex<Option<(ProcessTarget, Option<u64>)>>,
    exec_identity: StdMutex<Option<DriverExecRequest>>,
    signal_process_identity: StdMutex<Option<DriverSignalProcessRequest>>,
    pause_identity: StdMutex<Option<(OperationId, ContainerTarget)>>,
    resume_identity: StdMutex<Option<(OperationId, ContainerTarget)>>,
    processes_identity: StdMutex<Option<ContainerTarget>>,
    update_identity: StdMutex<Option<DriverUpdateRequest>>,
    stats_identity: StdMutex<Option<ContainerTarget>>,
    read_output_identity: StdMutex<Option<DriverReadOutputRequest>>,
    write_stdin_identity: StdMutex<Option<DriverWriteStdinRequest>>,
    close_stdin_identity: StdMutex<Option<DriverCloseStdinRequest>>,
    resize_identity: StdMutex<Option<DriverResizeRequest>>,
    file_identity: StdMutex<Option<FileRequest>>,
    filesystem_identity: StdMutex<Option<FilesystemRequest>>,
    start_calls: AtomicU32,
    kill_calls: AtomicU32,
    delete_calls: AtomicU32,
    wait_calls: AtomicU32,
    wait_process_calls: AtomicU32,
    exec_calls: AtomicU32,
    signal_process_calls: AtomicU32,
    pause_calls: AtomicU32,
    resume_calls: AtomicU32,
    processes_calls: AtomicU32,
    update_calls: AtomicU32,
    stats_calls: AtomicU32,
    read_output_calls: AtomicU32,
    write_stdin_calls: AtomicU32,
    close_stdin_calls: AtomicU32,
    resize_calls: AtomicU32,
    file_calls: AtomicU32,
    filesystem_calls: AtomicU32,
    recovery_calls: AtomicU32,
    rehydrated_created_record: AtomicBool,
    rehydrated_running_record: AtomicBool,
    rehydrated_stopped_record: AtomicBool,
    rehydrated_exec_record: AtomicBool,
    rehydrated_signal_process: AtomicBool,
    rehydrated_write_stdin: AtomicBool,
    rehydrated_close_stdin: AtomicBool,
    rehydrated_resize: AtomicBool,
    rehydrated_file: AtomicBool,
    rehydrated_filesystem: AtomicBool,
    rehydrated_paused_record: AtomicBool,
    rehydrated_resumed_record: AtomicBool,
    rehydrated_update: AtomicBool,
    rehydrated_running_pid: AtomicI32,
    rehydrated_exec_pid: AtomicI32,
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
            retained_exec: None,
            retained_signal_process: None,
            retained_signal_ready_marker: None,
            retained_write_stdin: None,
            retained_write_ready_marker: None,
            retained_close_stdin: None,
            retained_close_ready_marker: None,
            retained_resize: None,
            retained_resize_ready_marker: None,
            retained_file: None,
            retained_file_ready_marker: None,
            retained_filesystem: None,
            retained_filesystem_ready_marker: None,
            retained_pause: None,
            retained_pause_ready_marker: None,
            retained_resume: None,
            retained_update: None,
            retained_update_ready_marker: None,
            recovery_exec_is_live: true,
            recovery_marker: None,
            qualification,
            session: Mutex::new(None),
            completed_report: Mutex::new(None),
            create_identity: StdMutex::new(None),
            start_identity: StdMutex::new(None),
            kill_identity: StdMutex::new(None),
            delete_identity: StdMutex::new(None),
            wait_identity: StdMutex::new(None),
            wait_process_identity: StdMutex::new(None),
            exec_identity: StdMutex::new(None),
            signal_process_identity: StdMutex::new(None),
            pause_identity: StdMutex::new(None),
            resume_identity: StdMutex::new(None),
            processes_identity: StdMutex::new(None),
            update_identity: StdMutex::new(None),
            stats_identity: StdMutex::new(None),
            read_output_identity: StdMutex::new(None),
            write_stdin_identity: StdMutex::new(None),
            close_stdin_identity: StdMutex::new(None),
            resize_identity: StdMutex::new(None),
            file_identity: StdMutex::new(None),
            filesystem_identity: StdMutex::new(None),
            start_calls: AtomicU32::new(0),
            kill_calls: AtomicU32::new(0),
            delete_calls: AtomicU32::new(0),
            wait_calls: AtomicU32::new(0),
            wait_process_calls: AtomicU32::new(0),
            exec_calls: AtomicU32::new(0),
            signal_process_calls: AtomicU32::new(0),
            pause_calls: AtomicU32::new(0),
            resume_calls: AtomicU32::new(0),
            processes_calls: AtomicU32::new(0),
            update_calls: AtomicU32::new(0),
            stats_calls: AtomicU32::new(0),
            read_output_calls: AtomicU32::new(0),
            write_stdin_calls: AtomicU32::new(0),
            close_stdin_calls: AtomicU32::new(0),
            resize_calls: AtomicU32::new(0),
            file_calls: AtomicU32::new(0),
            filesystem_calls: AtomicU32::new(0),
            recovery_calls: AtomicU32::new(0),
            rehydrated_created_record: AtomicBool::new(false),
            rehydrated_running_record: AtomicBool::new(false),
            rehydrated_stopped_record: AtomicBool::new(false),
            rehydrated_exec_record: AtomicBool::new(false),
            rehydrated_signal_process: AtomicBool::new(false),
            rehydrated_write_stdin: AtomicBool::new(false),
            rehydrated_close_stdin: AtomicBool::new(false),
            rehydrated_resize: AtomicBool::new(false),
            rehydrated_file: AtomicBool::new(false),
            rehydrated_filesystem: AtomicBool::new(false),
            rehydrated_paused_record: AtomicBool::new(false),
            rehydrated_resumed_record: AtomicBool::new(false),
            rehydrated_update: AtomicBool::new(false),
            rehydrated_running_pid: AtomicI32::new(0),
            rehydrated_exec_pid: AtomicI32::new(0),
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

    pub(super) fn with_update_recovery(
        prepared: &PreparedUtilityVmLayout,
        console: PathBuf,
        retained_create: CreateRequest,
        retained_start: StartRequest,
        retained_update: Option<UpdateRequest>,
        retained_update_ready_marker: Option<(PathBuf, Vec<u8>)>,
    ) -> Self {
        let mut driver =
            Self::with_start_recovery(prepared, console, retained_create, retained_start);
        driver.retained_update = retained_update;
        driver.retained_update_ready_marker = retained_update_ready_marker;
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

    pub(super) fn with_exec_recovery(
        prepared: &PreparedUtilityVmLayout,
        console: PathBuf,
        retained_create: CreateRequest,
        retained_start: StartRequest,
        retained_exec: Option<ExecRequest>,
    ) -> Self {
        let mut driver =
            Self::with_start_recovery(prepared, console, retained_create, retained_start);
        driver.retained_exec = retained_exec;
        driver
    }

    pub(super) fn with_signal_process_recovery(
        prepared: &PreparedUtilityVmLayout,
        console: PathBuf,
        retained_create: CreateRequest,
        retained_start: StartRequest,
        retained_exec: ExecRequest,
        retained_signal_process: Option<SignalProcessRequest>,
        retained_signal_ready_marker: Option<(PathBuf, Vec<u8>)>,
    ) -> Self {
        let mut driver = Self::with_exec_recovery(
            prepared,
            console,
            retained_create,
            retained_start,
            Some(retained_exec),
        );
        driver.retained_signal_process = retained_signal_process;
        driver.retained_signal_ready_marker = retained_signal_ready_marker;
        driver
    }

    pub(super) fn with_write_stdin_recovery(
        prepared: &PreparedUtilityVmLayout,
        console: PathBuf,
        retained_create: CreateRequest,
        retained_start: StartRequest,
        retained_exec: ExecRequest,
        retained_write_stdin: Option<WriteStdinRequest>,
        retained_write_ready_marker: Option<(PathBuf, Vec<u8>)>,
    ) -> Self {
        let mut driver = Self::with_exec_recovery(
            prepared,
            console,
            retained_create,
            retained_start,
            Some(retained_exec),
        );
        driver.retained_write_stdin = retained_write_stdin;
        driver.retained_write_ready_marker = retained_write_ready_marker;
        driver
    }

    pub(super) fn with_close_stdin_recovery(
        prepared: &PreparedUtilityVmLayout,
        console: PathBuf,
        retained_create: CreateRequest,
        retained_start: StartRequest,
        retained_exec: ExecRequest,
        retained_close_stdin: Option<CloseStdinRequest>,
        retained_close_ready_marker: Option<(PathBuf, Vec<u8>)>,
    ) -> Self {
        let mut driver = Self::with_exec_recovery(
            prepared,
            console,
            retained_create,
            retained_start,
            Some(retained_exec),
        );
        driver.retained_close_stdin = retained_close_stdin;
        driver.retained_close_ready_marker = retained_close_ready_marker;
        driver
    }

    pub(super) fn with_resize_recovery(
        prepared: &PreparedUtilityVmLayout,
        console: PathBuf,
        retained_create: CreateRequest,
        retained_start: StartRequest,
        retained_exec: ExecRequest,
        retained_resize: Option<ResizeRequest>,
        retained_resize_ready_marker: Option<(PathBuf, Vec<u8>)>,
    ) -> Self {
        let mut driver = Self::with_exec_recovery(
            prepared,
            console,
            retained_create,
            retained_start,
            Some(retained_exec),
        );
        driver.retained_resize = retained_resize;
        driver.retained_resize_ready_marker = retained_resize_ready_marker;
        driver
    }

    pub(super) fn with_file_recovery(
        prepared: &PreparedUtilityVmLayout,
        console: PathBuf,
        retained_create: CreateRequest,
        retained_start: StartRequest,
        retained_file: Option<FileRequest>,
        retained_file_ready_marker: Option<(PathBuf, Vec<u8>)>,
    ) -> Self {
        let mut driver =
            Self::with_start_recovery(prepared, console, retained_create, retained_start);
        driver.retained_file = retained_file;
        driver.retained_file_ready_marker = retained_file_ready_marker;
        driver
    }

    pub(super) fn with_filesystem_recovery(
        prepared: &PreparedUtilityVmLayout,
        console: PathBuf,
        retained_create: CreateRequest,
        retained_start: StartRequest,
        retained_filesystem: Option<FilesystemRequest>,
        retained_filesystem_ready_marker: Option<(PathBuf, Vec<u8>)>,
    ) -> Self {
        let mut driver =
            Self::with_start_recovery(prepared, console, retained_create, retained_start);
        driver.retained_filesystem = retained_filesystem;
        driver.retained_filesystem_ready_marker = retained_filesystem_ready_marker;
        driver
    }

    pub(super) fn with_wait_process_recovery(
        prepared: &PreparedUtilityVmLayout,
        console: PathBuf,
        retained_create: CreateRequest,
        retained_start: StartRequest,
        retained_exec: ExecRequest,
        recovery: WaitProcessRecovery,
    ) -> Self {
        let mut driver = Self::with_signal_process_recovery(
            prepared,
            console,
            retained_create,
            retained_start,
            retained_exec,
            Some(recovery.signal_process),
            Some(recovery.signal_ready_marker),
        );
        driver.recovery_exec_is_live = recovery.exec_is_live;
        driver
    }

    pub(super) fn with_pause_recovery(
        prepared: &PreparedUtilityVmLayout,
        console: PathBuf,
        retained_create: CreateRequest,
        retained_start: StartRequest,
        retained_pause: Option<ContainerOperationRequest>,
        retained_pause_ready_marker: Option<(PathBuf, Vec<u8>)>,
    ) -> Self {
        let mut driver =
            Self::with_start_recovery(prepared, console, retained_create, retained_start);
        driver.retained_pause = retained_pause;
        driver.retained_pause_ready_marker = retained_pause_ready_marker;
        driver
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn with_resume_recovery(
        prepared: &PreparedUtilityVmLayout,
        console: PathBuf,
        retained_create: CreateRequest,
        retained_start: StartRequest,
        retained_pause: ContainerOperationRequest,
        retained_pause_ready_marker: (PathBuf, Vec<u8>),
        retained_resume: Option<ContainerOperationRequest>,
    ) -> Self {
        let mut driver = Self::with_pause_recovery(
            prepared,
            console,
            retained_create,
            retained_start,
            Some(retained_pause),
            Some(retained_pause_ready_marker),
        );
        driver.retained_resume = retained_resume;
        driver
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
        // Keep the active owner published until its destructive shutdown has
        // completed.  If this caller is cancelled while the VM is being
        // reaped, a replacement caller can resume the same idempotent owner
        // shutdown instead of observing an empty slot and losing the handle.
        let owner = self
            .session
            .lock()
            .await
            .as_ref()
            .map(|active| Arc::clone(&active.owner));
        if let Some(owner) = owner {
            let report = owner.shutdown().await;
            *self.completed_report.lock().await = Some(report.clone());
            self.session.lock().await.take();
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

    async fn exec(&self, request: DriverExecRequest) -> Result<DriverProcess> {
        self.dispatch_exec(request).await
    }

    async fn signal_process(&self, request: DriverSignalProcessRequest) -> Result<()> {
        self.dispatch_signal_process(request).await
    }

    async fn wait_process(&self, request: DriverWaitProcessRequest) -> Result<ExitStatus> {
        self.dispatch_wait_process(request).await
    }

    async fn pause(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.dispatch_pause(request).await
    }

    async fn resume(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.dispatch_resume(request).await
    }

    async fn processes(&self, target: ContainerTarget) -> Result<Vec<ProcessRecord>> {
        self.dispatch_processes(target).await
    }

    async fn update(&self, request: DriverUpdateRequest) -> Result<DriverState> {
        self.dispatch_update(request).await
    }

    async fn stats(&self, target: ContainerTarget) -> Result<ContainerStats> {
        self.dispatch_stats(target).await
    }

    async fn read_output(&self, request: DriverReadOutputRequest) -> Result<Vec<OutputChunk>> {
        self.dispatch_read_output(request).await
    }

    async fn write_stdin(&self, request: DriverWriteStdinRequest) -> Result<()> {
        self.dispatch_write_stdin(request).await
    }

    async fn close_stdin(&self, request: DriverCloseStdinRequest) -> Result<()> {
        self.dispatch_close_stdin(request).await
    }

    async fn resize(&self, request: DriverResizeRequest) -> Result<()> {
        self.dispatch_resize(request).await
    }

    async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        self.dispatch_file(request).await
    }

    async fn filesystem(&self, request: FilesystemRequest) -> Result<FilesystemResponse> {
        self.dispatch_filesystem(request).await
    }
}

fn qualification_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("qualification-kvm-operation-reopen")
}
