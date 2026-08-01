use std::collections::BTreeMap;
use std::fmt;
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Weak};

use a3s_oci_agent_protocol::{GuestAgentService, GuestPath};
use a3s_oci_core::{CapabilityStatus, DriverCapability, DriverReadiness, IsolationClass};
use a3s_oci_sdk::{
    async_trait, ContainerId, ContainerRecord, ContainerStats, ContainerTarget, Error, ErrorCode,
    ExitStatus, OutputChunk, ProcessRecord, Result, RuntimeOperation,
};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

use crate::agent_driver::{AgentDriverClient, AGENT_DRIVER_HOOKS, AGENT_DRIVER_OPERATIONS};
use crate::agent_session::UtilityVmSession;
use crate::driver::{
    DriverCloseStdinRequest, DriverContainerOperationRequest, DriverCreateRequest,
    DriverDeleteRequest, DriverExecRequest, DriverKillRequest, DriverProcess,
    DriverReadOutputRequest, DriverResizeRequest, DriverSignalProcessRequest, DriverStartRequest,
    DriverState, DriverUpdateRequest, DriverWaitProcessRequest, DriverWaitRequest,
    DriverWriteStdinRequest, OciHookPhase, RuntimeDriver,
};

const CONSOLE_DIRECTORY: &str = "console";

/// Protected host paths used by the one-VM-per-container WHPX driver candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhpxRuntimeDriverConfig {
    shim: PathBuf,
    runtime_root: PathBuf,
    vm_rootfs: PathBuf,
}

impl WhpxRuntimeDriverConfig {
    /// Describe the isolated libkrun shim, protected runtime root, and guest root.
    ///
    /// The guest root must be a strict descendant of `runtime_root`. Opening the
    /// candidate verifies plain paths and applies the private Windows DACL to
    /// both roots before any VM can launch.
    #[must_use]
    pub fn new(
        shim: impl Into<PathBuf>,
        runtime_root: impl Into<PathBuf>,
        vm_rootfs: impl Into<PathBuf>,
    ) -> Self {
        Self {
            shim: shim.into(),
            runtime_root: runtime_root.into(),
            vm_rootfs: vm_rootfs.into(),
        }
    }

    /// Isolated libkrun shim executable.
    #[must_use]
    pub fn shim(&self) -> &Path {
        &self.shim
    }

    /// Protected root that owns every mutable WHPX runtime artifact.
    #[must_use]
    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }

    /// Guest root exported to each dedicated utility VM.
    #[must_use]
    pub fn vm_rootfs(&self) -> &Path {
        &self.vm_rootfs
    }
}

/// Candidate WHPX driver that owns one authenticated utility VM per container.
///
/// The complete live eighteen-operation contract is implemented and
/// qualification tests may invoke it directly. Its capability deliberately
/// remains `probe-only`, so
/// [`crate::HostRuntimeService`] rejects production registration until the
/// immutable-system-root and restart-reattachment gates are complete.
pub struct WhpxRuntimeDriver {
    capability: DriverCapability,
    vm_rootfs: PathBuf,
    factory: Arc<dyn UtilityVmFactory>,
    sessions: Mutex<BTreeMap<ContainerId, WhpxAttachment>>,
    create_gates: Mutex<BTreeMap<ContainerId, Weak<Mutex<()>>>>,
}

impl fmt::Debug for WhpxRuntimeDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WhpxRuntimeDriver")
            .field("capability", &self.capability)
            .field("vm_rootfs", &self.vm_rootfs)
            .finish_non_exhaustive()
    }
}

impl WhpxRuntimeDriver {
    /// Open the non-registerable WHPX driver candidate around protected paths.
    pub async fn open_candidate(config: WhpxRuntimeDriverConfig) -> Result<Self> {
        let mut capability = crate::platform::whpx_driver_capability();
        if capability.status != CapabilityStatus::Available {
            return Err(Error::new(
                ErrorCode::Unavailable,
                capability
                    .reason
                    .clone()
                    .unwrap_or_else(|| "Windows Hypervisor Platform is unavailable".to_string()),
            )
            .for_operation("open-whpx-driver-candidate"));
        }
        let prepared = PreparedWhpxLayout::open(config).await?;
        capability.readiness = DriverReadiness::ProbeOnly;
        capability.isolation_classes = vec![IsolationClass::DedicatedVm];
        capability.evidence.insert(
            "execution_path".to_string(),
            "one-utility-vm-per-container".to_string(),
        );
        capability
            .evidence
            .insert("runtime_root_protected".to_string(), "true".to_string());
        capability
            .evidence
            .insert("owner_death_recovery".to_string(), "stopped".to_string());
        capability
            .evidence
            .insert("restart_exit_evidence".to_string(), "pending".to_string());
        capability
            .evidence
            .insert("opt_in".to_string(), "qualification-only".to_string());

        let factory = Arc::new(LiveUtilityVmFactory {
            shim: prepared.shim,
            vm_rootfs: prepared.vm_rootfs.clone(),
            console_directory: prepared.console_directory,
        });
        Ok(Self {
            capability,
            vm_rootfs: prepared.vm_rootfs,
            factory,
            sessions: Mutex::new(BTreeMap::new()),
            create_gates: Mutex::new(BTreeMap::new()),
        })
    }

    /// Close every attached guest transport, reap each owned VM once, and
    /// retain stopped tombstones for durable host reconciliation.
    pub async fn shutdown(&self) -> Result<()> {
        let sessions = {
            let sessions = self.sessions.lock().await;
            sessions
                .values()
                .filter_map(|attachment| match attachment {
                    WhpxAttachment::Live(session) => Some(Arc::clone(session)),
                    WhpxAttachment::RecoveredStopped(_) => None,
                })
                .collect::<Vec<_>>()
        };
        let mut shutdowns = JoinSet::new();
        for session in sessions {
            shutdowns.spawn(async move {
                let result = session.owner.shutdown().await;
                (session, result)
            });
        }
        let mut failures = Vec::new();
        while let Some(completed) = shutdowns.join_next().await {
            match completed {
                Ok((session, Ok(()))) => self.replace_with_stopped(&session).await,
                Ok((_session, Err(error))) => failures.push(error.to_string()),
                Err(error) => failures.push(format!("utility VM shutdown task failed: {error}")),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::Internal,
                format!(
                    "failed to shut down {} WHPX utility VM session(s): {}",
                    failures.len(),
                    failures.join("; ")
                ),
            )
            .for_operation("shutdown-whpx-driver"))
        }
    }

    /// Number of container generations with an attached utility VM.
    pub async fn active_session_count(&self) -> usize {
        self.sessions
            .lock()
            .await
            .values()
            .filter(|attachment| matches!(attachment, WhpxAttachment::Live(_)))
            .count()
    }

    async fn attachment_for(
        &self,
        target: &ContainerTarget,
        operation: &'static str,
    ) -> Result<WhpxAttachment> {
        require_exact_generation(target, operation)?;
        let sessions = self.sessions.lock().await;
        let attachment = sessions.get(&target.id).cloned().ok_or_else(|| {
            Error::new(
                ErrorCode::Unavailable,
                format!(
                    "container {} has neither an attached WHPX utility VM nor a recovered stop record",
                    target.id
                ),
            )
            .for_operation(operation)
        })?;
        if attachment.target() != target {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!(
                    "container {} is attached at generation {:?}, not {:?}",
                    target.id,
                    attachment.target().generation,
                    target.generation
                ),
            )
            .for_operation(operation));
        }
        Ok(attachment)
    }

    async fn session_for(
        &self,
        target: &ContainerTarget,
        operation: &'static str,
    ) -> Result<Arc<WhpxContainer>> {
        match self.attachment_for(target, operation).await? {
            WhpxAttachment::Live(session) => Ok(session),
            WhpxAttachment::RecoveredStopped(_) => Err(recovered_stopped_error(target, operation)),
        }
    }

    async fn remove_live_session(&self, expected: &Arc<WhpxContainer>) {
        let mut sessions = self.sessions.lock().await;
        let remove = matches!(
            sessions.get(&expected.target.id),
            Some(WhpxAttachment::Live(current)) if Arc::ptr_eq(current, expected)
        );
        if remove {
            sessions.remove(&expected.target.id);
        }
    }

    async fn replace_with_stopped(&self, expected: &Arc<WhpxContainer>) {
        let mut sessions = self.sessions.lock().await;
        let replace = matches!(
            sessions.get(&expected.target.id),
            Some(WhpxAttachment::Live(current)) if Arc::ptr_eq(current, expected)
        );
        if replace {
            sessions.insert(
                expected.target.id.clone(),
                WhpxAttachment::RecoveredStopped(expected.target.clone()),
            );
        }
    }

    async fn remove_stopped(&self, expected: &ContainerTarget) {
        let mut sessions = self.sessions.lock().await;
        let remove = matches!(
            sessions.get(&expected.id),
            Some(WhpxAttachment::RecoveredStopped(current)) if current == expected
        );
        if remove {
            sessions.remove(&expected.id);
        }
    }

    async fn cleanup_terminal_create_error(
        &self,
        session: &Arc<WhpxContainer>,
        mut error: Error,
    ) -> Error {
        match session.owner.shutdown().await {
            Ok(()) => self.remove_live_session(session).await,
            Err(cleanup) => {
                error.message = format!(
                    "{}; failed to reap the dedicated utility VM: {}",
                    error.message, cleanup
                );
            }
        }
        error
    }

    async fn create_gate_for(&self, id: &ContainerId) -> Arc<Mutex<()>> {
        let mut gates = self.create_gates.lock().await;
        gates.retain(|_, gate| gate.strong_count() > 0);
        if let Some(gate) = gates.get(id).and_then(Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(Mutex::new(()));
        gates.insert(id.clone(), Arc::downgrade(&gate));
        gate
    }
}

#[async_trait]
impl RuntimeDriver for WhpxRuntimeDriver {
    fn capability(&self) -> DriverCapability {
        self.capability.clone()
    }

    fn operations(&self) -> &[RuntimeOperation] {
        &AGENT_DRIVER_OPERATIONS
    }

    fn hooks(&self) -> &[OciHookPhase] {
        &AGENT_DRIVER_HOOKS
    }

    async fn recover(&self, record: &ContainerRecord) -> Result<Option<DriverState>> {
        let target =
            ContainerTarget::exact(ContainerId::new(record.state.id())?, record.generation);
        let can_commit_stopped =
            *record.state.status() != a3s_oci_sdk::oci_spec::runtime::ContainerState::Creating;
        let attachment = {
            let mut sessions = self.sessions.lock().await;
            match sessions.get(&target.id) {
                Some(attachment) => attachment.clone(),
                None => {
                    sessions.insert(target.id.clone(), WhpxAttachment::RecoveredStopped(target));
                    return Ok(can_commit_stopped.then_some(DriverState::stopped()));
                }
            }
        };
        if attachment.target() != &target {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!(
                    "container {} is attached at generation {:?}, not durable generation {:?}",
                    target.id,
                    attachment.target().generation,
                    target.generation
                ),
            )
            .for_operation("whpx-recover"));
        }
        match attachment {
            WhpxAttachment::Live(session) => {
                let observed = session
                    .client
                    .state_with_digest(target, Some(&record.config_digest))
                    .await?;
                Ok(can_commit_stopped.then_some(observed))
            }
            WhpxAttachment::RecoveredStopped(_) => {
                Ok(can_commit_stopped.then_some(DriverState::stopped()))
            }
        }
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        if request.isolation.class() != IsolationClass::DedicatedVm {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "the WHPX driver candidate provides only one-VM-per-container isolation",
            )
            .for_operation("whpx-create"));
        }
        require_exact_generation(&request.target, "whpx-create")?;
        let guest_directory =
            guest_bundle_path(&self.vm_rootfs, request.bundle.directory()).await?;
        let target = request.target.clone();

        let create_gate = self.create_gate_for(&target.id).await;
        let _create_guard = create_gate.lock().await;
        let session = match self.session_for_existing_create(&target).await? {
            Some(session) => session,
            None => {
                let launched = self.factory.launch(&target).await?;
                let session = Arc::new(WhpxContainer {
                    target: target.clone(),
                    client: launched.client,
                    owner: launched.owner,
                });
                self.sessions.lock().await.insert(
                    target.id.clone(),
                    WhpxAttachment::Live(Arc::clone(&session)),
                );
                session
            }
        };

        match session.client.create(request, guest_directory).await {
            Ok(state) => Ok(state),
            Err(error) if error.retryable => Err(error),
            Err(error) => Err(self.cleanup_terminal_create_error(&session, error).await),
        }
    }

    async fn state(&self, target: ContainerTarget) -> Result<DriverState> {
        match self.attachment_for(&target, "whpx-state").await? {
            WhpxAttachment::Live(session) => session.client.state(target).await,
            WhpxAttachment::RecoveredStopped(_) => Ok(DriverState::stopped()),
        }
    }

    async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        self.session_for(&request.target, "whpx-start")
            .await?
            .client
            .start(request)
            .await
    }

    async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        match self.attachment_for(&request.target, "whpx-kill").await? {
            WhpxAttachment::Live(session) => session.client.kill(request).await,
            WhpxAttachment::RecoveredStopped(_) => Ok(DriverState::stopped()),
        }
    }

    async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        match self.attachment_for(&request.target, "whpx-delete").await? {
            WhpxAttachment::Live(session) => {
                session.client.delete(request).await?;
                session.owner.shutdown().await?;
                self.remove_live_session(&session).await;
                Ok(())
            }
            WhpxAttachment::RecoveredStopped(target) => {
                self.remove_stopped(&target).await;
                Ok(())
            }
        }
    }

    async fn wait(&self, request: DriverWaitRequest) -> Result<ExitStatus> {
        match self.attachment_for(&request.target, "whpx-wait").await? {
            WhpxAttachment::Live(session) => session.client.wait(request).await,
            WhpxAttachment::RecoveredStopped(_) => {
                Err(recovered_exit_evidence_error(&request.target, "whpx-wait"))
            }
        }
    }

    async fn exec(&self, request: DriverExecRequest) -> Result<DriverProcess> {
        self.session_for(&request.target.container, "whpx-exec")
            .await?
            .client
            .exec(request)
            .await
    }

    async fn signal_process(&self, request: DriverSignalProcessRequest) -> Result<()> {
        self.session_for(&request.target.container, "whpx-signal-process")
            .await?
            .client
            .signal_process(request)
            .await
    }

    async fn wait_process(&self, request: DriverWaitProcessRequest) -> Result<ExitStatus> {
        self.session_for(&request.target.container, "whpx-wait-process")
            .await?
            .client
            .wait_process(request)
            .await
    }

    async fn pause(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.session_for(&request.target, "whpx-pause")
            .await?
            .client
            .pause(request)
            .await
    }

    async fn resume(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.session_for(&request.target, "whpx-resume")
            .await?
            .client
            .resume(request)
            .await
    }

    async fn processes(&self, target: ContainerTarget) -> Result<Vec<ProcessRecord>> {
        match self.attachment_for(&target, "whpx-processes").await? {
            WhpxAttachment::Live(session) => session.client.processes(target).await,
            WhpxAttachment::RecoveredStopped(_) => Ok(Vec::new()),
        }
    }

    async fn update(&self, request: DriverUpdateRequest) -> Result<DriverState> {
        self.session_for(&request.target, "whpx-update")
            .await?
            .client
            .update(request)
            .await
    }

    async fn stats(&self, target: ContainerTarget) -> Result<ContainerStats> {
        self.session_for(&target, "whpx-stats")
            .await?
            .client
            .stats(target)
            .await
    }

    async fn read_output(&self, request: DriverReadOutputRequest) -> Result<Vec<OutputChunk>> {
        self.session_for(&request.target.container, "whpx-read-output")
            .await?
            .client
            .read_output(request)
            .await
    }

    async fn write_stdin(&self, request: DriverWriteStdinRequest) -> Result<()> {
        self.session_for(&request.target.container, "whpx-write-stdin")
            .await?
            .client
            .write_stdin(request)
            .await
    }

    async fn close_stdin(&self, request: DriverCloseStdinRequest) -> Result<()> {
        self.session_for(&request.target.container, "whpx-close-stdin")
            .await?
            .client
            .close_stdin(request)
            .await
    }

    async fn resize(&self, request: DriverResizeRequest) -> Result<()> {
        self.session_for(&request.target.container, "whpx-resize")
            .await?
            .client
            .resize(request)
            .await
    }
}

impl WhpxRuntimeDriver {
    async fn session_for_existing_create(
        &self,
        target: &ContainerTarget,
    ) -> Result<Option<Arc<WhpxContainer>>> {
        let sessions = self.sessions.lock().await;
        let Some(attachment) = sessions.get(&target.id) else {
            return Ok(None);
        };
        if attachment.target() != target {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!(
                    "container {} already owns a WHPX attachment at generation {:?}",
                    target.id,
                    attachment.target().generation
                ),
            )
            .for_operation("whpx-create"));
        }
        match attachment {
            WhpxAttachment::Live(session) => Ok(Some(Arc::clone(session))),
            WhpxAttachment::RecoveredStopped(_) => {
                Err(recovered_stopped_error(target, "whpx-create"))
            }
        }
    }
}

#[derive(Clone)]
enum WhpxAttachment {
    Live(Arc<WhpxContainer>),
    RecoveredStopped(ContainerTarget),
}

impl WhpxAttachment {
    fn target(&self) -> &ContainerTarget {
        match self {
            Self::Live(session) => &session.target,
            Self::RecoveredStopped(target) => target,
        }
    }
}

struct WhpxContainer {
    target: ContainerTarget,
    client: AgentDriverClient,
    owner: Arc<dyn UtilityVmOwner>,
}

struct LaunchedUtilityVm {
    client: AgentDriverClient,
    owner: Arc<dyn UtilityVmOwner>,
}

#[async_trait]
trait UtilityVmFactory: Send + Sync {
    async fn launch(&self, target: &ContainerTarget) -> Result<LaunchedUtilityVm>;
}

#[async_trait]
trait UtilityVmOwner: Send + Sync {
    async fn shutdown(&self) -> Result<()>;
}

struct LiveUtilityVmFactory {
    shim: PathBuf,
    vm_rootfs: PathBuf,
    console_directory: PathBuf,
}

#[async_trait]
impl UtilityVmFactory for LiveUtilityVmFactory {
    async fn launch(&self, target: &ContainerTarget) -> Result<LaunchedUtilityVm> {
        let generation = require_exact_generation(target, "launch-whpx-utility-vm")?;
        let console = self
            .console_directory
            .join(format!("{}-{}.log", target.id, generation.0));
        let session = Arc::new(
            UtilityVmSession::connect(&self.shim, &self.vm_rootfs, &console)
                .await
                .map_err(vm_launch_error)?,
        );
        let service: Arc<dyn GuestAgentService> = Arc::new(session.client());
        Ok(LaunchedUtilityVm {
            client: AgentDriverClient::new(service, "WHPX guest agent", "whpx"),
            owner: Arc::new(LiveUtilityVmOwner { session }),
        })
    }
}

struct LiveUtilityVmOwner {
    session: Arc<UtilityVmSession>,
}

#[async_trait]
impl UtilityVmOwner for LiveUtilityVmOwner {
    async fn shutdown(&self) -> Result<()> {
        let report = self.session.shutdown().await;
        if report.is_success() {
            Ok(())
        } else {
            Err(vm_report_error("shutdown-whpx-utility-vm", report))
        }
    }
}

struct PreparedWhpxLayout {
    shim: PathBuf,
    vm_rootfs: PathBuf,
    console_directory: PathBuf,
}

impl PreparedWhpxLayout {
    async fn open(config: WhpxRuntimeDriverConfig) -> Result<Self> {
        let shim = canonical_plain_file(&config.shim, "WHPX shim").await?;
        let runtime_root =
            canonical_plain_directory(&config.runtime_root, "WHPX runtime root").await?;
        let vm_rootfs = canonical_plain_directory(&config.vm_rootfs, "WHPX guest root").await?;
        if vm_rootfs == runtime_root || !vm_rootfs.starts_with(&runtime_root) {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "WHPX guest root must be a strict descendant of protected runtime root {}: {}",
                    runtime_root.display(),
                    vm_rootfs.display()
                ),
            )
            .for_operation("open-whpx-driver-candidate"));
        }
        let guest_agent = canonical_plain_file(
            &vm_rootfs.join("usr/bin/a3s-oci-agent"),
            "fixed WHPX guest agent",
        )
        .await?;

        protect_path(runtime_root.clone()).await?;
        protect_path(vm_rootfs.clone()).await?;
        protect_path(guest_agent).await?;
        let console_directory = runtime_root.join(CONSOLE_DIRECTORY);
        ensure_private_directory(console_directory.clone()).await?;
        Ok(Self {
            shim,
            vm_rootfs,
            console_directory,
        })
    }
}

async fn canonical_plain_file(path: &Path, label: &str) -> Result<PathBuf> {
    canonical_plain_path(path, label, true).await
}

async fn canonical_plain_directory(path: &Path, label: &str) -> Result<PathBuf> {
    canonical_plain_path(path, label, false).await
}

async fn canonical_plain_path(path: &Path, label: &str, file: bool) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{label} must be absolute: {}", path.display()),
        )
        .for_operation("open-whpx-driver-candidate"));
    }
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        path_error(
            ErrorCode::FailedPrecondition,
            format!("failed to inspect {label} {}: {error}", path.display()),
        )
    })?;
    let expected_kind = if file {
        metadata.is_file()
    } else {
        metadata.is_dir()
    };
    if !expected_kind
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(path_error(
            ErrorCode::FailedPrecondition,
            format!(
                "{label} is not a plain {}: {}",
                if file { "file" } else { "directory" },
                path.display()
            ),
        ));
    }
    tokio::fs::canonicalize(path).await.map_err(|error| {
        path_error(
            ErrorCode::FailedPrecondition,
            format!("failed to resolve {label} {}: {error}", path.display()),
        )
    })
}

async fn protect_path(path: PathBuf) -> Result<()> {
    tokio::task::spawn_blocking(move || crate::windows_security::protect_path(&path))
        .await
        .map_err(|error| {
            path_error(
                ErrorCode::Internal,
                format!("WHPX path-protection task failed: {error}"),
            )
        })?
}

async fn ensure_private_directory(path: PathBuf) -> Result<()> {
    match tokio::fs::symlink_metadata(&path).await {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 =>
        {
            protect_path(path).await
        }
        Ok(_) => Err(path_error(
            ErrorCode::FailedPrecondition,
            format!(
                "WHPX console path is not a plain directory: {}",
                path.display()
            ),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            tokio::task::spawn_blocking(move || {
                crate::windows_security::create_private_directory(&path)
            })
            .await
            .map_err(|error| {
                path_error(
                    ErrorCode::Internal,
                    format!("WHPX console-directory task failed: {error}"),
                )
            })?
        }
        Err(error) => Err(path_error(
            ErrorCode::Internal,
            format!(
                "failed to inspect WHPX console directory {}: {error}",
                path.display()
            ),
        )),
    }
}

async fn guest_bundle_path(vm_rootfs: &Path, bundle: &Path) -> Result<GuestPath> {
    let bundle = canonical_plain_directory(bundle, "WHPX OCI bundle").await?;
    let relative = bundle.strip_prefix(vm_rootfs).map_err(|error| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "WHPX OCI bundle must be contained by guest root {}: {} ({error})",
                vm_rootfs.display(),
                bundle.display()
            ),
        )
        .for_operation("whpx-create")
    })?;
    let mut components = Vec::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "WHPX OCI bundle has a non-normal component: {}",
                    bundle.display()
                ),
            )
            .for_operation("whpx-create"));
        };
        let component = component.to_str().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("WHPX OCI bundle path is not Unicode: {}", bundle.display()),
            )
            .for_operation("whpx-create")
        })?;
        if component.contains(['/', '\\', '\0']) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "WHPX OCI bundle has an invalid guest component: {}",
                    bundle.display()
                ),
            )
            .for_operation("whpx-create"));
        }
        components.push(component);
    }
    if components.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "WHPX OCI bundle cannot be the guest root itself",
        )
        .for_operation("whpx-create"));
    }
    GuestPath::new(format!("/{}", components.join("/")))
}

fn require_exact_generation(
    target: &ContainerTarget,
    operation: &'static str,
) -> Result<a3s_oci_sdk::Generation> {
    target.generation.ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "WHPX driver operation requires an exact generation for container {}",
                target.id
            ),
        )
        .for_operation(operation)
    })
}

fn recovered_stopped_error(target: &ContainerTarget, operation: &'static str) -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        format!(
            "container {} generation {:?} was recovered as stopped after its WHPX owner exited; no live utility VM remains, so this generation must be deleted before another live operation",
            target.id, target.generation
        ),
    )
    .for_operation(operation)
}

fn recovered_exit_evidence_error(target: &ContainerTarget, operation: &'static str) -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        format!(
            "container {} generation {:?} was stopped by WHPX owner-death cleanup, but its exact init exit status was not retained",
            target.id, target.generation
        ),
    )
    .for_operation(operation)
}

fn vm_launch_error(report: crate::AgentVmSmokeReport) -> Error {
    let retryable = !report.protocol_negotiated;
    vm_report_error("launch-whpx-utility-vm", report).retryable(retryable)
}

fn vm_report_error(operation: &'static str, report: crate::AgentVmSmokeReport) -> Error {
    let reason = report.reason.unwrap_or_else(|| {
        "authenticated WHPX utility VM did not satisfy its contract".to_string()
    });
    Error::new(ErrorCode::Unavailable, reason).for_operation(operation)
}

fn path_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("open-whpx-driver-candidate")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};

    use a3s_oci_agent_protocol::{
        AgentCapabilities, AgentCreateRequest, AgentDeleteRequest, AgentKillRequest,
        AgentStartRequest, AgentState, AgentStateRequest, GuestAgentService,
    };
    use a3s_oci_core::{
        CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, IsolationClass,
    };
    use a3s_oci_sdk::oci_spec::runtime::{ContainerState, StateBuilder};
    use a3s_oci_sdk::{
        async_trait, ContainerId, ContainerRecord, ContainerTarget, DeleteMode, Error, ErrorCode,
        Generation, IsolationRequest, OciBundle, OperationContext, OperationId, ProcessIo, Result,
        Signal,
    };
    use tokio::sync::Mutex;

    use super::{
        AgentDriverClient, DriverCreateRequest, DriverDeleteRequest, DriverKillRequest,
        DriverWaitRequest, LaunchedUtilityVm, RuntimeDriver, UtilityVmFactory, UtilityVmOwner,
        WhpxRuntimeDriver,
    };
    use crate::DriverCreateAttachments;

    const TEST_CONFIG: &str = concat!(
        "{\n",
        "  \"ociVersion\": \"1.3.0\",\n",
        "  \"process\": {\n",
        "    \"terminal\": false,\n",
        "    \"user\": {\"uid\": 0, \"gid\": 0},\n",
        "    \"args\": [\"/bin/true\"],\n",
        "    \"cwd\": \"/\"\n",
        "  },\n",
        "  \"root\": {\"path\": \"rootfs\", \"readonly\": true}\n",
        "}\n",
    );

    #[derive(Default)]
    struct FakeGuest {
        create_calls: AtomicUsize,
        delete_calls: AtomicUsize,
        state_calls: AtomicUsize,
        next_create_failure: StdMutex<Option<Error>>,
        state: StdMutex<Option<AgentState>>,
    }

    impl FakeGuest {
        fn fail_next_create(&self, error: Error) {
            *self
                .next_create_failure
                .lock()
                .expect("create failure lock") = Some(error);
        }
    }

    #[async_trait]
    impl GuestAgentService for FakeGuest {
        fn capabilities(&self) -> AgentCapabilities {
            AgentCapabilities::linux_executor("test", "x86_64").expect("capabilities")
        }

        async fn create(&self, request: AgentCreateRequest) -> Result<AgentState> {
            self.create_calls.fetch_add(1, Ordering::Relaxed);
            if let Some(error) = self
                .next_create_failure
                .lock()
                .expect("create failure lock")
                .take()
            {
                return Err(error);
            }
            let state = AgentState::new(
                request.target,
                ContainerState::Created,
                Some(101),
                request.bundle.config_digest(),
            )?;
            *self.state.lock().expect("state lock") = Some(state.clone());
            Ok(state)
        }

        async fn state(&self, request: AgentStateRequest) -> Result<AgentState> {
            self.state_calls.fetch_add(1, Ordering::Relaxed);
            self.state
                .lock()
                .expect("state lock")
                .clone()
                .filter(|state| state.target() == &request.target)
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "missing fake guest state"))
        }

        async fn start(&self, request: AgentStartRequest) -> Result<AgentState> {
            let state = AgentState::new(
                request.target,
                ContainerState::Running,
                Some(101),
                request.expected_config_digest,
            )?;
            *self.state.lock().expect("state lock") = Some(state.clone());
            Ok(state)
        }

        async fn kill(&self, request: AgentKillRequest) -> Result<AgentState> {
            let digest = self
                .state
                .lock()
                .expect("state lock")
                .as_ref()
                .map(|state| state.config_digest().to_string())
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "missing fake guest state"))?;
            let state = AgentState::new(request.target, ContainerState::Stopped, None, digest)?;
            *self.state.lock().expect("state lock") = Some(state.clone());
            Ok(state)
        }

        async fn delete(&self, _request: AgentDeleteRequest) -> Result<()> {
            self.delete_calls.fetch_add(1, Ordering::Relaxed);
            *self.state.lock().expect("state lock") = None;
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeOwner {
        shutdown_calls: AtomicUsize,
        active_shutdowns: AtomicUsize,
        max_active_shutdowns: AtomicUsize,
    }

    #[async_trait]
    impl UtilityVmOwner for FakeOwner {
        async fn shutdown(&self) -> Result<()> {
            self.shutdown_calls.fetch_add(1, Ordering::Relaxed);
            let active = self.active_shutdowns.fetch_add(1, Ordering::Relaxed) + 1;
            self.max_active_shutdowns
                .fetch_max(active, Ordering::Relaxed);
            tokio::task::yield_now().await;
            self.active_shutdowns.fetch_sub(1, Ordering::Relaxed);
            Ok(())
        }
    }

    struct FakeFactory {
        launches: AtomicUsize,
        active_launches: AtomicUsize,
        max_active_launches: AtomicUsize,
        guest: Arc<FakeGuest>,
        owner: Arc<FakeOwner>,
    }

    #[async_trait]
    impl UtilityVmFactory for FakeFactory {
        async fn launch(&self, _target: &ContainerTarget) -> Result<LaunchedUtilityVm> {
            self.launches.fetch_add(1, Ordering::Relaxed);
            let active = self.active_launches.fetch_add(1, Ordering::Relaxed) + 1;
            self.max_active_launches
                .fetch_max(active, Ordering::Relaxed);
            tokio::task::yield_now().await;
            self.active_launches.fetch_sub(1, Ordering::Relaxed);
            let service: Arc<dyn GuestAgentService> = self.guest.clone();
            let owner: Arc<dyn UtilityVmOwner> = self.owner.clone();
            Ok(LaunchedUtilityVm {
                client: AgentDriverClient::new(service, "fake WHPX guest", "fake-whpx"),
                owner,
            })
        }
    }

    struct Fixture {
        _temporary: tempfile::TempDir,
        bundle: OciBundle,
        guest: Arc<FakeGuest>,
        owner: Arc<FakeOwner>,
        factory: Arc<FakeFactory>,
        driver: WhpxRuntimeDriver,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().expect("temporary WHPX fixture");
            let vm_rootfs = temporary.path().join("vm-root");
            let bundle_directory = vm_rootfs.join("workloads/test");
            std::fs::create_dir_all(&bundle_directory).expect("bundle directory");
            let vm_rootfs = std::fs::canonicalize(vm_rootfs).expect("canonical WHPX fixture root");
            let bundle_directory = vm_rootfs.join("workloads/test");
            let bundle = OciBundle::from_json(bundle_directory, TEST_CONFIG).expect("OCI bundle");
            let guest = Arc::new(FakeGuest::default());
            let owner = Arc::new(FakeOwner::default());
            let factory = Arc::new(FakeFactory {
                launches: AtomicUsize::new(0),
                active_launches: AtomicUsize::new(0),
                max_active_launches: AtomicUsize::new(0),
                guest: guest.clone(),
                owner: owner.clone(),
            });
            let factory_dyn: Arc<dyn UtilityVmFactory> = factory.clone();
            let driver = WhpxRuntimeDriver {
                capability: candidate_capability(),
                vm_rootfs: vm_rootfs.clone(),
                factory: factory_dyn,
                sessions: Mutex::new(BTreeMap::new()),
                create_gates: Mutex::new(BTreeMap::new()),
            };
            Self {
                _temporary: temporary,
                bundle,
                guest,
                owner,
                factory,
                driver,
            }
        }

        fn create_request(&self, generation: u64, operation: &str) -> DriverCreateRequest {
            DriverCreateRequest {
                context: context(operation),
                target: target(generation),
                bundle: self.bundle.clone(),
                isolation: IsolationRequest::DedicatedVm,
                io: ProcessIo::default(),
                attachments: DriverCreateAttachments::None,
            }
        }

        fn record(&self, generation: u64, status: ContainerState) -> ContainerRecord {
            let target = target(generation);
            let mut builder = StateBuilder::default()
                .version(self.bundle.spec().version())
                .id(target.id.as_str())
                .status(status)
                .bundle(self.bundle.directory().to_path_buf());
            if matches!(status, ContainerState::Created | ContainerState::Running) {
                builder = builder.pid(101);
            }
            ContainerRecord {
                state: builder.build().expect("recovery OCI state"),
                generation: Generation(generation),
                driver: DriverKind::LibkrunWhpx,
                isolation: IsolationClass::DedicatedVm,
                config_digest: self.bundle.config_digest().to_string(),
            }
        }
    }

    fn candidate_capability() -> DriverCapability {
        DriverCapability {
            driver: DriverKind::LibkrunWhpx,
            status: CapabilityStatus::Available,
            readiness: DriverReadiness::ProbeOnly,
            isolation_classes: vec![IsolationClass::DedicatedVm],
            reason: None,
            evidence: BTreeMap::new(),
        }
    }

    fn target(generation: u64) -> ContainerTarget {
        ContainerTarget::exact(
            ContainerId::new("whpx-test").expect("container ID"),
            Generation(generation),
        )
    }

    fn context(operation: &str) -> OperationContext {
        OperationContext::new(OperationId::new(operation).expect("operation ID"))
    }

    fn delete_request(generation: u64) -> DriverDeleteRequest {
        DriverDeleteRequest {
            context: context("delete"),
            target: target(generation),
            mode: DeleteMode::Force,
        }
    }

    #[tokio::test]
    async fn concurrent_create_reuses_one_vm_and_delete_reaps_it_once() {
        let fixture = Fixture::new();
        let request = fixture.create_request(1, "create");
        let (first, replay) = tokio::join!(
            fixture.driver.create(request.clone()),
            fixture.driver.create(request)
        );
        let first = first.expect("first create");
        let replay = replay.expect("concurrent replayed create");

        assert_eq!(first, replay);
        assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
        assert_eq!(
            fixture.factory.max_active_launches.load(Ordering::Relaxed),
            1
        );
        assert_eq!(fixture.guest.create_calls.load(Ordering::Relaxed), 2);
        assert_eq!(fixture.driver.active_session_count().await, 1);

        fixture
            .driver
            .delete(delete_request(1))
            .await
            .expect("delete");
        assert_eq!(fixture.guest.delete_calls.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.driver.active_session_count().await, 0);
        fixture
            .driver
            .shutdown()
            .await
            .expect("idempotent shutdown");
        assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn different_container_ids_launch_in_parallel() {
        let fixture = Fixture::new();
        let first = fixture.create_request(1, "parallel-create-a");
        let mut second = fixture.create_request(1, "parallel-create-b");
        second.target = ContainerTarget::exact(
            ContainerId::new("whpx-test-b").expect("second container ID"),
            Generation(1),
        );

        let (first, second) =
            tokio::join!(fixture.driver.create(first), fixture.driver.create(second));
        first.expect("first parallel create");
        second.expect("second parallel create");
        assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 2);
        assert_eq!(
            fixture.factory.max_active_launches.load(Ordering::Relaxed),
            2
        );
        assert_eq!(fixture.driver.active_session_count().await, 2);
        fixture.driver.shutdown().await.expect("parallel shutdown");
        assert_eq!(
            fixture.owner.max_active_shutdowns.load(Ordering::Relaxed),
            2
        );
    }

    #[tokio::test]
    async fn retryable_create_reuses_the_attached_vm() {
        let fixture = Fixture::new();
        fixture.guest.fail_next_create(
            Error::new(ErrorCode::Unavailable, "transient guest failure").retryable(true),
        );
        let request = fixture.create_request(1, "retryable-create");
        let error = fixture
            .driver
            .create(request.clone())
            .await
            .expect_err("first create must fail retryably");
        assert!(error.retryable);
        assert_eq!(fixture.driver.active_session_count().await, 1);
        assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 0);

        fixture
            .driver
            .create(request)
            .await
            .expect("retried create");
        assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
        fixture.driver.shutdown().await.expect("shutdown");
        assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn terminal_create_failure_reaps_and_releases_the_generation() {
        let fixture = Fixture::new();
        fixture.guest.fail_next_create(Error::new(
            ErrorCode::FailedPrecondition,
            "terminal guest failure",
        ));
        fixture
            .driver
            .create(fixture.create_request(1, "terminal-create"))
            .await
            .expect_err("terminal create must fail");

        assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.driver.active_session_count().await, 0);
    }

    #[tokio::test]
    async fn stale_generation_and_external_bundle_fail_before_another_launch() {
        let fixture = Fixture::new();
        fixture
            .driver
            .create(fixture.create_request(1, "create-one"))
            .await
            .expect("first generation");
        let stale = fixture
            .driver
            .create(fixture.create_request(2, "create-two"))
            .await
            .expect_err("second generation must not replace a live VM");
        assert_eq!(stale.code, ErrorCode::Conflict);
        assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);

        let external = fixture._temporary.path().join("outside/workload");
        std::fs::create_dir_all(&external).expect("external bundle directory");
        let bundle = OciBundle::from_json(external, TEST_CONFIG).expect("external bundle");
        let mut request = fixture.create_request(3, "external-bundle");
        request.target = ContainerTarget::exact(
            ContainerId::new("external-test").expect("container ID"),
            Generation(1),
        );
        request.bundle = bundle;
        let error = fixture
            .driver
            .create(request)
            .await
            .expect_err("external bundle must fail");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
        fixture.driver.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn owner_death_recovery_exposes_a_stopped_cleanup_tombstone() {
        let fixture = Fixture::new();
        let record = fixture.record(1, ContainerState::Running);
        let recovered = fixture
            .driver
            .recover(&record)
            .await
            .expect("recover missing live session")
            .expect("recovery observation");
        assert_eq!(recovered, super::DriverState::stopped());
        assert_eq!(fixture.driver.active_session_count().await, 0);

        let target = target(1);
        assert_eq!(
            fixture
                .driver
                .state(target.clone())
                .await
                .expect("state recovered tombstone"),
            super::DriverState::stopped()
        );
        assert_eq!(
            fixture
                .driver
                .kill(DriverKillRequest {
                    context: context("recovered-kill"),
                    target: target.clone(),
                    signal: Signal::new(9).expect("signal"),
                    all: true,
                })
                .await
                .expect("kill recovered tombstone"),
            super::DriverState::stopped()
        );
        assert!(fixture
            .driver
            .processes(target.clone())
            .await
            .expect("processes recovered tombstone")
            .is_empty());

        let wait_error = fixture
            .driver
            .wait(DriverWaitRequest {
                target: target.clone(),
                timeout_ms: None,
            })
            .await
            .expect_err("recovery must not invent an exit status");
        assert_eq!(wait_error.code, ErrorCode::FailedPrecondition);
        assert!(!wait_error.retryable);
        assert!(wait_error.message.contains("exact init exit status"));

        fixture
            .driver
            .delete(delete_request(1))
            .await
            .expect("delete recovered tombstone");
        assert_eq!(fixture.guest.delete_calls.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 0);
        let missing = fixture
            .driver
            .state(target)
            .await
            .expect_err("deleted tombstone must be absent");
        assert_eq!(missing.code, ErrorCode::Unavailable);
    }

    #[tokio::test]
    async fn recovery_queries_an_existing_live_generation() {
        let fixture = Fixture::new();
        fixture
            .driver
            .create(fixture.create_request(1, "live-recovery-create"))
            .await
            .expect("create live generation");
        let recovered = fixture
            .driver
            .recover(&fixture.record(1, ContainerState::Created))
            .await
            .expect("recover live generation")
            .expect("live recovery observation");
        assert_eq!(recovered.status(), ContainerState::Created);
        assert_eq!(recovered.pid(), Some(101));
        assert_eq!(fixture.guest.state_calls.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.driver.active_session_count().await, 1);
        fixture
            .driver
            .shutdown()
            .await
            .expect("shutdown live recovery");
    }

    #[tokio::test]
    async fn interrupted_create_cannot_replace_a_recovered_generation() {
        let fixture = Fixture::new();
        let observation = fixture
            .driver
            .recover(&fixture.record(1, ContainerState::Creating))
            .await
            .expect("recover interrupted create");
        assert_eq!(observation, None, "creating cannot transition to stopped");
        let error = fixture
            .driver
            .create(fixture.create_request(1, "recovered-create-retry"))
            .await
            .expect_err("recovered generation must not be recreated");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(!error.retryable);
        assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 0);
        fixture
            .driver
            .delete(delete_request(1))
            .await
            .expect("delete interrupted create tombstone");
    }

    #[tokio::test]
    async fn graceful_shutdown_reaps_live_vms_into_stopped_tombstones() {
        let fixture = Fixture::new();
        fixture
            .driver
            .create(fixture.create_request(1, "shutdown-create"))
            .await
            .expect("create before shutdown");
        fixture.driver.shutdown().await.expect("first shutdown");
        assert_eq!(fixture.driver.active_session_count().await, 0);
        assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            fixture
                .driver
                .state(target(1))
                .await
                .expect("state after shutdown"),
            super::DriverState::stopped()
        );
        fixture
            .driver
            .shutdown()
            .await
            .expect("idempotent shutdown");
        assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn candidate_remains_probe_only() {
        let fixture = Fixture::new();
        let capability = fixture.driver.capability();
        assert_eq!(capability.readiness, DriverReadiness::ProbeOnly);
        assert!(!capability.can_launch());
    }
}
