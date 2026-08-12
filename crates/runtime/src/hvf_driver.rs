use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use a3s_oci_agent_protocol::GuestAgentService;
use a3s_oci_core::{CapabilityStatus, DriverCapability, DriverReadiness, IsolationClass};
use a3s_oci_sdk::{
    async_trait, AttachmentCapabilities, ContainerId, ContainerRecord, ContainerStats,
    ContainerTarget, Error, ErrorCode, ExitStatus, FileRequest, FileResponse, FilesystemRequest,
    FilesystemResponse, OciBundle, OutputChunk, ProcessRecord, Result, RuntimeOperation,
    RUNTIME_BUNDLE_HANDOFF_EXTENSION, RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION,
};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::agent_driver::{AgentDriverClient, AGENT_DRIVER_HOOKS, AGENT_DRIVER_OPERATIONS};
use crate::agent_session::UtilityVmSession;
use crate::driver::{
    DriverCloseStdinRequest, DriverContainerOperationRequest, DriverCreateRequest,
    DriverDeleteRequest, DriverExecRequest, DriverKillRequest, DriverProcess,
    DriverReadOutputRequest, DriverResizeRequest, DriverSignalProcessRequest, DriverStartRequest,
    DriverState, DriverUpdateRequest, DriverWaitProcessRequest, DriverWaitRequest,
    DriverWriteStdinRequest, OciHookPhase, RuntimeDriver,
};

mod handoff;
mod layout;
mod recovery;
#[cfg(test)]
pub(crate) mod tests;

use handoff::BundleHandoffStore;
use layout::{require_exact_generation, PreparedHvfLayout};
use recovery::RecoveryStore;

/// Runtime-owned host paths for the Apple Silicon HVF driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HvfRuntimeDriverConfig {
    shim: PathBuf,
    runtime_root: PathBuf,
    system_image_manifest: PathBuf,
}

impl HvfRuntimeDriverConfig {
    /// Configure the signed shim, private writable runtime root, and immutable
    /// system-image manifest used by every dedicated utility VM.
    pub fn new(
        shim: impl Into<PathBuf>,
        runtime_root: impl Into<PathBuf>,
        system_image_manifest: impl Into<PathBuf>,
    ) -> Result<Self> {
        let config = Self {
            shim: shim.into(),
            runtime_root: runtime_root.into(),
            system_image_manifest: system_image_manifest.into(),
        };
        layout::validate_absolute_normalized_path(&config.shim, "HVF libkrun shim")?;
        layout::validate_absolute_normalized_path(&config.runtime_root, "HVF runtime root")?;
        layout::validate_absolute_normalized_path(
            &config.system_image_manifest,
            "HVF system-image manifest",
        )?;
        Ok(config)
    }

    /// Signed isolated libkrun shim executable.
    #[must_use]
    pub fn shim(&self) -> &Path {
        &self.shim
    }

    /// Same-UID private root for state, shares, consoles, and recovery evidence.
    #[must_use]
    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }

    /// Immutable, digest-bound macOS utility-VM system-image manifest.
    #[must_use]
    pub fn system_image_manifest(&self) -> &Path {
        &self.system_image_manifest
    }
}

/// Launch-ready Apple Silicon driver owning one authenticated HVF VM per generation.
pub struct HvfRuntimeDriver {
    capability: DriverCapability,
    runtime_root: PathBuf,
    runtime_share_root: PathBuf,
    system_image_manifest: PathBuf,
    system_image_manifest_sha256: String,
    recovery: RecoveryStore,
    handoff: BundleHandoffStore,
    factory: Arc<dyn HvfVmFactory>,
    sessions: Mutex<BTreeMap<ContainerId, HvfAttachment>>,
    create_gates: Mutex<BTreeMap<ContainerId, Weak<Mutex<()>>>>,
}

impl fmt::Debug for HvfRuntimeDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HvfRuntimeDriver")
            .field("capability", &self.capability)
            .field("runtime_root", &self.runtime_root)
            .field("runtime_share_root", &self.runtime_share_root)
            .field("system_image_manifest", &self.system_image_manifest)
            .field(
                "system_image_manifest_sha256",
                &self.system_image_manifest_sha256,
            )
            .finish_non_exhaustive()
    }
}

impl HvfRuntimeDriver {
    /// Verify the host, immutable image, shim, and private runtime layout before
    /// making a launch-ready experimental driver available to a host service.
    pub async fn open(config: HvfRuntimeDriverConfig) -> Result<Self> {
        let mut capability = crate::platform::hvf_driver_capability();
        if capability.status != CapabilityStatus::Available {
            return Err(Error::new(
                ErrorCode::Unavailable,
                capability.reason.clone().unwrap_or_else(|| {
                    "Apple Silicon Hypervisor.framework is unavailable".to_string()
                }),
            )
            .for_operation("open-hvf-runtime-driver"));
        }
        let prepared = PreparedHvfLayout::open(config).await?;
        capability.readiness = DriverReadiness::Experimental;
        capability.isolation_classes = vec![IsolationClass::DedicatedVm];
        capability.evidence.extend([
            (
                "execution_path".to_string(),
                "one-hvf-utility-vm-per-generation".to_string(),
            ),
            (
                "system_image_manifest_sha256".to_string(),
                prepared.system_image_manifest_sha256.clone(),
            ),
            (
                "runtime_share".to_string(),
                "same-uid-private-per-generation-virtiofs".to_string(),
            ),
            (
                "bundle_handoff".to_string(),
                "required-atomic-move-v1".to_string(),
            ),
            (
                "owner_death".to_string(),
                "kqueue-exact-owner-process-group-cleanup".to_string(),
            ),
        ]);
        let recovery = RecoveryStore::new(prepared.recovery_directory);
        let handoff = BundleHandoffStore::new(
            prepared.runtime_root.clone(),
            prepared.runtime_share_root.clone(),
        );
        let factory = Arc::new(LiveHvfVmFactory {
            shim: prepared.shim,
            system_image_manifest: prepared.system_image_manifest.clone(),
            console_directory: prepared.console_directory,
            recovery: recovery.clone(),
        });
        Ok(Self {
            capability,
            runtime_root: prepared.runtime_root,
            runtime_share_root: prepared.runtime_share_root,
            system_image_manifest: prepared.system_image_manifest,
            system_image_manifest_sha256: prepared.system_image_manifest_sha256,
            recovery,
            handoff,
            factory,
            sessions: Mutex::new(BTreeMap::new()),
            create_gates: Mutex::new(BTreeMap::new()),
        })
    }

    /// Close every live guest connection and reap each driver-owned VM once.
    pub async fn shutdown(&self) -> Result<()> {
        let sessions = {
            let sessions = self.sessions.lock().await;
            sessions
                .values()
                .filter_map(|attachment| match attachment {
                    HvfAttachment::Live(session) => Some(Arc::clone(session)),
                    HvfAttachment::RecoveredStopped { .. } => None,
                })
                .collect::<Vec<_>>()
        };
        let mut shutdowns = JoinSet::new();
        for session in sessions {
            shutdowns.spawn(async move {
                let result = shutdown_session(&session).await;
                (session, result)
            });
        }
        let mut failures = Vec::new();
        while let Some(completed) = shutdowns.join_next().await {
            match completed {
                Ok((session, Ok(()))) => self.replace_with_stopped(&session, None).await,
                Ok((_session, Err(error))) => failures.push(error.to_string()),
                Err(error) => failures.push(format!("HVF shutdown task failed: {error}")),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::Internal,
                format!(
                    "failed to shut down {} HVF utility VM session(s): {}",
                    failures.len(),
                    failures.join("; ")
                ),
            )
            .for_operation("shutdown-hvf-runtime-driver"))
        }
    }

    /// Number of exact generations still owning a live utility VM.
    pub async fn active_session_count(&self) -> usize {
        self.sessions
            .lock()
            .await
            .values()
            .filter(|attachment| matches!(attachment, HvfAttachment::Live(_)))
            .count()
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

    async fn attachment_for(
        &self,
        target: &ContainerTarget,
        operation: &'static str,
    ) -> Result<HvfAttachment> {
        require_exact_generation(target, operation)?;
        let sessions = self.sessions.lock().await;
        let attachment = sessions.get(&target.id).cloned().ok_or_else(|| {
            Error::new(
                ErrorCode::Unavailable,
                format!(
                    "container {} has neither an attached HVF utility VM nor a recovered stop record",
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

    async fn live_session_for(
        &self,
        target: &ContainerTarget,
        operation: &'static str,
    ) -> Result<Arc<HvfContainer>> {
        match self.attachment_for(target, operation).await? {
            HvfAttachment::Live(session) => Ok(session),
            HvfAttachment::RecoveredStopped { .. } => {
                Err(recovered_stopped_error(target, operation))
            }
        }
    }

    async fn existing_create_session(
        &self,
        target: &ContainerTarget,
    ) -> Result<Option<Arc<HvfContainer>>> {
        let sessions = self.sessions.lock().await;
        let Some(attachment) = sessions.get(&target.id) else {
            return Ok(None);
        };
        if attachment.target() != target {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!(
                    "container {} already owns an HVF attachment at generation {:?}",
                    target.id,
                    attachment.target().generation
                ),
            )
            .for_operation("hvf-create"));
        }
        match attachment {
            HvfAttachment::Live(session) => Ok(Some(Arc::clone(session))),
            HvfAttachment::RecoveredStopped { .. } => {
                Err(recovered_stopped_error(target, "hvf-create"))
            }
        }
    }

    async fn launch(&self, target: &ContainerTarget) -> Result<Arc<HvfContainer>> {
        let runtime_share =
            layout::exact_runtime_share_path(&self.runtime_share_root, target).await?;
        let launched = self.factory.launch(target, &runtime_share).await?;
        Ok(Arc::new(HvfContainer {
            target: target.clone(),
            client: launched.client,
            owner: launched.owner,
        }))
    }

    async fn remove_live(&self, expected: &Arc<HvfContainer>) {
        let mut sessions = self.sessions.lock().await;
        if matches!(
            sessions.get(&expected.target.id),
            Some(HvfAttachment::Live(current)) if Arc::ptr_eq(current, expected)
        ) {
            sessions.remove(&expected.target.id);
        }
    }

    async fn replace_with_stopped(
        &self,
        expected: &Arc<HvfContainer>,
        init_exit_status: Option<ExitStatus>,
    ) {
        let mut sessions = self.sessions.lock().await;
        if matches!(
            sessions.get(&expected.target.id),
            Some(HvfAttachment::Live(current)) if Arc::ptr_eq(current, expected)
        ) {
            sessions.insert(
                expected.target.id.clone(),
                HvfAttachment::RecoveredStopped {
                    target: expected.target.clone(),
                    init_exit_status,
                },
            );
        }
    }

    async fn remove_stopped(&self, target: &ContainerTarget) {
        let mut sessions = self.sessions.lock().await;
        if matches!(
            sessions.get(&target.id),
            Some(HvfAttachment::RecoveredStopped { target: current, .. }) if current == target
        ) {
            sessions.remove(&target.id);
        }
    }

    async fn cleanup_terminal_create(
        &self,
        session: &Arc<HvfContainer>,
        mut error: Error,
    ) -> Error {
        match shutdown_session(session).await {
            Ok(()) => self.remove_live(session).await,
            Err(cleanup) => {
                error.message = format!(
                    "{}; failed to reap the dedicated HVF utility VM: {}",
                    error.message, cleanup
                );
            }
        }
        for cleanup in [
            self.recovery.remove(&session.target).await,
            self.handoff.cleanup(&session.target).await,
        ] {
            if let Err(cleanup) = cleanup {
                error.message = format!("{}; cleanup failed: {}", error.message, cleanup);
            }
        }
        error
    }
}

#[async_trait]
impl RuntimeDriver for HvfRuntimeDriver {
    fn capability(&self) -> DriverCapability {
        self.capability.clone()
    }

    fn operations(&self) -> &[RuntimeOperation] {
        &AGENT_DRIVER_OPERATIONS
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
            .expect("the fixed HVF bundle-handoff extension is valid")
    }

    async fn prepare_create_bundle(&self, request: &DriverCreateRequest) -> Result<OciBundle> {
        if !request.attachment_contract.uses_runtime_bundle_handoff() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "HVF create requires the explicit runtime bundle-handoff extension; arbitrary host bundle directories are never exported to the guest",
            )
            .for_operation("prepare-hvf-bundle-handoff"));
        }
        let gate = self.create_gate_for(&request.target.id).await;
        let _guard = gate.lock().await;
        self.handoff.prepare(request).await
    }

    async fn recover(&self, record: &ContainerRecord) -> Result<crate::DriverRecovery> {
        let target =
            ContainerTarget::exact(ContainerId::new(record.state.id())?, record.generation);

        if *record.state.status() == a3s_oci_sdk::oci_spec::runtime::ContainerState::Creating {
            // An interrupted durable Create must resume through its original
            // operation. Wait for any owner-death report handoff to settle so
            // the replacement owner cannot race the old shim, but never
            // convert the active create intent into a stopped attachment.
            self.recovery.recover(&target, record).await?;
            let mut sessions = self.sessions.lock().await;
            if let Some(attachment) = sessions.get(&target.id) {
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
                    .for_operation("hvf-recover"));
                }
                if matches!(attachment, HvfAttachment::RecoveredStopped { .. }) {
                    sessions.remove(&target.id);
                }
            }
            return Ok(crate::DriverRecovery::none());
        }

        let attachment = {
            let mut sessions = self.sessions.lock().await;
            let recovered = HvfAttachment::RecoveredStopped {
                target: target.clone(),
                init_exit_status: None,
            };
            sessions
                .entry(target.id.clone())
                .or_insert_with(|| recovered.clone())
                .clone()
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
            .for_operation("hvf-recover"));
        }
        match attachment {
            HvfAttachment::Live(session) => {
                let observed = session
                    .client
                    .state_with_digest(target, Some(&record.config_digest))
                    .await?;
                Ok(crate::DriverRecovery::observed(observed))
            }
            HvfAttachment::RecoveredStopped { .. } => {
                let recovery = self.recovery.recover(&target, record).await?;
                let init_exit_status = recovery.clone().into_parts().1;
                let mut sessions = self.sessions.lock().await;
                sessions.insert(
                    target.id.clone(),
                    HvfAttachment::RecoveredStopped {
                        target,
                        init_exit_status,
                    },
                );
                Ok(recovery)
            }
        }
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        if request.isolation.class() != IsolationClass::DedicatedVm {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "the HVF driver provides only one-VM-per-generation isolation",
            )
            .for_operation("hvf-create"));
        }
        require_exact_generation(&request.target, "hvf-create")?;
        if !request.attachment_contract.uses_runtime_bundle_handoff() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "HVF create rejected a bundle without runtime ownership handoff",
            )
            .for_operation("hvf-create"));
        }
        let guest_directory = self
            .handoff
            .guest_bundle_path(&request.target, request.bundle.directory())
            .await?;
        let target = request.target.clone();
        let gate = self.create_gate_for(&target.id).await;
        let _guard = gate.lock().await;
        let session = match self.existing_create_session(&target).await? {
            Some(session) => session,
            None => match self.launch(&target).await {
                Ok(session) => {
                    self.sessions
                        .lock()
                        .await
                        .insert(target.id.clone(), HvfAttachment::Live(Arc::clone(&session)));
                    session
                }
                Err(error) if error.retryable => return Err(error),
                Err(mut error) => {
                    if let Err(cleanup) = self.handoff.cleanup(&target).await {
                        error.message = format!(
                            "{}; failed to remove runtime-owned HVF bundle: {}",
                            error.message, cleanup
                        );
                    }
                    return Err(error);
                }
            },
        };
        match session.client.create(request, guest_directory).await {
            Ok(state) => Ok(state),
            Err(error) if error.retryable => Err(error),
            Err(error) => Err(self.cleanup_terminal_create(&session, error).await),
        }
    }

    async fn state(&self, target: ContainerTarget) -> Result<DriverState> {
        match self.attachment_for(&target, "hvf-state").await? {
            HvfAttachment::Live(session) => session.client.state(target).await,
            HvfAttachment::RecoveredStopped { .. } => Ok(DriverState::stopped()),
        }
    }

    async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        self.live_session_for(&request.target, "hvf-start")
            .await?
            .client
            .start(request)
            .await
    }

    async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        match self.attachment_for(&request.target, "hvf-kill").await? {
            HvfAttachment::Live(session) => session.client.kill(request).await,
            HvfAttachment::RecoveredStopped { .. } => Ok(DriverState::stopped()),
        }
    }

    async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        match self.attachment_for(&request.target, "hvf-delete").await? {
            HvfAttachment::Live(session) => {
                session.client.delete(request).await?;
                shutdown_session(&session).await?;
                self.replace_with_stopped(&session, None).await;
                self.recovery.remove(&session.target).await?;
                self.handoff.cleanup(&session.target).await?;
                self.remove_stopped(&session.target).await;
                Ok(())
            }
            HvfAttachment::RecoveredStopped { target, .. } => {
                self.recovery.remove(&target).await?;
                self.handoff.cleanup(&target).await?;
                self.remove_stopped(&target).await;
                Ok(())
            }
        }
    }

    async fn wait(&self, request: DriverWaitRequest) -> Result<ExitStatus> {
        match self.attachment_for(&request.target, "hvf-wait").await? {
            HvfAttachment::Live(session) => session.client.wait(request).await,
            HvfAttachment::RecoveredStopped {
                init_exit_status: Some(status),
                ..
            } => Ok(status),
            HvfAttachment::RecoveredStopped { .. } => {
                Err(recovered_exit_error(&request.target, "hvf-wait"))
            }
        }
    }

    async fn exec(&self, request: DriverExecRequest) -> Result<DriverProcess> {
        self.live_session_for(&request.target.container, "hvf-exec")
            .await?
            .client
            .exec(request)
            .await
    }

    async fn signal_process(&self, request: DriverSignalProcessRequest) -> Result<()> {
        self.live_session_for(&request.target.container, "hvf-signal-process")
            .await?
            .client
            .signal_process(request)
            .await
    }

    async fn wait_process(&self, request: DriverWaitProcessRequest) -> Result<ExitStatus> {
        self.live_session_for(&request.target.container, "hvf-wait-process")
            .await?
            .client
            .wait_process(request)
            .await
    }

    async fn pause(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.live_session_for(&request.target, "hvf-pause")
            .await?
            .client
            .pause(request)
            .await
    }

    async fn resume(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.live_session_for(&request.target, "hvf-resume")
            .await?
            .client
            .resume(request)
            .await
    }

    async fn processes(&self, target: ContainerTarget) -> Result<Vec<ProcessRecord>> {
        match self.attachment_for(&target, "hvf-processes").await? {
            HvfAttachment::Live(session) => session.client.processes(target).await,
            HvfAttachment::RecoveredStopped { .. } => Ok(Vec::new()),
        }
    }

    async fn update(&self, request: DriverUpdateRequest) -> Result<DriverState> {
        self.live_session_for(&request.target, "hvf-update")
            .await?
            .client
            .update(request)
            .await
    }

    async fn stats(&self, target: ContainerTarget) -> Result<ContainerStats> {
        self.live_session_for(&target, "hvf-stats")
            .await?
            .client
            .stats(target)
            .await
    }

    async fn read_output(&self, request: DriverReadOutputRequest) -> Result<Vec<OutputChunk>> {
        self.live_session_for(&request.target.container, "hvf-read-output")
            .await?
            .client
            .read_output(request)
            .await
    }

    async fn write_stdin(&self, request: DriverWriteStdinRequest) -> Result<()> {
        self.live_session_for(&request.target.container, "hvf-write-stdin")
            .await?
            .client
            .write_stdin(request)
            .await
    }

    async fn close_stdin(&self, request: DriverCloseStdinRequest) -> Result<()> {
        self.live_session_for(&request.target.container, "hvf-close-stdin")
            .await?
            .client
            .close_stdin(request)
            .await
    }

    async fn resize(&self, request: DriverResizeRequest) -> Result<()> {
        self.live_session_for(&request.target.container, "hvf-resize")
            .await?
            .client
            .resize(request)
            .await
    }

    async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        self.live_session_for(&request.target, "hvf-file")
            .await?
            .client
            .file(request)
            .await
    }

    async fn filesystem(&self, request: FilesystemRequest) -> Result<FilesystemResponse> {
        self.live_session_for(&request.target, "hvf-filesystem")
            .await?
            .client
            .filesystem(request)
            .await
    }
}

#[derive(Clone)]
enum HvfAttachment {
    Live(Arc<HvfContainer>),
    RecoveredStopped {
        target: ContainerTarget,
        init_exit_status: Option<ExitStatus>,
    },
}

impl HvfAttachment {
    fn target(&self) -> &ContainerTarget {
        match self {
            Self::Live(session) => &session.target,
            Self::RecoveredStopped { target, .. } => target,
        }
    }
}

struct HvfContainer {
    target: ContainerTarget,
    client: AgentDriverClient,
    owner: Arc<dyn HvfVmOwner>,
}

async fn shutdown_session(session: &HvfContainer) -> Result<()> {
    session.owner.shutdown().await
}

struct LaunchedHvfVm {
    client: AgentDriverClient,
    owner: Arc<dyn HvfVmOwner>,
}

#[async_trait]
trait HvfVmFactory: Send + Sync {
    async fn launch(&self, target: &ContainerTarget, runtime_share: &Path)
        -> Result<LaunchedHvfVm>;
}

#[async_trait]
trait HvfVmOwner: Send + Sync {
    async fn shutdown(&self) -> Result<()>;
}

struct LiveHvfVmFactory {
    shim: PathBuf,
    system_image_manifest: PathBuf,
    console_directory: PathBuf,
    recovery: RecoveryStore,
}

#[async_trait]
impl HvfVmFactory for LiveHvfVmFactory {
    async fn launch(
        &self,
        target: &ContainerTarget,
        runtime_share: &Path,
    ) -> Result<LaunchedHvfVm> {
        let generation = require_exact_generation(target, "launch-hvf-utility-vm")?;
        let console = self
            .console_directory
            .join(format!("{}-{}.log", target.id, generation.0));
        let recovery_report = self.recovery.path(target)?;
        let session = Arc::new(
            UtilityVmSession::connect_with_runtime_share(
                &self.shim,
                &self.system_image_manifest,
                runtime_share,
                &console,
                Some(&recovery_report),
            )
            .await
            .map_err(vm_launch_error)?,
        );
        let service: Arc<dyn GuestAgentService> = Arc::new(session.client());
        Ok(LaunchedHvfVm {
            client: AgentDriverClient::new(service, "HVF guest agent", "hvf"),
            owner: Arc::new(LiveHvfVmOwner { session }),
        })
    }
}

struct LiveHvfVmOwner {
    session: Arc<UtilityVmSession>,
}

#[async_trait]
impl HvfVmOwner for LiveHvfVmOwner {
    async fn shutdown(&self) -> Result<()> {
        let report = self.session.shutdown().await;
        if report.is_success() {
            Ok(())
        } else {
            Err(vm_report_error("shutdown-hvf-utility-vm", report))
        }
    }
}

fn vm_launch_error(report: crate::AgentVmSmokeReport) -> Error {
    let retryable = !report.protocol_negotiated;
    vm_report_error("launch-hvf-utility-vm", report).retryable(retryable)
}

fn vm_report_error(operation: &'static str, report: crate::AgentVmSmokeReport) -> Error {
    let reason = report
        .reason
        .unwrap_or_else(|| "authenticated HVF utility VM did not satisfy its contract".to_string());
    Error::new(ErrorCode::Unavailable, reason).for_operation(operation)
}

fn recovered_stopped_error(target: &ContainerTarget, operation: &'static str) -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        format!(
            "container {} generation {:?} was recovered as stopped after its HVF owner exited; delete this generation before another live operation",
            target.id, target.generation
        ),
    )
    .for_operation(operation)
}

fn recovered_exit_error(target: &ContainerTarget, operation: &'static str) -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        format!(
            "container {} generation {:?} was stopped by HVF owner-death cleanup, but its exact init exit status was not retained",
            target.id, target.generation
        ),
    )
    .for_operation(operation)
}
