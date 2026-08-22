use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use a3s_oci_core::{DriverCapability, IsolationClass};
use a3s_oci_sdk::{
    async_trait, AttachmentCapabilities, ContainerId, ContainerRecord, ContainerStats,
    ContainerTarget, Error, ErrorCode, ExitStatus, FileRequest, FileResponse, FilesystemRequest,
    FilesystemResponse, OciBundle, OperationId, OutputChunk, ProcessRecord, Result,
    RuntimeOperation, RUNTIME_BUNDLE_HANDOFF_EXTENSION, RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION,
};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::agent_driver::{AgentDriverClient, AGENT_DRIVER_HOOKS, AGENT_DRIVER_OPERATIONS};
use crate::driver::{
    DriverCloseStdinRequest, DriverContainerOperationRequest, DriverCreateRequest,
    DriverDeleteRequest, DriverExecRequest, DriverKillRequest, DriverProcess,
    DriverReadOutputRequest, DriverResizeRequest, DriverSignalProcessRequest, DriverStartRequest,
    DriverState, DriverUpdateRequest, DriverWaitProcessRequest, DriverWaitRequest,
    DriverWriteStdinRequest, OciHookPhase, RuntimeDriver,
};

mod handoff;
pub(crate) mod layout;
pub(crate) mod recovery;
#[cfg(test)]
pub(crate) mod tests;

use handoff::BundleHandoffStore;
use layout::require_exact_generation;
use recovery::RecoveryStore;

/// Platform-neutral lifecycle for one authenticated utility VM per generation.
pub(crate) struct UtilityVmRuntimeDriver {
    capability: DriverCapability,
    backend_name: &'static str,
    runtime_root: PathBuf,
    runtime_share_root: PathBuf,
    system_image_manifest: PathBuf,
    system_image_manifest_sha256: String,
    recovery: RecoveryStore,
    handoff: BundleHandoffStore,
    factory: Arc<dyn UtilityVmFactory>,
    sessions: Mutex<BTreeMap<ContainerId, UtilityVmAttachment>>,
    create_gates: Mutex<BTreeMap<ContainerId, Weak<Mutex<()>>>>,
}

impl fmt::Debug for UtilityVmRuntimeDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UtilityVmRuntimeDriver")
            .field("capability", &self.capability)
            .field("backend_name", &self.backend_name)
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

impl UtilityVmRuntimeDriver {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        capability: DriverCapability,
        backend_name: &'static str,
        runtime_root: PathBuf,
        runtime_share_root: PathBuf,
        system_image_manifest: PathBuf,
        system_image_manifest_sha256: String,
        recovery_directory: PathBuf,
        factory: Arc<dyn UtilityVmFactory>,
    ) -> Self {
        let recovery = RecoveryStore::new(recovery_directory);
        let handoff = BundleHandoffStore::new(runtime_root.clone(), runtime_share_root.clone());
        Self {
            capability,
            backend_name,
            runtime_root,
            runtime_share_root,
            system_image_manifest,
            system_image_manifest_sha256,
            recovery,
            handoff,
            factory,
            sessions: Mutex::new(BTreeMap::new()),
            create_gates: Mutex::new(BTreeMap::new()),
        }
    }

    /// Close every live guest connection and reap each driver-owned VM once.
    pub async fn shutdown(&self) -> Result<()> {
        let sessions = {
            let sessions = self.sessions.lock().await;
            sessions
                .values()
                .filter_map(|attachment| match attachment {
                    UtilityVmAttachment::Live(session) => Some(Arc::clone(session)),
                    UtilityVmAttachment::RecoveredStopped { .. } => None,
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
                Err(error) => failures.push(format!("utility-VM shutdown task failed: {error}")),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::Internal,
                format!(
                    "failed to shut down {} utility VM session(s): {}",
                    failures.len(),
                    failures.join("; ")
                ),
            )
            .for_operation("shutdown-utility-vm-runtime-driver"))
        }
    }

    /// Number of exact generations still owning a live utility VM.
    pub async fn active_session_count(&self) -> usize {
        self.sessions
            .lock()
            .await
            .values()
            .filter(|attachment| matches!(attachment, UtilityVmAttachment::Live(_)))
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

    fn validate_create_contract(&self, request: &DriverCreateRequest) -> Result<()> {
        if request.isolation.class() != IsolationClass::DedicatedVm {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "the {} driver provides only one-VM-per-generation isolation",
                    self.backend_name
                ),
            )
            .for_operation("utility-vm-create"));
        }
        require_exact_generation(&request.target, "utility-vm-create")?;
        if !request.attachment_contract.uses_runtime_bundle_handoff() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "{} create requires runtime ownership handoff for its OCI bundle",
                    self.backend_name
                ),
            )
            .for_operation("utility-vm-create"));
        }
        Ok(())
    }

    async fn attachment_for(
        &self,
        target: &ContainerTarget,
        operation: &'static str,
    ) -> Result<UtilityVmAttachment> {
        require_exact_generation(target, operation)?;
        let sessions = self.sessions.lock().await;
        let attachment = sessions.get(&target.id).cloned().ok_or_else(|| {
            Error::new(
                ErrorCode::Unavailable,
                format!(
                    "container {} has neither an attached utility VM nor a recovered stop record",
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
    ) -> Result<Arc<UtilityVmContainer>> {
        match self.attachment_for(target, operation).await? {
            UtilityVmAttachment::Live(session) => Ok(session),
            UtilityVmAttachment::RecoveredStopped { .. } => {
                Err(recovered_stopped_error(target, operation))
            }
        }
    }

    async fn existing_create_session(
        &self,
        target: &ContainerTarget,
    ) -> Result<Option<Arc<UtilityVmContainer>>> {
        let sessions = self.sessions.lock().await;
        let Some(attachment) = sessions.get(&target.id) else {
            return Ok(None);
        };
        if attachment.target() != target {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!(
                    "container {} already owns a utility-VM attachment at generation {:?}",
                    target.id,
                    attachment.target().generation
                ),
            )
            .for_operation("utility-vm-create"));
        }
        match attachment {
            UtilityVmAttachment::Live(session) => Ok(Some(Arc::clone(session))),
            UtilityVmAttachment::RecoveredStopped { .. } => {
                Err(recovered_stopped_error(target, "utility-vm-create"))
            }
        }
    }

    async fn launch(&self, target: &ContainerTarget) -> Result<Arc<UtilityVmContainer>> {
        let runtime_share =
            layout::exact_runtime_share_path(&self.runtime_share_root, target).await?;
        let launched = self.factory.launch(target, &runtime_share).await?;
        Ok(Arc::new(UtilityVmContainer {
            target: target.clone(),
            client: launched.client,
            owner: launched.owner,
        }))
    }

    async fn remove_live(&self, expected: &Arc<UtilityVmContainer>) {
        let mut sessions = self.sessions.lock().await;
        if matches!(
            sessions.get(&expected.target.id),
            Some(UtilityVmAttachment::Live(current)) if Arc::ptr_eq(current, expected)
        ) {
            sessions.remove(&expected.target.id);
        }
    }

    async fn replace_with_stopped(
        &self,
        expected: &Arc<UtilityVmContainer>,
        init_exit_status: Option<ExitStatus>,
    ) {
        let mut sessions = self.sessions.lock().await;
        if matches!(
            sessions.get(&expected.target.id),
            Some(UtilityVmAttachment::Live(current)) if Arc::ptr_eq(current, expected)
        ) {
            sessions.insert(
                expected.target.id.clone(),
                UtilityVmAttachment::RecoveredStopped {
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
            Some(UtilityVmAttachment::RecoveredStopped { target: current, .. }) if current == target
        ) {
            sessions.remove(&target.id);
        }
    }

    async fn cleanup_terminal_create(
        &self,
        session: &Arc<UtilityVmContainer>,
        mut error: Error,
    ) -> Error {
        match shutdown_session(session).await {
            Ok(()) => self.remove_live(session).await,
            Err(cleanup) => {
                error.message = format!(
                    "{}; failed to reap the dedicated utility VM: {}",
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
impl RuntimeDriver for UtilityVmRuntimeDriver {
    fn capability(&self) -> DriverCapability {
        self.capability.clone()
    }

    fn linux_support(&self) -> Result<a3s_oci_sdk::OciLinuxSupport> {
        a3s_oci_sdk::OciLinuxSupport::shared_executor()
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
            .expect("the fixed utility-VM bundle-handoff extension is valid")
    }

    async fn acknowledge_operation(&self, operation_id: &OperationId) -> Result<()> {
        let clients = self
            .sessions
            .lock()
            .await
            .values()
            .filter_map(|attachment| match attachment {
                UtilityVmAttachment::Live(session) => Some(session.client.clone()),
                UtilityVmAttachment::RecoveredStopped { .. } => None,
            })
            .collect::<Vec<_>>();
        for client in clients {
            client.acknowledge_operation(operation_id).await?;
        }
        Ok(())
    }

    async fn prepare_create_bundle(&self, request: &DriverCreateRequest) -> Result<OciBundle> {
        self.validate_create_contract(request)?;
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
                    .for_operation("utility-vm-recover"));
                }
                if matches!(attachment, UtilityVmAttachment::RecoveredStopped { .. }) {
                    sessions.remove(&target.id);
                }
            }
            return Ok(crate::DriverRecovery::none());
        }

        let attachment = {
            let mut sessions = self.sessions.lock().await;
            let recovered = UtilityVmAttachment::RecoveredStopped {
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
            .for_operation("utility-vm-recover"));
        }
        match attachment {
            UtilityVmAttachment::Live(session) => {
                let observed = session
                    .client
                    .state_with_digest(target, Some(&record.config_digest))
                    .await?;
                Ok(crate::DriverRecovery::observed(observed))
            }
            UtilityVmAttachment::RecoveredStopped { .. } => {
                let recovery = self.recovery.recover(&target, record).await?;
                let init_exit_status = recovery.clone().into_parts().1;
                let mut sessions = self.sessions.lock().await;
                sessions.insert(
                    target.id.clone(),
                    UtilityVmAttachment::RecoveredStopped {
                        target,
                        init_exit_status,
                    },
                );
                Ok(recovery)
            }
        }
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        self.validate_create_contract(&request)?;
        let guest_directory = self
            .handoff
            .guest_bundle_path(&request.target, request.bundle.directory())
            .await?;
        let target = request.target.clone();
        let gate = self.create_gate_for(&target.id).await;
        let _guard = gate.lock().await;
        let existing = match self.existing_create_session(&target).await {
            Ok(existing) => existing,
            Err(mut error) => {
                if !error.retryable {
                    if let Err(cleanup) = self.handoff.cleanup(&target).await {
                        error.message = format!(
                            "{}; failed to remove rejected exact-generation handoff: {}",
                            error.message, cleanup
                        );
                    }
                }
                return Err(error);
            }
        };
        let session = match existing {
            Some(session) => session,
            None => match self.launch(&target).await {
                Ok(session) => {
                    self.sessions.lock().await.insert(
                        target.id.clone(),
                        UtilityVmAttachment::Live(Arc::clone(&session)),
                    );
                    session
                }
                Err(error) if error.retryable => return Err(error),
                Err(mut error) => {
                    if let Err(cleanup) = self.handoff.cleanup(&target).await {
                        error.message = format!(
                            "{}; failed to remove runtime-owned utility-VM bundle: {}",
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
        match self.attachment_for(&target, "utility-vm-state").await? {
            UtilityVmAttachment::Live(session) => session.client.state(target).await,
            UtilityVmAttachment::RecoveredStopped { .. } => Ok(DriverState::stopped()),
        }
    }

    async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        self.live_session_for(&request.target, "utility-vm-start")
            .await?
            .client
            .start(request)
            .await
    }

    async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        match self
            .attachment_for(&request.target, "utility-vm-kill")
            .await?
        {
            UtilityVmAttachment::Live(session) => session.client.kill(request).await,
            UtilityVmAttachment::RecoveredStopped { .. } => Ok(DriverState::stopped()),
        }
    }

    async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        match self
            .attachment_for(&request.target, "utility-vm-delete")
            .await?
        {
            UtilityVmAttachment::Live(session) => {
                session.client.delete(request).await?;
                shutdown_session(&session).await?;
                self.replace_with_stopped(&session, None).await;
                self.recovery.remove(&session.target).await?;
                self.handoff.cleanup(&session.target).await?;
                self.remove_stopped(&session.target).await;
                Ok(())
            }
            UtilityVmAttachment::RecoveredStopped { target, .. } => {
                self.recovery.remove(&target).await?;
                self.handoff.cleanup(&target).await?;
                self.remove_stopped(&target).await;
                Ok(())
            }
        }
    }

    async fn wait(&self, request: DriverWaitRequest) -> Result<ExitStatus> {
        match self
            .attachment_for(&request.target, "utility-vm-wait")
            .await?
        {
            UtilityVmAttachment::Live(session) => session.client.wait(request).await,
            UtilityVmAttachment::RecoveredStopped {
                init_exit_status: Some(status),
                ..
            } => Ok(status),
            UtilityVmAttachment::RecoveredStopped { .. } => {
                Err(recovered_exit_error(&request.target, "utility-vm-wait"))
            }
        }
    }

    async fn exec(&self, request: DriverExecRequest) -> Result<DriverProcess> {
        self.live_session_for(&request.target.container, "utility-vm-exec")
            .await?
            .client
            .exec(request)
            .await
    }

    async fn signal_process(&self, request: DriverSignalProcessRequest) -> Result<()> {
        self.live_session_for(&request.target.container, "utility-vm-signal-process")
            .await?
            .client
            .signal_process(request)
            .await
    }

    async fn wait_process(&self, request: DriverWaitProcessRequest) -> Result<ExitStatus> {
        self.live_session_for(&request.target.container, "utility-vm-wait-process")
            .await?
            .client
            .wait_process(request)
            .await
    }

    async fn pause(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.live_session_for(&request.target, "utility-vm-pause")
            .await?
            .client
            .pause(request)
            .await
    }

    async fn resume(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.live_session_for(&request.target, "utility-vm-resume")
            .await?
            .client
            .resume(request)
            .await
    }

    async fn processes(&self, target: ContainerTarget) -> Result<Vec<ProcessRecord>> {
        match self.attachment_for(&target, "utility-vm-processes").await? {
            UtilityVmAttachment::Live(session) => session.client.processes(target).await,
            UtilityVmAttachment::RecoveredStopped { .. } => Ok(Vec::new()),
        }
    }

    async fn update(&self, request: DriverUpdateRequest) -> Result<DriverState> {
        self.live_session_for(&request.target, "utility-vm-update")
            .await?
            .client
            .update(request)
            .await
    }

    async fn stats(&self, target: ContainerTarget) -> Result<ContainerStats> {
        self.live_session_for(&target, "utility-vm-stats")
            .await?
            .client
            .stats(target)
            .await
    }

    async fn read_output(&self, request: DriverReadOutputRequest) -> Result<Vec<OutputChunk>> {
        self.live_session_for(&request.target.container, "utility-vm-read-output")
            .await?
            .client
            .read_output(request)
            .await
    }

    async fn write_stdin(&self, request: DriverWriteStdinRequest) -> Result<()> {
        self.live_session_for(&request.target.container, "utility-vm-write-stdin")
            .await?
            .client
            .write_stdin(request)
            .await
    }

    async fn close_stdin(&self, request: DriverCloseStdinRequest) -> Result<()> {
        self.live_session_for(&request.target.container, "utility-vm-close-stdin")
            .await?
            .client
            .close_stdin(request)
            .await
    }

    async fn resize(&self, request: DriverResizeRequest) -> Result<()> {
        self.live_session_for(&request.target.container, "utility-vm-resize")
            .await?
            .client
            .resize(request)
            .await
    }

    async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        self.live_session_for(&request.target, "utility-vm-file")
            .await?
            .client
            .file(request)
            .await
    }

    async fn filesystem(&self, request: FilesystemRequest) -> Result<FilesystemResponse> {
        self.live_session_for(&request.target, "utility-vm-filesystem")
            .await?
            .client
            .filesystem(request)
            .await
    }
}

#[derive(Clone)]
enum UtilityVmAttachment {
    Live(Arc<UtilityVmContainer>),
    RecoveredStopped {
        target: ContainerTarget,
        init_exit_status: Option<ExitStatus>,
    },
}

impl UtilityVmAttachment {
    fn target(&self) -> &ContainerTarget {
        match self {
            Self::Live(session) => &session.target,
            Self::RecoveredStopped { target, .. } => target,
        }
    }
}

struct UtilityVmContainer {
    target: ContainerTarget,
    client: AgentDriverClient,
    owner: Arc<dyn UtilityVmOwner>,
}

async fn shutdown_session(session: &UtilityVmContainer) -> Result<()> {
    session.owner.shutdown().await
}

pub(crate) struct LaunchedUtilityVm {
    pub(crate) client: AgentDriverClient,
    pub(crate) owner: Arc<dyn UtilityVmOwner>,
}

#[async_trait]
pub(crate) trait UtilityVmFactory: Send + Sync {
    async fn launch(
        &self,
        target: &ContainerTarget,
        runtime_share: &Path,
    ) -> Result<LaunchedUtilityVm>;
}

#[async_trait]
pub(crate) trait UtilityVmOwner: Send + Sync {
    async fn shutdown(&self) -> Result<()>;
}

fn recovered_stopped_error(target: &ContainerTarget, operation: &'static str) -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        format!(
            "container {} generation {:?} was recovered as stopped after its utility-VM owner exited; delete this generation before another live operation",
            target.id, target.generation
        ),
    )
    .for_operation(operation)
}

fn recovered_exit_error(target: &ContainerTarget, operation: &'static str) -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        format!(
            "container {} generation {:?} was stopped by utility-VM owner-death cleanup, but its exact init exit status was not retained",
            target.id, target.generation
        ),
    )
    .for_operation(operation)
}

macro_rules! delegate_utility_vm_runtime_driver {
    ($driver:ty, $inner:ident) => {
        #[a3s_oci_sdk::async_trait]
        impl $crate::RuntimeDriver for $driver {
            fn capability(&self) -> a3s_oci_core::DriverCapability {
                $crate::RuntimeDriver::capability(&self.$inner)
            }

            fn linux_support(&self) -> a3s_oci_sdk::Result<a3s_oci_sdk::OciLinuxSupport> {
                $crate::RuntimeDriver::linux_support(&self.$inner)
            }

            fn operations(&self) -> &[a3s_oci_sdk::RuntimeOperation] {
                $crate::RuntimeDriver::operations(&self.$inner)
            }

            fn hooks(&self) -> &[$crate::OciHookPhase] {
                $crate::RuntimeDriver::hooks(&self.$inner)
            }

            fn attachment_capabilities(&self) -> a3s_oci_sdk::AttachmentCapabilities {
                $crate::RuntimeDriver::attachment_capabilities(&self.$inner)
            }

            async fn acknowledge_operation(
                &self,
                operation_id: &a3s_oci_sdk::OperationId,
            ) -> a3s_oci_sdk::Result<()> {
                $crate::RuntimeDriver::acknowledge_operation(&self.$inner, operation_id).await
            }

            async fn prepare_create_bundle(
                &self,
                request: &$crate::DriverCreateRequest,
            ) -> a3s_oci_sdk::Result<a3s_oci_sdk::OciBundle> {
                $crate::RuntimeDriver::prepare_create_bundle(&self.$inner, request).await
            }

            async fn recover(
                &self,
                record: &a3s_oci_sdk::ContainerRecord,
            ) -> a3s_oci_sdk::Result<$crate::DriverRecovery> {
                $crate::RuntimeDriver::recover(&self.$inner, record).await
            }

            async fn create(
                &self,
                request: $crate::DriverCreateRequest,
            ) -> a3s_oci_sdk::Result<$crate::DriverState> {
                $crate::RuntimeDriver::create(&self.$inner, request).await
            }

            async fn state(
                &self,
                target: a3s_oci_sdk::ContainerTarget,
            ) -> a3s_oci_sdk::Result<$crate::DriverState> {
                $crate::RuntimeDriver::state(&self.$inner, target).await
            }

            async fn start(
                &self,
                request: $crate::DriverStartRequest,
            ) -> a3s_oci_sdk::Result<$crate::DriverState> {
                $crate::RuntimeDriver::start(&self.$inner, request).await
            }

            async fn kill(
                &self,
                request: $crate::DriverKillRequest,
            ) -> a3s_oci_sdk::Result<$crate::DriverState> {
                $crate::RuntimeDriver::kill(&self.$inner, request).await
            }

            async fn delete(
                &self,
                request: $crate::DriverDeleteRequest,
            ) -> a3s_oci_sdk::Result<()> {
                $crate::RuntimeDriver::delete(&self.$inner, request).await
            }

            async fn wait(
                &self,
                request: $crate::DriverWaitRequest,
            ) -> a3s_oci_sdk::Result<a3s_oci_sdk::ExitStatus> {
                $crate::RuntimeDriver::wait(&self.$inner, request).await
            }

            async fn exec(
                &self,
                request: $crate::DriverExecRequest,
            ) -> a3s_oci_sdk::Result<$crate::DriverProcess> {
                $crate::RuntimeDriver::exec(&self.$inner, request).await
            }

            async fn signal_process(
                &self,
                request: $crate::DriverSignalProcessRequest,
            ) -> a3s_oci_sdk::Result<()> {
                $crate::RuntimeDriver::signal_process(&self.$inner, request).await
            }

            async fn wait_process(
                &self,
                request: $crate::DriverWaitProcessRequest,
            ) -> a3s_oci_sdk::Result<a3s_oci_sdk::ExitStatus> {
                $crate::RuntimeDriver::wait_process(&self.$inner, request).await
            }

            async fn pause(
                &self,
                request: $crate::DriverContainerOperationRequest,
            ) -> a3s_oci_sdk::Result<$crate::DriverState> {
                $crate::RuntimeDriver::pause(&self.$inner, request).await
            }

            async fn resume(
                &self,
                request: $crate::DriverContainerOperationRequest,
            ) -> a3s_oci_sdk::Result<$crate::DriverState> {
                $crate::RuntimeDriver::resume(&self.$inner, request).await
            }

            async fn processes(
                &self,
                target: a3s_oci_sdk::ContainerTarget,
            ) -> a3s_oci_sdk::Result<Vec<a3s_oci_sdk::ProcessRecord>> {
                $crate::RuntimeDriver::processes(&self.$inner, target).await
            }

            async fn update(
                &self,
                request: $crate::DriverUpdateRequest,
            ) -> a3s_oci_sdk::Result<$crate::DriverState> {
                $crate::RuntimeDriver::update(&self.$inner, request).await
            }

            async fn stats(
                &self,
                target: a3s_oci_sdk::ContainerTarget,
            ) -> a3s_oci_sdk::Result<a3s_oci_sdk::ContainerStats> {
                $crate::RuntimeDriver::stats(&self.$inner, target).await
            }

            async fn read_output(
                &self,
                request: $crate::DriverReadOutputRequest,
            ) -> a3s_oci_sdk::Result<Vec<a3s_oci_sdk::OutputChunk>> {
                $crate::RuntimeDriver::read_output(&self.$inner, request).await
            }

            async fn write_stdin(
                &self,
                request: $crate::DriverWriteStdinRequest,
            ) -> a3s_oci_sdk::Result<()> {
                $crate::RuntimeDriver::write_stdin(&self.$inner, request).await
            }

            async fn close_stdin(
                &self,
                request: $crate::DriverCloseStdinRequest,
            ) -> a3s_oci_sdk::Result<()> {
                $crate::RuntimeDriver::close_stdin(&self.$inner, request).await
            }

            async fn resize(
                &self,
                request: $crate::DriverResizeRequest,
            ) -> a3s_oci_sdk::Result<()> {
                $crate::RuntimeDriver::resize(&self.$inner, request).await
            }

            async fn file(
                &self,
                request: a3s_oci_sdk::FileRequest,
            ) -> a3s_oci_sdk::Result<a3s_oci_sdk::FileResponse> {
                $crate::RuntimeDriver::file(&self.$inner, request).await
            }

            async fn filesystem(
                &self,
                request: a3s_oci_sdk::FilesystemRequest,
            ) -> a3s_oci_sdk::Result<a3s_oci_sdk::FilesystemResponse> {
                $crate::RuntimeDriver::filesystem(&self.$inner, request).await
            }
        }
    };
}

pub(crate) use delegate_utility_vm_runtime_driver;
