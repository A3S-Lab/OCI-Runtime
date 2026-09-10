use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use a3s_oci_agent::{
    InheritedDescriptorPlan, LinuxExecutor, LinuxExecutorTombstone, LinuxLiveSupervisedSession,
    RootlessDevicePolicyBootstrap, StaleGenerationRecovery,
};
use a3s_oci_agent_protocol::{AgentBundle, AgentCreateRequest, GuestAgentService, GuestPath};
use a3s_oci_core::{CapabilityStatus, DriverCapability, DriverReadiness, IsolationClass};
use a3s_oci_sdk::{
    async_trait, AttachmentCapabilities, ContainerId, ContainerRecord, ContainerStats,
    ContainerTarget, Error, ErrorCode, ExitStatus, FileRequest, FileResponse, FilesystemRequest,
    FilesystemResponse, OperationId, OutputChunk, ProcessRecord, Result, RuntimeOperation,
    NETWORK_ENFORCEMENT_EXTENSION, NETWORK_ENFORCEMENT_EXTENSION_VERSION,
};
use tokio::sync::Mutex;

use crate::agent_driver::{AgentDriverClient, AGENT_DRIVER_HOOKS, AGENT_DRIVER_OPERATIONS};
use crate::driver::{
    DriverCheckpointRequest, DriverCheckpointResult, DriverCloseStdinRequest,
    DriverContainerOperationRequest, DriverCreateAttachments, DriverCreateRequest,
    DriverDeleteRequest, DriverExecRequest, DriverKillRequest, DriverProcess,
    DriverReadOutputRequest, DriverResizeRequest, DriverRestoreRequest,
    DriverRestoreValidationRequest, DriverSignalProcessRequest, DriverStartRequest, DriverState,
    DriverUpdateRequest, DriverWaitProcessRequest, DriverWaitRequest, DriverWriteStdinRequest,
    OciHookPhase, RuntimeDriver,
};
use crate::native_checkpoint::{NativeCriuCheckpoint, NativeRestoreRecovery};

/// Explicitly opted-in native Linux runtime driver.
///
/// The default feature inventory remains `probe-only`. Constructing this
/// driver is the explicit experimental opt-in that allows
/// [`crate::HostRuntimeService`] to exercise the currently reviewed executor
/// profile without linking or initializing libkrun.
#[derive(Debug)]
pub struct NativeLinuxDriver {
    capability: DriverCapability,
    attachment_capabilities: AttachmentCapabilities,
    operations: Vec<RuntimeOperation>,
    executor: Arc<LinuxExecutor>,
    client: AgentDriverClient,
    checkpoint: Option<Arc<NativeCriuCheckpoint>>,
    recovered: Mutex<BTreeMap<ContainerId, LinuxExecutorTombstone>>,
    live: Mutex<BTreeMap<ContainerId, Arc<LinuxLiveSupervisedSession>>>,
}

impl NativeLinuxDriver {
    /// Open the experimental native driver beneath a runtime-owned directory.
    ///
    /// `init_executable` must be the matching `a3s-oci-agent` binary. The
    /// caller must invoke [`Self::shutdown`] before removing the runtime
    /// directory.
    pub async fn open_experimental(
        runtime_parent: impl AsRef<Path>,
        init_executable: impl AsRef<Path>,
    ) -> Result<Self> {
        let mut capability = crate::platform::native_driver_capability();
        if capability.status != CapabilityStatus::Available {
            return Err(Error::new(
                ErrorCode::Unavailable,
                capability
                    .reason
                    .clone()
                    .unwrap_or_else(|| "native Linux prerequisites are unavailable".to_string()),
            )
            .for_operation("open-native-linux-driver"));
        }
        capability.readiness = DriverReadiness::Experimental;
        capability.evidence.insert(
            "execution_path".to_string(),
            "shared-linux-executor".to_string(),
        );
        capability
            .evidence
            .insert("kvm_required".to_string(), "false".to_string());
        capability
            .evidence
            .insert("opt_in".to_string(), "open-experimental".to_string());

        let executor = Arc::new(
            LinuxExecutor::open_native_with_absolute_rootfs(runtime_parent, init_executable)
                .await?,
        );
        let attachment_capabilities =
            native_attachment_capabilities(executor.has_network_device_authority())?;
        let service: Arc<dyn GuestAgentService> = executor.clone();
        Ok(Self {
            capability,
            attachment_capabilities,
            operations: AGENT_DRIVER_OPERATIONS.to_vec(),
            executor,
            client: AgentDriverClient::new(service, "native Linux executor", "native-linux"),
            checkpoint: None,
            recovered: Mutex::new(BTreeMap::new()),
            live: Mutex::new(BTreeMap::new()),
        })
    }

    /// Open the rootful experimental native driver with one exact CRIU binary.
    ///
    /// This is the only constructor that advertises `Checkpoint` and `Restore`.
    /// It verifies CRIU's immutable executable identity and host feature probe
    /// before the driver becomes visible.
    pub async fn open_experimental_with_criu(
        runtime_parent: impl AsRef<Path>,
        init_executable: impl AsRef<Path>,
        criu_executable: impl AsRef<Path>,
    ) -> Result<Self> {
        let runtime_parent = PathBuf::from(runtime_parent.as_ref());
        let init_executable = PathBuf::from(init_executable.as_ref());
        let checkpoint = Arc::new(
            NativeCriuCheckpoint::open(&runtime_parent, &init_executable, criu_executable).await?,
        );
        let mut driver = Self::open_experimental(&runtime_parent, &init_executable).await?;
        driver.operations.push(RuntimeOperation::Checkpoint);
        driver.operations.push(RuntimeOperation::Restore);
        driver
            .capability
            .evidence
            .insert("checkpoint_backend".to_string(), "criu".to_string());
        driver.capability.evidence.insert(
            "checkpoint_format".to_string(),
            format!(
                "{}-v{}",
                checkpoint.format().name(),
                checkpoint.format().version()
            ),
        );
        driver.capability.evidence.insert(
            "checkpoint_criu_version".to_string(),
            checkpoint.tool_version().to_string(),
        );
        driver.capability.evidence.insert(
            "checkpoint_criu_digest".to_string(),
            checkpoint.tool_digest().to_string(),
        );
        driver.capability.evidence.insert(
            "checkpoint_driver_build_digest".to_string(),
            checkpoint.driver_build_digest().to_string(),
        );
        driver.capability.evidence.insert(
            "checkpoint_source_revision".to_string(),
            option_env!("A3S_OCI_GIT_REVISION")
                .unwrap_or("unavailable")
                .to_string(),
        );
        driver.capability.evidence.insert(
            "checkpoint_opt_in".to_string(),
            "open-experimental-with-criu".to_string(),
        );
        driver
            .capability
            .evidence
            .insert("restore_backend".to_string(), "criu".to_string());
        driver.checkpoint = Some(checkpoint);
        Ok(driver)
    }

    /// Open the experimental native driver with one explicit rootless
    /// cgroup-v2 delegation supplied by the host.
    pub async fn open_experimental_with_rootless_cgroup_delegation(
        runtime_parent: impl AsRef<Path>,
        init_executable: impl AsRef<Path>,
        delegated_cgroup_root: impl AsRef<Path>,
    ) -> Result<Self> {
        let mut capability = crate::platform::native_driver_capability();
        if capability.status != CapabilityStatus::Available {
            return Err(Error::new(
                ErrorCode::Unavailable,
                capability
                    .reason
                    .clone()
                    .unwrap_or_else(|| "native Linux prerequisites are unavailable".to_string()),
            )
            .for_operation("open-native-linux-driver"));
        }
        capability.readiness = DriverReadiness::Experimental;
        capability.evidence.insert(
            "execution_path".to_string(),
            "shared-linux-executor".to_string(),
        );
        capability
            .evidence
            .insert("kvm_required".to_string(), "false".to_string());
        capability.evidence.insert(
            "rootless_cgroup_delegation".to_string(),
            "explicit-v1".to_string(),
        );

        let executor = Arc::new(
            LinuxExecutor::open_native_with_rootless_cgroup_delegation(
                runtime_parent,
                init_executable,
                delegated_cgroup_root,
            )
            .await?,
        );
        let attachment_capabilities =
            native_attachment_capabilities(executor.has_network_device_authority())?;
        let service: Arc<dyn GuestAgentService> = executor.clone();
        Ok(Self {
            capability,
            attachment_capabilities,
            operations: AGENT_DRIVER_OPERATIONS.to_vec(),
            executor,
            client: AgentDriverClient::new(service, "native Linux executor", "native-linux"),
            checkpoint: None,
            recovered: Mutex::new(BTreeMap::new()),
            live: Mutex::new(BTreeMap::new()),
        })
    }

    /// Open rootless native Linux from an effective-root bootstrap and retain
    /// that privilege only inside a parent-bound delegated-cgroup device helper.
    ///
    /// The process must have non-root real UID/GID and effective UID/GID zero.
    /// Construction drops the caller permanently to its real identity before
    /// returning; only the helper retains privilege for the fixed default-device
    /// mounts and structured cgroup-device requests below the exact delegation.
    pub async fn open_experimental_with_rootless_device_policy(
        runtime_parent: impl AsRef<Path>,
        init_executable: impl AsRef<Path>,
        bootstrap: RootlessDevicePolicyBootstrap,
    ) -> Result<Self> {
        let mut capability = crate::platform::native_driver_capability();
        if capability.status != CapabilityStatus::Available {
            return Err(Error::new(
                ErrorCode::Unavailable,
                capability
                    .reason
                    .clone()
                    .unwrap_or_else(|| "native Linux prerequisites are unavailable".to_string()),
            )
            .for_operation("open-native-linux-driver"));
        }
        capability.readiness = DriverReadiness::Experimental;
        capability.evidence.insert(
            "execution_path".to_string(),
            "shared-linux-executor".to_string(),
        );
        capability
            .evidence
            .insert("kvm_required".to_string(), "false".to_string());
        capability.evidence.insert(
            "rootless_cgroup_delegation".to_string(),
            "explicit-v1".to_string(),
        );
        capability.evidence.insert(
            "rootless_device_policy".to_string(),
            "parent-bound-helper-v1".to_string(),
        );

        let executor = Arc::new(
            LinuxExecutor::open_native_with_rootless_cgroup_device_policy(
                runtime_parent,
                init_executable,
                bootstrap,
            )
            .await?,
        );
        let attachment_capabilities =
            native_attachment_capabilities(executor.has_network_device_authority())?;
        let service: Arc<dyn GuestAgentService> = executor.clone();
        Ok(Self {
            capability,
            attachment_capabilities,
            operations: AGENT_DRIVER_OPERATIONS.to_vec(),
            executor,
            client: AgentDriverClient::new(service, "native Linux executor", "native-linux"),
            checkpoint: None,
            recovered: Mutex::new(BTreeMap::new()),
            live: Mutex::new(BTreeMap::new()),
        })
    }

    /// Stop every process owned by this driver and remove transient state.
    pub async fn shutdown(&self) -> Result<()> {
        self.executor.shutdown().await
    }

    /// Private transient executor root used by this driver instance.
    #[must_use]
    pub fn executor_root(&self) -> &Path {
        self.executor.runtime_root()
    }

    async fn recovered_for(
        &self,
        target: &ContainerTarget,
        operation: &'static str,
    ) -> Result<Option<LinuxExecutorTombstone>> {
        let recovered = self.recovered.lock().await;
        let Some(tombstone) = recovered.get(&target.id) else {
            return Ok(None);
        };
        if tombstone.target() != target {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!(
                    "container {} has native recovery evidence for generation {:?}, not requested generation {:?}",
                    target.id,
                    tombstone.target().generation,
                    target.generation
                ),
            )
            .for_operation(operation));
        }
        Ok(Some(tombstone.clone()))
    }

    async fn live_for(
        &self,
        target: &ContainerTarget,
        operation: &'static str,
    ) -> Result<Option<Arc<LinuxLiveSupervisedSession>>> {
        let live = self.live.lock().await;
        let Some(session) = live.get(&target.id) else {
            return Ok(None);
        };
        if session.target() != target {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!(
                    "container {} has live supervised recovery for generation {:?}, not requested generation {:?}",
                    target.id,
                    session.target().generation,
                    target.generation
                ),
            )
            .for_operation(operation));
        }
        Ok(Some(Arc::clone(session)))
    }

    async fn require_live_process_session(
        &self,
        target: &ContainerTarget,
        operation: &'static str,
    ) -> Result<()> {
        if self.live_for(target, operation).await?.is_some() {
            return Err(Error::new(
                ErrorCode::Unavailable,
                format!(
                    "container {} generation {:?} is retained through a reattached session supervisor without a restored PreparedProcess; {operation} requires full process-session restore",
                    target.id, target.generation
                ),
            )
            .for_operation(operation));
        }
        if self.recovered_for(target, operation).await?.is_some() {
            Err(recovered_stopped_error(target, operation))
        } else {
            Ok(())
        }
    }

    async fn require_live(&self, target: &ContainerTarget, operation: &'static str) -> Result<()> {
        self.require_live_process_session(target, operation).await
    }
}

#[async_trait]
impl RuntimeDriver for NativeLinuxDriver {
    fn capability(&self) -> DriverCapability {
        self.capability.clone()
    }

    fn linux_support(&self) -> Result<a3s_oci_sdk::OciLinuxSupport> {
        a3s_oci_sdk::OciLinuxSupport::shared_executor()
    }

    fn operations(&self) -> &[RuntimeOperation] {
        &self.operations
    }

    fn hooks(&self) -> &[OciHookPhase] {
        &AGENT_DRIVER_HOOKS
    }

    fn attachment_capabilities(&self) -> AttachmentCapabilities {
        self.attachment_capabilities.clone()
    }

    async fn acknowledge_operation(&self, operation_id: &OperationId) -> Result<()> {
        if let Some(checkpoint) = &self.checkpoint {
            checkpoint.acknowledge(operation_id).await?;
        }
        self.client.acknowledge_operation(operation_id).await
    }

    async fn recover(&self, record: &ContainerRecord) -> Result<crate::DriverRecovery> {
        let target =
            ContainerTarget::exact(ContainerId::new(record.state.id())?, record.generation);
        if let Some(checkpoint) = &self.checkpoint {
            match checkpoint.recover_restore(&self.executor, record).await? {
                Some(NativeRestoreRecovery::Pending) => {
                    return Ok(crate::DriverRecovery::none());
                }
                Some(NativeRestoreRecovery::Recreated(state)) => {
                    let observed =
                        self.client
                            .map_state(&target, Some(&record.config_digest), state)?;
                    return crate::DriverRecovery::recreated_paused_running(observed);
                }
                None => {}
            }
        }
        let can_commit_stopped =
            *record.state.status() != a3s_oci_sdk::oci_spec::runtime::ContainerState::Creating;
        match self
            .client
            .state_with_digest(target.clone(), Some(&record.config_digest))
            .await
        {
            Ok(observed) => {
                if !can_commit_stopped {
                    return Ok(crate::DriverRecovery::none());
                }
                if observed.status() == a3s_oci_sdk::oci_spec::runtime::ContainerState::Stopped {
                    let status = self
                        .client
                        .wait(DriverWaitRequest {
                            target,
                            timeout_ms: Some(0),
                        })
                        .await?;
                    return crate::DriverRecovery::stopped_with_exit(status);
                }
                return Ok(crate::DriverRecovery::observed(observed));
            }
            Err(error) if error.code == ErrorCode::NotFound => {}
            Err(error) => return Err(error),
        }

        let durable_pid = *record.state.pid();
        let recovery = self
            .executor
            .recover_stale_generation(&target, &record.config_digest, durable_pid)
            .await?;
        if !can_commit_stopped {
            match recovery {
                Some(StaleGenerationRecovery::Stopped(tombstone)) => {
                    self.executor.delete_stale_generation(&tombstone).await?;
                }
                Some(StaleGenerationRecovery::Live(live)) => {
                    let mut sessions = self.live.lock().await;
                    sessions.insert(target.id.clone(), Arc::new(live));
                }
                None => {}
            }
            return Ok(crate::DriverRecovery::none());
        }
        let recovery = recovery.ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "no authenticated native recovery record exists for container {} generation {:?}",
                    target.id, target.generation
                ),
            )
            .for_operation("native-linux-recover")
        })?;

        match recovery {
            StaleGenerationRecovery::Stopped(tombstone) => {
                let mut recovered = self.recovered.lock().await;
                match recovered.get(&target.id) {
                    Some(existing) if existing.target() == &target => {}
                    Some(existing) => {
                        return Err(Error::new(
                            ErrorCode::Conflict,
                            format!(
                                "container {} already has native recovery evidence for generation {:?}",
                                target.id,
                                existing.target().generation
                            ),
                        )
                        .for_operation("native-linux-recover"));
                    }
                    None => {
                        recovered.insert(target.id.clone(), tombstone);
                    }
                }
                Ok(crate::DriverRecovery::observed(DriverState::stopped()))
            }
            StaleGenerationRecovery::Live(live) => {
                let observation = observe_live_supervised_state(record, &live)?;
                let mut sessions = self.live.lock().await;
                match sessions.get(&target.id) {
                    Some(existing) if existing.target() == &target => {}
                    Some(existing) => {
                        return Err(Error::new(
                            ErrorCode::Conflict,
                            format!(
                                "container {} already has live supervised recovery for generation {:?}",
                                target.id,
                                existing.target().generation
                            ),
                        )
                        .for_operation("native-linux-recover"));
                    }
                    None => {
                        sessions.insert(target.id.clone(), Arc::new(live));
                    }
                }
                Ok(observation)
            }
        }
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        if request.isolation.class() != IsolationClass::SharedHostKernel {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "native Linux execution requires shared-host-kernel isolation",
            )
            .for_operation("native-linux-create"));
        }
        if let Some(tombstone) = self.recovered.lock().await.get(&request.target.id) {
            return Err(recovered_stopped_error(
                tombstone.target(),
                "native-linux-create",
            ));
        }
        if let Some(live) = self.live.lock().await.get(&request.target.id) {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "container {} generation {:?} is retained through a reattached session supervisor; create requires a fresh generation",
                    live.target().id,
                    live.target().generation
                ),
            )
            .for_operation("native-linux-create"));
        }
        let inherited_descriptors = match &request.attachments {
            DriverCreateAttachments::None => InheritedDescriptorPlan::empty(),
            DriverCreateAttachments::NativeControl(descriptors) => descriptors.descriptor_plan()?,
        };
        let guest_directory = guest_path(request.bundle.directory()).await?;
        let expected_digest = request.bundle.config_digest().to_string();
        let expected_target = request.target.clone();
        let state = self
            .executor
            .create_with_inherited_descriptors(
                AgentCreateRequest {
                    context: request.context,
                    target: request.target,
                    bundle: AgentBundle::new(&request.bundle, guest_directory),
                    io: request.io,
                },
                inherited_descriptors,
            )
            .await?;
        self.client
            .map_state(&expected_target, Some(&expected_digest), state)
    }

    async fn state(&self, target: ContainerTarget) -> Result<DriverState> {
        if let Some(live) = self.live_for(&target, "native-linux-state").await? {
            return observe_live_supervised_driver_state(&live);
        }
        if self
            .recovered_for(&target, "native-linux-state")
            .await?
            .is_some()
        {
            return Ok(DriverState::stopped());
        }
        self.client.state(target).await
    }

    async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        self.require_live(&request.target, "native-linux-start")
            .await?;
        self.client.start(request).await
    }

    async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        if let Some(live) = self.live_for(&request.target, "native-linux-kill").await? {
            live.kill_init()?;
            live.kill_launcher()?;
            return observe_live_supervised_driver_state(&live);
        }
        if self
            .recovered_for(&request.target, "native-linux-kill")
            .await?
            .is_some()
        {
            return Ok(DriverState::stopped());
        }
        self.client.kill(request).await
    }

    async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        if let Some(live) = self
            .live_for(&request.target, "native-linux-delete")
            .await?
        {
            let tombstone = live
                .stopped_tombstone()
                .map_err(|error| error.for_operation("native-linux-delete"))?;
            {
                let mut sessions = self.live.lock().await;
                sessions.remove(&request.target.id);
            }
            self.executor.delete_stale_generation(&tombstone).await?;
            return Ok(());
        }
        if let Some(tombstone) = self
            .recovered_for(&request.target, "native-linux-delete")
            .await?
        {
            self.executor.delete_stale_generation(&tombstone).await?;
            let mut recovered = self.recovered.lock().await;
            if recovered
                .get(&request.target.id)
                .is_some_and(|current| current.target() == &request.target)
            {
                recovered.remove(&request.target.id);
            }
            return Ok(());
        }
        self.client.delete(request).await
    }

    async fn wait(&self, request: DriverWaitRequest) -> Result<ExitStatus> {
        if let Some(live) = self.live_for(&request.target, "native-linux-wait").await? {
            let raw = live.wait_launcher()?;
            return supervised_wait_status(raw, "native-linux-wait");
        }
        if self
            .recovered_for(&request.target, "native-linux-wait")
            .await?
            .is_some()
        {
            return Err(recovered_exit_evidence_error(
                &request.target,
                "native-linux-wait",
            ));
        }
        self.client.wait(request).await
    }

    async fn exec(&self, request: DriverExecRequest) -> Result<DriverProcess> {
        if let Some(live) = self
            .live_for(&request.target.container, "native-linux-exec")
            .await?
        {
            let (init_executable, pinned) = self
                .executor
                .duplicate_init_executable()
                .map_err(|error| error.for_operation("native-linux-exec"))?;
            let (pid, terminal) = live
                .exec(
                    &request.target.process_id,
                    &request.process,
                    &request.io,
                    &init_executable,
                )
                .await
                .map_err(|error| error.for_operation("native-linux-exec"))?;
            drop(pinned);
            return DriverProcess::new(pid, terminal);
        }
        if self
            .recovered_for(&request.target.container, "native-linux-exec")
            .await?
            .is_some()
        {
            return Err(recovered_stopped_error(
                &request.target.container,
                "native-linux-exec",
            ));
        }
        self.client.exec(request).await
    }

    async fn signal_process(&self, request: DriverSignalProcessRequest) -> Result<()> {
        if let Some(live) = self
            .live_for(&request.target.container, "native-linux-signal-process")
            .await?
        {
            return live
                .signal_process(&request.target.process_id, request.signal.get())
                .map_err(|error| error.for_operation("native-linux-signal-process"));
        }
        if self
            .recovered_for(&request.target.container, "native-linux-signal-process")
            .await?
            .is_some()
        {
            return Err(recovered_stopped_error(
                &request.target.container,
                "native-linux-signal-process",
            ));
        }
        self.client.signal_process(request).await
    }

    async fn wait_process(&self, request: DriverWaitProcessRequest) -> Result<ExitStatus> {
        if let Some(live) = self
            .live_for(&request.target.container, "native-linux-wait-process")
            .await?
        {
            let raw = live
                .wait_process(&request.target.process_id)
                .map_err(|error| error.for_operation("native-linux-wait-process"))?;
            return supervised_wait_status(raw, "native-linux-wait-process");
        }
        if self
            .recovered_for(&request.target.container, "native-linux-wait-process")
            .await?
            .is_some()
        {
            return Err(recovered_exit_evidence_error(
                &request.target.container,
                "native-linux-wait-process",
            ));
        }
        self.client.wait_process(request).await
    }

    async fn pause(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        if let Some(live) = self.live_for(&request.target, "native-linux-pause").await? {
            live.pause()
                .await
                .map_err(|error| error.for_operation("native-linux-pause"))?;
            return observe_live_supervised_driver_state(&live);
        }
        if self
            .recovered_for(&request.target, "native-linux-pause")
            .await?
            .is_some()
        {
            return Err(recovered_stopped_error(
                &request.target,
                "native-linux-pause",
            ));
        }
        self.client.pause(request).await
    }

    async fn resume(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        if let Some(live) = self
            .live_for(&request.target, "native-linux-resume")
            .await?
        {
            live.resume()
                .await
                .map_err(|error| error.for_operation("native-linux-resume"))?;
            return observe_live_supervised_driver_state(&live);
        }
        if self
            .recovered_for(&request.target, "native-linux-resume")
            .await?
            .is_some()
        {
            return Err(recovered_stopped_error(
                &request.target,
                "native-linux-resume",
            ));
        }
        self.client.resume(request).await
    }

    async fn processes(&self, target: ContainerTarget) -> Result<Vec<ProcessRecord>> {
        if let Some(live) = self.live_for(&target, "native-linux-processes").await? {
            return live
                .process_inventory()
                .map_err(|error| error.for_operation("native-linux-processes"));
        }
        if self
            .recovered_for(&target, "native-linux-processes")
            .await?
            .is_some()
        {
            return Ok(Vec::new());
        }
        self.client.processes(target).await
    }

    async fn update(&self, request: DriverUpdateRequest) -> Result<DriverState> {
        self.require_live(&request.target, "native-linux-update")
            .await?;
        self.client.update(request).await
    }

    async fn stats(&self, target: ContainerTarget) -> Result<ContainerStats> {
        if let Some(live) = self.live_for(&target, "native-linux-stats").await? {
            return live
                .stats()
                .await
                .map_err(|error| error.for_operation("native-linux-stats"));
        }
        if self
            .recovered_for(&target, "native-linux-stats")
            .await?
            .is_some()
        {
            return Err(recovered_stopped_error(&target, "native-linux-stats"));
        }
        self.client.stats(target).await
    }

    async fn read_output(&self, request: DriverReadOutputRequest) -> Result<Vec<OutputChunk>> {
        if let Some(live) = self
            .live_for(&request.target.container, "native-linux-read-output")
            .await?
        {
            return live
                .read_output(
                    &request.target.process_id,
                    request.after_sequence,
                    request.max_bytes,
                    request.wait_timeout_ms,
                )
                .map_err(|error| error.for_operation("native-linux-read-output"));
        }
        if self
            .recovered_for(&request.target.container, "native-linux-read-output")
            .await?
            .is_some()
        {
            return Err(recovered_stopped_error(
                &request.target.container,
                "native-linux-read-output",
            ));
        }
        self.client.read_output(request).await
    }

    async fn write_stdin(&self, request: DriverWriteStdinRequest) -> Result<()> {
        if let Some(live) = self
            .live_for(&request.target.container, "native-linux-write-stdin")
            .await?
        {
            return live
                .write_stdin(&request.target.process_id, &request.data)
                .await
                .map_err(|error| error.for_operation("native-linux-write-stdin"));
        }
        if self
            .recovered_for(&request.target.container, "native-linux-write-stdin")
            .await?
            .is_some()
        {
            return Err(recovered_stopped_error(
                &request.target.container,
                "native-linux-write-stdin",
            ));
        }
        self.client.write_stdin(request).await
    }

    async fn close_stdin(&self, request: DriverCloseStdinRequest) -> Result<()> {
        if let Some(live) = self
            .live_for(&request.target.container, "native-linux-close-stdin")
            .await?
        {
            return live
                .close_stdin(&request.target.process_id)
                .await
                .map_err(|error| error.for_operation("native-linux-close-stdin"));
        }
        if self
            .recovered_for(&request.target.container, "native-linux-close-stdin")
            .await?
            .is_some()
        {
            return Err(recovered_stopped_error(
                &request.target.container,
                "native-linux-close-stdin",
            ));
        }
        self.client.close_stdin(request).await
    }

    async fn resize(&self, request: DriverResizeRequest) -> Result<()> {
        self.require_live(&request.target.container, "native-linux-resize")
            .await?;
        self.client.resize(request).await
    }

    async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        self.require_live(&request.target, "native-linux-file")
            .await?;
        self.client.file(request).await
    }

    async fn filesystem(&self, request: FilesystemRequest) -> Result<FilesystemResponse> {
        self.require_live(&request.target, "native-linux-filesystem")
            .await?;
        self.client.filesystem(request).await
    }

    async fn checkpoint(&self, request: DriverCheckpointRequest) -> Result<DriverCheckpointResult> {
        let checkpoint = self.checkpoint.as_ref().ok_or_else(|| {
            Error::unsupported("checkpoint").for_operation("native-linux-checkpoint")
        })?;
        let target = ContainerTarget::exact(
            ContainerId::new(request.source.state.id().to_string())?,
            request.source.generation,
        );
        self.require_live(&target, "native-linux-checkpoint")
            .await?;
        checkpoint.checkpoint(&self.executor, request).await
    }

    async fn validate_restore_artifact(
        &self,
        request: DriverRestoreValidationRequest,
    ) -> Result<()> {
        let checkpoint = self
            .checkpoint
            .as_ref()
            .ok_or_else(|| Error::unsupported("restore").for_operation("native-linux-restore"))?;
        checkpoint.validate_restore_artifact(&request).await
    }

    async fn restore(&self, request: DriverRestoreRequest) -> Result<DriverState> {
        let checkpoint = self
            .checkpoint
            .as_ref()
            .ok_or_else(|| Error::unsupported("restore").for_operation("native-linux-restore"))?;
        if request.isolation.class() != IsolationClass::SharedHostKernel {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "native Linux restore requires shared-host-kernel isolation",
            )
            .for_operation("native-linux-restore"));
        }
        if let Some(tombstone) = self.recovered.lock().await.get(&request.target.id) {
            return Err(recovered_stopped_error(
                tombstone.target(),
                "native-linux-restore",
            ));
        }
        if let Some(live) = self.live.lock().await.get(&request.target.id) {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "container {} generation {:?} is retained through a reattached session supervisor; restore requires a fresh generation",
                    live.target().id,
                    live.target().generation
                ),
            )
            .for_operation("native-linux-restore"));
        }
        let guest_directory = guest_path(request.bundle.directory()).await?;
        let expected_target = request.target.clone();
        let expected_digest = request.bundle.config_digest().to_string();
        let agent_request = AgentCreateRequest {
            context: request.context.clone(),
            target: request.target.clone(),
            bundle: AgentBundle::new(&request.bundle, guest_directory),
            io: request.io.clone(),
        };
        let state = checkpoint
            .restore(&self.executor, &request, agent_request)
            .await?;
        self.client
            .map_state(&expected_target, Some(&expected_digest), state)
    }
}

fn native_attachment_capabilities(
    has_network_device_authority: bool,
) -> Result<AttachmentCapabilities> {
    if has_network_device_authority {
        AttachmentCapabilities::base_v3().with_extension(
            NETWORK_ENFORCEMENT_EXTENSION,
            vec![NETWORK_ENFORCEMENT_EXTENSION_VERSION],
        )
    } else {
        Ok(AttachmentCapabilities::base_v2())
    }
}

fn observe_live_supervised_state(
    record: &ContainerRecord,
    live: &LinuxLiveSupervisedSession,
) -> Result<crate::DriverRecovery> {
    // Keep `observed` rather than `recreated_running_with_processes`. Dead
    // durable execs are omitted from Live inventory without inventing exit
    // status; Host exact-match exec rebind would Conflict on that omission.
    // Driver `processes` reads authentic inventory from the live session.
    Ok(crate::DriverRecovery::observed(
        observe_live_supervised_driver_state_for_status(*record.state.status(), live)?,
    ))
}

fn observe_live_supervised_driver_state(live: &LinuxLiveSupervisedSession) -> Result<DriverState> {
    observe_live_supervised_driver_state_for_status(
        a3s_oci_sdk::oci_spec::runtime::ContainerState::Running,
        live,
    )
}

fn observe_live_supervised_driver_state_for_status(
    durable_status: a3s_oci_sdk::oci_spec::runtime::ContainerState,
    live: &LinuxLiveSupervisedSession,
) -> Result<DriverState> {
    use a3s_oci_sdk::oci_spec::runtime::ContainerState;
    // Prefer authenticated /proc liveness. Never invent exit status here.
    if live.init_is_live()? {
        let state = match durable_status {
            ContainerState::Created | ContainerState::Creating => {
                DriverState::created(live.init_pid())?
            }
            _ => DriverState::running(live.init_pid())?,
        };
        // Authentic freezer observation from the durable cgroup leaf when
        // present. Missing cgroup evidence keeps paused=false rather than
        // inventing a frozen state (pause itself fail-closes Unavailable).
        let paused = match live.is_paused() {
            Ok(paused) => paused,
            Err(error) if error.code == ErrorCode::Unavailable => false,
            Err(error) => {
                return Err(error.for_operation("native-linux-state"));
            }
        };
        return state.with_paused(paused);
    }
    if live.launcher_is_live()? {
        return DriverState::created(live.launcher_pid());
    }
    Ok(DriverState::stopped())
}

fn supervised_wait_status(raw: i32, operation: &'static str) -> Result<ExitStatus> {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus as ProcessExitStatus;

    let status = ProcessExitStatus::from_raw(raw);
    if let Some(code) = status.code() {
        return ExitStatus::exited(code);
    }
    if let Some(signal) = status.signal() {
        return ExitStatus::signaled(signal, false);
    }
    Err(Error::new(
        ErrorCode::Internal,
        format!("supervised process returned unsupported wait status {raw}"),
    )
    .for_operation(operation))
}

fn recovered_stopped_error(target: &ContainerTarget, operation: &'static str) -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        format!(
            "container {} generation {:?} was safely terminated after its native Linux owner exited; delete this stopped generation before another live operation",
            target.id, target.generation
        ),
    )
    .for_operation(operation)
}

fn recovered_exit_evidence_error(target: &ContainerTarget, operation: &'static str) -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        format!(
            "container {} generation {:?} was safely terminated by native Linux owner-death cleanup, but no authenticated parent remained to retain its exact init exit status",
            target.id, target.generation
        ),
    )
    .for_operation(operation)
}

async fn guest_path(bundle: &Path) -> Result<GuestPath> {
    let canonical = tokio::fs::canonicalize(bundle).await.map_err(|error| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to resolve native Linux bundle {}: {error}",
                bundle.display()
            ),
        )
        .for_operation("native-linux-create")
    })?;
    let value = canonical.to_str().ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "native Linux bundle path is not valid UTF-8: {}",
                canonical.display()
            ),
        )
        .for_operation("native-linux-create")
    })?;
    GuestPath::new(value.to_string())
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::{
        AMD_SEV_SNP_LAUNCH_EXTENSION, ATTACHMENT_SCHEMA_V2, ATTACHMENT_SCHEMA_V3,
        INTEL_TDX_LAUNCH_EXTENSION, NETWORK_ENFORCEMENT_EXTENSION,
        NETWORK_ENFORCEMENT_EXTENSION_VERSION, TEE_LAUNCH_EXTENSION_VERSION,
    };

    use super::native_attachment_capabilities;

    #[test]
    fn network_attachment_capability_requires_rootful_device_authority() {
        let rootful = native_attachment_capabilities(true).expect("rootful capabilities");
        assert!(rootful.supports_schema(ATTACHMENT_SCHEMA_V2));
        assert!(rootful.supports_schema(ATTACHMENT_SCHEMA_V3));
        assert!(rootful.supports_extension(
            NETWORK_ENFORCEMENT_EXTENSION,
            NETWORK_ENFORCEMENT_EXTENSION_VERSION,
        ));

        let rootless = native_attachment_capabilities(false).expect("rootless capabilities");
        assert!(rootless.supports_schema(ATTACHMENT_SCHEMA_V2));
        assert!(!rootless.supports_schema(ATTACHMENT_SCHEMA_V3));
        assert!(!rootless.supports_extension(
            NETWORK_ENFORCEMENT_EXTENSION,
            NETWORK_ENFORCEMENT_EXTENSION_VERSION,
        ));
        for capabilities in [rootful, rootless] {
            assert!(!capabilities
                .supports_extension(AMD_SEV_SNP_LAUNCH_EXTENSION, TEE_LAUNCH_EXTENSION_VERSION,));
            assert!(!capabilities
                .supports_extension(INTEL_TDX_LAUNCH_EXTENSION, TEE_LAUNCH_EXTENSION_VERSION,));
        }
    }
}
