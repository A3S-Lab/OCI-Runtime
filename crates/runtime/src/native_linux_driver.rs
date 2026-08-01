use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent::{InheritedDescriptorPlan, LinuxExecutor};
use a3s_oci_agent_protocol::{AgentBundle, AgentCreateRequest, GuestAgentService, GuestPath};
use a3s_oci_core::{CapabilityStatus, DriverCapability, DriverReadiness, IsolationClass};
use a3s_oci_sdk::{
    async_trait, ContainerStats, ContainerTarget, Error, ErrorCode, ExitStatus, FileRequest,
    FileResponse, FilesystemRequest, FilesystemResponse, OutputChunk, ProcessRecord, Result,
    RuntimeOperation,
};

use crate::agent_driver::{AgentDriverClient, AGENT_DRIVER_HOOKS, AGENT_DRIVER_OPERATIONS};
use crate::driver::{
    DriverCloseStdinRequest, DriverContainerOperationRequest, DriverCreateAttachments,
    DriverCreateRequest, DriverDeleteRequest, DriverExecRequest, DriverKillRequest, DriverProcess,
    DriverReadOutputRequest, DriverResizeRequest, DriverSignalProcessRequest, DriverStartRequest,
    DriverState, DriverUpdateRequest, DriverWaitProcessRequest, DriverWaitRequest,
    DriverWriteStdinRequest, OciHookPhase, RuntimeDriver,
};

/// Explicitly opted-in native Linux runtime driver.
///
/// The default feature inventory remains `probe-only`. Constructing this
/// driver is the explicit experimental opt-in that allows
/// [`crate::HostRuntimeService`] to exercise the currently reviewed executor
/// profile without linking or initializing libkrun.
#[derive(Debug)]
pub struct NativeLinuxDriver {
    capability: DriverCapability,
    executor: Arc<LinuxExecutor>,
    client: AgentDriverClient,
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
        let service: Arc<dyn GuestAgentService> = executor.clone();
        Ok(Self {
            capability,
            executor,
            client: AgentDriverClient::new(service, "native Linux executor", "native-linux"),
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
}

#[async_trait]
impl RuntimeDriver for NativeLinuxDriver {
    fn capability(&self) -> DriverCapability {
        self.capability.clone()
    }

    fn operations(&self) -> &[RuntimeOperation] {
        &AGENT_DRIVER_OPERATIONS
    }

    fn hooks(&self) -> &[OciHookPhase] {
        &AGENT_DRIVER_HOOKS
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        if request.isolation.class() != IsolationClass::SharedHostKernel {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "native Linux execution requires shared-host-kernel isolation",
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
        self.client.state(target).await
    }

    async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        self.client.start(request).await
    }

    async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        self.client.kill(request).await
    }

    async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        self.client.delete(request).await
    }

    async fn wait(&self, request: DriverWaitRequest) -> Result<ExitStatus> {
        self.client.wait(request).await
    }

    async fn exec(&self, request: DriverExecRequest) -> Result<DriverProcess> {
        self.client.exec(request).await
    }

    async fn signal_process(&self, request: DriverSignalProcessRequest) -> Result<()> {
        self.client.signal_process(request).await
    }

    async fn wait_process(&self, request: DriverWaitProcessRequest) -> Result<ExitStatus> {
        self.client.wait_process(request).await
    }

    async fn pause(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.client.pause(request).await
    }

    async fn resume(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.client.resume(request).await
    }

    async fn processes(&self, target: ContainerTarget) -> Result<Vec<ProcessRecord>> {
        self.client.processes(target).await
    }

    async fn update(&self, request: DriverUpdateRequest) -> Result<DriverState> {
        self.client.update(request).await
    }

    async fn stats(&self, target: ContainerTarget) -> Result<ContainerStats> {
        self.client.stats(target).await
    }

    async fn read_output(&self, request: DriverReadOutputRequest) -> Result<Vec<OutputChunk>> {
        self.client.read_output(request).await
    }

    async fn write_stdin(&self, request: DriverWriteStdinRequest) -> Result<()> {
        self.client.write_stdin(request).await
    }

    async fn close_stdin(&self, request: DriverCloseStdinRequest) -> Result<()> {
        self.client.close_stdin(request).await
    }

    async fn resize(&self, request: DriverResizeRequest) -> Result<()> {
        self.client.resize(request).await
    }

    async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        self.client.file(request).await
    }

    async fn filesystem(&self, request: FilesystemRequest) -> Result<FilesystemResponse> {
        self.client.filesystem(request).await
    }
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
