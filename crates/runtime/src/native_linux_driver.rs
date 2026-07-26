use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent::{InheritedDescriptorPlan, LinuxExecutor};
use a3s_oci_agent_protocol::{
    AgentBundle, AgentCloseStdinRequest, AgentContainerOperationRequest, AgentCreateRequest,
    AgentDeleteRequest, AgentExecRequest, AgentKillRequest, AgentProcessesRequest,
    AgentReadOutputRequest, AgentResizeRequest, AgentSignalProcessRequest, AgentStartRequest,
    AgentState, AgentStateRequest, AgentStatsRequest, AgentUpdateRequest, AgentWaitProcessRequest,
    AgentWaitRequest, AgentWriteStdinRequest, GuestAgentService, GuestPath,
    AGENT_MAX_IO_PAYLOAD_BYTES,
};
use a3s_oci_core::{CapabilityStatus, DriverCapability, DriverReadiness, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    async_trait, ContainerStats, ContainerTarget, Error, ErrorCode, ExitStatus, OperationContext,
    OperationId, OutputChunk, ProcessRecord, Result, RuntimeOperation,
};
use sha2::{Digest, Sha256};

use crate::driver::{
    DriverCloseStdinRequest, DriverContainerOperationRequest, DriverCreateAttachments,
    DriverCreateRequest, DriverDeleteRequest, DriverExecRequest, DriverKillRequest, DriverProcess,
    DriverReadOutputRequest, DriverResizeRequest, DriverSignalProcessRequest, DriverStartRequest,
    DriverState, DriverUpdateRequest, DriverWaitProcessRequest, DriverWaitRequest,
    DriverWriteStdinRequest, OciHookPhase, RuntimeDriver,
};

const NATIVE_LINUX_OPERATIONS: [RuntimeOperation; 18] = [
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
];
const NATIVE_LINUX_HOOKS: [OciHookPhase; 6] = OciHookPhase::ALL;

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

        Ok(Self {
            capability,
            executor: Arc::new(LinuxExecutor::open(runtime_parent, init_executable).await?),
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
        &NATIVE_LINUX_OPERATIONS
    }

    fn hooks(&self) -> &[OciHookPhase] {
        &NATIVE_LINUX_HOOKS
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
        driver_state(&expected_target, Some(&expected_digest), state)
    }

    async fn state(&self, target: ContainerTarget) -> Result<DriverState> {
        let state = self
            .executor
            .state(AgentStateRequest {
                target: target.clone(),
            })
            .await?;
        driver_state(&target, None, state)
    }

    async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        let expected_digest = request.bundle.config_digest().to_string();
        let expected_target = request.target.clone();
        let state = self
            .executor
            .start(AgentStartRequest {
                context: request.context,
                target: request.target,
                expected_config_digest: expected_digest.clone(),
            })
            .await?;
        driver_state(&expected_target, Some(&expected_digest), state)
    }

    async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        let expected_target = request.target.clone();
        let state = self
            .executor
            .kill(AgentKillRequest {
                context: request.context,
                target: request.target,
                signal: request.signal,
                all: request.all,
            })
            .await?;
        driver_state(&expected_target, None, state)
    }

    async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        self.executor
            .delete(AgentDeleteRequest {
                context: request.context,
                target: request.target,
                mode: request.mode,
            })
            .await
    }

    async fn wait(&self, request: DriverWaitRequest) -> Result<ExitStatus> {
        self.executor
            .wait(AgentWaitRequest {
                target: request.target,
                timeout_ms: request.timeout_ms,
            })
            .await
    }

    async fn exec(&self, request: DriverExecRequest) -> Result<DriverProcess> {
        let expected_target = request.target.clone();
        let expected_terminal = request.process.terminal().unwrap_or(false);
        let process = self
            .executor
            .exec(AgentExecRequest {
                context: request.context,
                target: request.target,
                process: request.process,
                io: request.io,
            })
            .await?;
        if process.target() != &expected_target {
            return Err(Error::new(
                ErrorCode::Conflict,
                "native Linux executor returned a different process target",
            )
            .for_operation("map-native-linux-process"));
        }
        if process.terminal() != expected_terminal {
            return Err(Error::new(
                ErrorCode::Conflict,
                "native Linux executor returned a different process terminal mode",
            )
            .for_operation("map-native-linux-process"));
        }
        DriverProcess::new(process.pid(), process.terminal())
    }

    async fn signal_process(&self, request: DriverSignalProcessRequest) -> Result<()> {
        self.executor
            .signal_process(AgentSignalProcessRequest {
                context: request.context,
                target: request.target,
                signal: request.signal,
            })
            .await
    }

    async fn wait_process(&self, request: DriverWaitProcessRequest) -> Result<ExitStatus> {
        self.executor
            .wait_process(AgentWaitProcessRequest {
                target: request.target,
                timeout_ms: request.timeout_ms,
            })
            .await
    }

    async fn pause(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        let expected_target = request.target.clone();
        let state = self
            .executor
            .pause(AgentContainerOperationRequest {
                context: request.context,
                target: request.target,
            })
            .await?;
        driver_state(&expected_target, None, state)
    }

    async fn resume(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        let expected_target = request.target.clone();
        let state = self
            .executor
            .resume(AgentContainerOperationRequest {
                context: request.context,
                target: request.target,
            })
            .await?;
        driver_state(&expected_target, None, state)
    }

    async fn processes(&self, target: ContainerTarget) -> Result<Vec<ProcessRecord>> {
        self.executor
            .processes(AgentProcessesRequest { target })
            .await
    }

    async fn update(&self, request: DriverUpdateRequest) -> Result<DriverState> {
        let expected_target = request.target.clone();
        let state = self
            .executor
            .update(AgentUpdateRequest {
                context: request.context,
                target: request.target,
                resources: request.resources,
            })
            .await?;
        driver_state(&expected_target, None, state)
    }

    async fn stats(&self, target: ContainerTarget) -> Result<ContainerStats> {
        let stats = self
            .executor
            .stats(AgentStatsRequest {
                target: target.clone(),
            })
            .await?;
        if stats.target != target {
            return Err(Error::new(
                ErrorCode::Conflict,
                "native Linux executor returned stats for a different container generation",
            )
            .for_operation("map-native-linux-stats"));
        }
        stats.validate()?;
        Ok(stats)
    }

    async fn read_output(&self, request: DriverReadOutputRequest) -> Result<Vec<OutputChunk>> {
        self.executor
            .read_output(AgentReadOutputRequest {
                process: request.target,
                after_sequence: request.after_sequence,
                max_bytes: request.max_bytes.min(AGENT_MAX_IO_PAYLOAD_BYTES),
                wait_timeout_ms: request.wait_timeout_ms,
            })
            .await
    }

    async fn write_stdin(&self, request: DriverWriteStdinRequest) -> Result<()> {
        if request.data.is_empty() {
            return self
                .executor
                .write_stdin(AgentWriteStdinRequest {
                    context: Some(request.context),
                    process: request.target,
                    data: Vec::new(),
                })
                .await;
        }
        let chunk_bytes = AGENT_MAX_IO_PAYLOAD_BYTES as usize;
        let chunk_count = request.data.len().div_ceil(chunk_bytes);
        for (index, data) in request.data.chunks(chunk_bytes).enumerate() {
            let context = if chunk_count == 1 {
                request.context.clone()
            } else {
                process_io_chunk_context(&request.context, index)?
            };
            self.executor
                .write_stdin(AgentWriteStdinRequest {
                    context: Some(context),
                    process: request.target.clone(),
                    data: data.to_vec(),
                })
                .await?;
        }
        Ok(())
    }

    async fn close_stdin(&self, request: DriverCloseStdinRequest) -> Result<()> {
        self.executor
            .close_stdin(AgentCloseStdinRequest {
                context: Some(request.context),
                process: request.target,
            })
            .await
    }

    async fn resize(&self, request: DriverResizeRequest) -> Result<()> {
        self.executor
            .resize(AgentResizeRequest {
                context: Some(request.context),
                process: request.target,
                size: request.size,
            })
            .await
    }
}

fn process_io_chunk_context(parent: &OperationContext, index: usize) -> Result<OperationContext> {
    let index = u64::try_from(index).map_err(|error| {
        Error::new(
            ErrorCode::ResourceExhausted,
            format!("stdin chunk index does not fit the guest journal: {error}"),
        )
        .for_operation("derive-stdin-chunk-operation")
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"a3s-oci-stdin-chunk-v1\0");
    hasher.update(parent.operation_id.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(index.to_be_bytes());
    let operation_id = OperationId::new(format!("io.{:x}", hasher.finalize()))?;
    Ok(OperationContext {
        operation_id,
        deadline_unix_ms: parent.deadline_unix_ms,
    })
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

fn driver_state(
    expected_target: &ContainerTarget,
    expected_digest: Option<&str>,
    state: AgentState,
) -> Result<DriverState> {
    if state.target() != expected_target {
        return Err(Error::new(
            ErrorCode::Conflict,
            "native Linux executor returned a different container generation",
        )
        .for_operation("map-native-linux-state"));
    }
    if expected_digest.is_some_and(|digest| state.config_digest() != digest) {
        return Err(Error::new(
            ErrorCode::Conflict,
            "native Linux executor returned a different configuration digest",
        )
        .for_operation("map-native-linux-state"));
    }
    let mapped = match state.status() {
        ContainerState::Created => DriverState::created(required_pid(&state)?),
        ContainerState::Running => DriverState::running(required_pid(&state)?),
        ContainerState::Stopped => Ok(DriverState::stopped()),
        status => Err(Error::new(
            ErrorCode::Internal,
            format!("native Linux executor returned invalid lifecycle state {status}"),
        )
        .for_operation("map-native-linux-state")),
    }?;
    mapped.with_paused(state.paused())
}

fn required_pid(state: &AgentState) -> Result<i32> {
    state.pid().ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            format!(
                "native Linux executor returned {} without an init PID",
                state.status()
            ),
        )
        .for_operation("map-native-linux-state")
    })
}

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::AgentState;
    use a3s_oci_sdk::oci_spec::runtime::ContainerState;
    use a3s_oci_sdk::{ContainerId, ContainerTarget, Generation, OperationContext, OperationId};

    use super::{driver_state, process_io_chunk_context};

    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const OTHER_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn maps_exact_created_running_and_stopped_states() {
        let target = ContainerTarget::exact(
            ContainerId::new("native-test").expect("container ID"),
            Generation(1),
        );
        for (status, pid) in [
            (ContainerState::Created, Some(101)),
            (ContainerState::Running, Some(101)),
            (ContainerState::Stopped, None),
        ] {
            let state = AgentState::new(target.clone(), status, pid, DIGEST).expect("agent state");
            let mapped = driver_state(&target, Some(DIGEST), state).expect("mapped driver state");
            assert_eq!(mapped.status(), status);
            assert_eq!(mapped.pid(), pid);
            assert!(!mapped.paused());
        }

        let paused = AgentState::new_with_pause(
            target.clone(),
            ContainerState::Running,
            Some(101),
            DIGEST,
            true,
        )
        .expect("paused agent state");
        assert!(driver_state(&target, Some(DIGEST), paused)
            .expect("mapped paused driver state")
            .paused());
        assert!(AgentState::new_with_pause(
            target,
            ContainerState::Created,
            Some(101),
            DIGEST,
            true,
        )
        .is_err());
    }

    #[test]
    fn rejects_a_mismatched_generation_or_digest() {
        let target = ContainerTarget::exact(
            ContainerId::new("native-test").expect("container ID"),
            Generation(1),
        );
        let other = ContainerTarget::exact(target.id.clone(), Generation(2));
        let state = AgentState::new(other, ContainerState::Created, Some(101), DIGEST)
            .expect("agent state");
        assert!(driver_state(&target, Some(DIGEST), state).is_err());

        let state = AgentState::new(
            target.clone(),
            ContainerState::Created,
            Some(101),
            OTHER_DIGEST,
        )
        .expect("agent state");
        assert!(driver_state(&target, Some(DIGEST), state).is_err());
    }

    #[test]
    fn derives_stable_distinct_chunk_operation_contexts() {
        let parent = OperationContext {
            operation_id: OperationId::new("stdin-parent").expect("operation ID"),
            deadline_unix_ms: Some(42),
        };
        let first = process_io_chunk_context(&parent, 0).expect("first chunk context");
        let first_replay =
            process_io_chunk_context(&parent, 0).expect("replayed first chunk context");
        let second = process_io_chunk_context(&parent, 1).expect("second chunk context");
        let other_parent = OperationContext::new(
            OperationId::new("other-stdin-parent").expect("other operation ID"),
        );
        let other = process_io_chunk_context(&other_parent, 0).expect("other chunk context");

        assert_eq!(first, first_replay);
        assert_ne!(first.operation_id, second.operation_id);
        assert_ne!(first.operation_id, other.operation_id);
        assert_eq!(first.deadline_unix_ms, parent.deadline_unix_ms);
        assert!(first.operation_id.as_str().starts_with("io."));
    }
}
