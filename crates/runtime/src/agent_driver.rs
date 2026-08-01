use std::fmt;
use std::sync::Arc;

#[cfg(target_os = "windows")]
use a3s_oci_agent_protocol::{AgentBundle, AgentCreateRequest, GuestPath};
use a3s_oci_agent_protocol::{
    AgentCloseStdinRequest, AgentContainerOperationRequest, AgentDeleteRequest, AgentExecRequest,
    AgentKillRequest, AgentProcessesRequest, AgentReadOutputRequest, AgentResizeRequest,
    AgentSignalProcessRequest, AgentStartRequest, AgentState, AgentStateRequest, AgentStatsRequest,
    AgentUpdateRequest, AgentWaitProcessRequest, AgentWaitRequest, AgentWriteStdinRequest,
    GuestAgentService, AGENT_MAX_IO_PAYLOAD_BYTES,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerStats, ContainerTarget, Error, ErrorCode, ExitStatus, OperationContext, OperationId,
    OutputChunk, ProcessRecord, Result, RuntimeOperation,
};
use sha2::{Digest, Sha256};

#[cfg(target_os = "windows")]
use crate::driver::DriverCreateRequest;
use crate::driver::{
    DriverCloseStdinRequest, DriverContainerOperationRequest, DriverDeleteRequest,
    DriverExecRequest, DriverKillRequest, DriverProcess, DriverReadOutputRequest,
    DriverResizeRequest, DriverSignalProcessRequest, DriverStartRequest, DriverState,
    DriverUpdateRequest, DriverWaitProcessRequest, DriverWaitRequest, DriverWriteStdinRequest,
    OciHookPhase,
};

pub(crate) const AGENT_DRIVER_OPERATIONS: [RuntimeOperation; 18] = [
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

pub(crate) const AGENT_DRIVER_HOOKS: [OciHookPhase; 6] = OciHookPhase::ALL;

/// Driver-facing mapping around either an in-process executor or one
/// authenticated utility-VM connection.
#[derive(Clone)]
pub(crate) struct AgentDriverClient {
    service: Arc<dyn GuestAgentService>,
    source: &'static str,
    mapping_scope: &'static str,
}

impl fmt::Debug for AgentDriverClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentDriverClient")
            .field("source", &self.source)
            .field("mapping_scope", &self.mapping_scope)
            .finish_non_exhaustive()
    }
}

impl AgentDriverClient {
    pub(crate) fn new(
        service: Arc<dyn GuestAgentService>,
        source: &'static str,
        mapping_scope: &'static str,
    ) -> Self {
        Self {
            service,
            source,
            mapping_scope,
        }
    }

    #[cfg(target_os = "windows")]
    pub(crate) async fn create(
        &self,
        request: DriverCreateRequest,
        guest_directory: GuestPath,
    ) -> Result<DriverState> {
        if !request.attachments.is_empty() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "{} cannot receive native inherited descriptors",
                    self.source
                ),
            )
            .for_operation("agent-driver-create"));
        }
        let expected_target = request.target.clone();
        let expected_digest = request.bundle.config_digest().to_string();
        let state = self
            .service
            .create(AgentCreateRequest {
                context: request.context,
                target: request.target,
                bundle: AgentBundle::new(&request.bundle, guest_directory),
                io: request.io,
            })
            .await?;
        self.map_state(&expected_target, Some(&expected_digest), state)
    }

    pub(crate) async fn state(&self, target: ContainerTarget) -> Result<DriverState> {
        self.state_with_digest(target, None).await
    }

    pub(crate) async fn state_with_digest(
        &self,
        target: ContainerTarget,
        expected_digest: Option<&str>,
    ) -> Result<DriverState> {
        let state = self
            .service
            .state(AgentStateRequest {
                target: target.clone(),
            })
            .await?;
        self.map_state(&target, expected_digest, state)
    }

    pub(crate) async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        let expected_target = request.target.clone();
        let expected_digest = request.bundle.config_digest().to_string();
        let state = self
            .service
            .start(AgentStartRequest {
                context: request.context,
                target: request.target,
                expected_config_digest: expected_digest.clone(),
            })
            .await?;
        self.map_state(&expected_target, Some(&expected_digest), state)
    }

    pub(crate) async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        let expected_target = request.target.clone();
        let state = self
            .service
            .kill(AgentKillRequest {
                context: request.context,
                target: request.target,
                signal: request.signal,
                all: request.all,
            })
            .await?;
        self.map_state(&expected_target, None, state)
    }

    pub(crate) async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        self.service
            .delete(AgentDeleteRequest {
                context: request.context,
                target: request.target,
                mode: request.mode,
            })
            .await
    }

    pub(crate) async fn wait(&self, request: DriverWaitRequest) -> Result<ExitStatus> {
        self.service
            .wait(AgentWaitRequest {
                target: request.target,
                timeout_ms: request.timeout_ms,
            })
            .await
    }

    pub(crate) async fn exec(&self, request: DriverExecRequest) -> Result<DriverProcess> {
        let expected_target = request.target.clone();
        let expected_terminal = request.process.terminal().unwrap_or(false);
        let process = self
            .service
            .exec(AgentExecRequest {
                context: request.context,
                target: request.target,
                process: request.process,
                io: request.io,
            })
            .await?;
        if process.target() != &expected_target {
            return Err(self.mapping_error(
                ErrorCode::Conflict,
                "process",
                format!("{} returned a different process target", self.source),
            ));
        }
        if process.terminal() != expected_terminal {
            return Err(self.mapping_error(
                ErrorCode::Conflict,
                "process",
                format!("{} returned a different process terminal mode", self.source),
            ));
        }
        DriverProcess::new(process.pid(), process.terminal())
    }

    pub(crate) async fn signal_process(&self, request: DriverSignalProcessRequest) -> Result<()> {
        self.service
            .signal_process(AgentSignalProcessRequest {
                context: request.context,
                target: request.target,
                signal: request.signal,
            })
            .await
    }

    pub(crate) async fn wait_process(
        &self,
        request: DriverWaitProcessRequest,
    ) -> Result<ExitStatus> {
        self.service
            .wait_process(AgentWaitProcessRequest {
                target: request.target,
                timeout_ms: request.timeout_ms,
            })
            .await
    }

    pub(crate) async fn pause(
        &self,
        request: DriverContainerOperationRequest,
    ) -> Result<DriverState> {
        let expected_target = request.target.clone();
        let state = self
            .service
            .pause(AgentContainerOperationRequest {
                context: request.context,
                target: request.target,
            })
            .await?;
        self.map_state(&expected_target, None, state)
    }

    pub(crate) async fn resume(
        &self,
        request: DriverContainerOperationRequest,
    ) -> Result<DriverState> {
        let expected_target = request.target.clone();
        let state = self
            .service
            .resume(AgentContainerOperationRequest {
                context: request.context,
                target: request.target,
            })
            .await?;
        self.map_state(&expected_target, None, state)
    }

    pub(crate) async fn processes(&self, target: ContainerTarget) -> Result<Vec<ProcessRecord>> {
        self.service
            .processes(AgentProcessesRequest { target })
            .await
    }

    pub(crate) async fn update(&self, request: DriverUpdateRequest) -> Result<DriverState> {
        let expected_target = request.target.clone();
        let state = self
            .service
            .update(AgentUpdateRequest {
                context: request.context,
                target: request.target,
                resources: request.resources,
            })
            .await?;
        self.map_state(&expected_target, None, state)
    }

    pub(crate) async fn stats(&self, target: ContainerTarget) -> Result<ContainerStats> {
        let stats = self
            .service
            .stats(AgentStatsRequest {
                target: target.clone(),
            })
            .await?;
        if stats.target != target {
            return Err(self.mapping_error(
                ErrorCode::Conflict,
                "stats",
                format!(
                    "{} returned stats for a different container generation",
                    self.source
                ),
            ));
        }
        stats.validate()?;
        Ok(stats)
    }

    pub(crate) async fn read_output(
        &self,
        request: DriverReadOutputRequest,
    ) -> Result<Vec<OutputChunk>> {
        self.service
            .read_output(AgentReadOutputRequest {
                process: request.target,
                after_sequence: request.after_sequence,
                max_bytes: request.max_bytes.min(AGENT_MAX_IO_PAYLOAD_BYTES),
                wait_timeout_ms: request.wait_timeout_ms,
            })
            .await
    }

    pub(crate) async fn write_stdin(&self, request: DriverWriteStdinRequest) -> Result<()> {
        if request.data.is_empty() {
            return self
                .service
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
            self.service
                .write_stdin(AgentWriteStdinRequest {
                    context: Some(context),
                    process: request.target.clone(),
                    data: data.to_vec(),
                })
                .await?;
        }
        Ok(())
    }

    pub(crate) async fn close_stdin(&self, request: DriverCloseStdinRequest) -> Result<()> {
        self.service
            .close_stdin(AgentCloseStdinRequest {
                context: Some(request.context),
                process: request.target,
            })
            .await
    }

    pub(crate) async fn resize(&self, request: DriverResizeRequest) -> Result<()> {
        self.service
            .resize(AgentResizeRequest {
                context: Some(request.context),
                process: request.target,
                size: request.size,
            })
            .await
    }

    pub(crate) fn map_state(
        &self,
        expected_target: &ContainerTarget,
        expected_digest: Option<&str>,
        state: AgentState,
    ) -> Result<DriverState> {
        if state.target() != expected_target {
            return Err(self.mapping_error(
                ErrorCode::Conflict,
                "state",
                format!("{} returned a different container generation", self.source),
            ));
        }
        if expected_digest.is_some_and(|digest| state.config_digest() != digest) {
            return Err(self.mapping_error(
                ErrorCode::Conflict,
                "state",
                format!("{} returned a different configuration digest", self.source),
            ));
        }
        let mapped = match state.status() {
            ContainerState::Created => DriverState::created(self.required_pid(&state)?),
            ContainerState::Running => DriverState::running(self.required_pid(&state)?),
            ContainerState::Stopped => Ok(DriverState::stopped()),
            status => Err(self.mapping_error(
                ErrorCode::Internal,
                "state",
                format!("{} returned invalid lifecycle state {status}", self.source),
            )),
        }?;
        mapped.with_paused(state.paused())
    }

    fn required_pid(&self, state: &AgentState) -> Result<i32> {
        state.pid().ok_or_else(|| {
            self.mapping_error(
                ErrorCode::Internal,
                "state",
                format!(
                    "{} returned {} without an init PID",
                    self.source,
                    state.status()
                ),
            )
        })
    }

    fn mapping_error(
        &self,
        code: ErrorCode,
        subject: &'static str,
        message: impl Into<String>,
    ) -> Error {
        Error::new(code, message).for_operation(format!("map-{}-{subject}", self.mapping_scope))
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use a3s_oci_agent_protocol::{AgentCapabilities, AgentState, GuestAgentService};
    use a3s_oci_sdk::oci_spec::runtime::ContainerState;
    use a3s_oci_sdk::{
        async_trait, ContainerId, ContainerTarget, Error, Generation, OperationContext,
        OperationId, Result,
    };

    use super::{process_io_chunk_context, AgentDriverClient};

    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const OTHER_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    struct MappingOnlyGuest;

    #[async_trait]
    impl GuestAgentService for MappingOnlyGuest {
        fn capabilities(&self) -> AgentCapabilities {
            AgentCapabilities::linux_executor("test", "x86_64").expect("capabilities")
        }

        async fn create(
            &self,
            _request: a3s_oci_agent_protocol::AgentCreateRequest,
        ) -> Result<AgentState> {
            Err(Error::unsupported("mapping-test-create"))
        }

        async fn state(
            &self,
            _request: a3s_oci_agent_protocol::AgentStateRequest,
        ) -> Result<AgentState> {
            Err(Error::unsupported("mapping-test-state"))
        }

        async fn start(
            &self,
            _request: a3s_oci_agent_protocol::AgentStartRequest,
        ) -> Result<AgentState> {
            Err(Error::unsupported("mapping-test-start"))
        }

        async fn kill(
            &self,
            _request: a3s_oci_agent_protocol::AgentKillRequest,
        ) -> Result<AgentState> {
            Err(Error::unsupported("mapping-test-kill"))
        }

        async fn delete(&self, _request: a3s_oci_agent_protocol::AgentDeleteRequest) -> Result<()> {
            Err(Error::unsupported("mapping-test-delete"))
        }
    }

    fn client() -> AgentDriverClient {
        AgentDriverClient::new(Arc::new(MappingOnlyGuest), "test guest", "test-agent")
    }

    #[test]
    fn maps_exact_created_running_and_stopped_states() {
        let target = ContainerTarget::exact(
            ContainerId::new("agent-test").expect("container ID"),
            Generation(1),
        );
        for (status, pid) in [
            (ContainerState::Created, Some(101)),
            (ContainerState::Running, Some(101)),
            (ContainerState::Stopped, None),
        ] {
            let state = AgentState::new(target.clone(), status, pid, DIGEST).expect("agent state");
            let mapped = client()
                .map_state(&target, Some(DIGEST), state)
                .expect("mapped driver state");
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
        assert!(client()
            .map_state(&target, Some(DIGEST), paused)
            .expect("mapped paused driver state")
            .paused());
    }

    #[test]
    fn rejects_a_mismatched_generation_or_digest() {
        let target = ContainerTarget::exact(
            ContainerId::new("agent-test").expect("container ID"),
            Generation(1),
        );
        let other = ContainerTarget::exact(target.id.clone(), Generation(2));
        let state =
            AgentState::new(other, ContainerState::Created, Some(101), DIGEST).expect("state");
        assert!(client().map_state(&target, Some(DIGEST), state).is_err());

        let state = AgentState::new(
            target.clone(),
            ContainerState::Created,
            Some(101),
            OTHER_DIGEST,
        )
        .expect("agent state");
        assert!(client().map_state(&target, Some(DIGEST), state).is_err());
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
