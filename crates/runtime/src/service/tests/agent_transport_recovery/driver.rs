use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentBundle, AgentClient, AgentCloseStdinRequest, AgentContainerOperationRequest,
    AgentCreateRequest, AgentDeleteRequest, AgentExecRequest, AgentKillRequest,
    AgentProcessesRequest, AgentReadOutputRequest, AgentResizeRequest, AgentSignalProcessRequest,
    AgentStartRequest, AgentState, AgentStateRequest, AgentStatsRequest, AgentUpdateRequest,
    AgentWaitProcessRequest, AgentWaitRequest, AgentWriteStdinRequest, GuestPath,
};
use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, IsolationClass,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    async_trait, ContainerRecord, ContainerStats, ContainerTarget, Error, ErrorCode, ExitStatus,
    FileRequest, FileResponse, FilesystemRequest, FilesystemResponse, OciBundle, OperationContext,
    OutputChunk, ProcessIo, ProcessRecord, Result, RuntimeOperation,
};
use tokio::io::DuplexStream;

use crate::{
    DriverCloseStdinRequest, DriverContainerOperationRequest, DriverCreateRequest,
    DriverDeleteRequest, DriverExecRequest, DriverKillRequest, DriverProcess,
    DriverReadOutputRequest, DriverRecovery, DriverResizeRequest, DriverSignalProcessRequest,
    DriverStartRequest, DriverState, DriverUpdateRequest, DriverWaitProcessRequest,
    DriverWaitRequest, DriverWriteStdinRequest, RuntimeDriver,
};

mod metrics;

pub(super) use metrics::DriverMetrics;

const DRIVER_OPERATIONS: [RuntimeOperation; 20] = [
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

#[derive(Debug)]
pub(super) struct AgentLifecycleDriver {
    client: AgentClient<DuplexStream>,
    metrics: Arc<DriverMetrics>,
}

impl AgentLifecycleDriver {
    pub(super) fn new(client: AgentClient<DuplexStream>, metrics: Arc<DriverMetrics>) -> Self {
        Self { client, metrics }
    }
}

#[async_trait]
impl RuntimeDriver for AgentLifecycleDriver {
    fn capability(&self) -> DriverCapability {
        DriverCapability {
            driver: DriverKind::LibkrunWhpx,
            status: CapabilityStatus::Available,
            readiness: DriverReadiness::Experimental,
            isolation_classes: vec![IsolationClass::DedicatedVm],
            reason: None,
            evidence: BTreeMap::from([(
                "test-driver".to_string(),
                "authenticated-in-memory-agent".to_string(),
            )]),
        }
    }

    fn operations(&self) -> &[RuntimeOperation] {
        &DRIVER_OPERATIONS
    }

    async fn recover(&self, _record: &ContainerRecord) -> Result<DriverRecovery> {
        self.metrics.recoveries.fetch_add(1, Ordering::SeqCst);
        Ok(DriverRecovery::none())
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        self.metrics
            .create_dispatches
            .fetch_add(1, Ordering::SeqCst);
        let expected_target = request.target.clone();
        let expected_digest = request.bundle.config_digest().to_string();
        let state = self
            .client
            .create(agent_create_request(
                request.context,
                request.target,
                &request.bundle,
                request.io,
            )?)
            .await?;
        map_agent_state(&expected_target, Some(&expected_digest), state)
    }

    async fn state(&self, target: ContainerTarget) -> Result<DriverState> {
        self.metrics.state_dispatches.fetch_add(1, Ordering::SeqCst);
        let state = self
            .client
            .state(AgentStateRequest {
                target: target.clone(),
            })
            .await?;
        map_agent_state(&target, None, state)
    }

    async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        self.metrics.start_dispatches.fetch_add(1, Ordering::SeqCst);
        let expected_target = request.target.clone();
        let expected_digest = request.bundle.config_digest().to_string();
        let state = self
            .client
            .start(AgentStartRequest {
                context: request.context,
                target: request.target,
                expected_config_digest: expected_digest.clone(),
            })
            .await?;
        map_agent_state(&expected_target, Some(&expected_digest), state)
    }

    async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        self.metrics.kill_dispatches.fetch_add(1, Ordering::SeqCst);
        let expected_target = request.target.clone();
        let state = self
            .client
            .kill(AgentKillRequest {
                context: request.context,
                target: request.target,
                signal: request.signal,
                all: request.all,
            })
            .await?;
        map_agent_state(&expected_target, None, state)
    }

    async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        self.metrics
            .delete_dispatches
            .fetch_add(1, Ordering::SeqCst);
        self.client
            .delete(AgentDeleteRequest {
                context: request.context,
                target: request.target,
                mode: request.mode,
            })
            .await
    }

    async fn wait(&self, request: DriverWaitRequest) -> Result<ExitStatus> {
        self.metrics.wait_dispatches.fetch_add(1, Ordering::SeqCst);
        self.client
            .wait(AgentWaitRequest {
                target: request.target,
                timeout_ms: request.timeout_ms,
            })
            .await
    }

    async fn exec(&self, request: DriverExecRequest) -> Result<DriverProcess> {
        self.metrics.exec_dispatches.fetch_add(1, Ordering::SeqCst);
        let expected_target = request.target.clone();
        let expected_terminal = request.process.terminal().unwrap_or(false);
        let process = self
            .client
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
                "guest returned a different exec process target",
            )
            .for_operation("map-agent-process"));
        }
        if process.terminal() != expected_terminal {
            return Err(Error::new(
                ErrorCode::Conflict,
                "guest returned a different exec terminal mode",
            )
            .for_operation("map-agent-process"));
        }
        DriverProcess::new(process.pid(), process.terminal())
    }

    async fn signal_process(&self, request: DriverSignalProcessRequest) -> Result<()> {
        self.metrics
            .signal_process_dispatches
            .fetch_add(1, Ordering::SeqCst);
        self.client
            .signal_process(AgentSignalProcessRequest {
                context: request.context,
                target: request.target,
                signal: request.signal,
            })
            .await
    }

    async fn wait_process(&self, request: DriverWaitProcessRequest) -> Result<ExitStatus> {
        self.metrics
            .wait_process_dispatches
            .fetch_add(1, Ordering::SeqCst);
        self.client
            .wait_process(AgentWaitProcessRequest {
                target: request.target,
                timeout_ms: request.timeout_ms,
            })
            .await
    }

    async fn pause(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.metrics.pause_dispatches.fetch_add(1, Ordering::SeqCst);
        let expected_target = request.target.clone();
        let state = self
            .client
            .pause(AgentContainerOperationRequest {
                context: request.context,
                target: request.target,
            })
            .await?;
        map_agent_state(&expected_target, None, state)
    }

    async fn resume(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.metrics
            .resume_dispatches
            .fetch_add(1, Ordering::SeqCst);
        let expected_target = request.target.clone();
        let state = self
            .client
            .resume(AgentContainerOperationRequest {
                context: request.context,
                target: request.target,
            })
            .await?;
        map_agent_state(&expected_target, None, state)
    }

    async fn processes(&self, target: ContainerTarget) -> Result<Vec<ProcessRecord>> {
        self.metrics
            .processes_dispatches
            .fetch_add(1, Ordering::SeqCst);
        self.client
            .processes(AgentProcessesRequest { target })
            .await
    }

    async fn update(&self, request: DriverUpdateRequest) -> Result<DriverState> {
        self.metrics
            .update_dispatches
            .fetch_add(1, Ordering::SeqCst);
        let expected_target = request.target.clone();
        let state = self
            .client
            .update(AgentUpdateRequest {
                context: request.context,
                target: request.target,
                resources: request.resources,
            })
            .await?;
        map_agent_state(&expected_target, None, state)
    }

    async fn stats(&self, target: ContainerTarget) -> Result<ContainerStats> {
        self.metrics.stats_dispatches.fetch_add(1, Ordering::SeqCst);
        self.client.stats(AgentStatsRequest { target }).await
    }

    async fn read_output(&self, request: DriverReadOutputRequest) -> Result<Vec<OutputChunk>> {
        self.metrics
            .read_output_dispatches
            .fetch_add(1, Ordering::SeqCst);
        self.client
            .read_output(AgentReadOutputRequest {
                process: request.target,
                after_sequence: request.after_sequence,
                max_bytes: request.max_bytes,
                wait_timeout_ms: request.wait_timeout_ms,
            })
            .await
    }

    async fn write_stdin(&self, request: DriverWriteStdinRequest) -> Result<()> {
        self.metrics
            .write_stdin_dispatches
            .fetch_add(1, Ordering::SeqCst);
        self.client
            .write_stdin(AgentWriteStdinRequest {
                context: Some(request.context),
                process: request.target,
                data: request.data,
            })
            .await
    }

    async fn close_stdin(&self, request: DriverCloseStdinRequest) -> Result<()> {
        self.metrics
            .close_stdin_dispatches
            .fetch_add(1, Ordering::SeqCst);
        self.client
            .close_stdin(AgentCloseStdinRequest {
                context: Some(request.context),
                process: request.target,
            })
            .await
    }

    async fn resize(&self, request: DriverResizeRequest) -> Result<()> {
        self.metrics
            .resize_dispatches
            .fetch_add(1, Ordering::SeqCst);
        self.client
            .resize(AgentResizeRequest {
                context: Some(request.context),
                process: request.target,
                size: request.size,
            })
            .await
    }

    async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        self.metrics.file_dispatches.fetch_add(1, Ordering::SeqCst);
        self.client.file(request).await
    }

    async fn filesystem(&self, request: FilesystemRequest) -> Result<FilesystemResponse> {
        self.metrics
            .filesystem_dispatches
            .fetch_add(1, Ordering::SeqCst);
        self.client.filesystem(request).await
    }
}

pub(super) fn agent_create_request(
    context: OperationContext,
    target: ContainerTarget,
    bundle: &OciBundle,
    io: ProcessIo,
) -> Result<AgentCreateRequest> {
    Ok(AgentCreateRequest {
        context,
        target,
        bundle: AgentBundle::new(bundle, GuestPath::new("/run/a3s/reopen-test-bundle")?),
        io,
    })
}

fn map_agent_state(
    expected_target: &ContainerTarget,
    expected_digest: Option<&str>,
    state: AgentState,
) -> Result<DriverState> {
    if state.target() != expected_target {
        return Err(Error::new(
            ErrorCode::Conflict,
            "guest returned a different container generation",
        )
        .for_operation("map-agent-state"));
    }
    if expected_digest.is_some_and(|digest| state.config_digest() != digest) {
        return Err(Error::new(
            ErrorCode::Conflict,
            "guest returned a different configuration digest",
        )
        .for_operation("map-agent-state"));
    }
    let mapped = match state.status() {
        ContainerState::Created => DriverState::created(required_pid(&state)?)?,
        ContainerState::Running => DriverState::running(required_pid(&state)?)?,
        ContainerState::Stopped => DriverState::stopped(),
        status => {
            return Err(Error::new(
                ErrorCode::Internal,
                format!("guest returned invalid lifecycle state {status}"),
            )
            .for_operation("map-agent-state"));
        }
    };
    mapped.with_paused(state.paused())
}

fn required_pid(state: &AgentState) -> Result<i32> {
    state.pid().ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            format!("guest returned {} without an init PID", state.status()),
        )
        .for_operation("map-agent-state")
    })
}
