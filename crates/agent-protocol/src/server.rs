use std::sync::Arc;

use a3s_oci_sdk::{
    async_trait, ContainerStats, Error, ErrorCode, ExitStatus, FileRequest, FileResponse,
    FilesystemRequest, FilesystemResponse, OutputChunk, ProcessRecord, Result,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::model::{
    protocol_error, AgentCapabilities, AgentCloseStdinRequest, AgentContainerOperationRequest,
    AgentCreateRequest, AgentDeleteRequest, AgentExecRequest, AgentHello, AgentKillRequest,
    AgentProcess, AgentProcessExit, AgentProcessSignal, AgentProcessesRequest,
    AgentReadOutputRequest, AgentRequest, AgentResizeRequest, AgentResponse,
    AgentSignalProcessRequest, AgentStartRequest, AgentState, AgentStateRequest, AgentStatsRequest,
    AgentUpdateRequest, AgentWaitProcessRequest, AgentWaitRequest, AgentWriteStdinRequest,
    HelloOutcome, HostHello, RequestEnvelope, ResponseEnvelope, ResponseOutcome, SessionToken,
};
use crate::validation::negotiate_protocol;
use crate::wire::{read_frame, write_frame};

/// Linux guest executor behind the versioned protocol server.
///
/// Every mutating method must be idempotent by
/// [`a3s_oci_sdk::OperationContext::operation_id`]. The implementation must
/// retain enough state to reconcile a retry after the agent process restarts.
#[async_trait]
pub trait GuestAgentService: Send + Sync {
    /// Protocol and executor features available in this guest.
    fn capabilities(&self) -> AgentCapabilities;

    /// Prepare an init process without running its configured program.
    async fn create(&self, request: AgentCreateRequest) -> Result<AgentState>;

    /// Query one exact container generation.
    async fn state(&self, request: AgentStateRequest) -> Result<AgentState>;

    /// Release the prepared init process.
    async fn start(&self, request: AgentStartRequest) -> Result<AgentState>;

    /// Deliver the exact requested signal.
    async fn kill(&self, request: AgentKillRequest) -> Result<AgentState>;

    /// Delete only resources owned by the requested generation.
    async fn delete(&self, request: AgentDeleteRequest) -> Result<()>;

    /// Wait for the exact container init process.
    async fn wait(&self, _request: AgentWaitRequest) -> Result<ExitStatus> {
        Err(Error::unsupported("agent-wait"))
    }

    /// Execute an additional complete OCI process configuration.
    async fn exec(&self, _request: AgentExecRequest) -> Result<AgentProcess> {
        Err(Error::unsupported("agent-exec"))
    }

    /// Signal one exact init or exec process.
    async fn signal_process(&self, _request: AgentSignalProcessRequest) -> Result<()> {
        Err(Error::unsupported("agent-signal-process"))
    }

    /// Wait for one exact init or exec process.
    async fn wait_process(&self, _request: AgentWaitProcessRequest) -> Result<ExitStatus> {
        Err(Error::unsupported("agent-wait-process"))
    }

    /// Freeze every process in one exact container generation.
    async fn pause(&self, _request: AgentContainerOperationRequest) -> Result<AgentState> {
        Err(Error::unsupported("agent-pause"))
    }

    /// Thaw every process in one exact container generation.
    async fn resume(&self, _request: AgentContainerOperationRequest) -> Result<AgentState> {
        Err(Error::unsupported("agent-resume"))
    }

    /// List every live init and exec process in one exact generation.
    async fn processes(&self, _request: AgentProcessesRequest) -> Result<Vec<ProcessRecord>> {
        Err(Error::unsupported("agent-processes"))
    }

    /// Apply supported live OCI Linux resource changes.
    async fn update(&self, _request: AgentUpdateRequest) -> Result<AgentState> {
        Err(Error::unsupported("agent-update"))
    }

    /// Read normalized cgroup v2 resource counters.
    async fn stats(&self, _request: AgentStatsRequest) -> Result<ContainerStats> {
        Err(Error::unsupported("agent-stats"))
    }

    /// Poll captured stdout and stderr through one byte-accurate cursor.
    async fn read_output(&self, _request: AgentReadOutputRequest) -> Result<Vec<OutputChunk>> {
        Err(Error::unsupported("agent-read-output"))
    }

    /// Write one bounded payload to process stdin with backpressure.
    async fn write_stdin(&self, _request: AgentWriteStdinRequest) -> Result<()> {
        Err(Error::unsupported("agent-write-stdin"))
    }

    /// Close process stdin. Repeated closes should remain idempotent.
    async fn close_stdin(&self, _request: AgentCloseStdinRequest) -> Result<()> {
        Err(Error::unsupported("agent-close-stdin"))
    }

    /// Resize one process terminal.
    async fn resize(&self, _request: AgentResizeRequest) -> Result<()> {
        Err(Error::unsupported("agent-resize"))
    }

    /// Upload or download one bounded file through the retained container root.
    async fn file(&self, _request: FileRequest) -> Result<FileResponse> {
        Err(Error::unsupported("agent-file"))
    }

    /// Inspect or mutate the retained container filesystem.
    async fn filesystem(&self, _request: FilesystemRequest) -> Result<FilesystemResponse> {
        Err(Error::unsupported("agent-filesystem"))
    }
}

/// Authenticate, negotiate, and serve one host connection until clean EOF.
pub async fn serve_agent_connection<T>(
    mut stream: T,
    expected_token: SessionToken,
    service: Arc<dyn GuestAgentService>,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    let host: HostHello = read_frame(&mut stream).await?.ok_or_else(|| {
        protocol_error(
            ErrorCode::Unavailable,
            "host closed the stream before agent protocol negotiation",
        )
    })?;
    let selected_version = match validate_hello(&host, &expected_token, service.as_ref()) {
        Ok(selected_version) => selected_version,
        Err(error) => {
            write_frame(
                &mut stream,
                &HelloOutcome::Rejected {
                    error: error.clone(),
                },
            )
            .await?;
            return Err(error);
        }
    };
    let capabilities = match service.capabilities().for_protocol(selected_version) {
        Ok(capabilities) => capabilities,
        Err(error) => {
            write_frame(
                &mut stream,
                &HelloOutcome::Rejected {
                    error: error.clone(),
                },
            )
            .await?;
            return Err(error);
        }
    };
    let hello = AgentHello::new(selected_version, capabilities);
    write_frame(&mut stream, &HelloOutcome::Accepted { hello }).await?;

    while let Some(envelope) = read_frame::<RequestEnvelope, _>(&mut stream).await? {
        if let Err(error) = envelope.validate(selected_version) {
            let terminal = envelope.version != selected_version || envelope.request_id == 0;
            write_response(
                &mut stream,
                selected_version,
                envelope.request_id,
                ResponseOutcome::Failed {
                    error: error.clone(),
                },
            )
            .await?;
            if terminal {
                return Err(error);
            }
            continue;
        }

        let outcome = match dispatch(service.as_ref(), envelope.request).await {
            Ok(response) => match response.validate() {
                Ok(()) => ResponseOutcome::Succeeded {
                    response: Box::new(response),
                },
                Err(error) => ResponseOutcome::Failed {
                    error: invalid_service_response(error),
                },
            },
            Err(error) => ResponseOutcome::Failed { error },
        };
        write_response(&mut stream, selected_version, envelope.request_id, outcome).await?;
    }
    Ok(())
}

fn validate_hello(
    host: &HostHello,
    expected_token: &SessionToken,
    service: &dyn GuestAgentService,
) -> Result<u16> {
    host.protocols.validate()?;
    if !expected_token.matches(&host.token) {
        return Err(protocol_error(
            ErrorCode::PermissionDenied,
            "agent session authentication failed",
        ));
    }
    service.capabilities().validate()?;
    negotiate_protocol(host.protocols)
}

async fn dispatch(service: &dyn GuestAgentService, request: AgentRequest) -> Result<AgentResponse> {
    match request {
        AgentRequest::Create(request) => service.create(request).await.map(AgentResponse::State),
        AgentRequest::State(request) => service.state(request).await.map(AgentResponse::State),
        AgentRequest::Start(request) => service.start(request).await.map(AgentResponse::State),
        AgentRequest::Kill(request) => service.kill(request).await.map(AgentResponse::State),
        AgentRequest::Delete(request) => {
            service.delete(request).await?;
            Ok(AgentResponse::Deleted)
        }
        AgentRequest::Wait(request) => service.wait(request).await.map(AgentResponse::ExitStatus),
        AgentRequest::Exec(request) => {
            let expected_target = request.target.clone();
            let process = service.exec(*request).await?;
            if process.target() != &expected_target {
                return Err(invalid_service_response(protocol_error(
                    ErrorCode::Conflict,
                    format!(
                        "exec service returned process target {:?}, expected {expected_target:?}",
                        process.target()
                    ),
                )));
            }
            Ok(AgentResponse::Process(process))
        }
        AgentRequest::SignalProcess(request) => {
            let target = request.target.clone();
            service.signal_process(request).await?;
            AgentProcessSignal::new(target).map(AgentResponse::ProcessSignaled)
        }
        AgentRequest::WaitProcess(request) => {
            let target = request.target.clone();
            let status = service.wait_process(request).await?;
            AgentProcessExit::new(target, status).map(AgentResponse::ProcessExit)
        }
        AgentRequest::Pause(request) => service.pause(request).await.map(AgentResponse::State),
        AgentRequest::Resume(request) => service.resume(request).await.map(AgentResponse::State),
        AgentRequest::Processes(request) => service
            .processes(request)
            .await
            .map(AgentResponse::Processes),
        AgentRequest::Update(request) => service.update(*request).await.map(AgentResponse::State),
        AgentRequest::Stats(request) => service.stats(request).await.map(AgentResponse::Stats),
        AgentRequest::ReadOutput(request) => service
            .read_output(request)
            .await
            .map(AgentResponse::Output),
        AgentRequest::WriteStdin(request) => {
            let target = request.process.clone();
            service.write_stdin(request).await?;
            Ok(AgentResponse::StdinWritten(target))
        }
        AgentRequest::CloseStdin(request) => {
            let target = request.process.clone();
            service.close_stdin(request).await?;
            Ok(AgentResponse::StdinClosed(target))
        }
        AgentRequest::Resize(request) => {
            let target = request.process.clone();
            service.resize(request).await?;
            Ok(AgentResponse::TerminalResized(target))
        }
        AgentRequest::File(request) => service.file(request).await.map(AgentResponse::File),
        AgentRequest::Filesystem(request) => service
            .filesystem(request)
            .await
            .map(AgentResponse::Filesystem),
    }
}

async fn write_response<T>(
    stream: &mut T,
    version: u16,
    request_id: u64,
    outcome: ResponseOutcome,
) -> Result<()>
where
    T: AsyncWrite + Unpin,
{
    write_frame(
        stream,
        &ResponseEnvelope {
            version,
            request_id,
            outcome,
        },
    )
    .await
}

fn invalid_service_response(error: Error) -> Error {
    protocol_error(
        ErrorCode::Internal,
        format!("guest service produced an invalid response: {error}"),
    )
}
