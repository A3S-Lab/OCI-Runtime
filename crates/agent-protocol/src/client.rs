use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{Error, ErrorCode, ExitStatus, ProcessRecord, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::model::{
    protocol_error, AgentContainerOperationRequest, AgentCreateRequest, AgentDeleteRequest,
    AgentExecRequest, AgentHello, AgentKillRequest, AgentOperation, AgentProcess,
    AgentProcessesRequest, AgentRequest, AgentResponse, AgentSignalProcessRequest,
    AgentStartRequest, AgentState, AgentStateRequest, AgentWaitProcessRequest, AgentWaitRequest,
    HelloOutcome, HostHello, ProtocolRange, RequestEnvelope, ResponseEnvelope, ResponseOutcome,
    SessionToken,
};
use crate::wire::{read_frame, write_frame};

const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Authenticated, correlated client for one guest-agent stream.
pub struct AgentClient<T> {
    connection: Arc<Mutex<ClientConnection<T>>>,
    hello: Arc<AgentHello>,
}

impl<T> fmt::Debug for AgentClient<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentClient")
            .field("hello", &self.hello)
            .finish_non_exhaustive()
    }
}

struct ClientConnection<T> {
    stream: T,
    selected_version: u16,
    next_request_id: u64,
    poisoned: bool,
}

impl<T> Clone for AgentClient<T> {
    fn clone(&self) -> Self {
        Self {
            connection: Arc::clone(&self.connection),
            hello: Arc::clone(&self.hello),
        }
    }
}

impl<T> AgentClient<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Authenticate and negotiate the highest common protocol version.
    pub async fn connect(stream: T, token: SessionToken) -> Result<Self> {
        Self::connect_with_range(stream, token, ProtocolRange::CURRENT).await
    }

    async fn connect_with_range(
        mut stream: T,
        token: SessionToken,
        protocols: ProtocolRange,
    ) -> Result<Self> {
        protocols.validate()?;
        write_frame(&mut stream, &HostHello { protocols, token }).await?;
        let outcome: HelloOutcome = read_frame(&mut stream).await?.ok_or_else(|| {
            protocol_error(
                ErrorCode::Unavailable,
                "guest closed the stream before protocol negotiation",
            )
            .retryable(true)
        })?;
        let hello = match outcome {
            HelloOutcome::Accepted { hello } => hello,
            HelloOutcome::Rejected { error } => return Err(error),
        };
        hello.validate(protocols)?;
        let selected_version = hello.selected_version();

        Ok(Self {
            connection: Arc::new(Mutex::new(ClientConnection {
                stream,
                selected_version,
                next_request_id: 1,
                poisoned: false,
            })),
            hello: Arc::new(hello),
        })
    }

    /// Negotiated version and guest capability report.
    #[must_use]
    pub fn hello(&self) -> &AgentHello {
        &self.hello
    }

    /// Perform OCI create without releasing the configured user process.
    pub async fn create(&self, request: AgentCreateRequest) -> Result<AgentState> {
        expect_state(self.call(AgentRequest::Create(request)).await?, "create")
    }

    /// Query the guest state for one exact container generation.
    pub async fn state(&self, request: AgentStateRequest) -> Result<AgentState> {
        expect_state(self.call(AgentRequest::State(request)).await?, "state")
    }

    /// Freeze every process in one exact container generation.
    pub async fn pause(&self, request: AgentContainerOperationRequest) -> Result<AgentState> {
        expect_state(self.call(AgentRequest::Pause(request)).await?, "pause")
    }

    /// Thaw every process in one exact container generation.
    pub async fn resume(&self, request: AgentContainerOperationRequest) -> Result<AgentState> {
        expect_state(self.call(AgentRequest::Resume(request)).await?, "resume")
    }

    /// List every live init and exec process in one exact generation.
    pub async fn processes(&self, request: AgentProcessesRequest) -> Result<Vec<ProcessRecord>> {
        match self.call(AgentRequest::Processes(request)).await? {
            AgentResponse::Processes(processes) => Ok(processes),
            _ => Err(protocol_error(
                ErrorCode::Internal,
                "guest returned the wrong response for a process inventory request",
            )),
        }
    }

    /// Release a prepared init process.
    pub async fn start(&self, request: AgentStartRequest) -> Result<AgentState> {
        expect_state(self.call(AgentRequest::Start(request)).await?, "start")
    }

    /// Deliver a Linux signal.
    pub async fn kill(&self, request: AgentKillRequest) -> Result<AgentState> {
        expect_state(self.call(AgentRequest::Kill(request)).await?, "kill")
    }

    /// Delete guest-owned resources for one exact generation.
    pub async fn delete(&self, request: AgentDeleteRequest) -> Result<()> {
        match self.call(AgentRequest::Delete(request)).await? {
            AgentResponse::Deleted => Ok(()),
            _ => Err(protocol_error(
                ErrorCode::Internal,
                "guest returned the wrong response for an OCI delete request",
            )),
        }
    }

    /// Wait for one exact init process and return its stable terminal result.
    pub async fn wait(&self, request: AgentWaitRequest) -> Result<ExitStatus> {
        let limit = request.timeout_ms.map(Duration::from_millis);
        let started = Instant::now();
        loop {
            let poll_timeout = match limit {
                Some(limit) => WAIT_POLL_INTERVAL.min(limit.saturating_sub(started.elapsed())),
                None => WAIT_POLL_INTERVAL,
            };
            let poll = AgentWaitRequest {
                target: request.target.clone(),
                timeout_ms: Some(duration_millis(poll_timeout)),
            };
            match self.call(AgentRequest::Wait(poll)).await {
                Ok(AgentResponse::ExitStatus(status)) => return Ok(status),
                Ok(_) => {
                    return Err(protocol_error(
                        ErrorCode::Internal,
                        "guest returned the wrong response for an OCI wait request",
                    ));
                }
                Err(error) if error.code == ErrorCode::DeadlineExceeded => {
                    if limit.is_some_and(|limit| started.elapsed() >= limit) {
                        return Err(protocol_error(
                            ErrorCode::DeadlineExceeded,
                            format!(
                                "timed out after {} ms waiting for container {}",
                                request.timeout_ms.unwrap_or_default(),
                                request.target.id
                            ),
                        )
                        .retryable(true));
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Execute one additional OCI process inside an exact container generation.
    pub async fn exec(&self, request: AgentExecRequest) -> Result<AgentProcess> {
        match self.call(AgentRequest::Exec(Box::new(request))).await? {
            AgentResponse::Process(process) => Ok(process),
            _ => Err(protocol_error(
                ErrorCode::Internal,
                "guest returned the wrong response for an OCI exec request",
            )),
        }
    }

    /// Deliver a Linux signal to one exact init or exec process.
    pub async fn signal_process(&self, request: AgentSignalProcessRequest) -> Result<()> {
        match self.call(AgentRequest::SignalProcess(request)).await? {
            AgentResponse::ProcessSignaled(_) => Ok(()),
            _ => Err(protocol_error(
                ErrorCode::Internal,
                "guest returned the wrong response for a process signal request",
            )),
        }
    }

    /// Wait for one exact init or exec process and return its stable result.
    pub async fn wait_process(&self, request: AgentWaitProcessRequest) -> Result<ExitStatus> {
        let limit = request.timeout_ms.map(Duration::from_millis);
        let started = Instant::now();
        loop {
            let poll_timeout = match limit {
                Some(limit) => WAIT_POLL_INTERVAL.min(limit.saturating_sub(started.elapsed())),
                None => WAIT_POLL_INTERVAL,
            };
            let poll = AgentWaitProcessRequest {
                target: request.target.clone(),
                timeout_ms: Some(duration_millis(poll_timeout)),
            };
            match self.call(AgentRequest::WaitProcess(poll)).await {
                Ok(AgentResponse::ProcessExit(exit)) => return Ok(exit.into_status()),
                Ok(_) => {
                    return Err(protocol_error(
                        ErrorCode::Internal,
                        "guest returned the wrong response for a process wait request",
                    ));
                }
                Err(error) if error.code == ErrorCode::DeadlineExceeded => {
                    if limit.is_some_and(|limit| started.elapsed() >= limit) {
                        return Err(protocol_error(
                            ErrorCode::DeadlineExceeded,
                            format!(
                                "timed out after {} ms waiting for process {} in container {}",
                                request.timeout_ms.unwrap_or_default(),
                                request.target.process_id,
                                request.target.container.id
                            ),
                        )
                        .retryable(true));
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn call(&self, request: AgentRequest) -> Result<AgentResponse> {
        request.validate()?;
        ensure_advertised(self.hello.capabilities().operations(), &request)?;

        let mut connection = self.connection.lock().await;
        if connection.poisoned {
            return Err(protocol_error(
                ErrorCode::Unavailable,
                "guest-agent connection is closed after an earlier protocol failure",
            )
            .retryable(true));
        }
        let request_id = connection.next_request_id;
        connection.next_request_id = match request_id.checked_add(1) {
            Some(next) => next,
            None => {
                connection.poisoned = true;
                return Err(protocol_error(
                    ErrorCode::ResourceExhausted,
                    "guest-agent request ID space is exhausted",
                ));
            }
        };
        let envelope = RequestEnvelope {
            version: connection.selected_version,
            request_id,
            request: request.clone(),
        };
        if let Err(error) = write_frame(&mut connection.stream, &envelope).await {
            connection.poisoned = true;
            return Err(error);
        }
        let response: ResponseEnvelope = match read_frame(&mut connection.stream).await {
            Ok(Some(response)) => response,
            Ok(None) => {
                connection.poisoned = true;
                return Err(protocol_error(
                    ErrorCode::Unavailable,
                    "guest closed the stream before returning a response",
                )
                .retryable(true));
            }
            Err(error) => {
                connection.poisoned = true;
                return Err(error);
            }
        };
        if let Err(error) = response.validate(connection.selected_version, request_id) {
            connection.poisoned = true;
            return Err(error);
        }
        match response.outcome {
            ResponseOutcome::Succeeded { response } => {
                if let Err(error) = validate_response_for_request(&request, &response) {
                    connection.poisoned = true;
                    return Err(error);
                }
                Ok(response)
            }
            ResponseOutcome::Failed { error } => Err(error),
        }
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn ensure_advertised(operations: &[AgentOperation], request: &AgentRequest) -> Result<()> {
    let required = match request {
        AgentRequest::Create(_) => AgentOperation::Create,
        AgentRequest::State(_) => AgentOperation::State,
        AgentRequest::Start(_) => AgentOperation::Start,
        AgentRequest::Kill(_) => AgentOperation::Kill,
        AgentRequest::Delete(_) => AgentOperation::Delete,
        AgentRequest::Wait(_) => AgentOperation::Wait,
        AgentRequest::Exec(_) => AgentOperation::Exec,
        AgentRequest::SignalProcess(_) => AgentOperation::SignalProcess,
        AgentRequest::WaitProcess(_) => AgentOperation::WaitProcess,
        AgentRequest::Pause(_) => AgentOperation::Pause,
        AgentRequest::Resume(_) => AgentOperation::Resume,
        AgentRequest::Processes(_) => AgentOperation::Processes,
    };
    if operations.contains(&required) {
        Ok(())
    } else {
        Err(protocol_error(
            ErrorCode::Unsupported,
            format!("guest does not advertise {required:?}"),
        ))
    }
}

fn validate_response_for_request(request: &AgentRequest, response: &AgentResponse) -> Result<()> {
    match (request, response) {
        (AgentRequest::Create(request), AgentResponse::State(state)) => {
            validate_state_target(&request.target, state)?;
            if state.config_digest() != request.bundle.config_digest() {
                return Err(digest_mismatch("create"));
            }
            if state.status() != ContainerState::Created {
                return Err(state_mismatch("create", state.status()));
            }
            Ok(())
        }
        (AgentRequest::State(request), AgentResponse::State(state)) => {
            validate_state_target(&request.target, state)
        }
        (AgentRequest::Start(request), AgentResponse::State(state)) => {
            validate_state_target(&request.target, state)?;
            if state.config_digest() != request.expected_config_digest {
                return Err(digest_mismatch("start"));
            }
            if !matches!(
                state.status(),
                ContainerState::Running | ContainerState::Stopped
            ) {
                return Err(state_mismatch("start", state.status()));
            }
            Ok(())
        }
        (AgentRequest::Kill(request), AgentResponse::State(state)) => {
            validate_state_target(&request.target, state)
        }
        (AgentRequest::Delete(_), AgentResponse::Deleted) => Ok(()),
        (AgentRequest::Wait(_), AgentResponse::ExitStatus(status)) => status.validate(),
        (AgentRequest::Exec(request), AgentResponse::Process(process)) => {
            validate_process_target(&request.target, process.target())?;
            let expected_terminal = request.process.terminal().unwrap_or(false);
            if process.terminal() != expected_terminal {
                return Err(protocol_error(
                    ErrorCode::Conflict,
                    format!(
                        "guest exec response terminal={} does not match request terminal={expected_terminal}",
                        process.terminal()
                    ),
                ));
            }
            Ok(())
        }
        (AgentRequest::SignalProcess(request), AgentResponse::ProcessSignaled(signal)) => {
            validate_process_target(&request.target, signal.target())
        }
        (AgentRequest::WaitProcess(request), AgentResponse::ProcessExit(exit)) => {
            validate_process_target(&request.target, exit.target())?;
            exit.status().validate()
        }
        (AgentRequest::Pause(request), AgentResponse::State(state)) => {
            validate_state_target(&request.target, state)?;
            if state.paused() {
                Ok(())
            } else {
                Err(protocol_error(
                    ErrorCode::FailedPrecondition,
                    "guest pause response did not report a frozen container",
                ))
            }
        }
        (AgentRequest::Resume(request), AgentResponse::State(state)) => {
            validate_state_target(&request.target, state)?;
            if state.paused() {
                Err(protocol_error(
                    ErrorCode::FailedPrecondition,
                    "guest resume response still reported a frozen container",
                ))
            } else {
                Ok(())
            }
        }
        (AgentRequest::Processes(request), AgentResponse::Processes(processes)) => {
            if let Some(process) = processes
                .iter()
                .find(|process| process.target.container != request.target)
            {
                Err(protocol_error(
                    ErrorCode::Conflict,
                    format!(
                        "guest process {} belongs to a different container target",
                        process.target.process_id
                    ),
                ))
            } else {
                Ok(())
            }
        }
        (request, response) => Err(protocol_error(
            ErrorCode::Internal,
            format!(
                "guest response {response:?} does not match request {}",
                request_name(request)
            ),
        )),
    }
}

fn validate_state_target(
    expected: &a3s_oci_sdk::ContainerTarget,
    state: &AgentState,
) -> Result<()> {
    if state.target() == expected {
        Ok(())
    } else {
        Err(protocol_error(
            ErrorCode::Conflict,
            format!(
                "guest state target {:?} does not match request target {expected:?}",
                state.target()
            ),
        ))
    }
}

fn validate_process_target(
    expected: &a3s_oci_sdk::ProcessTarget,
    actual: &a3s_oci_sdk::ProcessTarget,
) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(protocol_error(
            ErrorCode::Conflict,
            format!("guest process target {actual:?} does not match request target {expected:?}"),
        ))
    }
}

fn expect_state(response: AgentResponse, operation: &'static str) -> Result<AgentState> {
    match response {
        AgentResponse::State(state) => Ok(state),
        _ => Err(protocol_error(
            ErrorCode::Internal,
            format!("guest returned the wrong response for OCI {operation}"),
        )),
    }
}

fn digest_mismatch(operation: &'static str) -> Error {
    protocol_error(
        ErrorCode::Conflict,
        format!("guest {operation} response configuration digest does not match the request"),
    )
}

fn state_mismatch(operation: &'static str, status: ContainerState) -> Error {
    protocol_error(
        ErrorCode::FailedPrecondition,
        format!("guest violated OCI {operation} barrier by returning {status}"),
    )
}

const fn request_name(request: &AgentRequest) -> &'static str {
    match request {
        AgentRequest::Create(_) => "create",
        AgentRequest::State(_) => "state",
        AgentRequest::Start(_) => "start",
        AgentRequest::Kill(_) => "kill",
        AgentRequest::Delete(_) => "delete",
        AgentRequest::Wait(_) => "wait",
        AgentRequest::Exec(_) => "exec",
        AgentRequest::SignalProcess(_) => "signal-process",
        AgentRequest::WaitProcess(_) => "wait-process",
        AgentRequest::Pause(_) => "pause",
        AgentRequest::Resume(_) => "resume",
        AgentRequest::Processes(_) => "processes",
    }
}

#[cfg(test)]
impl<T> AgentClient<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub(crate) async fn connect_for_test(
        stream: T,
        token: SessionToken,
        minimum: u16,
        maximum: u16,
    ) -> Result<Self> {
        Self::connect_with_range(
            stream,
            token,
            ProtocolRange {
                min: minimum,
                max: maximum,
            },
        )
        .await
    }
}
