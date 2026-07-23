use std::fmt;
use std::sync::Arc;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{Error, ErrorCode, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::model::{
    protocol_error, AgentCreateRequest, AgentDeleteRequest, AgentHello, AgentKillRequest,
    AgentOperation, AgentRequest, AgentResponse, AgentStartRequest, AgentState, AgentStateRequest,
    HelloOutcome, HostHello, ProtocolRange, RequestEnvelope, ResponseEnvelope, ResponseOutcome,
    SessionToken,
};
use crate::wire::{read_frame, write_frame};

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
            AgentResponse::State(_) => Err(protocol_error(
                ErrorCode::Internal,
                "guest returned state for an OCI delete request",
            )),
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

fn ensure_advertised(operations: &[AgentOperation], request: &AgentRequest) -> Result<()> {
    let required = match request {
        AgentRequest::Create(_) => AgentOperation::Create,
        AgentRequest::State(_) => AgentOperation::State,
        AgentRequest::Start(_) => AgentOperation::Start,
        AgentRequest::Kill(_) => AgentOperation::Kill,
        AgentRequest::Delete(_) => AgentOperation::Delete,
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

fn expect_state(response: AgentResponse, operation: &'static str) -> Result<AgentState> {
    match response {
        AgentResponse::State(state) => Ok(state),
        AgentResponse::Deleted => Err(protocol_error(
            ErrorCode::Internal,
            format!("guest returned delete acknowledgement for OCI {operation}"),
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
