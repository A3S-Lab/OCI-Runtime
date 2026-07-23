use std::sync::Arc;

use a3s_oci_sdk::{async_trait, Error, ErrorCode, Result};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::model::{
    protocol_error, AgentCapabilities, AgentCreateRequest, AgentDeleteRequest, AgentHello,
    AgentKillRequest, AgentRequest, AgentResponse, AgentStartRequest, AgentState,
    AgentStateRequest, HelloOutcome, HostHello, RequestEnvelope, ResponseEnvelope, ResponseOutcome,
    SessionToken,
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
    let capabilities = service.capabilities();
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
                Ok(()) => ResponseOutcome::Succeeded { response },
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
