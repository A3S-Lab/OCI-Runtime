//! Linux guest bootstrap for the authenticated OCI agent protocol.

#[cfg(target_os = "linux")]
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentCapabilities, AgentCreateRequest, AgentDeleteRequest, AgentKillRequest, AgentStartRequest,
    AgentState, AgentStateRequest, GuestAgentService, SessionToken, AGENT_SESSION_TOKEN_ENV,
};
use a3s_oci_sdk::{async_trait, Error, ErrorCode, Result};
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
mod vsock;

/// Guest implementation version sent during protocol negotiation.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Guest service that proves transport bootstrap without claiming execution.
#[derive(Debug)]
pub struct NegotiationOnlyAgent {
    capabilities: AgentCapabilities,
}

impl NegotiationOnlyAgent {
    /// Construct a guest that advertises only implemented bootstrap features.
    pub fn new() -> Result<Self> {
        Ok(Self {
            capabilities: AgentCapabilities::handshake_only(AGENT_VERSION, std::env::consts::ARCH)?,
        })
    }
}

#[async_trait]
impl GuestAgentService for NegotiationOnlyAgent {
    fn capabilities(&self) -> AgentCapabilities {
        self.capabilities.clone()
    }

    async fn create(&self, _request: AgentCreateRequest) -> Result<AgentState> {
        Err(Error::unsupported("agent-create"))
    }

    async fn state(&self, _request: AgentStateRequest) -> Result<AgentState> {
        Err(Error::unsupported("agent-state"))
    }

    async fn start(&self, _request: AgentStartRequest) -> Result<AgentState> {
        Err(Error::unsupported("agent-start"))
    }

    async fn kill(&self, _request: AgentKillRequest) -> Result<AgentState> {
        Err(Error::unsupported("agent-kill"))
    }

    async fn delete(&self, _request: AgentDeleteRequest) -> Result<()> {
        Err(Error::unsupported("agent-delete"))
    }
}

/// Remove and decode the protected bootstrap token from this process.
pub fn take_session_token_from_environment() -> Result<SessionToken> {
    let encoded = Zeroizing::new(std::env::var(AGENT_SESSION_TOKEN_ENV).map_err(|error| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!("guest bootstrap token is unavailable: {error}"),
        )
        .for_operation("bootstrap-guest-agent")
    })?);
    std::env::remove_var(AGENT_SESSION_TOKEN_ENV);
    SessionToken::from_hex(encoded.as_str()).map_err(|error| {
        Error::new(
            error.code,
            format!("guest bootstrap token is invalid: {error}"),
        )
        .for_operation("bootstrap-guest-agent")
    })
}

/// Connect to the host bridge and serve negotiation-only protocol version 1.
#[cfg(target_os = "linux")]
pub fn run(token: SessionToken) -> Result<()> {
    let service = Arc::new(NegotiationOnlyAgent::new()?);
    let stream = vsock::connect_host_with_retry()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("failed to initialize guest async runtime: {error}"),
            )
            .for_operation("run-guest-agent")
        })?;
    runtime.block_on(async move {
        let stream = tokio::net::UnixStream::from_std(stream).map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("failed to register guest vsock stream: {error}"),
            )
            .for_operation("run-guest-agent")
        })?;
        a3s_oci_agent_protocol::serve_agent_connection(stream, token, service).await
    })
}

/// Report that the guest binary cannot run on a non-Linux target.
#[cfg(not(target_os = "linux"))]
pub fn run(_token: SessionToken) -> Result<()> {
    Err(Error::new(
        ErrorCode::Unsupported,
        "the OCI guest agent requires Linux AF_VSOCK",
    )
    .for_operation("run-guest-agent"))
}

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::GuestAgentService;

    use super::NegotiationOnlyAgent;

    #[test]
    fn bootstrap_service_does_not_claim_executor_operations() {
        let agent = NegotiationOnlyAgent::new().expect("built-in capabilities are valid");
        let capabilities = agent.capabilities();
        assert!(capabilities.operations().is_empty());
    }
}
