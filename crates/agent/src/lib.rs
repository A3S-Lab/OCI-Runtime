//! Linux guest bootstrap for the authenticated OCI agent protocol.

use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

#[cfg(target_os = "linux")]
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentCapabilities, AgentCreateRequest, AgentDeleteRequest, AgentKillRequest, AgentStartRequest,
    AgentState, AgentStateRequest, AgentVsockEndpoint, GuestAgentService, SessionToken,
    AGENT_SESSION_TOKEN_DIRECTORY_PREFIX, AGENT_SESSION_TOKEN_ENV, AGENT_SESSION_TOKEN_FILE_ENV,
    AGENT_SESSION_TOKEN_FILE_NAME,
};
use a3s_oci_sdk::{async_trait, Error, ErrorCode, Result};
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
mod executor;
#[cfg(target_os = "linux")]
mod vsock;

/// Guest implementation version sent during protocol negotiation.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Run the internal prepared-init mode when selected by the guest executor.
///
/// Normal guest-agent startup returns `None`; the internal child mode returns
/// its terminal result and must not attempt host protocol bootstrap.
#[cfg(target_os = "linux")]
pub fn run_internal_container_init() -> Option<Result<()>> {
    executor::run_container_init_if_requested()
}

/// Non-Linux builds never enter the internal Linux init mode.
#[cfg(not(target_os = "linux"))]
pub const fn run_internal_container_init() -> Option<Result<()>> {
    None
}

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

/// Read, unlink, and decode the protected one-time bootstrap token file.
pub fn take_session_token_from_file() -> Result<SessionToken> {
    if std::env::var_os(AGENT_SESSION_TOKEN_ENV).is_some() {
        std::env::remove_var(AGENT_SESSION_TOKEN_ENV);
        return Err(Error::new(
            ErrorCode::FailedPrecondition,
            "guest bootstrap token must not be present directly in the guest environment",
        )
        .for_operation("bootstrap-guest-agent"));
    }

    let path = PathBuf::from(
        std::env::var(AGENT_SESSION_TOKEN_FILE_ENV).map_err(|error| {
            Error::new(
                ErrorCode::FailedPrecondition,
                format!("guest bootstrap token file is unavailable: {error}"),
            )
            .for_operation("bootstrap-guest-agent")
        })?,
    );
    std::env::remove_var(AGENT_SESSION_TOKEN_FILE_ENV);
    validate_token_path(&path)?;

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(&path).map_err(|error| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to open guest bootstrap token file {}: {error}",
                path.display()
            ),
        )
        .for_operation("bootstrap-guest-agent")
    })?;
    let metadata = file.metadata().map_err(|error| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect guest bootstrap token file {}: {error}",
                path.display()
            ),
        )
        .for_operation("bootstrap-guest-agent")
    })?;
    if !metadata.is_file() || metadata.len() != 64 {
        return Err(Error::new(
            ErrorCode::FailedPrecondition,
            "guest bootstrap token file must be a regular 64-byte file",
        )
        .for_operation("bootstrap-guest-agent"));
    }
    let mut encoded = Zeroizing::new(String::with_capacity(64));
    let read_result = file.take(65).read_to_string(&mut encoded);
    let unlink_result = std::fs::remove_file(&path);
    if let Some(parent) = path.parent() {
        let _ = std::fs::remove_dir(parent);
    }
    read_result.map_err(|error| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to read guest bootstrap token file {}: {error}",
                path.display()
            ),
        )
        .for_operation("bootstrap-guest-agent")
    })?;
    unlink_result.map_err(|error| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to unlink guest bootstrap token file {}: {error}",
                path.display()
            ),
        )
        .for_operation("bootstrap-guest-agent")
    })?;
    SessionToken::from_hex(encoded.as_str()).map_err(|error| {
        Error::new(
            error.code,
            format!("guest bootstrap token is invalid: {error}"),
        )
        .for_operation("bootstrap-guest-agent")
    })
}

fn validate_token_path(path: &Path) -> Result<()> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(invalid_token_path());
    }
    let Some(Component::Normal(directory)) = components.next() else {
        return Err(invalid_token_path());
    };
    let Some(Component::Normal(file)) = components.next() else {
        return Err(invalid_token_path());
    };
    let valid_directory = directory
        .to_str()
        .and_then(|value| value.strip_prefix(AGENT_SESSION_TOKEN_DIRECTORY_PREFIX))
        .is_some_and(|endpoint| AgentVsockEndpoint::new(endpoint).is_ok());
    if components.next().is_some() || file != AGENT_SESSION_TOKEN_FILE_NAME || !valid_directory {
        return Err(invalid_token_path());
    }
    Ok(())
}

fn invalid_token_path() -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        "guest bootstrap token file path is not the runtime-owned one-time path",
    )
    .for_operation("bootstrap-guest-agent")
}

/// Connect to the host bridge and serve the fail-closed Linux executor.
#[cfg(target_os = "linux")]
pub fn run(token: SessionToken) -> Result<()> {
    let stream = vsock::connect_host_with_retry()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
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
        let service = Arc::new(executor::LinuxExecutorAgent::new().await?);
        let protocol_service: Arc<dyn GuestAgentService> = service.clone();
        let serve_result =
            a3s_oci_agent_protocol::serve_agent_connection(stream, token, protocol_service).await;
        let cleanup_result = service.shutdown().await;
        match (serve_result, cleanup_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => Err(Error::new(
                error.code,
                format!("{error}; guest executor cleanup also failed: {cleanup}"),
            )
            .for_operation("run-guest-agent")
            .retryable(error.retryable)),
        }
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
    use std::path::Path;

    use a3s_oci_agent_protocol::GuestAgentService;

    use super::{validate_token_path, NegotiationOnlyAgent};

    #[test]
    fn bootstrap_service_does_not_claim_executor_operations() {
        let agent = NegotiationOnlyAgent::new().expect("built-in capabilities are valid");
        let capabilities = agent.capabilities();
        assert!(capabilities.operations().is_empty());
    }

    #[test]
    fn accepts_only_the_runtime_owned_token_file_shape() {
        assert!(validate_token_path(Path::new(
            "/.a3s-oci-bootstrap-a3s-oci-agent-test/session-token"
        ))
        .is_ok());
        for path in [
            "relative/session-token",
            "/session-token",
            "/.a3s-oci-bootstrap-/session-token",
            "/.a3s-oci-bootstrap-invalid endpoint/session-token",
            "/.a3s-oci-bootstrap-test/other",
            "/.a3s-oci-bootstrap-test/nested/session-token",
        ] {
            assert!(validate_token_path(Path::new(path)).is_err(), "{path}");
        }
    }
}
