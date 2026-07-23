use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;

use a3s_oci_agent_protocol::AgentVsockEndpoint;
use a3s_oci_sdk::{Error, ErrorCode, Result};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY, HANDLE};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

use crate::windows_security::PrivateSecurityDescriptor;

/// Exclusive, locally reachable Windows endpoint for one guest-agent session.
///
/// Binding creates the first pipe instance with a protected DACL granting
/// access only to the runtime principal and LocalSystem. Remote clients and
/// inheritable handles are disabled.
#[derive(Debug)]
pub struct WindowsAgentPipeListener {
    endpoint: AgentVsockEndpoint,
    server: NamedPipeServer,
}

impl WindowsAgentPipeListener {
    /// Bind and verify one runtime-owned agent pipe.
    pub fn bind(endpoint: AgentVsockEndpoint) -> Result<Self> {
        let pipe_path = endpoint.windows_pipe_path();
        let mut security = PrivateSecurityDescriptor::for_kernel_object(&pipe_path)?;
        let mut attributes =
            security.security_attributes("bind-agent-pipe", Path::new(&pipe_path))?;
        let mut options = ServerOptions::new();
        options
            .access_inbound(true)
            .access_outbound(true)
            .pipe_mode(PipeMode::Byte)
            .first_pipe_instance(true)
            .reject_remote_clients(true);

        // SAFETY: `attributes` points to a fully initialized descriptor whose
        // ACL and SIDs remain live until `CreateNamedPipeW` returns.
        let server = unsafe {
            options.create_with_security_attributes_raw(
                &pipe_path,
                ptr::from_mut(&mut attributes).cast::<c_void>(),
            )
        }
        .map_err(|error| bind_error(&pipe_path, error))?;
        let handle = server.as_raw_handle() as HANDLE;
        security.verify_kernel_object(handle, &pipe_path)?;

        Ok(Self { endpoint, server })
    }

    /// Borrow the exact endpoint that must be passed to the libkrun shim.
    #[must_use]
    pub fn endpoint(&self) -> &AgentVsockEndpoint {
        &self.endpoint
    }

    /// Accept only the previously spawned libkrun shim process.
    ///
    /// The peer PID is verified before returning the stream, so callers cannot
    /// disclose the session token to another process running as the same user.
    pub async fn accept_from_process(
        self,
        expected_client_process_id: u32,
    ) -> Result<NamedPipeServer> {
        if expected_client_process_id == 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "expected guest-agent bridge process ID must be nonzero",
            )
            .for_operation("accept-agent-pipe"));
        }
        self.server.connect().await.map_err(|error| {
            Error::new(
                ErrorCode::Unavailable,
                format!(
                    "failed to accept guest-agent bridge on {}: {error}",
                    self.endpoint.windows_pipe_path()
                ),
            )
            .for_operation("accept-agent-pipe")
            .retryable(true)
        })?;
        let mut client_process_id = 0;
        // SAFETY: the server owns a live connected named-pipe handle and the
        // output pointer is valid for one `u32`.
        if unsafe {
            GetNamedPipeClientProcessId(
                self.server.as_raw_handle() as HANDLE,
                &mut client_process_id,
            )
        } == 0
        {
            return Err(Error::new(
                ErrorCode::Internal,
                format!(
                    "failed to identify guest-agent pipe client on {}: {}",
                    self.endpoint.windows_pipe_path(),
                    std::io::Error::last_os_error()
                ),
            )
            .for_operation("accept-agent-pipe"));
        }
        if client_process_id != expected_client_process_id {
            return Err(Error::new(
                ErrorCode::PermissionDenied,
                format!(
                    "guest-agent pipe client PID {client_process_id} does not match expected \
                     libkrun shim PID {expected_client_process_id}"
                ),
            )
            .for_operation("accept-agent-pipe"));
        }
        Ok(self.server)
    }
}

fn bind_error(pipe_path: &str, error: std::io::Error) -> Error {
    let collision = error.raw_os_error().is_some_and(|code| {
        u32::try_from(code).is_ok_and(|code| matches!(code, ERROR_ACCESS_DENIED | ERROR_PIPE_BUSY))
    });
    let code = if collision {
        ErrorCode::Conflict
    } else {
        ErrorCode::Internal
    };
    Error::new(
        code,
        format!("failed to bind guest-agent pipe {pipe_path}: {error}"),
    )
    .for_operation("bind-agent-pipe")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use a3s_oci_agent_protocol::{
        serve_agent_connection, AgentCapabilities, AgentClient, AgentCreateRequest,
        AgentDeleteRequest, AgentKillRequest, AgentStartRequest, AgentState, AgentStateRequest,
        AgentVsockEndpoint, GuestAgentService, SessionToken,
    };
    use a3s_oci_sdk::{async_trait, Error, ErrorCode, Result};
    use tokio::net::windows::named_pipe::ClientOptions;

    use super::WindowsAgentPipeListener;

    #[derive(Debug)]
    struct NegotiationOnlyAgent;

    #[async_trait]
    impl GuestAgentService for NegotiationOnlyAgent {
        fn capabilities(&self) -> AgentCapabilities {
            AgentCapabilities::handshake_only("0.1.0-test", std::env::consts::ARCH)
                .expect("valid negotiation-only capabilities")
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

    fn unique_endpoint() -> AgentVsockEndpoint {
        AgentVsockEndpoint::generate().expect("operating-system random source")
    }

    #[test]
    fn listener_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WindowsAgentPipeListener>();
    }

    #[tokio::test]
    async fn protected_pipe_negotiates_the_authenticated_agent_protocol() {
        let endpoint = unique_endpoint();
        let listener =
            WindowsAgentPipeListener::bind(endpoint.clone()).expect("bind protected pipe");
        assert_eq!(listener.endpoint(), &endpoint);
        let token = SessionToken::generate().expect("operating-system random source");

        let guest_endpoint = endpoint.clone();
        let guest_token = token.clone();
        let guest_task = tokio::spawn(async move {
            let stream = ClientOptions::new()
                .open(guest_endpoint.windows_pipe_path())
                .expect("open protected local pipe");
            serve_agent_connection(stream, guest_token, Arc::new(NegotiationOnlyAgent)).await
        });

        let stream = listener
            .accept_from_process(std::process::id())
            .await
            .expect("accept expected local client");
        let client = AgentClient::connect(stream, token)
            .await
            .expect("negotiate authenticated agent protocol");
        assert_eq!(client.hello().selected_version(), 1);
        assert!(client.hello().capabilities().operations().is_empty());
        drop(client);
        guest_task
            .await
            .expect("guest task must join")
            .expect("guest connection must close cleanly");
    }

    #[tokio::test]
    async fn first_instance_prevents_pipe_name_squatting() {
        let endpoint = unique_endpoint();
        let _owner =
            WindowsAgentPipeListener::bind(endpoint.clone()).expect("bind first pipe instance");
        let error =
            WindowsAgentPipeListener::bind(endpoint).expect_err("second owner must be rejected");
        assert_eq!(error.code, ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn rejects_an_unexpected_pipe_client_before_protocol_authentication() {
        let endpoint = unique_endpoint();
        let listener =
            WindowsAgentPipeListener::bind(endpoint.clone()).expect("bind protected pipe");
        let _client = ClientOptions::new()
            .open(endpoint.windows_pipe_path())
            .expect("open protected local pipe");
        let wrong_process_id = std::process::id().checked_add(1).unwrap_or(1);

        let error = listener
            .accept_from_process(wrong_process_id)
            .await
            .expect_err("unexpected client process must be rejected");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
    }
}
