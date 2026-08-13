use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    serve_agent_connection, AgentCapabilities, AgentClient, AgentCreateRequest, AgentDeleteRequest,
    AgentKillRequest, AgentOperation, AgentStartRequest, AgentState, AgentStateRequest,
    AgentVsockEndpoint, GuestAgentService, SessionToken, AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_sdk::{async_trait, Error, ErrorCode, Result};
use tokio::process::{Child, Command};

use super::{MacosAgentSocketListener, PRIVATE_DIRECTORY_MODE, PRIVATE_SOCKET_MODE};

const CHILD_SOCKET_ENV: &str = "A3S_OCI_TEST_AGENT_SOCKET";
const CHILD_TOKEN_ENV: &str = "A3S_OCI_TEST_AGENT_TOKEN";
const CHILD_EXPECT_REJECTION_ENV: &str = "A3S_OCI_TEST_EXPECT_REJECTION";
const CHILD_TEST_NAME: &str = "agent_socket::tests::agent_socket_child";

#[derive(Debug)]
struct CoreAgent;

#[async_trait]
impl GuestAgentService for CoreAgent {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::core("0.1.0-test", "aarch64").expect("valid core capabilities")
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

fn unique_listener() -> MacosAgentSocketListener {
    MacosAgentSocketListener::bind(
        AgentVsockEndpoint::generate().expect("operating-system random source"),
    )
    .expect("bind private macOS agent socket")
}

fn spawn_agent_child(socket_path: &Path, token: &SessionToken, expect_rejection: bool) -> Child {
    let encoded = token.expose_hex();
    let mut command = Command::new(std::env::current_exe().expect("resolve test executable"));
    command
        .args(["--exact", CHILD_TEST_NAME, "--nocapture"])
        .env(CHILD_SOCKET_ENV, socket_path)
        .env(CHILD_TOKEN_ENV, encoded.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if expect_rejection {
        command.env(CHILD_EXPECT_REJECTION_ENV, "1");
    }
    command.spawn().expect("spawn direct agent test child")
}

async fn assert_child_succeeded(child: Child) {
    let output = child
        .wait_with_output()
        .await
        .expect("wait for agent test child");
    assert!(
        output.status.success(),
        "agent test child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn listener_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MacosAgentSocketListener>();
}

#[tokio::test]
async fn authenticated_connection_survives_consumed_endpoint_cleanup() {
    let listener = unique_listener();
    let directory = listener.directory().to_path_buf();
    let socket_path = listener.socket_path().to_path_buf();
    let token = SessionToken::generate().expect("operating-system random source");
    let child = spawn_agent_child(&socket_path, &token, false);
    let child_process_id = child.id().expect("test child has a process ID");

    let (stream, peer_process_id) = listener
        .accept_from_child(std::process::id())
        .await
        .expect("accept direct child");
    assert_eq!(peer_process_id, child_process_id);
    assert!(!socket_path.exists());
    assert!(!directory.exists());

    let client = AgentClient::connect(stream, token)
        .await
        .expect("authenticate direct child agent");
    assert!(!socket_path.exists());
    assert!(!directory.exists());
    assert_eq!(
        client.hello().selected_version(),
        AGENT_PROTOCOL_VERSION_MAX
    );
    assert_eq!(
        client.hello().capabilities().operations(),
        [
            AgentOperation::Create,
            AgentOperation::State,
            AgentOperation::Start,
            AgentOperation::Kill,
            AgentOperation::Delete,
        ]
    );
    drop(client);
    assert_child_succeeded(child).await;
}

#[tokio::test]
async fn rejects_wrong_tokens_after_direct_child_verification() {
    let listener = unique_listener();
    let socket_path = listener.socket_path().to_path_buf();
    let guest_token = SessionToken::generate().expect("operating-system random source");
    let host_token = SessionToken::generate().expect("operating-system random source");
    let child = spawn_agent_child(&socket_path, &guest_token, true);

    let (stream, _) = listener
        .accept_from_child(std::process::id())
        .await
        .expect("accept direct child");
    let error = AgentClient::connect(stream, host_token)
        .await
        .expect_err("wrong token must be rejected");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_child_succeeded(child).await;
}

#[tokio::test]
async fn rejects_an_unrelated_peer_before_token_negotiation() {
    let listener = unique_listener();
    let directory = listener.directory().to_path_buf();
    let socket_path = listener.socket_path().to_path_buf();
    let _unrelated = tokio::net::UnixStream::connect(&socket_path)
        .await
        .expect("connect same-process unrelated peer");

    let error = listener
        .accept_from_child(std::process::id())
        .await
        .expect_err("same-process peer is not a direct child");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert!(!socket_path.exists());
    assert!(!directory.exists());
}

#[tokio::test]
async fn endpoint_modes_collisions_and_drop_cleanup_are_fail_closed() {
    use std::os::unix::fs::MetadataExt;

    let listener = unique_listener();
    let endpoint = listener.endpoint().clone();
    let directory = listener.directory().to_path_buf();
    let socket_path = listener.socket_path().to_path_buf();
    assert_eq!(
        std::fs::symlink_metadata(&directory)
            .expect("private directory metadata")
            .mode()
            & 0o777,
        PRIVATE_DIRECTORY_MODE
    );
    assert_eq!(
        std::fs::symlink_metadata(&socket_path)
            .expect("private socket metadata")
            .mode()
            & 0o777,
        PRIVATE_SOCKET_MODE
    );

    let error = MacosAgentSocketListener::bind(endpoint)
        .expect_err("second endpoint owner must be rejected");
    assert_eq!(error.code, ErrorCode::Conflict);
    drop(listener);
    assert!(!socket_path.exists());
    assert!(!directory.exists());
}

#[test]
fn agent_socket_child() {
    let Ok(socket_path) = std::env::var(CHILD_SOCKET_ENV) else {
        return;
    };
    let encoded = std::env::var(CHILD_TOKEN_ENV).expect("child token environment");
    let expect_rejection = std::env::var_os(CHILD_EXPECT_REJECTION_ENV).is_some();
    std::env::remove_var(CHILD_SOCKET_ENV);
    std::env::remove_var(CHILD_TOKEN_ENV);
    std::env::remove_var(CHILD_EXPECT_REJECTION_ENV);
    let token = SessionToken::from_hex(&encoded).expect("valid child token");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("build child async runtime");
    let result = runtime.block_on(async move {
        let stream = tokio::net::UnixStream::connect(socket_path)
            .await
            .expect("child connects to private socket");
        serve_agent_connection(stream, token, Arc::new(CoreAgent)).await
    });
    if expect_rejection {
        let error = result.expect_err("wrong host token must reject the child");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
    } else {
        result.expect("direct child protocol connection closes cleanly");
    }
}
