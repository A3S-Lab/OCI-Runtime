use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    async_trait, ContainerId, ContainerTarget, DeleteMode, Error, ErrorCode, Generation, OciBundle,
    OperationContext, OperationId, ProcessIo, Result, Signal,
};
use tokio::io::{AsyncWriteExt, DuplexStream};

use crate::model::{
    AgentCreateRequest, AgentDeleteRequest, AgentHello, AgentKillRequest, AgentRequest,
    AgentResponse, AgentStartRequest, AgentState, AgentStateRequest, HelloOutcome, HostHello,
    RequestEnvelope, ResponseEnvelope, ResponseOutcome,
};
use crate::wire::{read_frame, read_frame_for_test, write_frame};
use crate::{
    serve_agent_connection, AgentCapabilities, AgentClient, GuestAgentService, GuestPath,
    SessionToken,
};

const TEST_CONFIG: &str = concat!(
    "{\n",
    "  \"ociVersion\": \"1.3.0\",\n",
    "  \"process\": {\n",
    "    \"terminal\": false,\n",
    "    \"user\": {\"uid\": 0, \"gid\": 0},\n",
    "    \"args\": [\"/bin/true\"],\n",
    "    \"cwd\": \"/\"\n",
    "  },\n",
    "  \"root\": {\"path\": \"rootfs\", \"readonly\": true}\n",
    "}\n",
);

#[derive(Debug, Default)]
struct TestAgent {
    states: Mutex<HashMap<ContainerId, AgentState>>,
}

#[async_trait]
impl GuestAgentService for TestAgent {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::core("0.1.0-test", std::env::consts::ARCH)
            .expect("valid test capabilities")
    }

    async fn create(&self, request: AgentCreateRequest) -> Result<AgentState> {
        let state = AgentState::new(
            request.target.clone(),
            ContainerState::Created,
            Some(101),
            request.bundle.config_digest(),
        )?;
        self.states
            .lock()
            .expect("agent states lock")
            .insert(request.target.id, state.clone());
        Ok(state)
    }

    async fn state(&self, request: AgentStateRequest) -> Result<AgentState> {
        self.states
            .lock()
            .expect("agent states lock")
            .get(&request.target.id)
            .cloned()
            .ok_or_else(|| {
                Error::new(ErrorCode::NotFound, "guest container does not exist")
                    .for_operation("agent-state")
            })
    }

    async fn start(&self, request: AgentStartRequest) -> Result<AgentState> {
        let state = AgentState::new(
            request.target.clone(),
            ContainerState::Running,
            Some(101),
            request.expected_config_digest,
        )?;
        self.states
            .lock()
            .expect("agent states lock")
            .insert(request.target.id, state.clone());
        Ok(state)
    }

    async fn kill(&self, request: AgentKillRequest) -> Result<AgentState> {
        let mut states = self.states.lock().expect("agent states lock");
        let digest = states
            .get(&request.target.id)
            .map(|state| state.config_digest().to_string())
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "guest container does not exist"))?;
        let state = AgentState::new(
            request.target.clone(),
            ContainerState::Stopped,
            None,
            digest,
        )?;
        states.insert(request.target.id, state.clone());
        Ok(state)
    }

    async fn delete(&self, request: AgentDeleteRequest) -> Result<()> {
        self.states
            .lock()
            .expect("agent states lock")
            .remove(&request.target.id);
        Ok(())
    }
}

fn identifier<T>(value: &str, constructor: impl FnOnce(String) -> a3s_oci_sdk::Result<T>) -> T {
    constructor(value.to_string()).unwrap_or_else(|error| panic!("valid identifier: {error}"))
}

fn container_id(value: &str) -> ContainerId {
    identifier(value, ContainerId::new)
}

fn operation_id(value: &str) -> OperationId {
    identifier(value, OperationId::new)
}

fn token(byte: u8) -> SessionToken {
    SessionToken::from_bytes([byte; 32]).expect("nonzero session token")
}

fn create_request() -> AgentCreateRequest {
    let directory = std::env::temp_dir().join("a3s-agent-protocol-test-bundle");
    let bundle = OciBundle::from_json(directory, TEST_CONFIG).expect("valid OCI bundle");
    AgentCreateRequest {
        context: OperationContext::new(operation_id("create-1")),
        target: ContainerTarget::exact(container_id("container-1"), Generation(1)),
        bundle: crate::AgentBundle::new(
            &bundle,
            GuestPath::new("/run/a3s/bundles/container-1").expect("guest path"),
        ),
        io: ProcessIo::default(),
    }
}

fn spawn_server(
    stream: DuplexStream,
    expected_token: SessionToken,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(serve_agent_connection(
        stream,
        expected_token,
        Arc::new(TestAgent::default()),
    ))
}

#[tokio::test]
async fn negotiates_and_round_trips_the_core_oci_lifecycle() {
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = spawn_server(guest, token(7));
    let client = AgentClient::connect(host, token(7))
        .await
        .expect("connect agent client");
    assert_eq!(client.hello().selected_version(), 1);
    assert_eq!(client.hello().capabilities().operations().len(), 5);

    let create = create_request();
    let digest = create.bundle.config_digest().to_string();
    let target = create.target.clone();
    let created = client.create(create).await.expect("agent create");
    assert_eq!(created.status(), ContainerState::Created);
    assert_eq!(created.pid(), Some(101));
    assert_eq!(
        client
            .state(AgentStateRequest {
                target: target.clone()
            })
            .await
            .expect("agent state"),
        created
    );

    let running = client
        .start(AgentStartRequest {
            context: OperationContext::new(operation_id("start-1")),
            target: target.clone(),
            expected_config_digest: digest,
        })
        .await
        .expect("agent start");
    assert_eq!(running.status(), ContainerState::Running);

    let stopped = client
        .kill(AgentKillRequest {
            context: OperationContext::new(operation_id("kill-1")),
            target: target.clone(),
            signal: Signal::new(15).expect("signal"),
            all: false,
        })
        .await
        .expect("agent kill");
    assert_eq!(stopped.status(), ContainerState::Stopped);

    client
        .delete(AgentDeleteRequest {
            context: OperationContext::new(operation_id("delete-1")),
            target,
            mode: DeleteMode::StoppedOnly,
        })
        .await
        .expect("agent delete");

    drop(client);
    server
        .await
        .expect("server task")
        .expect("clean server shutdown");
}

#[tokio::test]
async fn rejects_wrong_session_tokens_and_incompatible_versions() {
    let (host, guest) = tokio::io::duplex(64 * 1024);
    let server = spawn_server(guest, token(7));
    let error = AgentClient::connect(host, token(8))
        .await
        .expect_err("wrong token must fail");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(
        server
            .await
            .expect("server task")
            .expect_err("server rejects token")
            .code,
        ErrorCode::PermissionDenied
    );

    let (host, guest) = tokio::io::duplex(64 * 1024);
    let server = spawn_server(guest, token(9));
    let error = AgentClient::connect_for_test(host, token(9), 2, 2)
        .await
        .expect_err("incompatible version must fail");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(
        server
            .await
            .expect("server task")
            .expect_err("server rejects version")
            .code,
        ErrorCode::FailedPrecondition
    );
}

#[tokio::test]
async fn rejects_oversized_frames_before_reading_the_payload() {
    let (mut writer, mut reader) = tokio::io::duplex(64);
    writer
        .write_all(&11_u32.to_be_bytes())
        .await
        .expect("write frame header");

    let error = read_frame_for_test::<serde_json::Value, _>(&mut reader, 10)
        .await
        .expect_err("oversized frame must fail from its header");
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
}

#[tokio::test]
async fn rejects_tampered_bundle_digests_before_guest_dispatch() {
    let mut encoded = serde_json::to_value(create_request()).expect("encode request");
    encoded["bundle"]["configDigest"] =
        serde_json::Value::String(format!("sha256:{}", "0".repeat(64)));
    let request: AgentCreateRequest = serde_json::from_value(encoded).expect("decode request");
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = spawn_server(guest, token(10));
    let client = AgentClient::connect(host, token(10))
        .await
        .expect("connect agent client");

    let error = client
        .create(request)
        .await
        .expect_err("tampered digest must fail locally");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    drop(client);
    server
        .await
        .expect("server task")
        .expect("clean server shutdown");
}

#[tokio::test]
async fn correlation_failure_permanently_poisoned_the_client_connection() {
    let (host, mut guest) = tokio::io::duplex(1024 * 1024);
    let malicious = tokio::spawn(async move {
        let hello: HostHello = read_frame(&mut guest)
            .await?
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "missing hello"))?;
        let capabilities = AgentCapabilities::core("malicious-test", std::env::consts::ARCH)?;
        write_frame(
            &mut guest,
            &HelloOutcome::Accepted {
                hello: AgentHello::new(1, capabilities),
            },
        )
        .await?;
        let request: RequestEnvelope = read_frame(&mut guest)
            .await?
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "missing request"))?;
        let AgentRequest::Create(create) = request.request else {
            return Err(Error::new(ErrorCode::Internal, "expected create"));
        };
        let state = AgentState::new(
            create.target,
            ContainerState::Created,
            Some(101),
            create.bundle.config_digest(),
        )?;
        write_frame(
            &mut guest,
            &ResponseEnvelope {
                version: 1,
                request_id: request.request_id + 1,
                outcome: ResponseOutcome::Succeeded {
                    response: AgentResponse::State(state),
                },
            },
        )
        .await?;
        let _ = hello;
        Ok::<_, Error>(())
    });

    let client = AgentClient::connect(host, token(11))
        .await
        .expect("connect malicious peer");
    let error = client
        .create(create_request())
        .await
        .expect_err("mismatched response ID must fail");
    assert_eq!(error.code, ErrorCode::Conflict);
    let error = client
        .create(create_request())
        .await
        .expect_err("connection must stay poisoned");
    assert_eq!(error.code, ErrorCode::Unavailable);
    malicious
        .await
        .expect("malicious task")
        .expect("malicious response written");
}

#[test]
fn secrets_are_redacted_and_guest_paths_are_normalized() {
    assert_eq!(format!("{:?}", token(12)), "SessionToken([REDACTED])");
    for path in [
        "run/a3s",
        "/run//a3s",
        "/run/../a3s",
        "/run/./a3s",
        "/run/a3s/",
        r"/run\a3s",
    ] {
        assert!(GuestPath::new(path).is_err(), "{path:?} must be rejected");
    }
    assert!(GuestPath::new("/run/a3s").is_ok());
}
