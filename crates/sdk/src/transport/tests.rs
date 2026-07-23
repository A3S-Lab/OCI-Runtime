use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use oci_spec::runtime::{Features, State};
use serde_json::json;

use crate::{
    ContainerId, ContainerRecord, CreateRequest, DeleteRequest, DriverKind, Error, ErrorCode,
    EventsRequest, Generation, IsolationClass, IsolationRequest, KillRequest, OciBundle,
    OciRuntimeService, OperationContext, OperationId, ProcessIo, Result, RuntimeFeatures,
    RuntimeInfo, RuntimeOperation, StartRequest, StateRequest,
};

use super::wire::{read_frame, write_frame, ClientMessage, ServerMessage, WireResult};
use super::{serve_transport_connection, RuntimeTransportClient};

#[derive(Default)]
struct EchoService {
    exact_config: Mutex<Option<String>>,
}

#[async_trait]
impl OciRuntimeService for EchoService {
    async fn features(&self) -> Result<RuntimeInfo> {
        let oci: Features = serde_json::from_value(json!({
            "ociVersionMin": "1.0.0",
            "ociVersionMax": "1.3.0"
        }))
        .map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))?;
        Ok(RuntimeInfo {
            oci,
            drivers: RuntimeFeatures::current(Vec::new()),
            operations: vec![RuntimeOperation::Features, RuntimeOperation::Create],
        })
    }

    async fn create(&self, request: CreateRequest) -> Result<ContainerRecord> {
        *self
            .exact_config
            .lock()
            .map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))? =
            Some(request.bundle.config_json().to_string());
        let state: State = serde_json::from_value(json!({
            "ociVersion": "1.3.0",
            "id": request.id.as_str(),
            "status": "created",
            "bundle": request.bundle.directory()
        }))
        .map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))?;
        Ok(ContainerRecord {
            state,
            generation: Generation(7),
            driver: DriverKind::NativeLinux,
            isolation: IsolationClass::SharedHostKernel,
            config_digest: request.bundle.config_digest().to_string(),
        })
    }

    async fn state(&self, _request: StateRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("state-test"))
    }

    async fn start(&self, _request: StartRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("start-test"))
    }

    async fn kill(&self, _request: KillRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("kill-test"))
    }

    async fn delete(&self, _request: DeleteRequest) -> Result<()> {
        Err(Error::unsupported("delete-test"))
    }
}

#[tokio::test]
async fn negotiates_and_round_trips_typed_requests_responses_and_errors() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let service = Arc::new(EchoService::default());
    let server_service: Arc<dyn OciRuntimeService> = service.clone();
    let server =
        tokio::spawn(async move { serve_transport_connection(server_service, server_io).await });

    let client = RuntimeTransportClient::from_io(client_io)
        .await
        .expect("negotiate in-memory SDK transport");
    assert_eq!(client.protocol_version(), 1);

    let info = client.features().await.expect("transport features");
    assert_eq!(
        info.operations,
        vec![RuntimeOperation::Features, RuntimeOperation::Create]
    );

    let bundle_directory = std::env::current_dir()
        .expect("current directory")
        .join("transport-bundle");
    let exact_config = " {\n \"ociVersion\": \"1.3.0\",\n \"root\": {\"path\": \"rootfs\"}\n}\n";
    let bundle = OciBundle::from_json(bundle_directory, exact_config).expect("build bundle");
    let expected_digest = bundle.config_digest().to_string();
    let record = client
        .create(CreateRequest {
            context: OperationContext::new(
                OperationId::new("transport-create").expect("operation ID"),
            ),
            id: ContainerId::new("transport-container").expect("container ID"),
            bundle,
            isolation: IsolationRequest::SharedHostKernel,
            io: ProcessIo::default(),
        })
        .await
        .expect("transport create");
    assert_eq!(record.generation, Generation(7));
    assert_eq!(record.config_digest, expected_digest);
    assert_eq!(
        service
            .exact_config
            .lock()
            .expect("captured config")
            .as_deref(),
        Some(exact_config)
    );

    let error = client
        .state(StateRequest {
            target: crate::ContainerTarget::current(
                ContainerId::new("transport-container").expect("container ID"),
            ),
        })
        .await
        .expect_err("service error must cross transport");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert_eq!(error.operation.as_deref(), Some("state-test"));

    drop(client);
    server
        .await
        .expect("server task must join")
        .expect("server connection must close cleanly");
}

#[test]
fn transport_client_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RuntimeTransportClient>();
}

#[tokio::test]
async fn client_reports_an_incompatible_server_protocol() {
    let (client_io, mut server_io) = tokio::io::duplex(1024);
    let server = tokio::spawn(async move {
        let hello = read_frame::<ClientMessage>(&mut server_io)
            .await
            .expect("read client hello")
            .expect("client hello frame");
        assert!(matches!(hello, ClientMessage::Hello { .. }));
        write_frame(
            &mut server_io,
            &ServerMessage::Reject {
                protocol_min: 2,
                protocol_max: 3,
                message: "no common protocol".to_string(),
            },
        )
        .await
        .expect("write protocol rejection");
    });

    let error = RuntimeTransportClient::from_io(client_io)
        .await
        .expect_err("incompatible protocol must fail");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert_eq!(error.operation.as_deref(), Some("sdk-handshake"));
    server.await.expect("server task must join");
}

#[tokio::test]
async fn client_rejects_a_mismatched_response_id() {
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let hello = read_frame::<ClientMessage>(&mut server_io)
            .await
            .expect("read client hello")
            .expect("client hello frame");
        assert!(matches!(hello, ClientMessage::Hello { .. }));
        write_frame(&mut server_io, &ServerMessage::Welcome { protocol: 1 })
            .await
            .expect("write server welcome");

        let request = read_frame::<ClientMessage>(&mut server_io)
            .await
            .expect("read request")
            .expect("request frame");
        let request_id = match request {
            ClientMessage::Request { request_id, .. } => request_id,
            ClientMessage::Hello { .. } => panic!("unexpected repeated hello"),
        };
        write_frame(
            &mut server_io,
            &ServerMessage::Response {
                protocol: 1,
                request_id: request_id + 1,
                result: Box::new(WireResult::Error {
                    error: Error::unsupported("test"),
                }),
            },
        )
        .await
        .expect("write mismatched response");
    });

    let client = RuntimeTransportClient::from_io(client_io)
        .await
        .expect("negotiate transport");
    let error = client
        .features()
        .await
        .expect_err("mismatched response ID must fail closed");
    assert_eq!(error.code, ErrorCode::Internal);
    assert!(error.message.contains("correlation mismatch"));

    let closed = client
        .features()
        .await
        .expect_err("protocol failure must poison the connection");
    assert_eq!(closed.code, ErrorCode::Unavailable);
    assert!(closed.retryable);
    server.await.expect("server task must join");
}

#[tokio::test]
async fn server_rejects_the_reserved_zero_request_id() {
    let (mut client_io, server_io) = tokio::io::duplex(4096);
    let service: Arc<dyn OciRuntimeService> = Arc::new(EchoService::default());
    let server = tokio::spawn(async move { serve_transport_connection(service, server_io).await });

    write_frame(
        &mut client_io,
        &ClientMessage::Hello {
            protocol_min: 1,
            protocol_max: 1,
        },
    )
    .await
    .expect("write client hello");
    let welcome = read_frame::<ServerMessage>(&mut client_io)
        .await
        .expect("read welcome")
        .expect("welcome frame");
    assert_eq!(welcome, ServerMessage::Welcome { protocol: 1 });

    write_frame(
        &mut client_io,
        &ClientMessage::Request {
            protocol: 1,
            request_id: 0,
            request: Box::new(super::wire::WireRequest::Features),
        },
    )
    .await
    .expect("write invalid request");
    drop(client_io);

    let error = server
        .await
        .expect("server task must join")
        .expect_err("zero request ID must fail");
    assert_eq!(error.code, ErrorCode::Internal);
    assert!(error.message.contains("zero SDK request ID"));
}

#[tokio::test]
async fn server_validates_untrusted_wire_requests_before_dispatch() {
    let (mut client_io, server_io) = tokio::io::duplex(4096);
    let service: Arc<dyn OciRuntimeService> = Arc::new(EchoService::default());
    let server = tokio::spawn(async move { serve_transport_connection(service, server_io).await });

    write_frame(
        &mut client_io,
        &ClientMessage::Hello {
            protocol_min: 1,
            protocol_max: 1,
        },
    )
    .await
    .expect("write client hello");
    let welcome = read_frame::<ServerMessage>(&mut client_io)
        .await
        .expect("read welcome")
        .expect("welcome frame");
    assert_eq!(welcome, ServerMessage::Welcome { protocol: 1 });

    write_frame(
        &mut client_io,
        &ClientMessage::Request {
            protocol: 1,
            request_id: 1,
            request: Box::new(super::wire::WireRequest::Events(EventsRequest {
                container: None,
                after_sequence: 0,
                limit: 0,
                wait_timeout_ms: None,
            })),
        },
    )
    .await
    .expect("write invalid request");
    let response = read_frame::<ServerMessage>(&mut client_io)
        .await
        .expect("read validation response")
        .expect("validation response frame");
    let ServerMessage::Response { result, .. } = response else {
        panic!("expected SDK response");
    };
    let WireResult::Error { error } = *result else {
        panic!("invalid request must return an error");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(error.operation.as_deref(), Some("validate-sdk-request"));

    drop(client_io);
    server
        .await
        .expect("server task must join")
        .expect("server connection must close cleanly");
}
