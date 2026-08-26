use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use oci_spec::runtime::{Features, State};
use serde_json::json;

use crate::{
    AttachmentCapabilities, ContainerId, ContainerRecord, CreateAttachments, CreateRequest,
    DeleteRequest, DriverKind, Error, ErrorCode, EventsRequest, FileOp, FileRequest, FileResponse,
    FilesystemEntry, FilesystemEntryKind, FilesystemOp, FilesystemRequest, FilesystemResponse,
    Generation, IsolationClass, IsolationRequest, KillRequest, OciBundle, OciRuntimeService,
    OperationContext, OperationId, ProcessIo, Result, RuntimeFeatures, RuntimeInfo,
    RuntimeOperation, StartRequest, StateRequest, StorageAccessMode, StorageAttachmentId,
    StorageCleanup, StorageOwnership,
};

use super::wire::{read_frame, write_frame, ClientMessage, ServerMessage, WireRequest, WireResult};
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
            operations: vec![
                RuntimeOperation::Features,
                RuntimeOperation::Create,
                RuntimeOperation::File,
                RuntimeOperation::Filesystem,
            ],
            attachments: AttachmentCapabilities::base_v1(),
            extensions: Default::default(),
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
            attachments_digest: Some(request.attachments.digest()?),
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

    async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        Ok(FileResponse {
            target: request.target,
            data: (request.op == FileOp::Download).then(String::new),
            size: 0,
        })
    }

    async fn filesystem(&self, request: FilesystemRequest) -> Result<FilesystemResponse> {
        let entries = (request.op == FilesystemOp::ListDir)
            .then(|| FilesystemEntry {
                name: "transport.txt".to_string(),
                kind: FilesystemEntryKind::File,
                path: "/transport.txt".to_string(),
                size: 0,
                mode: 0o644,
                permissions: "-rw-r--r--".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified_seconds: 0,
                modified_nanos: 0,
                symlink_target: None,
                metadata: BTreeMap::new(),
            })
            .into_iter()
            .collect();
        Ok(FilesystemResponse {
            target: request.target,
            entry: None,
            entries,
        })
    }
}

fn storage_create_request() -> CreateRequest {
    let bundle = OciBundle::from_json(
        std::env::current_dir()
            .expect("current directory")
            .join("protocol-five-storage-bundle"),
        serde_json::to_string(&json!({
            "ociVersion": "1.3.0",
            "root": {"path": "rootfs"},
            "process": {
                "cwd": "/",
                "args": ["/bin/true"],
                "user": {"uid": 0, "gid": 0}
            },
            "mounts": [
                {"destination": "/data", "type": "bind", "source": "data", "options": ["ro"]}
            ]
        }))
        .expect("storage configuration"),
    )
    .expect("storage bundle");
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("base attachments")
        .attach_storage_mount(
            &bundle,
            0,
            StorageAttachmentId::new("protocol-storage-1").expect("storage identity"),
            StorageAccessMode::ReadOnly,
            StorageOwnership::Caller,
            StorageCleanup::DetachOnly,
        )
        .expect("storage attachments");
    CreateRequest {
        context: OperationContext::new(
            OperationId::new("protocol-storage-create").expect("operation ID"),
        ),
        id: ContainerId::new("protocol-storage-container").expect("container ID"),
        bundle,
        isolation: IsolationRequest::SharedHostKernel,
        attachments,
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
    assert_eq!(client.protocol_version(), 5);

    let info = client.features().await.expect("transport features");
    assert_eq!(
        info.operations,
        vec![
            RuntimeOperation::Features,
            RuntimeOperation::Create,
            RuntimeOperation::File,
            RuntimeOperation::Filesystem,
        ]
    );

    let bundle_directory = std::env::current_dir()
        .expect("current directory")
        .join("transport-bundle");
    let exact_config = " {\n \"ociVersion\": \"1.3.0\",\n \"root\": {\"path\": \"rootfs\"}\n}\n";
    let bundle = OciBundle::from_json(bundle_directory, exact_config).expect("build bundle");
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("build attachment contract");
    let expected_digest = bundle.config_digest().to_string();
    let record = client
        .create(CreateRequest {
            context: OperationContext::new(
                OperationId::new("transport-create").expect("operation ID"),
            ),
            id: ContainerId::new("transport-container").expect("container ID"),
            bundle,
            isolation: IsolationRequest::SharedHostKernel,
            attachments,
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

    let target = crate::ContainerTarget::exact(
        ContainerId::new(record.state.id()).expect("response container ID"),
        record.generation,
    );
    let upload = client
        .file(FileRequest {
            target: target.clone(),
            op: FileOp::Upload,
            path: "/transport.txt".to_string(),
            data: Some(String::new()),
            user: None,
            context: Some(OperationContext::new(
                OperationId::new("transport-file").expect("operation ID"),
            )),
        })
        .await
        .expect("transport file upload");
    assert_eq!(upload.target, target);
    assert_eq!(upload.size, 0);
    assert!(upload.data.is_none());

    let listed = client
        .filesystem(FilesystemRequest {
            target: target.clone(),
            op: FilesystemOp::ListDir,
            path: "/".to_string(),
            destination: None,
            depth: 1,
            user: None,
            context: None,
        })
        .await
        .expect("transport filesystem listing");
    assert_eq!(listed.target, target);
    assert_eq!(listed.entries.len(), 1);
    assert_eq!(listed.entries[0].path, "/transport.txt");

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

#[tokio::test]
async fn protocol_three_rejects_file_operations_before_dispatch() {
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let hello = read_frame::<ClientMessage>(&mut server_io)
            .await
            .expect("read client hello")
            .expect("client hello frame");
        assert!(matches!(hello, ClientMessage::Hello { .. }));
        write_frame(&mut server_io, &ServerMessage::Welcome { protocol: 3 })
            .await
            .expect("write protocol-three welcome");
        assert!(read_frame::<ClientMessage>(&mut server_io)
            .await
            .expect("read protocol-three connection close")
            .is_none());
    });

    let client = RuntimeTransportClient::from_io(client_io)
        .await
        .expect("negotiate protocol three");
    let error = client
        .file(FileRequest {
            target: crate::ContainerTarget::exact(
                ContainerId::new("legacy-file").expect("container ID"),
                Generation(1),
            ),
            op: FileOp::Download,
            path: "/file".to_string(),
            data: None,
            user: None,
            context: None,
        })
        .await
        .expect_err("protocol three must reject file operations");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("requires protocol 4"));
    drop(client);
    server.await.expect("server task must join");
}

#[tokio::test]
async fn protocol_four_rejects_storage_attachments_before_dispatch() {
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let hello = read_frame::<ClientMessage>(&mut server_io)
            .await
            .expect("read client hello")
            .expect("client hello frame");
        assert!(matches!(hello, ClientMessage::Hello { .. }));
        write_frame(&mut server_io, &ServerMessage::Welcome { protocol: 4 })
            .await
            .expect("write protocol-four welcome");
        assert!(read_frame::<ClientMessage>(&mut server_io)
            .await
            .expect("read protocol-four connection close")
            .is_none());
    });

    let client = RuntimeTransportClient::from_io(client_io)
        .await
        .expect("negotiate protocol four");
    let error = client
        .create(storage_create_request())
        .await
        .expect_err("protocol four must reject storage attachments");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("requires protocol 5"));
    drop(client);
    server.await.expect("server task must join");
}

#[tokio::test]
async fn server_rejects_protocol_four_storage_before_service_dispatch() {
    let (mut client_io, server_io) = tokio::io::duplex(16 * 1024);
    let service = Arc::new(EchoService::default());
    let server_service: Arc<dyn OciRuntimeService> = service.clone();
    let server =
        tokio::spawn(async move { serve_transport_connection(server_service, server_io).await });

    write_frame(
        &mut client_io,
        &ClientMessage::Hello {
            protocol_min: 4,
            protocol_max: 4,
        },
    )
    .await
    .expect("write protocol-four hello");
    assert_eq!(
        read_frame::<ServerMessage>(&mut client_io)
            .await
            .expect("read welcome")
            .expect("welcome frame"),
        ServerMessage::Welcome { protocol: 4 }
    );
    write_frame(
        &mut client_io,
        &ClientMessage::Request {
            protocol: 4,
            request_id: 7,
            request: Box::new(WireRequest::Create(storage_create_request())),
        },
    )
    .await
    .expect("write storage request");
    let response = read_frame::<ServerMessage>(&mut client_io)
        .await
        .expect("read storage rejection")
        .expect("storage rejection frame");
    let ServerMessage::Response { result, .. } = response else {
        panic!("expected SDK response");
    };
    let WireResult::Error { error } = *result else {
        panic!("protocol-four storage must fail");
    };
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("requires protocol 5"));
    assert!(service
        .exact_config
        .lock()
        .expect("captured configuration lock")
        .is_none());

    drop(client_io);
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
                protocol_min: 4,
                protocol_max: 5,
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
        write_frame(&mut server_io, &ServerMessage::Welcome { protocol: 3 })
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
                protocol: 3,
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
            protocol_min: 3,
            protocol_max: 3,
        },
    )
    .await
    .expect("write client hello");
    let welcome = read_frame::<ServerMessage>(&mut client_io)
        .await
        .expect("read welcome")
        .expect("welcome frame");
    assert_eq!(welcome, ServerMessage::Welcome { protocol: 3 });

    write_frame(
        &mut client_io,
        &ClientMessage::Request {
            protocol: 3,
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

#[test]
fn state_wire_request_requires_container_id() {
    let mut encoded = serde_json::to_value(ClientMessage::Request {
        protocol: 3,
        request_id: 1,
        request: Box::new(WireRequest::State(StateRequest {
            target: crate::ContainerTarget::current(
                ContainerId::new("state-wire-container").expect("container ID"),
            ),
        })),
    })
    .expect("encode valid state request");
    let target = encoded
        .get_mut("request")
        .and_then(|request| request.get_mut("request"))
        .and_then(|request| request.get_mut("target"))
        .and_then(serde_json::Value::as_object_mut)
        .expect("state target object");
    assert!(target.remove("id").is_some());

    let error = serde_json::from_value::<ClientMessage>(encoded)
        .expect_err("state request without a container ID must fail decoding");
    assert!(error.to_string().contains("id"));
}

#[test]
fn create_wire_request_requires_bundle_and_container_id() {
    let bundle = OciBundle::from_json(
        std::env::current_dir()
            .expect("current directory")
            .join("required-create-wire-bundle"),
        "{\"ociVersion\":\"1.3.0\",\"root\":{\"path\":\"rootfs\"}}",
    )
    .expect("valid bundle");
    let attachments =
        CreateAttachments::from_bundle(&bundle, ProcessIo::default()).expect("attachment contract");
    let encoded = serde_json::to_value(ClientMessage::Request {
        protocol: 3,
        request_id: 1,
        request: Box::new(WireRequest::Create(CreateRequest {
            context: OperationContext::new(
                OperationId::new("required-create-wire").expect("operation ID"),
            ),
            id: ContainerId::new("required-create-wire-container").expect("container ID"),
            bundle,
            isolation: IsolationRequest::SharedHostKernel,
            attachments,
        })),
    })
    .expect("encode valid create request");

    for required_field in ["id", "bundle"] {
        let mut missing = encoded.clone();
        let request = missing
            .get_mut("request")
            .and_then(|request| request.get_mut("request"))
            .and_then(serde_json::Value::as_object_mut)
            .expect("create request object");
        assert!(request.remove(required_field).is_some());

        let error = serde_json::from_value::<ClientMessage>(missing)
            .expect_err("create request without a required argument must fail decoding");
        assert!(error.to_string().contains(required_field));
    }
}

#[test]
fn lifecycle_wire_requests_require_container_id() {
    let target = crate::ContainerTarget::current(
        ContainerId::new("lifecycle-wire-container").expect("container ID"),
    );
    let requests = [
        (
            "start",
            WireRequest::Start(StartRequest {
                context: OperationContext::new(
                    OperationId::new("required-start-wire").expect("operation ID"),
                ),
                target: target.clone(),
            }),
        ),
        (
            "kill",
            WireRequest::Kill(KillRequest {
                context: OperationContext::new(
                    OperationId::new("required-kill-wire").expect("operation ID"),
                ),
                target: target.clone(),
                signal: crate::Signal::new(9).expect("signal"),
                all: false,
            }),
        ),
        (
            "delete",
            WireRequest::Delete(DeleteRequest {
                context: OperationContext::new(
                    OperationId::new("required-delete-wire").expect("operation ID"),
                ),
                target,
                mode: crate::DeleteMode::StoppedOnly,
            }),
        ),
    ];

    for (operation, request) in requests {
        let mut encoded = serde_json::to_value(ClientMessage::Request {
            protocol: 3,
            request_id: 1,
            request: Box::new(request),
        })
        .expect("encode valid lifecycle request");
        let target = encoded
            .get_mut("request")
            .and_then(|request| request.get_mut("request"))
            .and_then(|request| request.get_mut("target"))
            .and_then(serde_json::Value::as_object_mut)
            .expect("lifecycle target object");
        assert!(target.remove("id").is_some());

        let error = serde_json::from_value::<ClientMessage>(encoded)
            .expect_err("lifecycle request without a container ID must fail decoding");
        assert!(
            error.to_string().contains("id"),
            "{operation} returned an unrelated decode error: {error}"
        );
    }
}

#[tokio::test]
async fn server_validates_untrusted_wire_requests_before_dispatch() {
    let (mut client_io, server_io) = tokio::io::duplex(4096);
    let service: Arc<dyn OciRuntimeService> = Arc::new(EchoService::default());
    let server = tokio::spawn(async move { serve_transport_connection(service, server_io).await });

    write_frame(
        &mut client_io,
        &ClientMessage::Hello {
            protocol_min: 3,
            protocol_max: 3,
        },
    )
    .await
    .expect("write client hello");
    let welcome = read_frame::<ServerMessage>(&mut client_io)
        .await
        .expect("read welcome")
        .expect("welcome frame");
    assert_eq!(welcome, ServerMessage::Welcome { protocol: 3 });

    write_frame(
        &mut client_io,
        &ClientMessage::Request {
            protocol: 3,
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
