use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use oci_spec::runtime::{ContainerState, Features, State, StateBuilder};
use serde_json::json;
use tokio::sync::oneshot;

use crate::{
    AttachmentCapabilities, CheckpointArtifactPath, CheckpointCompatibility, CheckpointDigest,
    CheckpointFormat, CheckpointReference, CheckpointRequest, CheckpointResponse, ContainerId,
    ContainerRecord, ContainerTarget, CreateAttachments, CreateRequest, DeleteRequest, DriverKind,
    Error, ErrorCode, EventBatch, EventsRequest, FileOp, FileRequest, FileResponse,
    FilesystemEntry, FilesystemEntryKind, FilesystemOp, FilesystemRequest, FilesystemResponse,
    Generation, GuestSessionCapacity, GuestSessionGeneration, GuestSessionId, GuestSessionReset,
    HostPlatform, IsolationClass, IsolationRequest, KillRequest, NetworkAttachmentIdentity,
    NetworkCleanup, NetworkCleanupId, NetworkEnforcementAttachment, NetworkEnforcementId,
    NetworkInterfaceId, NetworkMechanismDigest, NetworkMechanismGeneration, NetworkNamespaceId,
    OciBundle, OciRuntimeService, OperationContext, OperationId, ProcessIo, RestoreRequest, Result,
    RuntimeArtifact, RuntimeEvent, RuntimeEventKind, RuntimeFeatures, RuntimeInfo,
    RuntimeOperation, StartRequest, StateRequest, StorageAccessMode, StorageAttachmentId,
    StorageCleanup, StorageOwnership, TeeAttestationRequest, TeeAttestationResponse, TeeEvidence,
    TeeLaunchRequest, TeeMeasurement, TeeMode, TeeReportData, TeeSha256Digest, TeeTechnology,
    TrustDomainId, AMD_SEV_SNP_LAUNCH_EXTENSION, NETWORK_ENFORCEMENT_EXTENSION,
    PAUSED_STATE_ANNOTATION,
};

use super::wire::{
    read_frame, write_frame, ClientMessage, ServerMessage, WireRequest, WireResponse, WireResult,
};
use super::{serve_transport_connection, RuntimeTransportClient};

#[derive(Default)]
struct EchoService {
    exact_config: Mutex<Option<String>>,
    checkpoint_response: Mutex<Option<CheckpointResponse>>,
    checkpoint_calls: AtomicUsize,
    attestation_response: Mutex<Option<TeeAttestationResponse>>,
    attestation_calls: AtomicUsize,
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
            isolation: request.isolation.class(),
            guest_session: request.attachments.guest_session().cloned(),
            network_enforcement: request.attachments.network_enforcement(&request.bundle)?,
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

    async fn checkpoint(&self, _request: CheckpointRequest) -> Result<CheckpointResponse> {
        self.checkpoint_calls.fetch_add(1, Ordering::Relaxed);
        self.checkpoint_response
            .lock()
            .map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))?
            .take()
            .ok_or_else(|| Error::unsupported("checkpoint-test"))
    }

    async fn attest(&self, _request: TeeAttestationRequest) -> Result<TeeAttestationResponse> {
        self.attestation_calls.fetch_add(1, Ordering::Relaxed);
        self.attestation_response
            .lock()
            .map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))?
            .take()
            .ok_or_else(|| Error::unsupported("attestation-test"))
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

fn network_create_request() -> CreateRequest {
    let bundle = OciBundle::from_json(
        std::env::current_dir()
            .expect("current directory")
            .join("protocol-six-network-bundle"),
        serde_json::to_string(&json!({
            "ociVersion": "1.3.0",
            "root": {"path": "rootfs"},
            "process": {
                "cwd": "/",
                "args": ["/bin/true"],
                "user": {"uid": 0, "gid": 0}
            },
            "linux": {
                "namespaces": [{"type": "network"}],
                "netDevices": {"tap0": {"name": "eth0"}}
            }
        }))
        .expect("network configuration"),
    )
    .expect("network bundle");
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("base attachments")
        .attach_linux_network_interface(
            &bundle,
            0,
            "tap0",
            NetworkAttachmentIdentity::new(
                NetworkNamespaceId::new("protocol-network-namespace-1")
                    .expect("namespace identity"),
                NetworkInterfaceId::new("protocol-network-interface-1")
                    .expect("interface identity"),
                NetworkCleanupId::new("protocol-network-cleanup-1").expect("cleanup identity"),
            ),
            NetworkCleanup::ReleaseRuntimeNamespace,
        )
        .expect("network attachments");
    CreateRequest {
        context: OperationContext::new(
            OperationId::new("protocol-network-create").expect("operation ID"),
        ),
        id: ContainerId::new("protocol-network-container").expect("container ID"),
        bundle,
        isolation: IsolationRequest::SharedHostKernel,
        attachments,
    }
}

fn network_enforcement_create_request() -> CreateRequest {
    let namespace =
        NetworkNamespaceId::new("protocol-enforcement-namespace-1").expect("namespace identity");
    let enforcement = NetworkEnforcementAttachment::new(
        NetworkEnforcementId::new("protocol-enforcement-1").expect("enforcement identity"),
        NetworkMechanismGeneration::new(1).expect("enforcement generation"),
        NetworkMechanismDigest::new(format!("sha256:{}", "a".repeat(64)))
            .expect("compiled-policy digest"),
        namespace.clone(),
        None,
    );
    let mut configuration = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"},
        "process": {
            "cwd": "/",
            "args": ["/bin/true"],
            "user": {"uid": 0, "gid": 0}
        },
        "linux": {
            "namespaces": [{
                "type": "network",
                "path": "/run/a3s/network/protocol-enforcement-namespace-1"
            }],
            "netDevices": {"tap0": {"name": "eth0"}}
        },
        "annotations": {}
    });
    configuration["annotations"][NETWORK_ENFORCEMENT_EXTENSION] = json!(enforcement
        .to_annotation_value()
        .expect("network-enforcement annotation"));
    let bundle = OciBundle::from_json(
        std::env::current_dir()
            .expect("current directory")
            .join("protocol-six-network-enforcement-bundle"),
        serde_json::to_string(&configuration).expect("network-enforcement configuration"),
    )
    .expect("network-enforcement bundle");
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("base attachments")
        .attach_linux_network_interface(
            &bundle,
            0,
            "tap0",
            NetworkAttachmentIdentity::new(
                namespace,
                NetworkInterfaceId::new("protocol-enforcement-interface-1")
                    .expect("interface identity"),
                NetworkCleanupId::new("protocol-enforcement-cleanup-1").expect("cleanup identity"),
            ),
            NetworkCleanup::PreserveCallerNamespace,
        )
        .expect("joined network attachment")
        .attach_network_enforcement(&bundle)
        .expect("network-enforcement attachment");
    CreateRequest {
        context: OperationContext::new(
            OperationId::new("protocol-network-enforcement-create").expect("operation ID"),
        ),
        id: ContainerId::new("protocol-network-enforcement-container").expect("container ID"),
        bundle,
        isolation: IsolationRequest::SharedHostKernel,
        attachments,
    }
}

fn guest_session_create_request() -> CreateRequest {
    let bundle = OciBundle::from_json(
        std::env::current_dir()
            .expect("current directory")
            .join("protocol-seven-guest-session-bundle"),
        serde_json::to_string(&json!({
            "ociVersion": "1.3.0",
            "root": {"path": "rootfs"},
            "process": {
                "cwd": "/",
                "args": ["/bin/true"],
                "user": {"uid": 0, "gid": 0}
            }
        }))
        .expect("guest-session configuration"),
    )
    .expect("guest-session bundle");
    let trust_domain =
        TrustDomainId::new("protocol-guest-trust-domain").expect("guest-session trust domain");
    let isolation = IsolationRequest::SharedGuestKernel {
        trust_domain: trust_domain.clone(),
    };
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("base attachments")
        .attach_reusable_guest_session(
            &bundle,
            &isolation,
            GuestSessionId::new("protocol-guest-session").expect("guest-session ID"),
            GuestSessionGeneration::new(1).expect("guest-session generation"),
            GuestSessionCapacity::new(4).expect("guest-session capacity"),
            GuestSessionReset::DestroyOnEmpty,
        )
        .expect("guest-session attachments");
    CreateRequest {
        context: OperationContext::new(
            OperationId::new("protocol-guest-session-create").expect("operation ID"),
        ),
        id: ContainerId::new("protocol-guest-session-container").expect("container ID"),
        bundle,
        isolation,
        attachments,
    }
}

fn tee_create_request() -> CreateRequest {
    let launch = TeeLaunchRequest::new(TeeTechnology::AmdSevSnp, TeeMode::Simulated);
    let mut configuration = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"},
        "process": {
            "cwd": "/",
            "args": ["/bin/true"],
            "user": {"uid": 0, "gid": 0}
        },
        "annotations": {}
    });
    configuration["annotations"][AMD_SEV_SNP_LAUNCH_EXTENSION] =
        json!(launch.to_annotation_value().expect("TEE launch annotation"));
    let bundle = OciBundle::from_json(
        std::env::current_dir()
            .expect("current directory")
            .join("protocol-nine-tee-bundle"),
        serde_json::to_string(&configuration).expect("TEE configuration"),
    )
    .expect("TEE bundle");
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("base attachments")
        .attach_tee_launch(&bundle)
        .expect("TEE attachments");
    CreateRequest {
        context: OperationContext::new(
            OperationId::new("protocol-nine-tee-create").expect("operation ID"),
        ),
        id: ContainerId::new("protocol-nine-tee-container").expect("container ID"),
        bundle,
        isolation: IsolationRequest::DedicatedVm,
        attachments,
    }
}

fn attestation_fixture() -> (TeeAttestationRequest, TeeAttestationResponse) {
    let target = ContainerTarget::exact(
        ContainerId::new("protocol-nine-tee-container").expect("container ID"),
        Generation(7),
    );
    let report_data = TeeReportData::new([0x5a; crate::TEE_REPORT_DATA_BYTES]);
    let request = TeeAttestationRequest::new(
        OperationContext::new(OperationId::new("protocol-nine-attest").expect("operation ID")),
        target.clone(),
        report_data,
    )
    .expect("attestation request");
    let response = TeeAttestationResponse::new(
        target,
        TeeLaunchRequest::new(TeeTechnology::AmdSevSnp, TeeMode::Simulated),
        report_data,
        TeeSha256Digest::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
        TeeSha256Digest::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
        DriverKind::LibkrunKvm,
        RuntimeArtifact::new(
            "a3s-oci-runtime",
            "0.3.1",
            format!("sha256:{}", "3".repeat(64)),
            None,
        )
        .unwrap(),
        TeeSha256Digest::new(format!("sha256:{}", "4".repeat(64))).unwrap(),
        TeeMeasurement::new(format!("sha384:{}", "5".repeat(96))).unwrap(),
        TeeEvidence::new("application/vnd.amd.sev-snp.report", vec![6, 7]).unwrap(),
    )
    .expect("attestation response");
    (request, response)
}

fn checkpoint_source(create: &CreateRequest) -> ContainerRecord {
    let state = StateBuilder::default()
        .version("1.3.0")
        .id(create.id.as_str())
        .status(ContainerState::Running)
        .pid(4_242)
        .bundle(create.bundle.directory().to_path_buf())
        .annotations(HashMap::from([(
            PAUSED_STATE_ANNOTATION.to_string(),
            "true".to_string(),
        )]))
        .build()
        .expect("paused checkpoint source state");
    ContainerRecord {
        state,
        generation: Generation(7),
        driver: match create.isolation.class() {
            IsolationClass::SharedHostKernel => DriverKind::NativeLinux,
            IsolationClass::DedicatedVm | IsolationClass::SharedGuestKernel => {
                DriverKind::LibkrunKvm
            }
        },
        isolation: create.isolation.class(),
        guest_session: create.attachments.guest_session().cloned(),
        network_enforcement: create
            .attachments
            .network_enforcement(&create.bundle)
            .expect("network-enforcement attachment"),
        config_digest: create.bundle.config_digest().to_string(),
        attachments_digest: Some(
            create
                .attachments
                .digest()
                .expect("checkpoint attachment digest"),
        ),
    }
}

fn checkpoint_reference(create: &CreateRequest) -> (ContainerRecord, CheckpointReference) {
    let source = checkpoint_source(create);
    let compatibility = CheckpointCompatibility::new(
        source.driver,
        source.isolation,
        HostPlatform::Linux,
        "x86_64",
        RuntimeArtifact::new(
            "a3s-oci-runtime",
            "0.3.1",
            format!("sha256:{}", "a".repeat(64)),
            Some("sdk-transport-test".to_string()),
        )
        .expect("runtime artifact"),
        CheckpointDigest::new(format!("sha256:{}", "b".repeat(64))).expect("driver build digest"),
        CheckpointFormat::new("transport-test", 1).expect("checkpoint format"),
    )
    .expect("checkpoint compatibility");
    let reference = CheckpointReference::new(
        &source,
        compatibility,
        CheckpointDigest::new(format!("sha256:{}", "c".repeat(64))).expect("artifact digest"),
        4_096,
    )
    .expect("checkpoint reference");
    (source, reference)
}

fn checkpoint_fixture(
    create: &CreateRequest,
    operation: &str,
) -> (CheckpointRequest, CheckpointResponse) {
    let (source, reference) = checkpoint_reference(create);
    let request = CheckpointRequest::new(
        OperationContext::new(OperationId::new(operation).expect("checkpoint operation ID")),
        ContainerTarget::exact(create.id.clone(), source.generation),
        CheckpointArtifactPath::new(
            std::env::current_dir()
                .expect("current directory")
                .join(format!("{operation}.checkpoint")),
        )
        .expect("checkpoint artifact path"),
    )
    .expect("checkpoint request");
    let response = CheckpointResponse::new(source, reference).expect("checkpoint response");
    (request, response)
}

fn restore_request(create: CreateRequest, operation: &str) -> RestoreRequest {
    let (_, reference) = checkpoint_reference(&create);
    RestoreRequest::new(
        OperationContext::new(OperationId::new(operation).expect("restore operation ID")),
        create.id,
        create.bundle,
        CheckpointArtifactPath::new(
            std::env::current_dir()
                .expect("current directory")
                .join(format!("{operation}.checkpoint")),
        )
        .expect("restore artifact path"),
        create.isolation,
        create.attachments,
        reference,
    )
    .expect("restore request")
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
    assert_eq!(client.protocol_version(), 9);

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
            request: Box::new(WireRequest::Create(Box::new(storage_create_request()))),
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

#[tokio::test]
async fn protocol_five_rejects_network_attachments_before_dispatch() {
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let hello = read_frame::<ClientMessage>(&mut server_io)
            .await
            .expect("read client hello")
            .expect("client hello frame");
        assert!(matches!(hello, ClientMessage::Hello { .. }));
        write_frame(&mut server_io, &ServerMessage::Welcome { protocol: 5 })
            .await
            .expect("write protocol-five welcome");
        assert!(read_frame::<ClientMessage>(&mut server_io)
            .await
            .expect("read protocol-five connection close")
            .is_none());
    });

    let client = RuntimeTransportClient::from_io(client_io)
        .await
        .expect("negotiate protocol five");
    let error = client
        .create(network_create_request())
        .await
        .expect_err("protocol five must reject network attachments");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("requires protocol 6"));
    drop(client);
    server.await.expect("server task must join");
}

#[test]
fn protocol_six_gates_network_create_while_restore_requires_protocol_eight() {
    let create = network_create_request();
    assert_eq!(
        WireRequest::Create(Box::new(create.clone())).minimum_protocol(),
        6
    );
    let restore = restore_request(create, "protocol-eight-network-restore");
    assert_eq!(
        WireRequest::Restore(Box::new(restore)).minimum_protocol(),
        8
    );
}

#[tokio::test]
async fn protocol_six_round_trips_network_enforcement_without_a_wire_bump() {
    let create = network_enforcement_create_request();
    let expected = create
        .attachments
        .network_enforcement(&create.bundle)
        .expect("decode network-enforcement attachment")
        .expect("network-enforcement attachment");
    assert_eq!(
        WireRequest::Create(Box::new(create.clone())).minimum_protocol(),
        6
    );

    let (mut client_io, server_io) = tokio::io::duplex(32 * 1024);
    let service = Arc::new(EchoService::default());
    let server_service: Arc<dyn OciRuntimeService> = service;
    let server =
        tokio::spawn(async move { serve_transport_connection(server_service, server_io).await });

    write_frame(
        &mut client_io,
        &ClientMessage::Hello {
            protocol_min: 6,
            protocol_max: 6,
        },
    )
    .await
    .expect("write protocol-six hello");
    assert_eq!(
        read_frame::<ServerMessage>(&mut client_io)
            .await
            .expect("read protocol-six welcome")
            .expect("protocol-six welcome frame"),
        ServerMessage::Welcome { protocol: 6 }
    );
    write_frame(
        &mut client_io,
        &ClientMessage::Request {
            protocol: 6,
            request_id: 61,
            request: Box::new(WireRequest::Create(Box::new(create))),
        },
    )
    .await
    .expect("write protocol-six network-enforcement create");
    let response = read_frame::<ServerMessage>(&mut client_io)
        .await
        .expect("read network-enforcement response")
        .expect("network-enforcement response frame");
    let ServerMessage::Response { result, .. } = response else {
        panic!("expected SDK response");
    };
    let WireResult::Ok { response } = *result else {
        panic!("protocol-six network enforcement must succeed");
    };
    let WireResponse::Create(record) = *response else {
        panic!("expected create response");
    };
    assert_eq!(record.network_enforcement.as_ref(), Some(&expected));

    drop(client_io);
    server
        .await
        .expect("server task must join")
        .expect("server connection must close cleanly");
}

#[tokio::test]
async fn protocol_six_rejects_guest_session_attachments_before_dispatch() {
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let hello = read_frame::<ClientMessage>(&mut server_io)
            .await
            .expect("read client hello")
            .expect("client hello frame");
        assert!(matches!(hello, ClientMessage::Hello { .. }));
        write_frame(&mut server_io, &ServerMessage::Welcome { protocol: 6 })
            .await
            .expect("write protocol-six welcome");
        assert!(read_frame::<ClientMessage>(&mut server_io)
            .await
            .expect("read protocol-six connection close")
            .is_none());
    });

    let client = RuntimeTransportClient::from_io(client_io)
        .await
        .expect("negotiate protocol six");
    let error = client
        .create(guest_session_create_request())
        .await
        .expect_err("protocol six must reject guest-session attachments");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("requires protocol 7"));
    drop(client);
    server.await.expect("server task must join");
}

#[test]
fn protocol_seven_gates_guest_session_create_while_restore_requires_protocol_eight() {
    let create = guest_session_create_request();
    assert_eq!(
        WireRequest::Create(Box::new(create.clone())).minimum_protocol(),
        7
    );
    let restore = restore_request(create, "protocol-eight-guest-restore");
    assert_eq!(
        WireRequest::Restore(Box::new(restore)).minimum_protocol(),
        8
    );
}

#[tokio::test]
async fn protocol_eight_round_trips_checkpoint_reference_and_paused_source() {
    let create = network_create_request();
    let (request, expected) = checkpoint_fixture(&create, "protocol-eight-checkpoint");
    let service = Arc::new(EchoService::default());
    *service
        .checkpoint_response
        .lock()
        .expect("checkpoint response lock") = Some(expected.clone());
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_service: Arc<dyn OciRuntimeService> = service.clone();
    let server =
        tokio::spawn(async move { serve_transport_connection(server_service, server_io).await });

    let client = RuntimeTransportClient::from_io(client_io)
        .await
        .expect("negotiate protocol eight");
    assert_eq!(client.protocol_version(), 9);
    let response = client
        .checkpoint(request)
        .await
        .expect("checkpoint protocol round trip");
    assert_eq!(response, expected);
    assert_eq!(service.checkpoint_calls.load(Ordering::Relaxed), 1);

    drop(client);
    server
        .await
        .expect("server task must join")
        .expect("server connection must close cleanly");
}

#[test]
fn protocol_nine_gates_tee_create_restore_and_attestation() {
    let create = tee_create_request();
    assert_eq!(
        WireRequest::Create(Box::new(create.clone())).minimum_protocol(),
        9
    );
    assert_eq!(
        WireRequest::Restore(Box::new(restore_request(
            create,
            "protocol-nine-tee-restore"
        )))
        .minimum_protocol(),
        9
    );
    let (request, _) = attestation_fixture();
    assert_eq!(WireRequest::Attest(request).minimum_protocol(), 9);
}

#[tokio::test]
async fn protocol_eight_rejects_attestation_before_dispatch() {
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let hello = read_frame::<ClientMessage>(&mut server_io)
            .await
            .expect("read client hello")
            .expect("client hello frame");
        assert!(matches!(hello, ClientMessage::Hello { .. }));
        write_frame(&mut server_io, &ServerMessage::Welcome { protocol: 8 })
            .await
            .expect("write protocol-eight welcome");
        assert!(read_frame::<ClientMessage>(&mut server_io)
            .await
            .expect("read protocol-eight connection close")
            .is_none());
    });
    let client = RuntimeTransportClient::from_io(client_io)
        .await
        .expect("negotiate protocol eight");
    let (request, _) = attestation_fixture();
    let error = client
        .attest(request)
        .await
        .expect_err("protocol eight must reject attestation");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("requires protocol 9"));
    drop(client);
    server.await.expect("server task must join");
}

#[tokio::test]
async fn protocol_nine_round_trips_exact_attestation_evidence() {
    let (request, expected) = attestation_fixture();
    let service = Arc::new(EchoService::default());
    *service
        .attestation_response
        .lock()
        .expect("attestation response lock") = Some(expected.clone());
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_service: Arc<dyn OciRuntimeService> = service.clone();
    let server =
        tokio::spawn(async move { serve_transport_connection(server_service, server_io).await });
    let client = RuntimeTransportClient::from_io(client_io)
        .await
        .expect("negotiate protocol nine");
    assert_eq!(client.protocol_version(), 9);
    assert_eq!(
        client
            .attest(request)
            .await
            .expect("attestation round trip"),
        expected
    );
    assert_eq!(service.attestation_calls.load(Ordering::Relaxed), 1);
    drop(client);
    server
        .await
        .expect("server task must join")
        .expect("server connection must close cleanly");
}

#[tokio::test]
async fn server_rejects_protocol_seven_checkpoint_before_service_dispatch() {
    let create = network_create_request();
    let (request, response) = checkpoint_fixture(&create, "protocol-seven-checkpoint");
    let service = Arc::new(EchoService::default());
    *service
        .checkpoint_response
        .lock()
        .expect("checkpoint response lock") = Some(response);
    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_service: Arc<dyn OciRuntimeService> = service.clone();
    let server =
        tokio::spawn(async move { serve_transport_connection(server_service, server_io).await });

    write_frame(
        &mut client_io,
        &ClientMessage::Hello {
            protocol_min: 7,
            protocol_max: 7,
        },
    )
    .await
    .expect("write protocol-seven hello");
    assert_eq!(
        read_frame::<ServerMessage>(&mut client_io)
            .await
            .expect("read protocol-seven welcome")
            .expect("protocol-seven welcome frame"),
        ServerMessage::Welcome { protocol: 7 }
    );
    write_frame(
        &mut client_io,
        &ClientMessage::Request {
            protocol: 7,
            request_id: 78,
            request: Box::new(WireRequest::Checkpoint(request)),
        },
    )
    .await
    .expect("write protocol-seven checkpoint");
    let response = read_frame::<ServerMessage>(&mut client_io)
        .await
        .expect("read checkpoint rejection")
        .expect("checkpoint rejection frame");
    let ServerMessage::Response { result, .. } = response else {
        panic!("expected SDK response");
    };
    let WireResult::Error { error } = *result else {
        panic!("protocol-seven checkpoint must fail");
    };
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("requires protocol 8"));
    assert_eq!(service.checkpoint_calls.load(Ordering::Relaxed), 0);

    drop(client_io);
    server
        .await
        .expect("server task must join")
        .expect("server connection must close cleanly");
}

#[tokio::test]
async fn server_rejects_protocol_six_guest_session_before_service_dispatch() {
    let (mut client_io, server_io) = tokio::io::duplex(16 * 1024);
    let service = Arc::new(EchoService::default());
    let server_service: Arc<dyn OciRuntimeService> = service.clone();
    let server =
        tokio::spawn(async move { serve_transport_connection(server_service, server_io).await });

    write_frame(
        &mut client_io,
        &ClientMessage::Hello {
            protocol_min: 6,
            protocol_max: 6,
        },
    )
    .await
    .expect("write protocol-six hello");
    assert_eq!(
        read_frame::<ServerMessage>(&mut client_io)
            .await
            .expect("read welcome")
            .expect("welcome frame"),
        ServerMessage::Welcome { protocol: 6 }
    );
    write_frame(
        &mut client_io,
        &ClientMessage::Request {
            protocol: 6,
            request_id: 9,
            request: Box::new(WireRequest::Create(
                Box::new(guest_session_create_request()),
            )),
        },
    )
    .await
    .expect("write guest-session request");
    let response = read_frame::<ServerMessage>(&mut client_io)
        .await
        .expect("read guest-session rejection")
        .expect("guest-session rejection frame");
    let ServerMessage::Response { result, .. } = response else {
        panic!("expected SDK response");
    };
    let WireResult::Error { error } = *result else {
        panic!("protocol-six guest session must fail");
    };
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("requires protocol 7"));
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

#[tokio::test]
async fn server_rejects_protocol_five_network_before_service_dispatch() {
    let (mut client_io, server_io) = tokio::io::duplex(16 * 1024);
    let service = Arc::new(EchoService::default());
    let server_service: Arc<dyn OciRuntimeService> = service.clone();
    let server =
        tokio::spawn(async move { serve_transport_connection(server_service, server_io).await });

    write_frame(
        &mut client_io,
        &ClientMessage::Hello {
            protocol_min: 5,
            protocol_max: 5,
        },
    )
    .await
    .expect("write protocol-five hello");
    assert_eq!(
        read_frame::<ServerMessage>(&mut client_io)
            .await
            .expect("read welcome")
            .expect("welcome frame"),
        ServerMessage::Welcome { protocol: 5 }
    );
    write_frame(
        &mut client_io,
        &ClientMessage::Request {
            protocol: 5,
            request_id: 8,
            request: Box::new(WireRequest::Create(Box::new(network_create_request()))),
        },
    )
    .await
    .expect("write network request");
    let response = read_frame::<ServerMessage>(&mut client_io)
        .await
        .expect("read network rejection")
        .expect("network rejection frame");
    let ServerMessage::Response { result, .. } = response else {
        panic!("expected SDK response");
    };
    let WireResult::Error { error } = *result else {
        panic!("protocol-five network must fail");
    };
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("requires protocol 6"));
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
async fn cancelled_request_discards_the_sdk_transport() {
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let (request_seen_tx, request_seen_rx) = oneshot::channel();
    let (observation_tx, observation_rx) = oneshot::channel();
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
            .expect("read in-flight request")
            .expect("in-flight request frame");
        assert!(matches!(request, ClientMessage::Request { .. }));
        request_seen_tx
            .send(())
            .expect("the client must observe that the request was written");

        let observation = read_frame::<ClientMessage>(&mut server_io)
            .await
            .expect("observe the cancelled client transport");
        observation_tx
            .send(observation)
            .expect("the test must receive the disconnect observation");
    });

    let client = RuntimeTransportClient::from_io(client_io)
        .await
        .expect("negotiate SDK transport");
    let in_flight = tokio::spawn({
        let client = client.clone();
        async move { client.features().await }
    });
    request_seen_rx
        .await
        .expect("the server must observe the request before cancellation");
    in_flight.abort();
    assert!(in_flight
        .await
        .expect_err("cancelled request must be aborted")
        .is_cancelled());

    let error = client
        .features()
        .await
        .expect_err("a from-io client must fail closed after cancellation");
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert!(error.retryable);

    let observation = observation_rx
        .await
        .expect("the server must observe the dropped stream");
    assert!(
        observation.is_none(),
        "cancelled client sent a second request"
    );
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
fn runtime_event_operation_identity_round_trips_on_existing_protocol() {
    let operation_id = OperationId::new("transport-pause-operation").expect("operation ID");
    let event = RuntimeEvent {
        sequence: 17,
        timestamp_unix_ns: 23,
        container: crate::ContainerTarget::exact(
            ContainerId::new("transport-event-container").expect("container ID"),
            Generation(5),
        ),
        operation_id: Some(operation_id.clone()),
        process_id: None,
        kind: RuntimeEventKind::ContainerPaused,
        attributes: BTreeMap::from([(
            "operation-id".to_string(),
            operation_id.as_str().to_string(),
        )]),
    };
    let message = ServerMessage::Response {
        protocol: 3,
        request_id: 11,
        result: Box::new(WireResult::Ok {
            response: Box::new(WireResponse::Events(EventBatch {
                events: vec![event.clone()],
                next_sequence: event.sequence,
            })),
        }),
    };

    let encoded = serde_json::to_value(&message).expect("encode event response");
    let decoded = serde_json::from_value::<ServerMessage>(encoded).expect("decode event response");
    assert_eq!(decoded, message);

    let ServerMessage::Response {
        protocol, result, ..
    } = decoded
    else {
        panic!("expected SDK response");
    };
    assert_eq!(protocol, 3);
    let WireResult::Ok { response } = *result else {
        panic!("expected successful event response");
    };
    let WireResponse::Events(batch) = *response else {
        panic!("expected event response");
    };
    assert_eq!(batch.events[0].operation_id.as_ref(), Some(&operation_id));
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
        request: Box::new(WireRequest::Create(Box::new(CreateRequest {
            context: OperationContext::new(
                OperationId::new("required-create-wire").expect("operation ID"),
            ),
            id: ContainerId::new("required-create-wire-container").expect("container ID"),
            bundle,
            isolation: IsolationRequest::SharedHostKernel,
            attachments,
        }))),
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
