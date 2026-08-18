use std::sync::{Arc, Mutex};

use a3s_oci_sdk::{
    async_trait, ContainerId, ContainerRecord, CreateAttachments, CreateRequest, DeleteRequest,
    Error, IsolationRequest, KillRequest, OciBundle, OciRuntimeService, OperationContext,
    OperationId, ProcessIo, Result, RuntimeClient, RuntimeInfo, StartRequest, StateRequest,
};
use serde_json::json;

#[derive(Default)]
struct RecordingService {
    create_request: Mutex<Option<CreateRequest>>,
}

#[async_trait]
impl OciRuntimeService for RecordingService {
    async fn features(&self) -> Result<RuntimeInfo> {
        Err(Error::unsupported("features"))
    }

    async fn create(&self, request: CreateRequest) -> Result<ContainerRecord> {
        let mut recorded = self.create_request.lock().map_err(|error| {
            Error::new(
                a3s_oci_sdk::ErrorCode::Internal,
                format!("recording service lock was poisoned: {error}"),
            )
        })?;
        *recorded = Some(request);
        Err(Error::unsupported("recorded-create"))
    }

    async fn state(&self, _request: StateRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("state"))
    }

    async fn start(&self, _request: StartRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("start"))
    }

    async fn kill(&self, _request: KillRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("kill"))
    }

    async fn delete(&self, _request: DeleteRequest) -> Result<()> {
        Err(Error::unsupported("delete"))
    }
}

#[tokio::test]
async fn client_preserves_complete_oci_spec_and_unknown_properties_at_service_boundary() {
    let config = json!({
        "ociVersion": "1.3.0",
        "futureTopLevel": {"version": 2},
        "process": {
            "terminal": false,
            "user": { "uid": 1000, "gid": 1000 },
            "args": ["/bin/true"],
            "cwd": "/",
            "futureProcessField": ["opaque", 7]
        },
        "root": { "path": "rootfs", "readonly": true },
        "linux": {
            "intelRdt": {
                "closID": "a3s",
                "enableMonitoring": true
            },
            "memoryPolicy": {
                "mode": "MPOL_BIND",
                "nodes": "0"
            }
        },
        "vm": {
            "hypervisor": { "path": "/ignored/by/a3s-policy" },
            "kernel": { "path": "/ignored/by/a3s-policy" },
            "image": {
                "path": "/ignored/by/a3s-policy",
                "format": "raw"
            }
        },
        "annotations": {
            "dev.a3s.test": "sdk-boundary"
        }
    });
    let bundle_path = std::env::current_dir()
        .expect("current directory")
        .join("sdk-contract-bundle");
    let config_json = serde_json::to_string(&config).expect("encode OCI 1.3 fixture");
    let bundle = OciBundle::from_json(bundle_path, config_json).expect("build immutable bundle");
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("build attachment contract");
    let request = CreateRequest {
        context: OperationContext::new(OperationId::new("operation-1").expect("operation ID")),
        id: ContainerId::new("container-1").expect("container ID"),
        bundle,
        isolation: IsolationRequest::DedicatedVm,
        attachments,
    };

    let service = Arc::new(RecordingService::default());
    let client = RuntimeClient::from_arc(service.clone());
    client
        .create(request)
        .await
        .expect_err("recording service intentionally rejects after capture");

    let recorded = service
        .create_request
        .lock()
        .expect("recording service lock")
        .clone()
        .expect("create request must reach service");
    let encoded = serde_json::to_value(recorded.bundle.spec()).expect("encode recorded spec");
    let raw: serde_json::Value = serde_json::from_str(recorded.bundle.config_json())
        .expect("decode exact recorded configuration");

    assert_eq!(
        encoded["linux"]["intelRdt"]["enableMonitoring"],
        json!(true)
    );
    assert_eq!(encoded["linux"]["memoryPolicy"]["mode"], json!("MPOL_BIND"));
    assert_eq!(
        encoded["vm"]["kernel"]["path"],
        json!("/ignored/by/a3s-policy")
    );
    assert_eq!(
        encoded["annotations"]["dev.a3s.test"],
        json!("sdk-boundary")
    );
    assert!(encoded.get("futureTopLevel").is_none());
    assert!(encoded["process"].get("futureProcessField").is_none());
    assert_eq!(raw["futureTopLevel"], json!({"version": 2}));
    assert_eq!(raw["process"]["futureProcessField"], json!(["opaque", 7]));
}
