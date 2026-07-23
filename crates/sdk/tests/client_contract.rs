use std::sync::{Arc, Mutex};

use a3s_oci_sdk::{
    async_trait, ContainerId, ContainerRecord, CreateRequest, DeleteRequest, Error,
    IsolationRequest, KillRequest, OciBundle, OciRuntimeService, OperationContext, OperationId,
    ProcessIo, Result, RuntimeClient, RuntimeInfo, StartRequest, StateRequest,
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
async fn client_preserves_complete_oci_spec_at_service_boundary() {
    let config = json!({
        "ociVersion": "1.3.0",
        "process": {
            "terminal": false,
            "user": { "uid": 1000, "gid": 1000 },
            "args": ["/bin/true"],
            "cwd": "/"
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
    let spec = serde_json::from_value(config).expect("decode OCI 1.3 fixture");
    let bundle_path = std::env::current_dir()
        .expect("current directory")
        .join("sdk-contract-bundle");
    let bundle = OciBundle::from_spec(bundle_path, spec).expect("build immutable bundle");
    let request = CreateRequest {
        context: OperationContext::new(OperationId::new("operation-1").expect("operation ID")),
        id: ContainerId::new("container-1").expect("container ID"),
        bundle,
        isolation: IsolationRequest::DedicatedVm,
        io: ProcessIo::default(),
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
}
