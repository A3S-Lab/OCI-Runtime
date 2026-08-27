use std::sync::{Arc, Mutex};

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, StateBuilder};
use a3s_oci_sdk::{
    async_trait, ContainerId, ContainerRecord, CreateAttachments, CreateRequest, DeleteMode,
    DeleteRequest, DriverKind, Error, ErrorCode, ExitStatus, Generation, IsolationClass,
    IsolationRequest, KillRequest, OciBundle, OciRuntimeService, OperationContext, OperationId,
    ProcessIo, Result, RunRequest, RuntimeClient, RuntimeInfo, StartRequest, StateRequest,
    WaitRequest,
};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Create(OperationId),
    Start(OperationId),
    Wait,
    Delete(OperationId, DeleteMode),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailurePoint {
    None,
    Create,
    Start,
    Wait,
    Delete,
    StartAndDelete,
}

struct RecordingService {
    calls: Mutex<Vec<Call>>,
    failure: FailurePoint,
}

impl RecordingService {
    fn new(failure: FailurePoint) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            failure,
        }
    }

    fn record(&self, call: Call) -> Result<()> {
        self.calls
            .lock()
            .map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))?
            .push(call);
        Ok(())
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().expect("call journal lock").clone()
    }
}

#[async_trait]
impl OciRuntimeService for RecordingService {
    async fn features(&self) -> Result<RuntimeInfo> {
        Err(Error::unsupported("features"))
    }

    async fn create(&self, request: CreateRequest) -> Result<ContainerRecord> {
        self.record(Call::Create(request.context.operation_id))?;
        if self.failure == FailurePoint::Create {
            return Err(failure("create", false));
        }
        record(&request.id, Generation(7), ContainerState::Created)
    }

    async fn state(&self, _request: StateRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("state"))
    }

    async fn start(&self, request: StartRequest) -> Result<ContainerRecord> {
        self.record(Call::Start(request.context.operation_id))?;
        if matches!(
            self.failure,
            FailurePoint::Start | FailurePoint::StartAndDelete
        ) {
            return Err(failure("start", false));
        }
        let generation = request
            .target
            .generation
            .ok_or_else(|| Error::new(ErrorCode::Internal, "run start target was not exact"))?;
        record(&request.target.id, generation, ContainerState::Running)
    }

    async fn kill(&self, _request: KillRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("kill"))
    }

    async fn delete(&self, request: DeleteRequest) -> Result<()> {
        self.record(Call::Delete(request.context.operation_id, request.mode))?;
        if matches!(
            self.failure,
            FailurePoint::Delete | FailurePoint::StartAndDelete
        ) {
            return Err(failure("delete", true));
        }
        Ok(())
    }

    async fn wait(&self, _request: WaitRequest) -> Result<ExitStatus> {
        self.record(Call::Wait)?;
        if self.failure == FailurePoint::Wait {
            return Err(failure("wait", false));
        }
        ExitStatus::exited(23)
    }
}

#[tokio::test]
async fn run_composes_exact_foreground_lifecycle_and_forced_cleanup() {
    let service = Arc::new(RecordingService::new(FailurePoint::None));
    let client = RuntimeClient::from_arc(service.clone());

    assert_eq!(
        client.run(run_request()).await.expect("run lifecycle"),
        ExitStatus::exited(23).expect("exit status")
    );
    assert_eq!(
        service.calls(),
        vec![
            Call::Create(operation_id("run-create")),
            Call::Start(operation_id("run-start")),
            Call::Wait,
            Call::Delete(operation_id("run-delete"), DeleteMode::Force),
        ]
    );
}

#[tokio::test]
async fn create_failure_does_not_delete_an_unclaimed_container() {
    let service = Arc::new(RecordingService::new(FailurePoint::Create));
    let client = RuntimeClient::from_arc(service.clone());

    let error = client
        .run(run_request())
        .await
        .expect_err("create must fail");
    assert_eq!(error.operation.as_deref(), Some("create"));
    assert_eq!(
        service.calls(),
        vec![Call::Create(operation_id("run-create"))]
    );
}

#[tokio::test]
async fn start_and_wait_failures_still_delete_with_the_stable_context() {
    for failure_point in [FailurePoint::Start, FailurePoint::Wait] {
        let service = Arc::new(RecordingService::new(failure_point));
        let client = RuntimeClient::from_arc(service.clone());

        let error = client
            .run(run_request())
            .await
            .expect_err("lifecycle stage must fail");
        let expected_operation = match failure_point {
            FailurePoint::Start => "start",
            FailurePoint::Wait => "wait",
            _ => unreachable!("test covers start and wait only"),
        };
        assert_eq!(error.operation.as_deref(), Some(expected_operation));
        assert_eq!(
            service.calls().last(),
            Some(&Call::Delete(operation_id("run-delete"), DeleteMode::Force,))
        );
    }
}

#[tokio::test]
async fn delete_failure_is_returned_after_a_successful_process_wait() {
    let service = Arc::new(RecordingService::new(FailurePoint::Delete));
    let client = RuntimeClient::from_arc(service.clone());

    let error = client
        .run(run_request())
        .await
        .expect_err("delete must fail");
    assert_eq!(error.operation.as_deref(), Some("delete"));
    assert!(error.retryable);
    assert_eq!(service.calls().len(), 4);
}

#[tokio::test]
async fn cleanup_failure_is_attached_without_hiding_the_primary_error() {
    let service = Arc::new(RecordingService::new(FailurePoint::StartAndDelete));
    let client = RuntimeClient::from_arc(service.clone());

    let error = client
        .run(run_request())
        .await
        .expect_err("start and cleanup must fail");
    assert_eq!(error.operation.as_deref(), Some("start"));
    assert!(error.message.contains("start failed"));
    assert!(error.message.contains("forced run cleanup"));
    assert!(error.message.contains("delete failed"));
    assert!(error.retryable);
}

#[tokio::test]
async fn duplicate_operation_ids_fail_before_service_dispatch() {
    let service = Arc::new(RecordingService::new(FailurePoint::None));
    let client = RuntimeClient::from_arc(service.clone());
    let mut request = run_request();
    request.start_context = request.create.context.clone();

    let error = client
        .run(request)
        .await
        .expect_err("duplicate operation IDs must fail");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("distinct create, start, and delete"));
    assert!(service.calls().is_empty());
}

#[tokio::test]
async fn missing_start_process_fails_before_create_mutation() {
    let service = Arc::new(RecordingService::new(FailurePoint::None));
    let client = RuntimeClient::from_arc(service.clone());
    let mut request = run_request();
    let spec = serde_json::from_value(json!({
        "ociVersion": "1.3.0",
        "root": { "path": "rootfs", "readonly": false }
    }))
    .expect("decode create-only OCI fixture");
    request.create.bundle = OciBundle::from_spec(
        std::env::temp_dir().join("a3s-oci-sdk-run-without-process"),
        spec,
    )
    .expect("construct create-only OCI bundle");

    let error = client
        .run(request)
        .await
        .expect_err("run must require a configured process");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("process"));
    assert!(service.calls().is_empty());
}

fn run_request() -> RunRequest {
    let spec = serde_json::from_value(json!({
        "ociVersion": "1.3.0",
        "process": {
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "args": ["/bin/true"],
            "cwd": "/"
        },
        "root": { "path": "rootfs", "readonly": false }
    }))
    .expect("decode OCI fixture");
    let bundle = OciBundle::from_spec(
        std::env::temp_dir().join("a3s-oci-sdk-run-composition"),
        spec,
    )
    .expect("construct OCI bundle");
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("construct attachment contract");
    RunRequest {
        create: CreateRequest {
            context: context("run-create"),
            id: ContainerId::new("run-container").expect("container ID"),
            bundle,
            isolation: IsolationRequest::SharedHostKernel,
            attachments,
        },
        start_context: context("run-start"),
        delete_context: context("run-delete"),
    }
}

fn record(
    id: &ContainerId,
    generation: Generation,
    status: ContainerState,
) -> Result<ContainerRecord> {
    let state = StateBuilder::default()
        .version("1.3.0")
        .id(id.as_str())
        .status(status)
        .pid(4242)
        .bundle(std::env::temp_dir().join("a3s-oci-sdk-run-composition"))
        .build()
        .map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))?;
    Ok(ContainerRecord {
        state,
        generation,
        driver: DriverKind::NativeLinux,
        isolation: IsolationClass::SharedHostKernel,
        guest_session: None,
        network_enforcement: None,
        config_digest: "0".repeat(64),
        attachments_digest: Some(format!("sha256:{}", "0".repeat(64))),
    })
}

fn context(value: &str) -> OperationContext {
    OperationContext::new(operation_id(value))
}

fn operation_id(value: &str) -> OperationId {
    OperationId::new(value).expect("operation ID")
}

fn failure(operation: &str, retryable: bool) -> Error {
    Error::new(ErrorCode::Internal, format!("{operation} failed"))
        .for_operation(operation)
        .retryable(retryable)
}
