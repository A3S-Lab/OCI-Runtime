use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, LinuxResources, StateBuilder};
use a3s_oci_sdk::{
    async_trait, ContainerOperationRequest, ContainerRecord, CreateRequest, DeleteRequest,
    Error as RuntimeError, ErrorCode, IsolationRequest, KillRequest, OciRuntimeService,
    OperationContext, RuntimeClient, RuntimeInfo, StartRequest, StateRequest, UpdateRequest,
    PAUSED_STATE_ANNOTATION,
};
use containerd_shim::{TtrpcContext, TtrpcResult};
use containerd_shim_protos::{api, protobuf, shim_async::Task, ttrpc};
use tokio::sync::Barrier;

use super::{metadata_from_task, recovery_service_instance, task_state};
use crate::adapter::RuntimeAdapter;
use crate::contract::OCI_LINUX_RESOURCES_TYPE_URL;
use crate::metadata::{ControlOperationKind, ShimMetadata};

#[derive(Debug, Clone)]
struct ControlCall {
    kind: &'static str,
    context: OperationContext,
    resources: Option<LinuxResources>,
}

#[derive(Clone)]
struct PauseBarriers {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[derive(Clone)]
struct ControlRuntime {
    record: Arc<StdMutex<ContainerRecord>>,
    calls: Arc<StdMutex<Vec<ControlCall>>>,
    pause_errors: Arc<StdMutex<VecDeque<RuntimeError>>>,
    resume_errors: Arc<StdMutex<VecDeque<RuntimeError>>>,
    update_errors: Arc<StdMutex<VecDeque<RuntimeError>>>,
    update_records: Arc<StdMutex<VecDeque<ContainerRecord>>>,
    pause_barriers: Arc<StdMutex<Option<PauseBarriers>>>,
}

impl ControlRuntime {
    fn new(record: ContainerRecord) -> Self {
        Self {
            record: Arc::new(StdMutex::new(record)),
            calls: Arc::new(StdMutex::new(Vec::new())),
            pause_errors: Arc::new(StdMutex::new(VecDeque::new())),
            resume_errors: Arc::new(StdMutex::new(VecDeque::new())),
            update_errors: Arc::new(StdMutex::new(VecDeque::new())),
            update_records: Arc::new(StdMutex::new(VecDeque::new())),
            pause_barriers: Arc::new(StdMutex::new(None)),
        }
    }

    fn calls(&self) -> Vec<ControlCall> {
        self.calls.lock().expect("control calls").clone()
    }

    fn push_update_error(&self, error: RuntimeError) {
        self.update_errors
            .lock()
            .expect("Update errors")
            .push_back(error);
    }

    fn push_pause_error(&self, error: RuntimeError) {
        self.pause_errors
            .lock()
            .expect("Pause errors")
            .push_back(error);
    }

    fn push_update_record(&self, record: ContainerRecord) {
        self.update_records
            .lock()
            .expect("Update records")
            .push_back(record);
    }

    fn push_resume_error(&self, error: RuntimeError) {
        self.resume_errors
            .lock()
            .expect("Resume errors")
            .push_back(error);
    }

    fn block_first_pause(&self, entered: Arc<Barrier>, release: Arc<Barrier>) {
        *self.pause_barriers.lock().expect("Pause barriers") =
            Some(PauseBarriers { entered, release });
    }

    fn record_call(
        &self,
        kind: &'static str,
        context: OperationContext,
        resources: Option<LinuxResources>,
    ) {
        self.calls.lock().expect("control calls").push(ControlCall {
            kind,
            context,
            resources,
        });
    }

    fn current_record(&self) -> ContainerRecord {
        self.record.lock().expect("runtime record").clone()
    }

    fn set_paused(&self, paused: bool) -> ContainerRecord {
        let mut record = self.record.lock().expect("runtime record");
        *record = record_with_paused_state(&record, paused);
        record.clone()
    }
}

#[async_trait]
impl OciRuntimeService for ControlRuntime {
    async fn features(&self) -> a3s_oci_sdk::Result<RuntimeInfo> {
        Err(RuntimeError::unsupported("test-features"))
    }

    async fn create(&self, _request: CreateRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(RuntimeError::unsupported("test-create"))
    }

    async fn state(&self, _request: StateRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        Ok(self.current_record())
    }

    async fn start(&self, _request: StartRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(RuntimeError::unsupported("test-start"))
    }

    async fn kill(&self, _request: KillRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(RuntimeError::unsupported("test-kill"))
    }

    async fn delete(&self, _request: DeleteRequest) -> a3s_oci_sdk::Result<()> {
        Err(RuntimeError::unsupported("test-delete"))
    }

    async fn pause(
        &self,
        request: ContainerOperationRequest,
    ) -> a3s_oci_sdk::Result<ContainerRecord> {
        self.record_call("pause", request.context, None);
        let barriers = self.pause_barriers.lock().expect("Pause barriers").take();
        if let Some(barriers) = barriers {
            barriers.entered.wait().await;
            barriers.release.wait().await;
        }
        if let Some(error) = self.pause_errors.lock().expect("Pause errors").pop_front() {
            return Err(error);
        }
        Ok(self.set_paused(true))
    }

    async fn resume(
        &self,
        request: ContainerOperationRequest,
    ) -> a3s_oci_sdk::Result<ContainerRecord> {
        self.record_call("resume", request.context, None);
        if let Some(error) = self
            .resume_errors
            .lock()
            .expect("Resume errors")
            .pop_front()
        {
            return Err(error);
        }
        Ok(self.set_paused(false))
    }

    async fn update(&self, request: UpdateRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        self.record_call("update", request.context, Some(request.resources));
        if let Some(error) = self
            .update_errors
            .lock()
            .expect("Update errors")
            .pop_front()
        {
            return Err(error);
        }
        if let Some(record) = self
            .update_records
            .lock()
            .expect("Update records")
            .pop_front()
        {
            return Ok(record);
        }
        Ok(self.current_record())
    }
}

#[tokio::test]
async fn repeated_pause_resume_cycles_use_fresh_durable_operation_ids() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;

    request_pause(&service).await.expect("first Pause");
    request_resume(&service).await.expect("first Resume");
    request_pause(&service).await.expect("second Pause");
    request_resume(&service).await.expect("second Resume");

    let calls = runtime.calls();
    assert_eq!(
        calls.iter().map(|call| call.kind).collect::<Vec<_>>(),
        ["pause", "resume", "pause", "resume"]
    );
    assert_eq!(
        calls
            .iter()
            .map(|call| call.context.operation_id.clone())
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
    let metadata = load_metadata(directory.path());
    assert_eq!(metadata.control_sequence(), 4);
    assert_eq!(metadata.pending_control(), None);
}

#[tokio::test]
async fn concurrent_duplicate_pause_dispatches_once() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    runtime.block_first_pause(entered.clone(), release.clone());

    let first_service = service.clone();
    let first = tokio::spawn(async move { request_pause(&first_service).await });
    tokio::time::timeout(Duration::from_secs(1), entered.wait())
        .await
        .expect("first Pause entered runtime");

    let second_service = service.clone();
    let second = tokio::spawn(async move { request_pause(&second_service).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        runtime.calls().len(),
        1,
        "the duplicate must wait behind the task control gate"
    );

    release.wait().await;
    tokio::time::timeout(Duration::from_secs(1), first)
        .await
        .expect("first Pause completed")
        .expect("first Pause task")
        .expect("first Pause response");
    tokio::time::timeout(Duration::from_secs(1), second)
        .await
        .expect("second Pause completed")
        .expect("second Pause task")
        .expect("second Pause response");

    assert_eq!(runtime.calls().len(), 1);
    let metadata = load_metadata(directory.path());
    assert_eq!(metadata.control_sequence(), 1);
    assert_eq!(metadata.pending_control(), None);
}

#[tokio::test]
async fn pending_pause_replays_during_reopen_with_the_same_operation_id() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    runtime.push_pause_error(retryable_control_error("Pause response was lost"));

    request_pause(&service)
        .await
        .expect_err("first Pause must retain a retryable pending operation");
    let pending = load_metadata(directory.path());
    assert_eq!(pending.control_sequence(), 0);
    assert_eq!(
        pending.pending_control().map(|operation| operation.kind()),
        Some(ControlOperationKind::Pause)
    );

    let replacement = service_for_runtime(directory.path(), runtime.clone());
    replacement
        .restore_task("task-a")
        .await
        .expect("replay pending Pause while restoring metadata");
    request_pause(&replacement)
        .await
        .expect("completed Pause must be idempotent");

    let calls = runtime.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].context.operation_id, calls[1].context.operation_id);
    assert!(calls.iter().all(|call| call.resources.is_none()));
    let completed = load_metadata(directory.path());
    assert_eq!(completed.control_sequence(), 1);
    assert_eq!(completed.pending_control(), None);
}

#[tokio::test]
async fn pending_resume_replays_during_reopen_with_the_same_operation_id() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    request_pause(&service).await.expect("baseline Pause");
    runtime.push_resume_error(retryable_control_error("Resume response was lost"));

    request_resume(&service)
        .await
        .expect_err("first Resume must retain a retryable pending operation");
    let replacement = service_for_runtime(directory.path(), runtime.clone());
    replacement
        .restore_task("task-a")
        .await
        .expect("replay pending Resume while restoring metadata");
    request_resume(&replacement)
        .await
        .expect("completed Resume must be idempotent");

    let calls = runtime.calls();
    assert_eq!(
        calls.iter().map(|call| call.kind).collect::<Vec<_>>(),
        ["pause", "resume", "resume"]
    );
    assert_eq!(calls[1].context.operation_id, calls[2].context.operation_id);
    assert!(calls.iter().all(|call| call.resources.is_none()));
    let completed = load_metadata(directory.path());
    assert_eq!(completed.control_sequence(), 2);
    assert_eq!(completed.pending_control(), None);
}

#[tokio::test]
async fn pending_update_replays_during_reopen_with_the_same_operation_id() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    runtime.push_update_error(
        RuntimeError::new(ErrorCode::Unavailable, "response was lost")
            .for_operation("test-update")
            .retryable(true),
    );

    request_update(
        &service,
        br#"{"unified":{"memory.low":"0","memory.high":"1"}}"#,
    )
    .await
    .expect_err("first Update must retain a retryable pending operation");
    let pending = load_metadata(directory.path());
    assert_eq!(pending.control_sequence(), 0);
    assert_eq!(
        pending.pending_control().map(|operation| operation.kind()),
        Some(ControlOperationKind::Update)
    );
    assert_eq!(
        pending
            .pending_control()
            .map(|operation| operation.sequence()),
        Some(1)
    );

    let replacement = service_for_runtime(directory.path(), runtime.clone());
    replacement
        .restore_task("task-a")
        .await
        .expect("replay pending Update while restoring metadata");

    let replayed = load_metadata(directory.path());
    assert_eq!(replayed.control_sequence(), 1);
    assert_eq!(replayed.pending_control(), None);
    assert!(replayed.last_update_digest().is_some());

    request_update(
        &replacement,
        br#"{"unified":{"memory.low":"0","memory.high":"1"}}"#,
    )
    .await
    .expect("replay completed Update without dispatch");

    let calls = runtime.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].context.operation_id, calls[1].context.operation_id);
    assert_eq!(calls[0].resources, calls[1].resources);
}

#[tokio::test]
async fn legacy_schema_v8_pending_update_waits_for_matching_caller_resources() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    runtime.push_update_error(retryable_control_error("Update response was lost"));
    request_update(&service, br#"{"pids":{"limit":64}}"#)
        .await
        .expect_err("first Update must retain a retryable pending operation");

    let path = ShimMetadata::path(directory.path());
    let mut document: serde_json::Value = serde_json::from_slice(
        &tokio::fs::read(&path)
            .await
            .expect("read schema-v10 task metadata"),
    )
    .expect("decode schema-v10 task metadata");
    document["schema_version"] = serde_json::json!(8);
    document["pending_control"]
        .as_object_mut()
        .expect("pending control object")
        .remove("resources");
    tokio::fs::write(
        &path,
        serde_json::to_vec_pretty(&document).expect("encode schema-v8 task metadata"),
    )
    .await
    .expect("write schema-v8 task metadata");

    let replacement = service_for_runtime(directory.path(), runtime.clone());
    replacement
        .restore_task("task-a")
        .await
        .expect("restore legacy pending Update without guessing its resources");
    assert_eq!(runtime.calls().len(), 1);
    let deferred = load_metadata(directory.path());
    assert_eq!(deferred.schema_version(), 8);
    assert!(deferred
        .pending_control()
        .is_some_and(|operation| operation.resources().is_none()));

    request_update(&replacement, br#"{"pids":{"limit":63}}"#)
        .await
        .expect_err("a different Update must not replace legacy pending resources");
    assert_eq!(runtime.calls().len(), 1);
    request_update(&replacement, br#"{"pids":{"limit":64}}"#)
        .await
        .expect("matching caller retry must supply and dispatch legacy resources");

    let calls = runtime.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].context.operation_id, calls[1].context.operation_id);
    assert_eq!(calls[0].resources, calls[1].resources);
    let upgraded = load_metadata(directory.path());
    assert_eq!(upgraded.schema_version(), 10);
    assert_eq!(upgraded.control_sequence(), 1);
    assert_eq!(upgraded.pending_control(), None);
}

#[tokio::test]
async fn retryable_control_replay_failure_keeps_the_pending_operation() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    runtime.push_update_error(retryable_control_error("first Update response was lost"));
    runtime.push_update_error(retryable_control_error("Runtime is still unavailable"));
    request_update(&service, br#"{"pids":{"limit":64}}"#)
        .await
        .expect_err("first Update must retain pending state");

    let replacement = service_for_runtime(directory.path(), runtime.clone());
    replacement
        .restore_task("task-a")
        .await
        .expect_err("retryable replay failure must fail task restoration");

    let calls = runtime.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].context.operation_id, calls[1].context.operation_id);
    let pending = load_metadata(directory.path());
    assert_eq!(pending.control_sequence(), 0);
    assert!(pending.pending_control().is_some());
}

#[tokio::test]
async fn terminal_control_replay_failure_settles_the_pending_sequence() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    runtime.push_update_error(retryable_control_error("first Update response was lost"));
    runtime.push_update_error(
        RuntimeError::new(ErrorCode::InvalidArgument, "terminal resource rejection")
            .for_operation("test-update"),
    );
    request_update(&service, br#"{"pids":{"limit":64}}"#)
        .await
        .expect_err("first Update must retain pending state");

    let replacement = service_for_runtime(directory.path(), runtime.clone());
    replacement
        .restore_task("task-a")
        .await
        .expect("terminal replay failure must settle task restoration");

    let completed = load_metadata(directory.path());
    assert_eq!(completed.control_sequence(), 1);
    assert_eq!(completed.pending_control(), None);
    assert_eq!(completed.last_update_digest(), None);
}

#[tokio::test]
async fn control_replay_rejects_runtime_target_or_freezer_drift() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    runtime.push_update_error(retryable_control_error("first Update response was lost"));
    request_update(&service, br#"{"pids":{"limit":64}}"#)
        .await
        .expect_err("first Update must retain pending state");
    let drifted = record_with_paused_state(&runtime.current_record(), true);
    runtime.push_update_record(drifted);

    let replacement = service_for_runtime(directory.path(), runtime.clone());
    let error = replacement
        .restore_task("task-a")
        .await
        .expect_err("Update replay must reject freezer drift");
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(error.message.contains("freezer state"));

    let pending = load_metadata(directory.path());
    assert_eq!(pending.control_sequence(), 0);
    assert!(pending.pending_control().is_some());
}

#[tokio::test]
async fn legacy_metadata_upgrades_to_current_schema_before_the_first_control() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let task = task_state(directory.path());
    metadata_from_task(&task)
        .store()
        .expect("store current task metadata");
    let path = ShimMetadata::path(directory.path());
    let mut document: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(&path).await.expect("read task metadata"))
            .expect("decode task metadata");
    document["schema_version"] = serde_json::json!(2);
    tokio::fs::write(
        &path,
        serde_json::to_vec_pretty(&document).expect("encode schema-v2 task metadata"),
    )
    .await
    .expect("write schema-v2 task metadata");

    let runtime = ControlRuntime::new(task.record.clone());
    let service = service_for_runtime(directory.path(), runtime.clone());
    service
        .restore_task("task-a")
        .await
        .expect("restore schema-v2 task metadata");
    request_pause(&service)
        .await
        .expect("run first control after schema-v2 restore");

    assert_eq!(runtime.calls().len(), 1);
    let upgraded = load_metadata(directory.path());
    assert_eq!(upgraded.control_sequence(), 1);
    assert_eq!(upgraded.pending_control(), None);
    let document: serde_json::Value = serde_json::from_slice(
        &tokio::fs::read(&path)
            .await
            .expect("read upgraded task metadata"),
    )
    .expect("decode upgraded task metadata");
    assert_eq!(document["schema_version"], serde_json::json!(10));
}

#[tokio::test]
async fn distinct_updates_advance_sequence_and_terminal_failures_close_pending_state() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    runtime.push_update_error(
        RuntimeError::new(ErrorCode::InvalidArgument, "terminal resource rejection")
            .for_operation("test-update"),
    );

    request_update(&service, br#"{"pids":{"limit":64}}"#)
        .await
        .expect_err("terminal Update must fail");
    let failed = load_metadata(directory.path());
    assert_eq!(failed.control_sequence(), 1);
    assert_eq!(failed.pending_control(), None);
    assert_eq!(failed.last_update_digest(), None);

    request_update(&service, br#"{"pids":{"limit":64}}"#)
        .await
        .expect("same Update may use a fresh identity after terminal failure");
    request_update(&service, br#"{"pids":{"limit":63}}"#)
        .await
        .expect("different Update must dispatch");
    request_update(&service, br#"{"pids":{"limit":63}}"#)
        .await
        .expect("completed identical Update must not dispatch twice");

    let calls = runtime.calls();
    assert_eq!(calls.len(), 3);
    assert_ne!(calls[0].context.operation_id, calls[1].context.operation_id);
    assert_ne!(calls[1].context.operation_id, calls[2].context.operation_id);
    let completed = load_metadata(directory.path());
    assert_eq!(completed.control_sequence(), 3);
    assert_eq!(completed.pending_control(), None);
    assert!(completed.last_update_digest().is_some());
}

async fn initialized_service(bundle: &std::path::Path) -> (super::Service, ControlRuntime) {
    let task = task_state(bundle);
    metadata_from_task(&task)
        .store()
        .expect("store initial task metadata");
    let runtime = ControlRuntime::new(task.record.clone());
    let service = service_for_runtime(bundle, runtime.clone());
    service
        .state
        .lock()
        .await
        .tasks
        .insert("task-a".to_string(), task);
    (service, runtime)
}

fn service_for_runtime(bundle: &std::path::Path, runtime: ControlRuntime) -> super::Service {
    let adapter = RuntimeAdapter::from_client(
        RuntimeClient::new(runtime),
        IsolationRequest::SharedHostKernel,
    );
    recovery_service_instance(bundle, adapter)
}

fn load_metadata(bundle: &std::path::Path) -> ShimMetadata {
    ShimMetadata::load(&ShimMetadata::path(bundle))
        .expect("load shim metadata")
        .expect("shim metadata exists")
}

fn ttrpc_context() -> TtrpcContext {
    TtrpcContext {
        mh: ttrpc::MessageHeader::default(),
        metadata: Default::default(),
        timeout_nano: 0,
    }
}

async fn request_pause(service: &super::Service) -> TtrpcResult<()> {
    let mut request = api::PauseRequest::new();
    request.set_id("task-a".to_string());
    Task::pause(service, &ttrpc_context(), request)
        .await
        .map(drop)
}

async fn request_resume(service: &super::Service) -> TtrpcResult<()> {
    let mut request = api::ResumeRequest::new();
    request.set_id("task-a".to_string());
    Task::resume(service, &ttrpc_context(), request)
        .await
        .map(drop)
}

async fn request_update(service: &super::Service, resources: &[u8]) -> TtrpcResult<()> {
    let mut request = api::UpdateTaskRequest::new();
    request.set_id("task-a".to_string());
    let mut resources_any = protobuf::well_known_types::any::Any::new();
    resources_any.type_url = OCI_LINUX_RESOURCES_TYPE_URL.to_string();
    resources_any.value = resources.to_vec();
    request.set_resources(resources_any);
    Task::update(service, &ttrpc_context(), request)
        .await
        .map(drop)
}

fn record_with_paused_state(record: &ContainerRecord, paused: bool) -> ContainerRecord {
    let mut record = record.clone();
    let mut annotations = record.state.annotations().clone().unwrap_or_default();
    if paused {
        annotations.insert(PAUSED_STATE_ANNOTATION.to_string(), "true".to_string());
    } else {
        annotations.remove(PAUSED_STATE_ANNOTATION);
    }
    let mut builder = StateBuilder::default()
        .version(record.state.version())
        .id(record.state.id())
        .status(ContainerState::Running)
        .bundle(record.state.bundle().clone())
        .annotations(annotations);
    if let Some(pid) = record.state.pid() {
        builder = builder.pid(*pid);
    }
    record.state = builder.build().expect("rebuild paused test state");
    record
}

fn retryable_control_error(message: &str) -> RuntimeError {
    RuntimeError::new(ErrorCode::Unavailable, message)
        .for_operation("test-control")
        .retryable(true)
}
