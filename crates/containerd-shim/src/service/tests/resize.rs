use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{
    async_trait, ContainerRecord, CreateRequest, DeleteRequest, Error as RuntimeError, ErrorCode,
    ExecRequest, ExitStatus, IsolationRequest, KillRequest, OciRuntimeService, OperationId,
    ProcessRecord, ProcessTarget, ProcessesRequest, ResizeRequest, RuntimeClient, StartRequest,
    StateRequest, TerminalSize, WaitProcessRequest, WaitRequest,
};
use containerd_shim::{TtrpcContext, TtrpcResult};
use containerd_shim_protos::{api, shim_async::Task, ttrpc};
use tokio::sync::{Barrier, Mutex};

use super::{
    metadata_from_task, recovery_service_instance, task_state, ExecStage, ExecState, Service,
    ShimMetadata, StdinCloseState,
};
use crate::adapter::RuntimeAdapter;

#[derive(Clone)]
struct ResizeBarriers {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[derive(Clone)]
struct ResizeRuntime {
    record: ContainerRecord,
    calls: Arc<StdMutex<Vec<ResizeRequest>>>,
    effects: Arc<StdMutex<BTreeMap<OperationId, (ProcessTarget, TerminalSize)>>>,
    current_size: Arc<StdMutex<Option<TerminalSize>>>,
    retryable_failures: Arc<AtomicUsize>,
    next_error: Arc<StdMutex<Option<RuntimeError>>>,
    process_exited: Arc<AtomicBool>,
    first_barriers: Arc<StdMutex<Option<ResizeBarriers>>>,
}

impl ResizeRuntime {
    fn new(record: ContainerRecord) -> Self {
        Self {
            record,
            calls: Arc::new(StdMutex::new(Vec::new())),
            effects: Arc::new(StdMutex::new(BTreeMap::new())),
            current_size: Arc::new(StdMutex::new(None)),
            retryable_failures: Arc::new(AtomicUsize::new(0)),
            next_error: Arc::new(StdMutex::new(None)),
            process_exited: Arc::new(AtomicBool::new(false)),
            first_barriers: Arc::new(StdMutex::new(None)),
        }
    }

    fn calls(&self) -> Vec<ResizeRequest> {
        self.calls.lock().expect("resize calls").clone()
    }

    fn effect_count(&self) -> usize {
        self.effects.lock().expect("resize effects").len()
    }

    fn current_size(&self) -> Option<TerminalSize> {
        *self.current_size.lock().expect("current terminal size")
    }

    fn fail_after_effect(&self, count: usize) {
        self.retryable_failures.store(count, Ordering::SeqCst);
    }

    fn fail_next(&self, error: RuntimeError) {
        *self.next_error.lock().expect("next resize error") = Some(error);
    }

    fn mark_process_exited(&self) {
        self.process_exited.store(true, Ordering::SeqCst);
    }

    fn block_first_resize(&self, entered: Arc<Barrier>, release: Arc<Barrier>) {
        *self.first_barriers.lock().expect("resize barriers") =
            Some(ResizeBarriers { entered, release });
    }
}

#[async_trait]
impl OciRuntimeService for ResizeRuntime {
    async fn features(&self) -> a3s_oci_sdk::Result<a3s_oci_sdk::RuntimeInfo> {
        Err(RuntimeError::unsupported("test-features"))
    }

    async fn create(&self, _request: CreateRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(RuntimeError::unsupported("test-create"))
    }

    async fn state(&self, request: StateRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        if request.target.generation != Some(self.record.generation)
            || request.target.id.as_str() != self.record.state.id()
        {
            return Err(
                RuntimeError::new(ErrorCode::Conflict, "resize test target drift")
                    .for_operation("test-resize-state"),
            );
        }
        Ok(self.record.clone())
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

    async fn exec(&self, _request: ExecRequest) -> a3s_oci_sdk::Result<ProcessRecord> {
        Err(RuntimeError::unsupported("test-exec"))
    }

    async fn resize(&self, request: ResizeRequest) -> a3s_oci_sdk::Result<()> {
        self.calls
            .lock()
            .expect("resize calls")
            .push(request.clone());
        {
            let mut effects = self.effects.lock().expect("resize effects");
            match effects.get(&request.context.operation_id) {
                Some((process, size)) if process != &request.process || size != &request.size => {
                    return Err(RuntimeError::new(
                        ErrorCode::Conflict,
                        "resize operation identity was reused with a changed request",
                    )
                    .for_operation("test-resize"));
                }
                Some(_) => {}
                None => {
                    effects.insert(
                        request.context.operation_id.clone(),
                        (request.process.clone(), request.size),
                    );
                    *self.current_size.lock().expect("current terminal size") = Some(request.size);
                }
            }
        }
        let barriers = self.first_barriers.lock().expect("resize barriers").take();
        if let Some(barriers) = barriers {
            barriers.entered.wait().await;
            barriers.release.wait().await;
        }
        if let Some(error) = self.next_error.lock().expect("next resize error").take() {
            return Err(error);
        }
        if self
            .retryable_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(
                RuntimeError::new(ErrorCode::Unavailable, "resize response was lost")
                    .for_operation("test-resize")
                    .retryable(true),
            );
        }
        Ok(())
    }

    async fn processes(
        &self,
        _request: ProcessesRequest,
    ) -> a3s_oci_sdk::Result<Vec<ProcessRecord>> {
        if self.process_exited.load(Ordering::SeqCst) {
            return Ok(Vec::new());
        }
        let mut targets = BTreeMap::new();
        for (target, _) in self.effects.lock().expect("resize effects").values() {
            targets.insert(target.process_id.as_str().to_string(), target.clone());
        }
        Ok(targets
            .into_values()
            .enumerate()
            .map(|(index, target)| ProcessRecord {
                target,
                pid: Some(5000 + u32::try_from(index).expect("bounded process index")),
                terminal: true,
            })
            .collect())
    }

    async fn wait(&self, _request: WaitRequest) -> a3s_oci_sdk::Result<ExitStatus> {
        std::future::pending().await
    }

    async fn wait_process(&self, _request: WaitProcessRequest) -> a3s_oci_sdk::Result<ExitStatus> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn same_size_is_suppressed_and_a_b_a_uses_fresh_operation_identities() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    let first = TerminalSize {
        width: 120,
        height: 40,
    };
    let second = TerminalSize {
        width: 132,
        height: 43,
    };

    request_resize(&service, None, first)
        .await
        .expect("first resize");
    request_resize(&service, None, first)
        .await
        .expect("same-size retry");
    request_resize(&service, None, second)
        .await
        .expect("second resize");
    request_resize(&service, None, first)
        .await
        .expect("return to first size");

    let calls = runtime.calls();
    assert_eq!(
        calls.iter().map(|request| request.size).collect::<Vec<_>>(),
        [first, second, first]
    );
    assert_eq!(
        calls
            .iter()
            .map(|request| request.context.operation_id.clone())
            .collect::<BTreeSet<_>>()
            .len(),
        3,
        "A→B→A must not reuse A's first completed operation identity"
    );
    assert_eq!(runtime.effect_count(), 3);
    assert_eq!(runtime.current_size(), Some(first));
    let metadata = load_metadata(directory.path());
    assert_eq!(metadata.resize_sequence(), 3);
    assert_eq!(metadata.pending_resize(), None);
    assert_eq!(metadata.terminal_size(), Some(first));
}

#[tokio::test]
async fn pending_resize_survives_reopen_and_replays_exactly_once() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    let size = TerminalSize {
        width: 143,
        height: 47,
    };
    runtime.fail_after_effect(1);

    request_resize(&service, None, size)
        .await
        .expect_err("lost response must retain pending resize");
    let pending = load_metadata(directory.path());
    assert_eq!(pending.resize_sequence(), 0);
    assert_eq!(
        pending.pending_resize().map(|resize| resize.sequence()),
        Some(1)
    );
    assert_eq!(
        pending.pending_resize().map(|resize| resize.size()),
        Some(size)
    );
    assert_eq!(runtime.effect_count(), 1);

    let replacement = service_for_runtime(directory.path(), runtime.clone());
    replacement
        .restore_task("task-a")
        .await
        .expect("replacement replays pending resize");
    request_resize(&replacement, None, size)
        .await
        .expect("same-size retry returns from durable state");

    let calls = runtime.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0].context.operation_id, calls[1].context.operation_id,
        "replacement must reuse the pending resize identity"
    );
    assert_eq!(runtime.effect_count(), 1);
    assert_eq!(runtime.current_size(), Some(size));
    let completed = load_metadata(directory.path());
    assert_eq!(completed.resize_sequence(), 1);
    assert_eq!(completed.pending_resize(), None);
    assert_eq!(completed.terminal_size(), Some(size));
    replacement.stop_all_monitors().await;
    replacement.stop_all_pumps().await;
}

#[tokio::test]
async fn pending_exec_resize_survives_reopen_and_replays_exactly_once() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut task = terminal_task(directory.path());
    add_terminal_exec(&mut task, "exec-a");
    metadata_from_task(&task)
        .store()
        .expect("store task metadata");
    let runtime = ResizeRuntime::new(task.record.clone());
    let service = service_for_runtime(directory.path(), runtime.clone());
    service
        .state
        .lock()
        .await
        .tasks
        .insert("task-a".to_string(), task);
    let size = TerminalSize {
        width: 111,
        height: 35,
    };
    runtime.fail_after_effect(1);

    request_resize(&service, Some("exec-a"), size)
        .await
        .expect_err("lost exec resize response must retain pending state");
    let pending = load_metadata(directory.path());
    assert_eq!(pending.execs()[0].resize_sequence, 0);
    assert_eq!(
        pending.execs()[0]
            .pending_resize
            .as_ref()
            .map(|resize| resize.sequence()),
        Some(1)
    );

    let replacement = service_for_runtime(directory.path(), runtime.clone());
    replacement
        .restore_task("task-a")
        .await
        .expect("replacement replays pending exec resize");
    request_resize(&replacement, Some("exec-a"), size)
        .await
        .expect("same-size exec retry returns from durable state");

    let calls = runtime.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].context.operation_id, calls[1].context.operation_id);
    assert_eq!(runtime.effect_count(), 1);
    let completed = load_metadata(directory.path());
    assert_eq!(completed.execs()[0].resize_sequence, 1);
    assert_eq!(completed.execs()[0].pending_resize, None);
    assert_eq!(completed.execs()[0].terminal_size, Some(size));
    replacement.stop_all_monitors().await;
    replacement.stop_all_pumps().await;
}

#[tokio::test]
async fn resize_is_committed_when_the_exact_process_has_already_exited() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    let size = TerminalSize {
        width: 101,
        height: 33,
    };
    runtime.mark_process_exited();
    runtime.fail_next(
        RuntimeError::new(
            ErrorCode::FailedPrecondition,
            "terminal process exited during resize",
        )
        .for_operation("test-resize"),
    );

    request_resize(&service, None, size)
        .await
        .expect("late resize after confirmed exit is complete");

    let metadata = load_metadata(directory.path());
    assert_eq!(metadata.resize_sequence(), 1);
    assert_eq!(metadata.pending_resize(), None);
    assert_eq!(metadata.terminal_size(), Some(size));
}

#[tokio::test]
async fn terminal_resize_failure_closes_pending_without_claiming_the_size() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    let size = TerminalSize {
        width: 109,
        height: 34,
    };
    runtime.fail_next(
        RuntimeError::new(ErrorCode::InvalidArgument, "terminal resize rejected")
            .for_operation("test-resize"),
    );

    request_resize(&service, None, size)
        .await
        .expect_err("terminal resize failure is returned");
    let failed = load_metadata(directory.path());
    assert_eq!(failed.resize_sequence(), 1);
    assert_eq!(failed.pending_resize(), None);
    assert_eq!(failed.terminal_size(), None);

    request_resize(&service, None, size)
        .await
        .expect("same size may retry under a fresh sequence");
    let completed = load_metadata(directory.path());
    assert_eq!(completed.resize_sequence(), 2);
    assert_eq!(completed.pending_resize(), None);
    assert_eq!(completed.terminal_size(), Some(size));
    let calls = runtime.calls();
    assert_eq!(calls.len(), 2);
    assert_ne!(calls[0].context.operation_id, calls[1].context.operation_id);
}

#[tokio::test]
async fn concurrent_same_size_requests_are_serialized_per_process() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    runtime.block_first_resize(entered.clone(), release.clone());
    let size = TerminalSize {
        width: 97,
        height: 37,
    };

    let first_service = service.clone();
    let first = tokio::spawn(async move { request_resize(&first_service, None, size).await });
    tokio::time::timeout(Duration::from_secs(1), entered.wait())
        .await
        .expect("first resize entered runtime");
    let second_service = service.clone();
    let second = tokio::spawn(async move { request_resize(&second_service, None, size).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        runtime.calls().len(),
        1,
        "duplicate resize must wait behind the per-process gate"
    );

    release.wait().await;
    tokio::time::timeout(Duration::from_secs(1), first)
        .await
        .expect("first resize completed")
        .expect("first resize task")
        .expect("first resize response");
    tokio::time::timeout(Duration::from_secs(1), second)
        .await
        .expect("second resize completed")
        .expect("second resize task")
        .expect("second resize response");
    assert_eq!(runtime.calls().len(), 1);
    assert_eq!(runtime.effect_count(), 1);
}

#[tokio::test]
async fn init_and_exec_keep_independent_resize_sequences() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut task = terminal_task(directory.path());
    add_terminal_exec(&mut task, "exec-a");
    metadata_from_task(&task)
        .store()
        .expect("store task metadata");
    let runtime = ResizeRuntime::new(task.record.clone());
    let service = service_for_runtime(directory.path(), runtime.clone());
    service
        .state
        .lock()
        .await
        .tasks
        .insert("task-a".to_string(), task);
    let init_size = TerminalSize {
        width: 91,
        height: 31,
    };
    let exec_size = TerminalSize {
        width: 97,
        height: 37,
    };

    request_resize(&service, None, init_size)
        .await
        .expect("resize init");
    request_resize(&service, Some("exec-a"), exec_size)
        .await
        .expect("resize exec");

    let metadata = load_metadata(directory.path());
    assert_eq!(metadata.resize_sequence(), 1);
    assert_eq!(metadata.terminal_size(), Some(init_size));
    assert_eq!(metadata.execs()[0].resize_sequence, 1);
    assert_eq!(metadata.execs()[0].terminal_size, Some(exec_size));
    let calls = runtime.calls();
    assert_eq!(calls.len(), 2);
    assert_ne!(
        calls[0].context.operation_id, calls[1].context.operation_id,
        "init and exec resize identities must remain process-scoped"
    );
}

#[tokio::test]
async fn schema_v5_defaults_resize_state_and_upgrades_on_restore() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let task = terminal_task(directory.path());
    metadata_from_task(&task)
        .store()
        .expect("store current metadata");
    let path = ShimMetadata::path(directory.path());
    let mut document: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(&path).await.expect("read current metadata"))
            .expect("decode current metadata");
    document["schema_version"] = serde_json::json!(5);
    for field in ["resize_sequence", "pending_resize", "terminal_size"] {
        document
            .as_object_mut()
            .expect("metadata object")
            .remove(field);
    }
    tokio::fs::write(
        &path,
        serde_json::to_vec_pretty(&document).expect("encode schema-v5 metadata"),
    )
    .await
    .expect("write schema-v5 metadata");

    let legacy = load_metadata(directory.path());
    assert_eq!(legacy.resize_sequence(), 0);
    assert_eq!(legacy.pending_resize(), None);
    assert_eq!(legacy.terminal_size(), None);
    let runtime = ResizeRuntime::new(task.record.clone());
    let replacement = service_for_runtime(directory.path(), runtime);
    replacement
        .restore_task("task-a")
        .await
        .expect("restore schema-v5 metadata");

    let upgraded: serde_json::Value = serde_json::from_slice(
        &tokio::fs::read(&path)
            .await
            .expect("read upgraded metadata"),
    )
    .expect("decode upgraded metadata");
    assert_eq!(upgraded["schema_version"], serde_json::json!(9));
    replacement.stop_all_monitors().await;
    replacement.stop_all_pumps().await;
}

async fn initialized_service(bundle: &std::path::Path) -> (Service, ResizeRuntime) {
    let task = terminal_task(bundle);
    metadata_from_task(&task)
        .store()
        .expect("store task metadata");
    let runtime = ResizeRuntime::new(task.record.clone());
    let service = service_for_runtime(bundle, runtime.clone());
    service
        .state
        .lock()
        .await
        .tasks
        .insert("task-a".to_string(), task);
    (service, runtime)
}

fn terminal_task(bundle: &std::path::Path) -> super::TaskState {
    let mut task = task_state(bundle);
    task.stdin.clear();
    task.stdout.clear();
    task.stderr.clear();
    task.terminal = true;
    task.exit = None;
    task.exited_at = None;
    task
}

fn add_terminal_exec(task: &mut super::TaskState, exec_id: &str) {
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": true,
        "user": {"uid": 0, "gid": 0},
        "args": ["/bin/sh"],
        "cwd": "/"
    }))
    .expect("OCI process");
    task.execs.insert(
        exec_id.to_string(),
        ExecState {
            incarnation: 0,
            process,
            stdin: String::new(),
            stdout: String::new(),
            stderr: String::new(),
            terminal: true,
            stdin_sequence: 0,
            pending_stdin_write: None,
            stdin_close_state: StdinCloseState::Open,
            resize_gate: Arc::new(Mutex::new(())),
            resize_sequence: 0,
            pending_resize: None,
            terminal_size: None,
            signal_gate: Arc::new(Mutex::new(())),
            signal_sequence: 0,
            pending_signal: None,
            output_cursor: 0,
            stage: ExecStage::Started,
            record: None,
            exit: None,
            exited_at: None,
        },
    );
}

fn service_for_runtime(bundle: &std::path::Path, runtime: ResizeRuntime) -> Service {
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

async fn request_resize(
    service: &Service,
    exec_id: Option<&str>,
    size: TerminalSize,
) -> TtrpcResult<()> {
    let mut request = api::ResizePtyRequest::new();
    request.set_id("task-a".to_string());
    if let Some(exec_id) = exec_id {
        request.set_exec_id(exec_id.to_string());
    }
    request.set_width(u32::from(size.width));
    request.set_height(u32::from(size.height));
    Task::resize_pty(service, &ttrpc_context(), request)
        .await
        .map(drop)
}
