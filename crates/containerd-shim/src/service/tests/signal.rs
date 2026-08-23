use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, Process, StateBuilder};
use a3s_oci_sdk::{
    async_trait, ContainerRecord, CreateRequest, DeleteRequest, Error as RuntimeError, ErrorCode,
    ExecRequest, ExitStatus, IsolationRequest, KillRequest, OciRuntimeService, OperationContext,
    OperationId, ProcessRecord, ProcessesRequest, RuntimeClient, SignalProcessRequest,
    StartRequest, StateRequest, WaitProcessRequest, WaitRequest,
};
use containerd_shim::{TtrpcContext, TtrpcResult};
use containerd_shim_protos::{api, shim_async::Task, ttrpc};
use tokio::sync::{Barrier, Mutex};

use super::{
    metadata_from_task, recovery_service_instance, task_state, ExecStage, ExecState, Service,
    ShimMetadata, StdinCloseState,
};
use crate::adapter::RuntimeAdapter;

#[derive(Debug, Clone)]
struct SignalCall {
    kind: &'static str,
    context: OperationContext,
    signal: i32,
    all: bool,
}

#[derive(Clone)]
struct SignalBarriers {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[derive(Clone)]
struct SignalRuntime {
    record: Arc<StdMutex<ContainerRecord>>,
    durable_exit: Arc<StdMutex<Option<ExitStatus>>>,
    wait_calls: Arc<AtomicUsize>,
    calls: Arc<StdMutex<Vec<SignalCall>>>,
    effects: Arc<StdMutex<BTreeMap<OperationId, String>>>,
    exec_targets: Arc<StdMutex<Vec<a3s_oci_sdk::ProcessTarget>>>,
    retryable_failures: Arc<AtomicUsize>,
    next_error: Arc<StdMutex<Option<RuntimeError>>>,
    first_barriers: Arc<StdMutex<Option<SignalBarriers>>>,
}

impl SignalRuntime {
    fn new(record: ContainerRecord) -> Self {
        Self {
            record: Arc::new(StdMutex::new(record)),
            durable_exit: Arc::new(StdMutex::new(None)),
            wait_calls: Arc::new(AtomicUsize::new(0)),
            calls: Arc::new(StdMutex::new(Vec::new())),
            effects: Arc::new(StdMutex::new(BTreeMap::new())),
            exec_targets: Arc::new(StdMutex::new(Vec::new())),
            retryable_failures: Arc::new(AtomicUsize::new(0)),
            next_error: Arc::new(StdMutex::new(None)),
            first_barriers: Arc::new(StdMutex::new(None)),
        }
    }

    fn calls(&self) -> Vec<SignalCall> {
        self.calls.lock().expect("signal calls").clone()
    }

    fn effect_count(&self) -> usize {
        self.effects.lock().expect("signal effects").len()
    }

    fn wait_calls(&self) -> usize {
        self.wait_calls.load(Ordering::SeqCst)
    }

    fn retain_terminal_exit(&self, exit: ExitStatus) {
        let mut record = self.record.lock().expect("signal record");
        let mut builder = StateBuilder::default()
            .version(record.state.version())
            .id(record.state.id())
            .status(ContainerState::Stopped)
            .bundle(record.state.bundle().clone());
        if let Some(pid) = record.state.pid() {
            builder = builder.pid(*pid);
        }
        if let Some(annotations) = record.state.annotations() {
            builder = builder.annotations(annotations.clone());
        }
        record.state = builder.build().expect("stopped signal test state");
        *self.durable_exit.lock().expect("durable signal exit") = Some(exit);
    }

    fn fail_after_effect(&self, count: usize) {
        self.retryable_failures.store(count, Ordering::SeqCst);
    }

    fn fail_next(&self, error: RuntimeError) {
        *self.next_error.lock().expect("next signal error") = Some(error);
    }

    fn block_first_signal(&self, entered: Arc<Barrier>, release: Arc<Barrier>) {
        *self.first_barriers.lock().expect("signal barriers") =
            Some(SignalBarriers { entered, release });
    }

    fn record_effect(&self, call: SignalCall, fingerprint: String) -> a3s_oci_sdk::Result<()> {
        let operation_id = call.context.operation_id.clone();
        self.calls.lock().expect("signal calls").push(call);
        let mut effects = self.effects.lock().expect("signal effects");
        match effects.get(&operation_id) {
            Some(existing) if existing != &fingerprint => Err(RuntimeError::new(
                ErrorCode::Conflict,
                "signal operation identity was reused with a changed request",
            )
            .for_operation("test-signal")),
            Some(_) => Ok(()),
            None => {
                effects.insert(operation_id, fingerprint);
                Ok(())
            }
        }
    }

    async fn finish_effect(&self) -> a3s_oci_sdk::Result<()> {
        let barriers = self.first_barriers.lock().expect("signal barriers").take();
        if let Some(barriers) = barriers {
            barriers.entered.wait().await;
            barriers.release.wait().await;
        }
        if let Some(error) = self.next_error.lock().expect("next signal error").take() {
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
                RuntimeError::new(ErrorCode::Unavailable, "signal response was lost")
                    .for_operation("test-signal")
                    .retryable(true),
            );
        }
        Ok(())
    }
}

#[async_trait]
impl OciRuntimeService for SignalRuntime {
    async fn features(&self) -> a3s_oci_sdk::Result<a3s_oci_sdk::RuntimeInfo> {
        Err(RuntimeError::unsupported("test-features"))
    }

    async fn create(&self, _request: CreateRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(RuntimeError::unsupported("test-create"))
    }

    async fn state(&self, request: StateRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        let record = self.record.lock().expect("signal record");
        if request.target.generation != Some(record.generation)
            || request.target.id.as_str() != record.state.id()
        {
            return Err(
                RuntimeError::new(ErrorCode::Conflict, "signal test target drift")
                    .for_operation("test-signal-state"),
            );
        }
        Ok(record.clone())
    }

    async fn start(&self, _request: StartRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(RuntimeError::unsupported("test-start"))
    }

    async fn kill(&self, request: KillRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        let fingerprint = format!(
            "init:{}:{:?}:{}:{}",
            request.target.id.as_str(),
            request.target.generation,
            request.signal.get(),
            request.all
        );
        self.record_effect(
            SignalCall {
                kind: "init",
                context: request.context,
                signal: request.signal.get(),
                all: request.all,
            },
            fingerprint,
        )?;
        self.finish_effect().await?;
        Ok(self.record.lock().expect("signal record").clone())
    }

    async fn delete(&self, _request: DeleteRequest) -> a3s_oci_sdk::Result<()> {
        Err(RuntimeError::unsupported("test-delete"))
    }

    async fn exec(&self, _request: ExecRequest) -> a3s_oci_sdk::Result<ProcessRecord> {
        Err(RuntimeError::unsupported("test-exec"))
    }

    async fn signal_process(&self, request: SignalProcessRequest) -> a3s_oci_sdk::Result<()> {
        let fingerprint = format!(
            "exec:{}:{:?}:{}:{}",
            request.process.container.id.as_str(),
            request.process.container.generation,
            request.process.process_id.as_str(),
            request.signal.get()
        );
        {
            let mut targets = self.exec_targets.lock().expect("exec targets");
            if !targets.contains(&request.process) {
                targets.push(request.process.clone());
            }
        }
        self.record_effect(
            SignalCall {
                kind: "exec",
                context: request.context,
                signal: request.signal.get(),
                all: false,
            },
            fingerprint,
        )?;
        self.finish_effect().await
    }

    async fn processes(
        &self,
        _request: ProcessesRequest,
    ) -> a3s_oci_sdk::Result<Vec<ProcessRecord>> {
        Ok(self
            .exec_targets
            .lock()
            .expect("exec targets")
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, target)| ProcessRecord {
                target,
                pid: Some(6000 + u32::try_from(index).expect("bounded process index")),
                terminal: false,
            })
            .collect())
    }

    async fn wait(&self, _request: WaitRequest) -> a3s_oci_sdk::Result<ExitStatus> {
        self.wait_calls.fetch_add(1, Ordering::SeqCst);
        let exit = self
            .durable_exit
            .lock()
            .expect("durable signal exit")
            .clone();
        match exit {
            Some(exit) => Ok(exit),
            None => std::future::pending().await,
        }
    }

    async fn wait_process(&self, _request: WaitProcessRequest) -> a3s_oci_sdk::Result<ExitStatus> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn stop_continue_stop_uses_fresh_task_signal_identities() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;

    request_signal(&service, None, libc::SIGSTOP, false)
        .await
        .expect("first SIGSTOP");
    request_signal(&service, None, libc::SIGCONT, false)
        .await
        .expect("SIGCONT");
    request_signal(&service, None, libc::SIGSTOP, false)
        .await
        .expect("second SIGSTOP");

    let calls = runtime.calls();
    assert_eq!(
        calls.iter().map(|call| call.signal).collect::<Vec<_>>(),
        [libc::SIGSTOP, libc::SIGCONT, libc::SIGSTOP]
    );
    assert!(calls.iter().all(|call| call.kind == "init" && !call.all));
    assert_eq!(
        calls
            .iter()
            .map(|call| call.context.operation_id.clone())
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );
    let metadata = load_metadata(directory.path());
    assert_eq!(metadata.signal_sequence(), 3);
    assert_eq!(metadata.pending_signal(), None);
}

#[tokio::test]
async fn init_and_exec_keep_independent_signal_sequences() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut task = running_task(directory.path());
    add_exec(&mut task, "exec-a");
    metadata_from_task(&task)
        .store()
        .expect("store task metadata");
    let runtime = SignalRuntime::new(task.record.clone());
    let service = service_for_runtime(directory.path(), runtime.clone());
    service
        .state
        .lock()
        .await
        .tasks
        .insert("task-a".to_string(), task);

    request_signal(&service, None, libc::SIGUSR1, true)
        .await
        .expect("signal init and all processes");
    request_signal(&service, Some("exec-a"), libc::SIGSTOP, true)
        .await
        .expect("signal exec");
    request_signal(&service, Some("exec-a"), libc::SIGCONT, false)
        .await
        .expect("continue exec");

    let metadata = load_metadata(directory.path());
    assert_eq!(metadata.signal_sequence(), 1);
    assert_eq!(metadata.execs()[0].signal_sequence, 2);
    assert_eq!(metadata.pending_signal(), None);
    assert_eq!(metadata.execs()[0].pending_signal, None);
    let calls = runtime.calls();
    assert_eq!(calls.len(), 3);
    assert!(calls[0].all);
    assert!(calls[1..].iter().all(|call| !call.all));
    assert_eq!(
        calls
            .iter()
            .map(|call| call.context.operation_id.clone())
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );
}

#[tokio::test]
async fn pending_task_signal_survives_reopen_and_replays_exactly_once() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    runtime.fail_after_effect(1);

    request_signal(&service, None, libc::SIGUSR1, false)
        .await
        .expect_err("lost signal response must retain pending state");
    let pending = load_metadata(directory.path());
    assert_eq!(pending.signal_sequence(), 0);
    assert_eq!(
        pending.pending_signal().map(|operation| (
            operation.sequence(),
            operation.signal().get(),
            operation.all()
        )),
        Some((1, libc::SIGUSR1, false))
    );
    assert_eq!(runtime.effect_count(), 1);

    let replacement = service_for_runtime(directory.path(), runtime.clone());
    replacement
        .restore_task("task-a")
        .await
        .expect("replacement replays pending task signal");

    let calls = runtime.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].context.operation_id, calls[1].context.operation_id);
    assert_eq!(runtime.effect_count(), 1);
    let completed = load_metadata(directory.path());
    assert_eq!(completed.signal_sequence(), 1);
    assert_eq!(completed.pending_signal(), None);
    replacement.stop_all_monitors().await;
    replacement.stop_all_pumps().await;
}

#[tokio::test]
async fn pending_task_signal_with_durable_exit_settles_without_redispatch() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    runtime.fail_after_effect(1);

    request_signal(&service, None, libc::SIGKILL, true)
        .await
        .expect_err("lost terminal signal response must retain pending state");
    let pending = load_metadata(directory.path());
    assert_eq!(pending.signal_sequence(), 0);
    assert_eq!(
        pending.pending_signal().map(|operation| (
            operation.sequence(),
            operation.signal().get(),
            operation.all()
        )),
        Some((1, libc::SIGKILL, true))
    );
    let exit = ExitStatus::signaled(libc::SIGKILL, false).expect("terminal signal exit");
    assert_eq!(pending.exit(), None);
    runtime.retain_terminal_exit(exit.clone());

    let replacement = service_for_runtime(directory.path(), runtime.clone());
    replacement
        .restore_task("task-a")
        .await
        .expect("replacement settles signal from durable exit");

    let calls = runtime.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].signal, libc::SIGKILL);
    assert!(calls[0].all);
    assert_eq!(runtime.effect_count(), 1);
    assert_eq!(runtime.wait_calls(), 1);
    let completed = load_metadata(directory.path());
    assert_eq!(completed.signal_sequence(), 1);
    assert_eq!(completed.pending_signal(), None);
    assert_eq!(completed.exit(), Some(&exit));
    replacement.stop_all_monitors().await;
    replacement.stop_all_pumps().await;
}

#[tokio::test]
async fn pending_exec_signal_survives_reopen_and_replays_exactly_once() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut task = running_task(directory.path());
    add_exec(&mut task, "exec-a");
    metadata_from_task(&task)
        .store()
        .expect("store task metadata");
    let runtime = SignalRuntime::new(task.record.clone());
    let service = service_for_runtime(directory.path(), runtime.clone());
    service
        .state
        .lock()
        .await
        .tasks
        .insert("task-a".to_string(), task);
    runtime.fail_after_effect(1);

    request_signal(&service, Some("exec-a"), libc::SIGUSR2, false)
        .await
        .expect_err("lost exec signal response must retain pending state");
    let pending = load_metadata(directory.path());
    assert_eq!(pending.execs()[0].signal_sequence, 0);
    assert_eq!(
        pending.execs()[0]
            .pending_signal
            .as_ref()
            .map(|operation| operation.sequence()),
        Some(1)
    );

    let replacement = service_for_runtime(directory.path(), runtime.clone());
    replacement
        .restore_task("task-a")
        .await
        .expect("replacement replays pending exec signal");

    let calls = runtime.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].context.operation_id, calls[1].context.operation_id);
    assert_eq!(runtime.effect_count(), 1);
    let completed = load_metadata(directory.path());
    assert_eq!(completed.execs()[0].signal_sequence, 1);
    assert_eq!(completed.execs()[0].pending_signal, None);
    replacement.stop_all_monitors().await;
    replacement.stop_all_pumps().await;
}

#[tokio::test]
async fn terminal_signal_failure_advances_sequence_and_allows_a_fresh_retry() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    runtime.fail_next(
        RuntimeError::new(ErrorCode::InvalidArgument, "signal rejected")
            .for_operation("test-signal"),
    );

    request_signal(&service, None, libc::SIGUSR1, false)
        .await
        .expect_err("terminal signal failure is returned");
    let failed = load_metadata(directory.path());
    assert_eq!(failed.signal_sequence(), 1);
    assert_eq!(failed.pending_signal(), None);

    request_signal(&service, None, libc::SIGUSR1, false)
        .await
        .expect("same signal may retry under a fresh sequence");
    let calls = runtime.calls();
    assert_eq!(calls.len(), 2);
    assert_ne!(calls[0].context.operation_id, calls[1].context.operation_id);
    let completed = load_metadata(directory.path());
    assert_eq!(completed.signal_sequence(), 2);
    assert_eq!(completed.pending_signal(), None);
}

#[tokio::test]
async fn concurrent_signal_requests_are_serialized_with_distinct_identities() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (service, runtime) = initialized_service(directory.path()).await;
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    runtime.block_first_signal(entered.clone(), release.clone());

    let first_service = service.clone();
    let first =
        tokio::spawn(
            async move { request_signal(&first_service, None, libc::SIGUSR1, false).await },
        );
    tokio::time::timeout(Duration::from_secs(1), entered.wait())
        .await
        .expect("first signal entered runtime");
    let second_service = service.clone();
    let second =
        tokio::spawn(
            async move { request_signal(&second_service, None, libc::SIGUSR1, false).await },
        );
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(runtime.calls().len(), 1);

    release.wait().await;
    tokio::time::timeout(Duration::from_secs(1), first)
        .await
        .expect("first signal completed")
        .expect("first signal task")
        .expect("first signal response");
    tokio::time::timeout(Duration::from_secs(1), second)
        .await
        .expect("second signal completed")
        .expect("second signal task")
        .expect("second signal response");

    let calls = runtime.calls();
    assert_eq!(calls.len(), 2);
    assert_ne!(calls[0].context.operation_id, calls[1].context.operation_id);
    assert_eq!(runtime.effect_count(), 2);
}

fn running_task(bundle: &std::path::Path) -> super::TaskState {
    let mut task = task_state(bundle);
    task.stdin.clear();
    task.stdout.clear();
    task.stderr.clear();
    task.rootfs_mounted = false;
    task.exit = None;
    task.exited_at = None;
    task
}

async fn initialized_service(bundle: &std::path::Path) -> (Service, SignalRuntime) {
    let task = running_task(bundle);
    metadata_from_task(&task)
        .store()
        .expect("store task metadata");
    let runtime = SignalRuntime::new(task.record.clone());
    let service = service_for_runtime(bundle, runtime.clone());
    service
        .state
        .lock()
        .await
        .tasks
        .insert("task-a".to_string(), task);
    (service, runtime)
}

fn add_exec(task: &mut super::TaskState, exec_id: &str) {
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0},
        "args": ["/bin/sh"],
        "cwd": "/"
    }))
    .expect("OCI process");
    let target = a3s_oci_sdk::ProcessTarget {
        container: a3s_oci_sdk::ContainerTarget::exact(
            task.identity.container_id.clone(),
            task.record.generation,
        ),
        process_id: crate::identity::process_id("k8s.io", "task-a", exec_id, 0)
            .expect("exec process identity"),
    };
    task.execs.insert(
        exec_id.to_string(),
        ExecState {
            incarnation: 0,
            process,
            stdin: String::new(),
            stdout: String::new(),
            stderr: String::new(),
            terminal: false,
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
            record: Some(ProcessRecord {
                target,
                pid: Some(6000),
                terminal: false,
            }),
            exit: None,
            exited_at: None,
        },
    );
}

fn service_for_runtime(bundle: &std::path::Path, runtime: SignalRuntime) -> Service {
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

async fn request_signal(
    service: &Service,
    exec_id: Option<&str>,
    signal: i32,
    all: bool,
) -> TtrpcResult<()> {
    let mut request = api::KillRequest::new();
    request.set_id("task-a".to_string());
    if let Some(exec_id) = exec_id {
        request.set_exec_id(exec_id.to_string());
    }
    request.set_signal(u32::try_from(signal).expect("positive test signal"));
    request.set_all(all);
    Task::kill(service, &ttrpc_context(), request)
        .await
        .map(drop)
}
