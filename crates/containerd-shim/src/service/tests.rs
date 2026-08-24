use super::*;
use a3s_oci_sdk::oci_spec::runtime::{
    ContainerState, LinuxSchedulerFlag, LinuxSchedulerPolicy, Process, StateBuilder,
};
use a3s_oci_sdk::{
    async_trait, CreateRequest, DeleteMode, DeleteRequest as RuntimeDeleteRequest, DriverKind,
    ExecRequest, Generation, IsolationClass, KillRequest as RuntimeKillRequest, OciRuntimeService,
    OutputChunk, OutputStream, ProcessesRequest, ReadOutputRequest, StateRequest,
    WaitProcessRequest, WaitRequest,
};
use containerd_shim::TtrpcContext;
use containerd_shim_protos::shim_async::Task;

mod control;
mod delete_shim_paused;
mod lifecycle;
mod resize;
mod signal;

#[derive(Clone)]
struct RecoveryService {
    record: ContainerRecord,
    processes: Arc<std::sync::Mutex<Vec<ProcessRecord>>>,
    exec_calls: Arc<std::sync::atomic::AtomicUsize>,
    output: Option<Vec<u8>>,
}

#[derive(Default)]
struct CreateIntentCleanupCalls {
    creates: Vec<CreateRequest>,
    kills: Vec<RuntimeKillRequest>,
    deletes: Vec<RuntimeDeleteRequest>,
}

#[derive(Clone)]
struct CreateIntentCleanupService {
    record: ContainerRecord,
    calls: Arc<std::sync::Mutex<CreateIntentCleanupCalls>>,
    retryable_create_failures: Arc<std::sync::atomic::AtomicUsize>,
}

#[derive(Default)]
struct DeletedRuntimeCalls {
    states: Vec<StateRequest>,
    kills: usize,
    deletes: Vec<RuntimeDeleteRequest>,
}

#[derive(Clone)]
struct DeletedRuntimeService {
    calls: Arc<std::sync::Mutex<DeletedRuntimeCalls>>,
    confirmed_delete_mode: Option<DeleteMode>,
}

#[async_trait]
impl OciRuntimeService for DeletedRuntimeService {
    async fn features(&self) -> a3s_oci_sdk::Result<a3s_oci_sdk::RuntimeInfo> {
        Err(RuntimeError::unsupported("test-features"))
    }

    async fn create(&self, _request: CreateRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(RuntimeError::unsupported("test-create"))
    }

    async fn state(&self, request: StateRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        self.calls
            .lock()
            .expect("deleted-runtime calls")
            .states
            .push(request);
        Err(RuntimeError::new(
            ErrorCode::NotFound,
            "runtime generation was already deleted",
        )
        .for_operation("test-state"))
    }

    async fn start(
        &self,
        _request: a3s_oci_sdk::StartRequest,
    ) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(RuntimeError::unsupported("test-start"))
    }

    async fn kill(&self, _request: RuntimeKillRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        self.calls.lock().expect("deleted-runtime calls").kills += 1;
        Err(RuntimeError::new(
            ErrorCode::NotFound,
            "runtime generation was already deleted",
        )
        .for_operation("test-kill"))
    }

    async fn delete(&self, request: RuntimeDeleteRequest) -> a3s_oci_sdk::Result<()> {
        let mode = request.mode;
        self.calls
            .lock()
            .expect("deleted-runtime calls")
            .deletes
            .push(request);
        if self.confirmed_delete_mode == Some(mode) {
            Ok(())
        } else {
            Err(RuntimeError::new(
                ErrorCode::NotFound,
                "runtime has no matching committed Delete operation",
            )
            .for_operation("test-delete"))
        }
    }
}

#[async_trait]
impl OciRuntimeService for CreateIntentCleanupService {
    async fn features(&self) -> a3s_oci_sdk::Result<a3s_oci_sdk::RuntimeInfo> {
        Err(RuntimeError::unsupported("test-features"))
    }

    async fn create(&self, request: CreateRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        self.calls
            .lock()
            .expect("create-intent cleanup calls")
            .creates
            .push(request);
        if self
            .retryable_create_failures
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
        {
            return Err(RuntimeError::new(
                ErrorCode::Conflict,
                "original Create request is still completing",
            )
            .for_operation("test-create")
            .retryable(true));
        }
        Ok(self.record.clone())
    }

    async fn state(&self, _request: StateRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        Ok(self.record.clone())
    }

    async fn start(
        &self,
        _request: a3s_oci_sdk::StartRequest,
    ) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(RuntimeError::unsupported("test-start"))
    }

    async fn kill(&self, request: RuntimeKillRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        self.calls
            .lock()
            .expect("create-intent cleanup calls")
            .kills
            .push(request);
        Ok(self.record.clone())
    }

    async fn delete(&self, request: RuntimeDeleteRequest) -> a3s_oci_sdk::Result<()> {
        self.calls
            .lock()
            .expect("create-intent cleanup calls")
            .deletes
            .push(request);
        Ok(())
    }

    async fn wait(&self, _request: WaitRequest) -> a3s_oci_sdk::Result<ExitStatus> {
        ExitStatus::signaled(9, false)
    }
}

#[async_trait]
impl OciRuntimeService for RecoveryService {
    async fn features(&self) -> a3s_oci_sdk::Result<a3s_oci_sdk::RuntimeInfo> {
        Err(RuntimeError::unsupported("test-features"))
    }

    async fn create(
        &self,
        _request: a3s_oci_sdk::CreateRequest,
    ) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(RuntimeError::unsupported("test-create"))
    }

    async fn state(&self, request: StateRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        if request.target.generation.is_none() {
            return Err(RuntimeError::new(
                ErrorCode::InvalidArgument,
                "state target must be exact",
            ));
        }
        if request.target.id.as_str() != self.record.state.id() {
            return Err(RuntimeError::new(
                ErrorCode::Conflict,
                "runtime container identity does not match",
            ));
        }
        Ok(self.record.clone())
    }

    async fn start(
        &self,
        _request: a3s_oci_sdk::StartRequest,
    ) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(RuntimeError::unsupported("test-start"))
    }

    async fn kill(
        &self,
        _request: a3s_oci_sdk::KillRequest,
    ) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(RuntimeError::unsupported("test-kill"))
    }

    async fn delete(&self, _request: a3s_oci_sdk::DeleteRequest) -> a3s_oci_sdk::Result<()> {
        Err(RuntimeError::unsupported("test-delete"))
    }

    async fn exec(&self, request: ExecRequest) -> a3s_oci_sdk::Result<ProcessRecord> {
        self.exec_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let record = ProcessRecord {
            target: a3s_oci_sdk::ProcessTarget {
                container: request.container,
                process_id: request.process_id,
            },
            pid: Some(5151),
            terminal: request.process.terminal().unwrap_or(false),
        };
        self.processes
            .lock()
            .expect("recovery process inventory")
            .push(record.clone());
        Ok(record)
    }

    async fn wait(&self, _request: WaitRequest) -> a3s_oci_sdk::Result<ExitStatus> {
        std::future::pending().await
    }

    async fn processes(
        &self,
        _request: ProcessesRequest,
    ) -> a3s_oci_sdk::Result<Vec<ProcessRecord>> {
        Ok(self
            .processes
            .lock()
            .expect("recovery process inventory")
            .clone())
    }

    async fn wait_process(&self, _request: WaitProcessRequest) -> a3s_oci_sdk::Result<ExitStatus> {
        std::future::pending().await
    }

    async fn read_output(
        &self,
        request: ReadOutputRequest,
    ) -> a3s_oci_sdk::Result<Vec<OutputChunk>> {
        let Some(output) = &self.output else {
            return std::future::pending().await;
        };
        let start = usize::try_from(request.after_sequence).map_err(|_| {
            RuntimeError::new(
                ErrorCode::ResourceExhausted,
                "test output cursor does not fit usize",
            )
        })?;
        if start == output.len() {
            return std::future::pending().await;
        }
        if start > output.len() {
            return Err(RuntimeError::new(
                ErrorCode::Conflict,
                "test output cursor advanced beyond the available bytes",
            ));
        }
        let max_bytes = usize::try_from(request.max_bytes).map_err(|_| {
            RuntimeError::new(
                ErrorCode::ResourceExhausted,
                "test output byte limit does not fit usize",
            )
        })?;
        let end = start.saturating_add(max_bytes).min(output.len());
        Ok(vec![OutputChunk {
            sequence: u64::try_from(end).expect("bounded test output cursor"),
            stream: OutputStream::Stdout,
            data: output[start..end].to_vec(),
            eof: false,
        }])
    }
}

fn task_state(bundle: &Path) -> TaskState {
    let identity = TaskIdentity::new("k8s.io", "task-a").expect("identity");
    let state = StateBuilder::default()
        .version("1.3.0")
        .id(identity.container_id.as_str())
        .status(ContainerState::Running)
        .pid(4242)
        .bundle(bundle)
        .build()
        .expect("OCI state");
    TaskState {
        identity,
        bundle: bundle.to_path_buf(),
        stdin: "stdin".to_string(),
        stdout: "stdout".to_string(),
        stderr: "stderr".to_string(),
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
        control_gate: Arc::new(Mutex::new(())),
        control_sequence: 0,
        pending_control: None,
        last_update_digest: None,
        rootfs_mounted: true,
        record: ContainerRecord {
            state,
            generation: Generation(7),
            driver: DriverKind::NativeLinux,
            isolation: IsolationClass::SharedHostKernel,
            config_digest: "0".repeat(64),
            attachments_digest: None,
        },
        exit: Some(ExitStatus::exited(42).expect("exit")),
        exited_at: Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(10)),
        exec_sequence: 0,
        execs: BTreeMap::new(),
    }
}

fn recovery_service(
    task: &TaskState,
    processes: Vec<ProcessRecord>,
) -> (RuntimeAdapter, Arc<std::sync::atomic::AtomicUsize>) {
    let exec_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let service = RecoveryService {
        record: task.record.clone(),
        processes: Arc::new(std::sync::Mutex::new(processes)),
        exec_calls: exec_calls.clone(),
        output: None,
    };
    (
        RuntimeAdapter::from_client(
            a3s_oci_sdk::RuntimeClient::new(service),
            IsolationRequest::SharedHostKernel,
        ),
        exec_calls,
    )
}

fn recovery_service_instance(bundle: &Path, adapter: RuntimeAdapter) -> Service {
    Service {
        namespace: "k8s.io".to_string(),
        task_id: "task-a".to_string(),
        endpoint: "unused-test-endpoint".to_string(),
        bundle: bundle.to_path_buf(),
        exit: Arc::new(ExitSignal::default()),
        state: Arc::new(Mutex::new(ServiceState::default())),
        metadata_gate: Arc::new(Mutex::new(())),
        monitors: Arc::new(Mutex::new(BTreeMap::new())),
        exit_notify: Arc::new(Notify::new()),
        publisher: None,
        test_adapter: Arc::new(Mutex::new(Some(adapter))),
    }
}

#[test]
fn runtime_errors_keep_containerd_failure_class() {
    let error = RuntimeError::new(ErrorCode::NotFound, "missing");
    let ttrpc::Error::RpcStatus(status) = runtime_error(error) else {
        panic!("runtime error must map to RPC status");
    };
    assert_eq!(status.code(), ttrpc::Code::NOT_FOUND);
}

#[test]
fn every_runtime_error_class_has_an_explicit_containerd_mapping() {
    for (runtime, expected) in [
        (ErrorCode::InvalidArgument, ttrpc::Code::INVALID_ARGUMENT),
        (ErrorCode::NotFound, ttrpc::Code::NOT_FOUND),
        (ErrorCode::AlreadyExists, ttrpc::Code::ALREADY_EXISTS),
        (
            ErrorCode::FailedPrecondition,
            ttrpc::Code::FAILED_PRECONDITION,
        ),
        (ErrorCode::Unsupported, ttrpc::Code::UNIMPLEMENTED),
        (ErrorCode::PermissionDenied, ttrpc::Code::PERMISSION_DENIED),
        (
            ErrorCode::ResourceExhausted,
            ttrpc::Code::RESOURCE_EXHAUSTED,
        ),
        (ErrorCode::DeadlineExceeded, ttrpc::Code::DEADLINE_EXCEEDED),
        (ErrorCode::Conflict, ttrpc::Code::ABORTED),
        (ErrorCode::Unavailable, ttrpc::Code::UNAVAILABLE),
        (ErrorCode::Internal, ttrpc::Code::INTERNAL),
    ] {
        let ttrpc::Error::RpcStatus(status) = runtime_error(RuntimeError::new(runtime, "test"))
        else {
            panic!("{runtime:?} did not map to RPC status");
        };
        assert_eq!(status.code(), expected, "{runtime:?}");
    }
}

#[test]
fn timestamp_is_populated() {
    let timestamp = timestamp_now();
    assert!(timestamp.seconds > 0);
}

#[tokio::test]
async fn containerd_exec_accepts_exact_oci_scheduler_flag_names() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let task = task_state(directory.path());
    let (adapter, _) = recovery_service(&task, Vec::new());
    let service = recovery_service_instance(directory.path(), adapter);
    service
        .state
        .lock()
        .await
        .tasks
        .insert("task-a".to_string(), task);

    let process = serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0},
        "args": ["/bin/true"],
        "cwd": "/",
        "scheduler": {
            "policy": "SCHED_DEADLINE",
            "flags": [
                "SCHED_FLAG_RESET_ON_FORK",
                "SCHED_FLAG_DL_OVERRUN"
            ],
            "runtime": 1024,
            "deadline": 2048,
            "period": 4096
        }
    });
    Task::exec(
        &service,
        &ttrpc_context(),
        exec_request_with_process("exec-scheduler", process),
    )
    .await
    .expect("add scheduler-configured exec process");

    let task = service
        .task_snapshot("task-a")
        .await
        .expect("task with scheduler-configured exec process");
    let scheduler = task.execs["exec-scheduler"]
        .process
        .scheduler()
        .as_ref()
        .expect("exec scheduler");
    assert_eq!(*scheduler.policy(), LinuxSchedulerPolicy::SchedDeadline);
    assert_eq!(
        scheduler.flags().as_deref(),
        Some(
            [
                LinuxSchedulerFlag::SchedResetOnFork,
                LinuxSchedulerFlag::SchedFlagDLOverrun,
            ]
            .as_slice()
        )
    );
}

#[tokio::test]
async fn stale_monitor_completion_cannot_remove_its_replacement() {
    let key = ("task-a".to_string(), String::new());
    let stale_owner = Arc::new(());
    let replacement_owner = Arc::new(());
    let stale_task = tokio::spawn(std::future::pending::<()>());
    let replacement_task = tokio::spawn(std::future::pending::<()>());
    let mut monitors = BTreeMap::from([(
        key.clone(),
        ExitMonitor {
            owner: replacement_owner.clone(),
            abort: replacement_task.abort_handle(),
        },
    )]);

    assert!(!remove_monitor_if_owner(&mut monitors, &key, &stale_owner));
    assert!(Arc::ptr_eq(
        &monitors.get(&key).expect("replacement monitor").owner,
        &replacement_owner
    ));

    stale_task.abort();
    replacement_task.abort();
}

#[tokio::test]
async fn output_cursor_commits_are_durable_for_init_and_exec() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut task = task_state(directory.path());
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": true,
        "user": {"uid": 0, "gid": 0},
        "args": ["/bin/sh"],
        "cwd": "/"
    }))
    .expect("OCI process");
    task.execs.insert(
        "exec-a".to_string(),
        ExecState {
            incarnation: 0,
            process,
            stdin: String::new(),
            stdout: "exec-out".to_string(),
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
    metadata_from_task(&task).store().expect("store metadata");
    let (adapter, _) = recovery_service(&task, Vec::new());
    let service = recovery_service_instance(directory.path(), adapter);
    service
        .state
        .lock()
        .await
        .tasks
        .insert("task-a".to_string(), task);

    service
        .output_cursor_committer("task-a", None)
        .commit(41)
        .await
        .expect("commit init output cursor");
    service
        .output_cursor_committer("task-a", Some("exec-a"))
        .commit(73)
        .await
        .expect("commit exec output cursor");
    service
        .output_cursor_committer("task-a", None)
        .commit(17)
        .await
        .expect("ignore stale init output cursor");

    let task = service
        .task_snapshot_unchecked("task-a")
        .await
        .expect("task state");
    assert_eq!(task.output_cursor, 41);
    assert_eq!(task.execs["exec-a"].output_cursor, 73);
    let metadata = ShimMetadata::load(&ShimMetadata::path(directory.path()))
        .expect("load metadata")
        .expect("metadata exists");
    assert_eq!(metadata.output_cursor(), 41);
    assert_eq!(metadata.execs()[0].output_cursor, 73);
}

#[tokio::test]
async fn delete_shim_replays_an_in_flight_create_intent_before_exact_cleanup() {
    let directory = tempfile::tempdir().expect("temporary directory");
    std::fs::create_dir(directory.path().join("rootfs")).expect("create rootfs");
    std::fs::write(
        directory.path().join("config.json"),
        include_str!("../../../../fixtures/native-linux/config.json"),
    )
    .expect("write OCI config");
    let incarnation =
        crate::identity::IncarnationId::new("03".repeat(32)).expect("task incarnation");
    let identity =
        TaskIdentity::with_incarnation("k8s.io", "task-a", incarnation).expect("task identity");
    let state = StateBuilder::default()
        .version("1.3.0")
        .id(identity.container_id.as_str())
        .status(ContainerState::Created)
        .pid(4242)
        .bundle(directory.path())
        .build()
        .expect("OCI state");
    let record = ContainerRecord {
        state,
        generation: Generation(7),
        driver: DriverKind::NativeLinux,
        isolation: IsolationClass::SharedHostKernel,
        config_digest: "0".repeat(64),
        attachments_digest: None,
    };
    ShimCreateIntent::new(NewShimCreateIntent {
        identity: identity.clone(),
        isolation: IsolationRequest::SharedHostKernel,
        bundle: directory.path().to_path_buf(),
        stdin: String::new(),
        stdout: String::new(),
        stderr: String::new(),
        terminal: false,
        rootfs_mounted: false,
    })
    .expect("create intent")
    .store()
    .expect("store create intent");
    let calls = Arc::new(std::sync::Mutex::new(CreateIntentCleanupCalls::default()));
    let adapter = RuntimeAdapter::from_client(
        a3s_oci_sdk::RuntimeClient::new(CreateIntentCleanupService {
            record,
            calls: calls.clone(),
            retryable_create_failures: Arc::new(std::sync::atomic::AtomicUsize::new(2)),
        }),
        IsolationRequest::SharedHostKernel,
    );
    let mut service = recovery_service_instance(directory.path(), adapter);

    let response = service
        .delete_shim()
        .await
        .expect("recover in-flight create intent");

    assert_eq!(response.pid(), 4242);
    assert_eq!(response.exit_status(), 137);
    assert!(!ShimCreateIntent::path(directory.path()).exists());
    let calls = calls.lock().expect("create-intent cleanup calls");
    assert_eq!(calls.creates.len(), 3);
    assert!(calls
        .creates
        .iter()
        .all(|request| request.id == identity.container_id));
    assert!(calls
        .creates
        .windows(2)
        .all(|pair| pair[0].context.operation_id == pair[1].context.operation_id));
    assert_eq!(calls.kills.len(), 1);
    assert_eq!(calls.kills[0].target.generation, Some(Generation(7)));
    assert_eq!(calls.deletes.len(), 1);
    assert_eq!(calls.deletes[0].mode, DeleteMode::Force);
    assert_eq!(calls.deletes[0].target.generation, Some(Generation(7)));
}

#[tokio::test]
async fn delete_shim_finishes_local_cleanup_after_runtime_delete_committed() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut task = task_state(directory.path());
    task.rootfs_mounted = false;
    metadata_from_task(&task)
        .store()
        .expect("store stopped task metadata");
    let runtime = DeletedRuntimeService {
        calls: Arc::new(std::sync::Mutex::new(DeletedRuntimeCalls::default())),
        confirmed_delete_mode: Some(DeleteMode::StoppedOnly),
    };
    let calls = runtime.calls.clone();
    let adapter = RuntimeAdapter::from_client(
        a3s_oci_sdk::RuntimeClient::new(runtime),
        IsolationRequest::SharedHostKernel,
    );
    let mut service = recovery_service_instance(directory.path(), adapter);

    let response = service
        .delete_shim()
        .await
        .expect("finish interrupted runtime delete");

    assert_eq!(response.pid(), 0);
    assert_eq!(response.exit_status(), 42);
    assert_eq!(response.exited_at().seconds, 10);
    assert!(!ShimMetadata::path(directory.path()).exists());
    let calls = calls.lock().expect("deleted-runtime calls");
    assert_eq!(calls.states.len(), 1);
    assert_eq!(calls.states[0].target.id, task.identity.container_id);
    assert_eq!(calls.states[0].target.generation, Some(Generation(7)));
    assert_eq!(calls.kills, 0);
    assert_eq!(calls.deletes.len(), 1);
    assert_eq!(calls.deletes[0].mode, DeleteMode::StoppedOnly);
    assert_eq!(calls.deletes[0].target.generation, Some(Generation(7)));
}

#[tokio::test]
async fn delete_shim_retains_metadata_when_runtime_absence_is_unconfirmed() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut task = task_state(directory.path());
    task.rootfs_mounted = false;
    metadata_from_task(&task)
        .store()
        .expect("store stopped task metadata");
    let runtime = DeletedRuntimeService {
        calls: Arc::new(std::sync::Mutex::new(DeletedRuntimeCalls::default())),
        confirmed_delete_mode: None,
    };
    let calls = runtime.calls.clone();
    let adapter = RuntimeAdapter::from_client(
        a3s_oci_sdk::RuntimeClient::new(runtime),
        IsolationRequest::SharedHostKernel,
    );
    let mut service = recovery_service_instance(directory.path(), adapter);

    service
        .delete_shim()
        .await
        .expect_err("unconfirmed runtime state loss must fail closed");

    assert!(ShimMetadata::path(directory.path()).exists());
    let calls = calls.lock().expect("deleted-runtime calls");
    assert_eq!(calls.states.len(), 1);
    assert_eq!(calls.kills, 0);
    assert_eq!(calls.deletes.len(), 2);
    assert_eq!(calls.deletes[0].mode, DeleteMode::StoppedOnly);
    assert_eq!(calls.deletes[1].mode, DeleteMode::Force);
    assert!(calls
        .deletes
        .iter()
        .all(|request| request.target.generation == Some(Generation(7))));
}

#[tokio::test]
async fn stdin_journal_prepare_and_commit_are_durable_for_init_and_exec() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut task = task_state(directory.path());
    task.exit = None;
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0},
        "args": ["/bin/cat"],
        "cwd": "/"
    }))
    .expect("OCI process");
    task.execs.insert(
        "exec-a".to_string(),
        ExecState {
            incarnation: 0,
            process,
            stdin: "exec-in".to_string(),
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
            record: None,
            exit: None,
            exited_at: None,
        },
    );
    metadata_from_task(&task).store().expect("store metadata");
    let (adapter, _) = recovery_service(&task, Vec::new());
    let service = recovery_service_instance(directory.path(), adapter);
    service
        .state
        .lock()
        .await
        .tasks
        .insert("task-a".to_string(), task);

    let init = service.stdin_journal("task-a", None);
    init.prepare(1, b"init".to_vec())
        .await
        .expect("prepare init stdin");
    init.prepare(1, b"init".to_vec())
        .await
        .expect("replay identical init stdin prepare");
    let prepared = ShimMetadata::load(&ShimMetadata::path(directory.path()))
        .expect("load prepared metadata")
        .expect("prepared metadata exists");
    assert_eq!(prepared.stdin_sequence(), 0);
    assert_eq!(
        prepared.pending_stdin_write(),
        Some(&PendingStdinWrite::new(1, b"init".to_vec()).expect("expected init stdin"))
    );
    assert_eq!(
        init.prepare(1, b"changed".to_vec())
            .await
            .expect_err("changed pending init stdin must fail")
            .code,
        ErrorCode::Conflict
    );
    init.commit(1).await.expect("commit init stdin");

    let exec = service.stdin_journal("task-a", Some("exec-a"));
    exec.prepare(1, b"exec".to_vec())
        .await
        .expect("prepare exec stdin");
    exec.commit(1).await.expect("commit exec stdin");
    let committed = ShimMetadata::load(&ShimMetadata::path(directory.path()))
        .expect("load committed metadata")
        .expect("committed metadata exists");
    assert_eq!(committed.stdin_sequence(), 1);
    assert_eq!(committed.pending_stdin_write(), None);
    assert_eq!(committed.execs()[0].stdin_sequence, 1);
    assert_eq!(committed.execs()[0].pending_stdin_write, None);
    assert_eq!(
        exec.prepare(3, b"skipped".to_vec())
            .await
            .expect_err("skipped exec stdin sequence must fail")
            .code,
        ErrorCode::Conflict
    );

    init.prepare_close()
        .await
        .expect("prepare init stdin close");
    init.prepare_close()
        .await
        .expect("replay init stdin close prepare");
    let closing = ShimMetadata::load(&ShimMetadata::path(directory.path()))
        .expect("load closing metadata")
        .expect("closing metadata exists");
    assert_eq!(closing.stdin_close_state(), StdinCloseState::Closing);
    assert_eq!(
        init.prepare(2, b"late".to_vec())
            .await
            .expect_err("write after init stdin close must fail")
            .code,
        ErrorCode::FailedPrecondition
    );
    init.commit_close().await.expect("commit init stdin close");
    init.commit_close()
        .await
        .expect("replay init stdin close commit");

    exec.prepare_close()
        .await
        .expect("prepare exec stdin close");
    exec.commit_close().await.expect("commit exec stdin close");
    let closed = ShimMetadata::load(&ShimMetadata::path(directory.path()))
        .expect("load closed metadata")
        .expect("closed metadata exists");
    assert_eq!(closed.stdin_close_state(), StdinCloseState::Closed);
    assert_eq!(closed.execs()[0].stdin_close_state, StdinCloseState::Closed);
}

#[test]
fn task_metadata_round_trip_preserves_terminal_evidence() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut task = task_state(directory.path());
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0},
        "args": ["/bin/true"],
        "cwd": "/"
    }))
    .expect("OCI process");
    task.execs.insert(
        "exec-a".to_string(),
        ExecState {
            incarnation: 0,
            process,
            stdin: String::new(),
            stdout: "exec-out".to_string(),
            stderr: "exec-err".to_string(),
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
            stage: ExecStage::Exited,
            record: None,
            exit: Some(ExitStatus::exited(0).expect("exec exit")),
            exited_at: Some(
                SystemTime::UNIX_EPOCH + std::time::Duration::from_nanos(10_000_000_123),
            ),
        },
    );

    let metadata = metadata_from_task(&task);
    metadata.store().expect("store metadata");
    let loaded = ShimMetadata::load(&ShimMetadata::path(directory.path()))
        .expect("load metadata")
        .expect("metadata exists");
    assert_eq!(loaded.generation(), Generation(7));
    assert_eq!(loaded.exit(), task.exit.as_ref());
    assert_eq!(loaded.execs().len(), 1);
    assert_eq!(loaded.execs()[0].stage, ExecStage::Exited);
    assert_eq!(
        system_time_from_unix_nanos(loaded.execs()[0].exited_at_unix_nanos.unwrap()),
        task.execs["exec-a"].exited_at
    );
}

#[test]
fn protobuf_status_prefers_durable_exit_over_stale_runtime_state() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let task = task_state(directory.path());
    assert_eq!(
        protobuf_task_status(&task.record, true).enum_value_or_default(),
        api::Status::STOPPED
    );
}

fn ttrpc_context() -> TtrpcContext {
    TtrpcContext {
        mh: ttrpc::MessageHeader::default(),
        metadata: Default::default(),
        timeout_nano: 0,
    }
}

fn exec_request(exec_id: &str) -> api::ExecProcessRequest {
    exec_request_with_process(
        exec_id,
        serde_json::json!({
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/true"],
            "cwd": "/"
        }),
    )
}

fn exec_request_with_process(exec_id: &str, process: serde_json::Value) -> api::ExecProcessRequest {
    let mut spec = protobuf::well_known_types::any::Any::new();
    spec.type_url = crate::contract::OCI_PROCESS_TYPE_URL.to_string();
    spec.value = serde_json::to_vec(&process).expect("encode exec process");
    let mut request = api::ExecProcessRequest::new();
    request.set_id("task-a".to_string());
    request.set_exec_id(exec_id.to_string());
    request.set_spec(spec);
    request
}
