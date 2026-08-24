use super::*;

#[tokio::test]
async fn exec_start_persists_starting_before_runtime_adapter_connection() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let task = task_state(directory.path());
    let (adapter, _) = recovery_service(&task, Vec::new());
    let mut service = recovery_service_instance(directory.path(), adapter);
    service
        .state
        .lock()
        .await
        .tasks
        .insert("task-a".to_string(), task);

    Task::exec(&service, &ttrpc_context(), exec_request("exec-a"))
        .await
        .expect("add exec process");
    service.endpoint = directory
        .path()
        .join("missing-runtime.sock")
        .to_string_lossy()
        .into_owned();
    *service.test_adapter.lock().await = None;

    let mut request = api::StartRequest::new();
    request.set_id("task-a".to_string());
    request.set_exec_id("exec-a".to_string());
    Task::start(&service, &ttrpc_context(), request)
        .await
        .expect_err("missing Runtime endpoint must reject Exec Start");

    let snapshot = service
        .task_snapshot("task-a")
        .await
        .expect("task after Runtime connection failure");
    assert_eq!(snapshot.execs["exec-a"].stage, ExecStage::Starting);
    let metadata = ShimMetadata::load(&ShimMetadata::path(directory.path()))
        .expect("load metadata")
        .expect("committed metadata");
    let persisted = metadata
        .execs()
        .iter()
        .find(|exec| exec.exec_id == "exec-a")
        .expect("persisted exec");
    assert_eq!(persisted.incarnation, 1);
    assert_eq!(persisted.stage, ExecStage::Starting);
    assert!(persisted.record.is_none());
}

#[tokio::test]
async fn rehydration_adopts_a_committed_init_start_from_exact_runtime_state() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut persisted = task_state(directory.path());
    persisted.stdin.clear();
    persisted.stdout.clear();
    persisted.stderr.clear();
    persisted.exit = None;
    persisted.exited_at = None;
    // Init lifecycle status belongs to the exact Runtime record rather than
    // shim metadata. This Created snapshot models a Start response lost before
    // the shim can observe and persist the Running record.
    persisted.record.state = StateBuilder::default()
        .version("1.3.0")
        .id(persisted.identity.container_id.as_str())
        .status(ContainerState::Created)
        .pid(4242)
        .bundle(directory.path())
        .build()
        .expect("created OCI state");
    metadata_from_task(&persisted)
        .store()
        .expect("store pre-Start metadata");

    let mut runtime = persisted.clone();
    runtime.record.state = StateBuilder::default()
        .version("1.3.0")
        .id(runtime.identity.container_id.as_str())
        .status(ContainerState::Running)
        .pid(4242)
        .bundle(directory.path())
        .build()
        .expect("running OCI state");
    let expected = runtime.record.clone();
    let (adapter, _) = recovery_service(&runtime, Vec::new());
    let service = recovery_service_instance(directory.path(), adapter);

    service
        .restore_task("task-a")
        .await
        .expect("rehydrate committed init Start");

    let restored = service
        .task_snapshot_unchecked("task-a")
        .await
        .expect("restored task");
    assert_eq!(restored.record, expected);
    assert_eq!(*restored.record.state.status(), ContainerState::Running);
    assert_eq!(*restored.record.state.pid(), Some(4242));
    service.stop_all_monitors().await;
    service.stop_all_pumps().await;
}

#[tokio::test]
async fn rehydration_replays_a_starting_exec_missing_from_runtime_inventory() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut task = task_state(directory.path());
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0},
        "args": ["/bin/true"],
        "cwd": "/"
    }))
    .expect("OCI process");
    task.exec_sequence = 1;
    task.execs.insert(
        "exec-a".to_string(),
        ExecState {
            incarnation: 1,
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
            stage: ExecStage::Starting,
            record: None,
            exit: None,
            exited_at: None,
        },
    );
    metadata_from_task(&task).store().expect("store metadata");
    let (adapter, exec_calls) = recovery_service(&task, Vec::new());
    let service = recovery_service_instance(directory.path(), adapter);

    service
        .restore_task("task-a")
        .await
        .expect("rehydrate pending exec Start");

    assert_eq!(
        exec_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "missing runtime inventory must replay the stable Exec operation once"
    );
    let restored = service
        .task_snapshot_unchecked("task-a")
        .await
        .expect("restored task");
    let exec = &restored.execs["exec-a"];
    assert_eq!(exec.stage, ExecStage::Started);
    assert_eq!(
        exec.record.as_ref().and_then(|record| record.pid),
        Some(5151)
    );
    assert_eq!(exec.incarnation, 1);

    let metadata = ShimMetadata::load(&ShimMetadata::path(directory.path()))
        .expect("load committed metadata")
        .expect("committed metadata");
    let persisted_exec = metadata
        .execs()
        .iter()
        .find(|exec| exec.exec_id == "exec-a")
        .expect("persisted exec");
    assert_eq!(persisted_exec.stage, ExecStage::Started);
    assert_eq!(
        persisted_exec.record.as_ref().and_then(|record| record.pid),
        Some(5151)
    );
    assert_eq!(persisted_exec.incarnation, 1);
    service.stop_all_monitors().await;
    service.stop_all_pumps().await;
}

#[tokio::test]
async fn exec_wait_can_arrive_before_start_and_completes_from_the_recorded_exit() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut task = task_state(directory.path());
    task.exit = None;
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0},
        "args": ["/bin/true"],
        "cwd": "/"
    }))
    .expect("OCI process");
    task.execs.insert(
        "exec-early-wait".to_string(),
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
            stage: ExecStage::Added,
            record: None,
            exit: None,
            exited_at: None,
        },
    );
    let (adapter, _) = recovery_service(&task, Vec::new());
    let service = recovery_service_instance(directory.path(), adapter);
    service
        .state
        .lock()
        .await
        .tasks
        .insert("task-a".to_string(), task.clone());

    let waiting_service = service.clone();
    let mut wait = tokio::spawn(async move {
        waiting_service
            .wait_for_recorded_exit("task-a", Some("exec-early-wait"))
            .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), &mut wait)
            .await
            .is_err(),
        "wait must remain pending before exec start"
    );

    let record = ProcessRecord {
        target: RuntimeAdapter::from_client(
            a3s_oci_sdk::RuntimeClient::new(RecoveryService {
                record: task.record.clone(),
                processes: Arc::new(std::sync::Mutex::new(Vec::new())),
                exec_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }),
            IsolationRequest::SharedHostKernel,
        )
        .process_target(
            &task.identity,
            task.record.generation,
            Some(&ExecIdentity::new("exec-early-wait", 0).expect("exec identity")),
        )
        .expect("process target"),
        pid: Some(6161),
        terminal: false,
    };
    {
        let mut state = service.state.lock().await;
        let exec = state
            .tasks
            .get_mut("task-a")
            .expect("task")
            .execs
            .get_mut("exec-early-wait")
            .expect("exec");
        exec.stage = ExecStage::Started;
        exec.record = Some(record);
    }
    service.exit_notify.notify_waiters();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), &mut wait)
            .await
            .is_err(),
        "wait must remain pending until exit is recorded"
    );

    let expected = ExitStatus::exited(23).expect("exit status");
    let exec_identity = ExecIdentity::new("exec-early-wait", 0).expect("exec identity");
    service
        .record_exit("task-a", Some(&exec_identity), expected.clone(), 6161)
        .await
        .expect("record exit");
    let (actual, pid, _) = tokio::time::timeout(std::time::Duration::from_secs(1), wait)
        .await
        .expect("wait completes")
        .expect("wait task")
        .expect("wait result");
    assert_eq!(actual, expected);
    assert_eq!(pid, 6161);
    service.stop_all_monitors().await;
}

#[tokio::test]
async fn rehydration_reuses_a_starting_exec_already_in_runtime_inventory() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut task = task_state(directory.path());
    task.exit = Some(ExitStatus::exited(0).expect("init exit"));
    task.exec_sequence = 1;
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0},
        "args": ["/bin/true"],
        "cwd": "/"
    }))
    .expect("OCI process");
    let exec_identity = ExecIdentity::new("exec-a", 1).expect("exec identity");
    let process_target = RuntimeAdapter::from_client(
        a3s_oci_sdk::RuntimeClient::new(RecoveryService {
            record: task.record.clone(),
            processes: Arc::new(std::sync::Mutex::new(Vec::new())),
            exec_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }),
        IsolationRequest::SharedHostKernel,
    )
    .process_target(&task.identity, task.record.generation, Some(&exec_identity))
    .expect("stable process target");
    let runtime_process = ProcessRecord {
        target: process_target,
        pid: Some(5151),
        terminal: false,
    };
    task.execs.insert(
        "exec-a".to_string(),
        ExecState {
            incarnation: 1,
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
            stage: ExecStage::Starting,
            record: None,
            exit: None,
            exited_at: None,
        },
    );
    metadata_from_task(&task).store().expect("store metadata");
    let (adapter, exec_calls) = recovery_service(&task, vec![runtime_process.clone()]);
    let service = recovery_service_instance(directory.path(), adapter);

    service
        .restore_task("task-a")
        .await
        .expect("rehydrate task");

    assert_eq!(
        exec_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "runtime exec must not be replayed when inventory already contains it"
    );
    let restored = service
        .task_snapshot_unchecked("task-a")
        .await
        .expect("task");
    assert_eq!(restored.execs["exec-a"].stage, ExecStage::Started);
    assert_eq!(restored.execs["exec-a"].incarnation, 1);
    assert_eq!(
        restored.execs["exec-a"].record.as_ref(),
        Some(&runtime_process)
    );
    let metadata = ShimMetadata::load(&ShimMetadata::path(directory.path()))
        .expect("load committed metadata")
        .expect("committed metadata");
    let persisted = metadata
        .execs()
        .iter()
        .find(|exec| exec.exec_id == "exec-a")
        .expect("persisted exec");
    assert_eq!(persisted.incarnation, 1);
    assert_eq!(persisted.stage, ExecStage::Started);
    assert_eq!(persisted.record.as_ref(), Some(&runtime_process));
    service.stop_all_monitors().await;
    service.stop_all_pumps().await;
}

#[tokio::test]
async fn rehydration_fails_closed_when_runtime_generation_drifts() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let task = task_state(directory.path());
    metadata_from_task(&task).store().expect("store metadata");
    let mut drifted = task.clone();
    drifted.record.generation = Generation(task.record.generation.0 + 1);
    let (adapter, _) = recovery_service(&drifted, Vec::new());
    let service = recovery_service_instance(directory.path(), adapter);

    let error = service
        .restore_task("task-a")
        .await
        .expect_err("generation drift must fail closed");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("no longer matches"));
    assert!(service.state.lock().await.tasks.is_empty());
    assert!(service.monitors.lock().await.is_empty());
}

#[tokio::test]
async fn exec_delete_response_replays_after_service_reopen() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let task = task_state(directory.path());
    metadata_from_task(&task)
        .store()
        .expect("store initial task metadata");
    let (adapter, _) = recovery_service(&task, Vec::new());
    let service = recovery_service_instance(directory.path(), adapter);
    service
        .state
        .lock()
        .await
        .tasks
        .insert("task-a".to_string(), task.clone());

    Task::exec(&service, &ttrpc_context(), exec_request("exec-a"))
        .await
        .expect("allocate exec incarnation");
    {
        let mut state = service.state.lock().await;
        let exec = state
            .tasks
            .get_mut("task-a")
            .expect("task")
            .execs
            .get_mut("exec-a")
            .expect("exec");
        exec.stage = ExecStage::Exited;
        exec.exit = Some(ExitStatus::exited(23).expect("exec exit"));
        exec.exited_at = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(23));
    }
    service
        .persist_task("task-a")
        .await
        .expect("persist exec exit");

    let mut request = api::DeleteRequest::new();
    request.set_id("task-a".to_string());
    request.set_exec_id("exec-a".to_string());
    let first = Task::delete(&service, &ttrpc_context(), request)
        .await
        .expect("delete exec before response loss");

    let (replacement_adapter, _) = recovery_service(&task, Vec::new());
    let replacement = recovery_service_instance(directory.path(), replacement_adapter);
    replacement
        .restore_task("task-a")
        .await
        .expect("restore task after exec delete response loss");

    let mut retry = api::DeleteRequest::new();
    retry.set_id("task-a".to_string());
    retry.set_exec_id("exec-a".to_string());
    let replayed = Task::delete(&replacement, &ttrpc_context(), retry)
        .await
        .expect("replay durable exec delete response");

    assert_eq!(replayed.pid(), first.pid());
    assert_eq!(replayed.exit_status(), 23);
    assert_eq!(replayed.exit_status(), first.exit_status());
    assert_eq!(replayed.exited_at(), first.exited_at());
    replacement.stop_all_monitors().await;
    replacement.stop_all_pumps().await;
}

#[tokio::test]
async fn uncommitted_exec_delete_intent_is_discarded_on_service_reopen() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let task = task_state(directory.path());
    let (adapter, _) = recovery_service(&task, Vec::new());
    let service = recovery_service_instance(directory.path(), adapter);
    service
        .state
        .lock()
        .await
        .tasks
        .insert("task-a".to_string(), task.clone());

    Task::exec(&service, &ttrpc_context(), exec_request("exec-a"))
        .await
        .expect("allocate exec incarnation");
    {
        let mut state = service.state.lock().await;
        let exec = state
            .tasks
            .get_mut("task-a")
            .expect("task")
            .execs
            .get_mut("exec-a")
            .expect("exec");
        exec.stage = ExecStage::Exited;
        exec.exit = Some(ExitStatus::exited(19).expect("exec exit"));
        exec.exited_at = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(19));
    }
    service
        .persist_task("task-a")
        .await
        .expect("persist exec exit");
    let snapshot = service
        .task_snapshot("task-a")
        .await
        .expect("task snapshot");
    let mut journal = ExecDeleteJournal::load_or_new(
        directory.path(),
        &snapshot.identity,
        snapshot.record.generation,
    )
    .expect("new exec delete journal");
    journal
        .insert(
            ExecDeleteReceipt::new(
                "exec-a".to_string(),
                snapshot.execs["exec-a"].incarnation,
                0,
                19,
                19_000_000_000,
            )
            .expect("prepared delete receipt"),
        )
        .expect("insert prepared delete receipt");
    journal.store().expect("store prepared delete receipt");

    let (replacement_adapter, _) = recovery_service(&task, Vec::new());
    let replacement = recovery_service_instance(directory.path(), replacement_adapter);
    replacement
        .restore_task("task-a")
        .await
        .expect("restore task with uncommitted delete intent");

    assert!(replacement
        .task_snapshot("task-a")
        .await
        .expect("restored task")
        .execs
        .contains_key("exec-a"));
    assert!(
        ExecDeleteJournal::load(directory.path())
            .expect("load reconciled delete journal")
            .is_none(),
        "a delete intent must not become a receipt while its exec remains durable"
    );
    replacement.stop_all_monitors().await;
    replacement.stop_all_pumps().await;
}

#[tokio::test]
async fn deleted_exec_id_reuse_allocates_durable_incarnation_across_restarts() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let task = task_state(directory.path());
    metadata_from_task(&task)
        .store()
        .expect("store initial task metadata");
    let (adapter, _) = recovery_service(&task, Vec::new());
    let service = recovery_service_instance(directory.path(), adapter);
    service
        .state
        .lock()
        .await
        .tasks
        .insert("task-a".to_string(), task.clone());

    Task::exec(&service, &ttrpc_context(), exec_request("exec-a"))
        .await
        .expect("allocate first exec incarnation");
    let first = service.task_snapshot("task-a").await.expect("first task");
    assert_eq!(first.exec_sequence, 1);
    assert_eq!(first.execs["exec-a"].incarnation, 1);
    let first_process = crate::identity::process_id("k8s.io", "task-a", "exec-a", 1)
        .expect("first process identity");

    {
        let mut state = service.state.lock().await;
        let exec = state
            .tasks
            .get_mut("task-a")
            .expect("task")
            .execs
            .get_mut("exec-a")
            .expect("first exec");
        exec.stage = ExecStage::Exited;
        exec.exit = Some(ExitStatus::exited(7).expect("first exec exit"));
        exec.exited_at = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(7));
    }
    service
        .persist_task("task-a")
        .await
        .expect("persist first exec exit");
    let mut delete = api::DeleteRequest::new();
    delete.set_id("task-a".to_string());
    delete.set_exec_id("exec-a".to_string());
    Task::delete(&service, &ttrpc_context(), delete)
        .await
        .expect("delete first exec incarnation");

    let deleted = service
        .task_snapshot("task-a")
        .await
        .expect("task after exec deletion");
    assert!(deleted.execs.is_empty());
    assert_eq!(deleted.exec_sequence, 1);
    let deleted_metadata = ShimMetadata::load(&ShimMetadata::path(directory.path()))
        .expect("load metadata")
        .expect("metadata exists");
    assert!(deleted_metadata.execs().is_empty());
    assert_eq!(deleted_metadata.exec_sequence(), 1);
    let delete_journal = ExecDeleteJournal::load_or_new(
        directory.path(),
        &deleted.identity,
        deleted.record.generation,
    )
    .expect("load first exec delete receipt");
    assert_eq!(
        delete_journal
            .receipt("exec-a")
            .expect("first exec delete receipt")
            .incarnation(),
        1
    );

    Task::exec(&service, &ttrpc_context(), exec_request("exec-a"))
        .await
        .expect("reuse deleted exec ID");
    let reused = service
        .task_snapshot("task-a")
        .await
        .expect("task after exec reuse");
    assert_eq!(reused.exec_sequence, 2);
    assert_eq!(reused.execs["exec-a"].incarnation, 2);
    assert!(
        ExecDeleteJournal::load(directory.path())
            .expect("load delete journal after exec reuse")
            .is_none(),
        "a new exec incarnation must consume the prior DeleteProcess receipt"
    );
    let reused_process = crate::identity::process_id("k8s.io", "task-a", "exec-a", 2)
        .expect("reused process identity");
    assert_ne!(first_process, reused_process);
    let stale_identity = ExecIdentity::new("exec-a", 1).expect("stale exec identity");
    let error = service
        .record_exit(
            "task-a",
            Some(&stale_identity),
            ExitStatus::exited(7).expect("stale exit"),
            5151,
        )
        .await
        .expect_err("stale monitor must not record an exit on the reused exec ID");
    let ttrpc::Error::RpcStatus(status) = error else {
        panic!("stale monitor rejection must preserve the RPC status");
    };
    assert_eq!(status.code(), ttrpc::Code::ABORTED);
    assert!(service
        .task_snapshot("task-a")
        .await
        .expect("task after stale exit")
        .execs["exec-a"]
        .exit
        .is_none());

    let (replacement_adapter, _) = recovery_service(&task, Vec::new());
    let replacement = recovery_service_instance(directory.path(), replacement_adapter);
    replacement
        .restore_task("task-a")
        .await
        .expect("restore reused exec incarnation");
    let restored = replacement
        .task_snapshot("task-a")
        .await
        .expect("restored task");
    assert_eq!(restored.exec_sequence, 2);
    assert_eq!(restored.execs["exec-a"].incarnation, 2);
}
