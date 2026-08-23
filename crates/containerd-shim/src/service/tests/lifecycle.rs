use super::*;

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
