use super::*;

#[test]
fn recreated_running_recovery_rejects_an_exec_pid_that_aliases_init() {
    let container = ContainerTarget::exact(container_id("pid-alias"), Generation(1));
    let error = DriverRecovery::recreated_running_with_processes(
        DriverState::running(42).expect("running init"),
        vec![ProcessRecord {
            target: ProcessTarget {
                container,
                process_id: ProcessId::new("worker").expect("process ID"),
            },
            pid: Some(42),
            terminal: true,
        }],
    )
    .expect_err("recovery must keep init and Exec PIDs distinct");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("distinct from init"));
}

#[tokio::test]
async fn recreated_running_recovery_rebinds_live_exec_and_repairs_its_replay() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("recreated-running-exec-state");
    let first_driver = Arc::new(RecordingDriver::with_process_operations());
    let service = HostRuntimeService::open(
        &state_root,
        Arc::clone(&first_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("open first exec owner");
    let create = create_request(&bundle_directory, "recreated-running-exec-create");
    let created = service.create(create.clone()).await.expect("first create");
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    let start = StartRequest {
        context: OperationContext::new(operation_id("recreated-running-exec-start")),
        target: target.clone(),
    };
    service.start(start.clone()).await.expect("first start");
    let exec = exec_request(
        target.clone(),
        "recreated-running-exec",
        "replacement-worker",
    );
    let original_process = service.exec(exec.clone()).await.expect("first exec");
    assert_eq!(original_process.pid, Some(5_000));
    drop(service);

    let replacement_process = ProcessRecord {
        target: original_process.target.clone(),
        pid: Some(6_262),
        terminal: original_process.terminal,
    };
    let replacement = Arc::new(RecordingDriver::with_process_operations());
    replacement.set_recreated_running_recovery_with_processes(
        DriverState::running(5_252).expect("replacement running state"),
        vec![replacement_process.clone()],
    );
    let reopened = HostRuntimeService::open(
        &state_root,
        Arc::clone(&replacement) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("reopen around replacement exec owner");
    assert_eq!(
        reopened
            .exec(exec.clone())
            .await
            .expect("repair completed Exec response"),
        replacement_process
    );
    assert!(replacement
        .calls()
        .iter()
        .all(|call| !matches!(call, DriverCall::Exec(_))));
    drop(reopened);

    let journal_reader = Arc::new(RecordingDriver::with_process_operations());
    journal_reader.set_recovery_observation(
        DriverState::running(5_252).expect("stable replacement running state"),
    );
    let reopened_again = HostRuntimeService::open(
        &state_root,
        Arc::clone(&journal_reader) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("reopen after Exec journal repair");
    assert_eq!(
        reopened_again
            .exec(exec)
            .await
            .expect("replay rebound Exec response"),
        replacement_process
    );
    assert!(journal_reader
        .calls()
        .iter()
        .all(|call| !matches!(call, DriverCall::Exec(_))));
}

#[tokio::test]
async fn recreated_running_recovery_rejects_missing_live_exec_evidence() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("missing-recreated-exec-state");
    let first_driver = Arc::new(RecordingDriver::with_process_operations());
    let service = HostRuntimeService::open(
        &state_root,
        Arc::clone(&first_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("open first missing-evidence owner");
    let create = create_request(&bundle_directory, "missing-recreated-exec-create");
    let created = service.create(create.clone()).await.expect("first create");
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("missing-recreated-exec-start")),
            target: target.clone(),
        })
        .await
        .expect("first start");
    service
        .exec(exec_request(
            target,
            "missing-recreated-exec",
            "missing-worker",
        ))
        .await
        .expect("first exec");
    drop(service);

    let replacement = Arc::new(RecordingDriver::with_process_operations());
    replacement.set_recreated_running_recovery(
        DriverState::running(5_252).expect("replacement running state"),
    );
    let error = HostRuntimeService::open(
        &state_root,
        Arc::clone(&replacement) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect_err("replacement owner must prove every live exec process");
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(error.message.contains("missing [missing-worker]"));
}

#[tokio::test]
async fn process_operations_are_generation_fenced_durable_and_exactly_replayed() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::with_process_operations());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let info = service.features().await.expect("configured features");
    for operation in [
        RuntimeOperation::Exec,
        RuntimeOperation::SignalProcess,
        RuntimeOperation::WaitProcess,
    ] {
        assert!(info.operations.contains(&operation));
    }

    let create = create_request(&bundle_directory, "process-create");
    let created = service.create(create.clone()).await.expect("create");
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("process-start")),
            target: target.clone(),
        })
        .await
        .expect("start");

    let exec = exec_request(
        ContainerTarget::current(create.id.clone()),
        "process-exec",
        "worker",
    );
    let expected_target = ProcessTarget {
        container: target.clone(),
        process_id: exec.process_id.clone(),
    };
    let expected_record = ProcessRecord {
        target: expected_target.clone(),
        pid: Some(5_000),
        terminal: false,
    };
    assert_eq!(
        service.exec(exec.clone()).await.expect("exec"),
        expected_record
    );
    assert_eq!(
        service.exec(exec.clone()).await.expect("replayed exec"),
        expected_record
    );

    let duplicate = exec_request(target.clone(), "process-exec-duplicate", "worker");
    let error = service
        .exec(duplicate)
        .await
        .expect_err("duplicate process ID must fail before driver dispatch");
    assert_eq!(error.code, ErrorCode::AlreadyExists);

    let signal = SignalProcessRequest {
        context: OperationContext::new(operation_id("process-signal")),
        process: ProcessTarget {
            container: ContainerTarget::current(create.id.clone()),
            process_id: exec.process_id.clone(),
        },
        signal: Signal::new(9).expect("signal"),
    };
    service
        .signal_process(signal.clone())
        .await
        .expect("signal process");
    service
        .signal_process(signal)
        .await
        .expect("replayed process signal");

    let wait = WaitProcessRequest {
        process: expected_target,
        timeout_ms: Some(1_000),
    };
    let expected_exit = ExitStatus::signaled(9, false).expect("signal exit");
    assert_eq!(
        service
            .wait_process(wait.clone())
            .await
            .expect("wait process"),
        expected_exit
    );
    assert_eq!(
        service
            .wait_process(wait.clone())
            .await
            .expect("repeat process wait"),
        expected_exit
    );

    let calls_before_restart = driver.calls();
    assert_eq!(
        calls_before_restart
            .iter()
            .filter(|call| matches!(call, DriverCall::Exec(_)))
            .count(),
        1
    );
    assert_eq!(
        calls_before_restart
            .iter()
            .filter(|call| matches!(call, DriverCall::SignalProcess(_)))
            .count(),
        1
    );
    assert_eq!(
        calls_before_restart
            .iter()
            .filter(|call| matches!(call, DriverCall::WaitProcess(_)))
            .count(),
        1
    );

    drop(service);
    let reopened = open_service(&temporary, Arc::clone(&driver)).await;
    assert_eq!(
        reopened
            .exec(exec.clone())
            .await
            .expect("durable exec replay after reopen"),
        expected_record
    );
    assert_eq!(
        reopened
            .wait_process(wait)
            .await
            .expect("durable process wait after reopen"),
        expected_exit
    );
    assert_eq!(driver.calls(), calls_before_restart);

    let mut conflicting = exec;
    conflicting.process_id = ProcessId::new("different-worker").expect("process ID");
    let error = reopened
        .exec(conflicting)
        .await
        .expect_err("operation ID reuse with another process must fail");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);

    let stale_wait = WaitProcessRequest {
        process: ProcessTarget {
            container: ContainerTarget::exact(create.id, Generation(created.generation.0 + 1)),
            process_id: ProcessId::new("worker").expect("process ID"),
        },
        timeout_ms: None,
    };
    let error = reopened
        .wait_process(stale_wait)
        .await
        .expect_err("stale process generation must fail");
    assert_eq!(error.code, ErrorCode::Conflict);
}

#[tokio::test]
async fn init_wait_reconciles_an_interrupted_start_operation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::supported());
    let service = open_service(&temporary, Arc::clone(&driver)).await;

    let create = create_request(&bundle_directory, "wait-start-create");
    let created = service.create(create.clone()).await.expect("create");
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    let start = StartRequest {
        context: OperationContext::new(operation_id("wait-start")),
        target: target.clone(),
    };
    let lifecycle = service.lifecycle("test").expect("lifecycle");
    assert!(matches!(
        lifecycle
            .store
            .prepare_start(&start)
            .await
            .expect("prepare start"),
        crate::state::RecordOperationPreparation::Prepared(_)
    ));
    let bundle = lifecycle.store.bundle(&target).await.expect("bundle");
    driver
        .start(DriverStartRequest {
            context: start.context.clone(),
            target: target.clone(),
            bundle,
        })
        .await
        .expect("driver start");
    let signal = Signal::new(9).expect("signal");
    driver
        .kill(DriverKillRequest {
            context: OperationContext::new(operation_id("wait-start-driver-kill")),
            target: target.clone(),
            signal,
            all: true,
        })
        .await
        .expect("driver kill");

    let exit = service
        .wait(WaitRequest {
            target,
            timeout_ms: Some(1_000),
        })
        .await
        .expect("wait");
    assert_eq!(
        exit,
        ExitStatus::signaled(signal.get(), false).expect("exit status")
    );
    assert!(matches!(
        lifecycle
            .store
            .prepare_start(&start)
            .await
            .expect("replay reconciled start"),
        crate::state::RecordOperationPreparation::Replayed(record)
            if *record.state.status() == ContainerState::Stopped
    ));
}

#[tokio::test]
async fn init_process_wait_reconciles_an_interrupted_kill_operation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::with_process_operations());
    let service = open_service(&temporary, Arc::clone(&driver)).await;

    let create = create_request(&bundle_directory, "wait-kill-create");
    let created = service.create(create.clone()).await.expect("create");
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("wait-kill-start")),
            target: target.clone(),
        })
        .await
        .expect("start");
    let signal = Signal::new(15).expect("signal");
    let kill = KillRequest {
        context: OperationContext::new(operation_id("wait-kill")),
        target: target.clone(),
        signal,
        all: true,
    };
    let lifecycle = service.lifecycle("test").expect("lifecycle");
    assert!(matches!(
        lifecycle
            .store
            .prepare_kill(&kill)
            .await
            .expect("prepare kill"),
        crate::state::RecordOperationPreparation::Prepared(_)
    ));
    driver
        .kill(DriverKillRequest {
            context: kill.context.clone(),
            target: target.clone(),
            signal,
            all: true,
        })
        .await
        .expect("driver kill");

    let exit = service
        .wait_process(WaitProcessRequest {
            process: ProcessTarget {
                container: target,
                process_id: ProcessId::init(),
            },
            timeout_ms: Some(1_000),
        })
        .await
        .expect("wait process");
    assert_eq!(
        exit,
        ExitStatus::signaled(signal.get(), false).expect("exit status")
    );
    assert!(matches!(
        lifecycle
            .store
            .prepare_kill(&kill)
            .await
            .expect("replay reconciled kill"),
        crate::state::RecordOperationPreparation::Replayed(record)
            if *record.state.status() == ContainerState::Stopped
    ));
}

#[tokio::test]
async fn init_process_wait_reconciles_an_interrupted_process_signal() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::with_process_operations());
    let service = open_service(&temporary, Arc::clone(&driver)).await;

    let create = create_request(&bundle_directory, "wait-signal-create");
    let created = service.create(create.clone()).await.expect("create");
    let target = ContainerTarget::exact(create.id, created.generation);
    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("wait-signal-start")),
            target: target.clone(),
        })
        .await
        .expect("start");
    let signal = SignalProcessRequest {
        context: OperationContext::new(operation_id("wait-signal")),
        process: ProcessTarget {
            container: target.clone(),
            process_id: ProcessId::init(),
        },
        signal: Signal::new(15).expect("signal"),
    };
    let lifecycle = service.lifecycle("test").expect("lifecycle");
    assert!(matches!(
        lifecycle
            .store
            .prepare_signal_process(&signal)
            .await
            .expect("prepare signal"),
        crate::state::SignalProcessPreparation::Prepared(_)
    ));
    driver
        .signal_process(DriverSignalProcessRequest {
            context: signal.context.clone(),
            target: signal.process.clone(),
            signal: signal.signal,
        })
        .await
        .expect("driver signal");

    let exit = service
        .wait_process(WaitProcessRequest {
            process: signal.process.clone(),
            timeout_ms: Some(1_000),
        })
        .await
        .expect("wait process");
    assert_eq!(
        exit,
        ExitStatus::signaled(signal.signal.get(), false).expect("exit status")
    );
    assert_eq!(
        lifecycle
            .store
            .prepare_signal_process(&signal)
            .await
            .expect("replay reconciled signal"),
        crate::state::SignalProcessPreparation::Replayed
    );
    service
        .delete(DeleteRequest {
            context: OperationContext::new(operation_id("wait-signal-delete")),
            target,
            mode: DeleteMode::StoppedOnly,
        })
        .await
        .expect("delete after reconciled signal");
}
