use std::io::Write;

use crate::state::model::StoredProcess;

use super::*;

const SIGKILL: i32 = 9;
const SIGTERM: i32 = 15;

pub(super) async fn exercise_process_success(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("process-success-create");
    let target = prepare_running_for_process(&fixture.root, &create).await;
    let exec = process_exec_request(&target, "process-success-exec", "worker");
    let signal =
        process_signal_request(&target, &exec.process_id, "process-success-signal", SIGKILL);
    let expected_exit = ExitStatus::signaled(SIGKILL, false).expect("process exit");

    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open process success store");
    let error = drive_process_success(&store, &exec, &signal, &expected_exit)
        .await
        .expect_err("process success checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen process success store");
    drive_process_success(&recovered, &exec, &signal, &expected_exit)
        .await
        .unwrap_or_else(|error| panic!("recover process success after {point}: {error}"));
    let target = ProcessTarget {
        container: target.clone(),
        process_id: exec.process_id.clone(),
    };
    assert_eq!(
        recovered
            .prepare_wait_process(&WaitProcessRequest {
                process: target,
                timeout_ms: None,
            })
            .await
            .expect("replay process wait"),
        ProcessWaitPreparation::Replayed(expected_exit)
    );
    assert_consistent_layout(recovered.root());
}

pub(super) async fn exercise_exec_claim_recovery(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("exec-claim-create");
    let target = prepare_running_for_process(&fixture.root, &create).await;
    let exec = process_exec_request(&target, "exec-claim", "worker");
    let setup = DurableStateStore::open(&fixture.root)
        .await
        .expect("open exec claim setup");
    setup.prepare_exec(&exec).await.expect("prepare exec claim");
    write_split_process_state(setup.root(), &target, &exec.process_id, None, None);
    drop(setup);

    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open exec claim recovery");
    let error = drive_exec(&store, &exec)
        .await
        .expect_err("exec claim checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen exec claim recovery");
    let process = drive_exec(&recovered, &exec)
        .await
        .unwrap_or_else(|error| panic!("recover exec claim after {point}: {error}"));
    assert_eq!(process.pid, Some(5_000), "{point}");
    assert_consistent_layout(recovered.root());
}

pub(super) async fn exercise_exec_reconcile(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("exec-reconcile-create");
    let target = prepare_running_for_process(&fixture.root, &create).await;
    let exec = process_exec_request(&target, "exec-reconcile", "worker");
    let setup = DurableStateStore::open(&fixture.root)
        .await
        .expect("open exec reconcile setup");
    setup.prepare_exec(&exec).await.expect("prepare split exec");
    write_split_process_state(
        setup.root(),
        &target,
        &exec.process_id,
        Some(5_000),
        Some(exec.context.operation_id.clone()),
    );
    drop(setup);

    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open exec reconcile store");
    let error = store
        .prepare_exec(&exec)
        .await
        .expect_err("exec reconcile checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen exec reconcile store");
    let process = drive_exec(&recovered, &exec)
        .await
        .unwrap_or_else(|error| panic!("recover exec reconciliation after {point}: {error}"));
    assert_eq!(process.pid, Some(5_000), "{point}");
    assert_consistent_layout(recovered.root());
}

pub(super) async fn exercise_exec_failure(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("exec-failure-create");
    let target = prepare_running_for_process(&fixture.root, &create).await;
    let exec = process_exec_request(&target, "exec-failure", "worker");
    let failure = terminal_failure("exec");
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open exec failure store");
    let error = drive_failed_exec(&store, &exec, &failure)
        .await
        .expect_err("exec failure checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen exec failure store");
    drive_failed_exec(&recovered, &exec, &failure)
        .await
        .unwrap_or_else(|error| panic!("recover exec failure after {point}: {error}"));
    assert_process_unclaimed(&recovered, &target, &exec.process_id).await;
    assert_consistent_layout(recovered.root());
}

pub(super) async fn exercise_signal_process_failure(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("signal-failure-create");
    let target = prepare_running_for_process(&fixture.root, &create).await;
    let exec = process_exec_request(&target, "signal-failure-exec", "worker");
    let setup = DurableStateStore::open(&fixture.root)
        .await
        .expect("open signal failure setup");
    drive_exec(&setup, &exec)
        .await
        .expect("create signal target");
    drop(setup);
    let signal = process_signal_request(&target, &exec.process_id, "signal-failure", SIGTERM);
    let failure = terminal_failure("signal-process");
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open signal failure store");
    let error = drive_failed_signal_process(&store, &signal, &failure)
        .await
        .expect_err("signal failure checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen signal failure store");
    drive_failed_signal_process(&recovered, &signal, &failure)
        .await
        .unwrap_or_else(|error| panic!("recover signal failure after {point}: {error}"));
    assert_process_unclaimed(&recovered, &target, &exec.process_id).await;
    assert_consistent_layout(recovered.root());
}

async fn drive_process_success(
    store: &DurableStateStore,
    exec: &ExecRequest,
    signal: &SignalProcessRequest,
    expected_exit: &ExitStatus,
) -> a3s_oci_sdk::Result<()> {
    let process = drive_exec(store, exec).await?;
    drive_signal_process(store, signal).await?;
    let exit = drive_process_wait(
        store,
        &WaitProcessRequest {
            process: process.target,
            timeout_ms: Some(1_000),
        },
        expected_exit.clone(),
    )
    .await?;
    if exit != *expected_exit {
        return Err(Error::new(
            ErrorCode::Conflict,
            "durable process wait returned a different exit status",
        )
        .for_operation("drive-process-success"));
    }
    drive_process_wait(
        store,
        &WaitProcessRequest {
            process: ProcessTarget {
                container: exec.container.clone(),
                process_id: ProcessId::init(),
            },
            timeout_ms: Some(1_000),
        },
        ExitStatus::exited(0)?,
    )
    .await?;
    Ok(())
}

async fn drive_exec(
    store: &DurableStateStore,
    request: &ExecRequest,
) -> a3s_oci_sdk::Result<a3s_oci_sdk::ProcessRecord> {
    match store.prepare_exec(request).await? {
        ProcessOperationPreparation::Prepared(_) | ProcessOperationPreparation::Resume(_) => {
            store
                .complete_exec(
                    &request.context.operation_id,
                    5_000,
                    request.process.terminal().unwrap_or(false),
                )
                .await
        }
        ProcessOperationPreparation::Replayed(record) => Ok(record),
    }
}

async fn drive_signal_process(
    store: &DurableStateStore,
    request: &SignalProcessRequest,
) -> a3s_oci_sdk::Result<()> {
    match store.prepare_signal_process(request).await? {
        SignalProcessPreparation::Prepared(_) | SignalProcessPreparation::Resume(_) => {
            store
                .complete_signal_process(&request.context.operation_id)
                .await
        }
        SignalProcessPreparation::Replayed => Ok(()),
    }
}

async fn drive_process_wait(
    store: &DurableStateStore,
    request: &WaitProcessRequest,
    observed: ExitStatus,
) -> a3s_oci_sdk::Result<ExitStatus> {
    match store.prepare_wait_process(request).await? {
        ProcessWaitPreparation::Replayed(status) => Ok(status),
        ProcessWaitPreparation::Prepared(target) => {
            store.complete_process_wait(&target, observed).await
        }
    }
}

async fn drive_failed_exec(
    store: &DurableStateStore,
    request: &ExecRequest,
    failure: &Error,
) -> a3s_oci_sdk::Result<()> {
    match store.prepare_exec(request).await {
        Ok(ProcessOperationPreparation::Prepared(_))
        | Ok(ProcessOperationPreparation::Resume(_)) => {
            store
                .fail_operation(&request.context.operation_id, failure)
                .await?;
        }
        Ok(ProcessOperationPreparation::Replayed(_)) => {
            return Err(Error::new(
                ErrorCode::Conflict,
                "failed exec unexpectedly replayed success",
            )
            .for_operation("drive-failed-exec"));
        }
        Err(error) if error == *failure => return Ok(()),
        Err(error) => return Err(error),
    }
    expect_failure(store.prepare_exec(request).await, failure)
}

async fn drive_failed_signal_process(
    store: &DurableStateStore,
    request: &SignalProcessRequest,
    failure: &Error,
) -> a3s_oci_sdk::Result<()> {
    match store.prepare_signal_process(request).await {
        Ok(SignalProcessPreparation::Prepared(_)) | Ok(SignalProcessPreparation::Resume(_)) => {
            store
                .fail_operation(&request.context.operation_id, failure)
                .await?;
        }
        Ok(SignalProcessPreparation::Replayed) => {
            return Err(Error::new(
                ErrorCode::Conflict,
                "failed process signal unexpectedly replayed success",
            )
            .for_operation("drive-failed-signal-process"));
        }
        Err(error) if error == *failure => return Ok(()),
        Err(error) => return Err(error),
    }
    expect_failure(store.prepare_signal_process(request).await, failure)
}

pub(super) async fn prepare_running_for_process(
    root: &Path,
    create: &CreateRequest,
) -> ContainerTarget {
    let (target, start) = prepare_created_for_start(root, create).await;
    let store = DurableStateStore::open(root)
        .await
        .expect("open process start setup");
    drive_start(&store, &start)
        .await
        .expect("start process container");
    drop(store);
    target
}

fn process_exec_request(
    target: &ContainerTarget,
    operation: &str,
    process_id: &str,
) -> ExecRequest {
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", "while :; do :; done"],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .expect("valid process fixture");
    ExecRequest {
        context: OperationContext::new(operation_id(operation)),
        container: target.clone(),
        process_id: ProcessId::new(process_id).expect("process ID"),
        process,
        io: ProcessIo {
            stdin: IoMode::Null,
            stdout: IoMode::Null,
            stderr: IoMode::Null,
            terminal_size: None,
        },
    }
}

fn process_signal_request(
    target: &ContainerTarget,
    process_id: &ProcessId,
    operation: &str,
    signal: i32,
) -> SignalProcessRequest {
    SignalProcessRequest {
        context: OperationContext::new(operation_id(operation)),
        process: ProcessTarget {
            container: target.clone(),
            process_id: process_id.clone(),
        },
        signal: Signal::new(signal).expect("signal"),
    }
}

fn write_split_process_state(
    root: &Path,
    target: &ContainerTarget,
    process_id: &ProcessId,
    pid: Option<u32>,
    active_operation: Option<OperationId>,
) {
    let path = root
        .join("containers")
        .join(target.id.as_str())
        .join("processes")
        .join(format!("{}.json", process_id.as_str()));
    let mut stored: StoredProcess =
        serde_json::from_slice(&fs::read(&path).expect("read process record"))
            .expect("decode process record");
    stored.record.pid = pid;
    stored.active_operation = active_operation;
    let mut bytes = serde_json::to_vec_pretty(&stored).expect("encode split process state");
    bytes.push(b'\n');
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .expect("open split process state");
    file.write_all(&bytes).expect("write split process state");
    file.sync_all().expect("sync split process state");
}

async fn assert_process_unclaimed(
    store: &DurableStateStore,
    container: &ContainerTarget,
    process_id: &ProcessId,
) {
    let process = store
        .load_stored_process(&ProcessTarget {
            container: container.clone(),
            process_id: process_id.clone(),
        })
        .await
        .expect("load failed process state");
    assert!(
        process.active_operation.is_none(),
        "failed process operation retained its claim"
    );
}
