use std::fs;
use std::sync::Arc;

use a3s_oci_sdk::{ContainerTarget, OciRuntimeService, StateRequest};

use super::*;
use crate::fault::testing::RecordingFaultInjector;
use crate::fault::{DriverBoundaryStage, DriverOperation, FaultInjector, FaultPoint};

#[tokio::test]
async fn every_host_driver_boundary_recovers_without_duplicate_effects() {
    let registry = FaultPoint::driver_registry();
    assert_eq!(
        registry.len(),
        50,
        "update the host/driver fault contract when the registry changes"
    );
    for point in registry {
        exercise_driver_boundary(point).await;
    }
}

#[tokio::test]
async fn guest_replay_acknowledgement_waits_for_the_durable_host_outcome() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let driver = Arc::new(RecordingDriver::supported());
    let setup =
        HostRuntimeService::open(&state_root, Arc::clone(&driver) as Arc<dyn RuntimeDriver>)
            .await
            .expect("open setup runtime");
    let create = create_request(&bundle_directory, "ack-boundary-create");
    let created = setup
        .create(create.clone())
        .await
        .expect("create setup container");
    drop(setup);

    let point = FaultPoint::DriverBoundary {
        operation: DriverOperation::Start,
        stage: DriverBoundaryStage::AfterCall,
    };
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let faults: Arc<dyn FaultInjector> = injector;
    let service = HostRuntimeService::open_with_fault_injector(
        &state_root,
        Arc::clone(&driver) as Arc<dyn RuntimeDriver>,
        faults,
    )
    .await
    .expect("open faulted runtime");
    let start = StartRequest {
        context: OperationContext::new(operation_id("ack-boundary-start")),
        target: ContainerTarget::exact(create.id, created.generation),
    };
    let error = service
        .start(start.clone())
        .await
        .expect_err("post-driver fault must interrupt Host commit");
    assert_injected(&error, point);
    assert!(
        !driver
            .acknowledgements()
            .contains(&start.context.operation_id),
        "a driver response is not enough to release guest replay evidence"
    );
    drop(service);

    let recovered =
        HostRuntimeService::open(&state_root, Arc::clone(&driver) as Arc<dyn RuntimeDriver>)
            .await
            .expect("reopen runtime");
    recovered
        .start(start.clone())
        .await
        .expect("resume interrupted start");
    assert_eq!(
        driver
            .acknowledgements()
            .iter()
            .filter(|operation_id| *operation_id == &start.context.operation_id)
            .count(),
        1,
        "the completed durable Host journal must acknowledge exactly once"
    );
}

async fn exercise_driver_boundary(point: FaultPoint) {
    let FaultPoint::DriverBoundary { operation, stage } = point else {
        panic!("driver registry contained non-driver point {point}");
    };
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let driver = Arc::new(RecordingDriver::with_restore_operations());
    let mut create = create_request(&bundle_directory, "boundary-create");
    create.isolation = match driver.capability.isolation_classes[0] {
        IsolationClass::SharedHostKernel => IsolationRequest::SharedHostKernel,
        IsolationClass::DedicatedVm => IsolationRequest::DedicatedVm,
        IsolationClass::SharedGuestKernel => {
            panic!("driver-boundary fixture does not use shared Guest isolation")
        }
    };

    let target = if operation_requires_created_container(operation) {
        let setup =
            HostRuntimeService::open(&state_root, Arc::clone(&driver) as Arc<dyn RuntimeDriver>)
                .await
                .expect("open setup runtime");
        let created = setup
            .create(create.clone())
            .await
            .expect("create setup container");
        let target = ContainerTarget::exact(create.id.clone(), created.generation);
        if matches!(
            operation,
            DriverOperation::Recover
                | DriverOperation::Kill
                | DriverOperation::Delete
                | DriverOperation::Wait
                | DriverOperation::Exec
                | DriverOperation::SignalProcess
                | DriverOperation::WaitProcess
                | DriverOperation::Pause
                | DriverOperation::Resume
                | DriverOperation::Processes
                | DriverOperation::Update
                | DriverOperation::Stats
                | DriverOperation::ReadOutput
                | DriverOperation::WriteStdin
                | DriverOperation::CloseStdin
                | DriverOperation::Resize
                | DriverOperation::Checkpoint
                | DriverOperation::RestoreValidation
                | DriverOperation::Restore
        ) {
            setup
                .start(StartRequest {
                    context: OperationContext::new(operation_id("boundary-setup-start")),
                    target: target.clone(),
                })
                .await
                .expect("start setup container");
        }
        if matches!(operation, DriverOperation::Delete | DriverOperation::Wait) {
            setup
                .kill(KillRequest {
                    context: OperationContext::new(operation_id("boundary-setup-kill")),
                    target: target.clone(),
                    signal: Signal::new(9).expect("signal"),
                    all: false,
                })
                .await
                .expect("stop setup container");
        }
        if matches!(
            operation,
            DriverOperation::SignalProcess | DriverOperation::WaitProcess
        ) {
            setup
                .exec(exec_request(
                    target.clone(),
                    "boundary-setup-exec",
                    "boundary-worker",
                ))
                .await
                .expect("exec setup process");
        }
        if operation == DriverOperation::WaitProcess {
            setup
                .signal_process(SignalProcessRequest {
                    context: OperationContext::new(operation_id("boundary-setup-signal")),
                    process: ProcessTarget {
                        container: target.clone(),
                        process_id: ProcessId::new("boundary-worker").expect("process ID"),
                    },
                    signal: Signal::new(9).expect("signal"),
                })
                .await
                .expect("signal setup process");
        }
        if matches!(
            operation,
            DriverOperation::Resume
                | DriverOperation::Checkpoint
                | DriverOperation::RestoreValidation
                | DriverOperation::Restore
        ) {
            setup
                .pause(ContainerOperationRequest {
                    context: OperationContext::new(operation_id("boundary-setup-pause")),
                    target: target.clone(),
                })
                .await
                .expect("pause setup container");
        }
        if matches!(
            operation,
            DriverOperation::RestoreValidation | DriverOperation::Restore
        ) {
            let artifact = create
                .bundle
                .directory()
                .parent()
                .expect("restore fixture root")
                .join("boundary-restore.checkpoint");
            setup
                .checkpoint(
                    CheckpointRequest::new(
                        OperationContext::new(operation_id("boundary-restore-checkpoint")),
                        target.clone(),
                        CheckpointArtifactPath::new(artifact)
                            .expect("restore checkpoint artifact path"),
                    )
                    .expect("restore checkpoint request"),
                )
                .await
                .expect("checkpoint restore boundary source");
        }
        drop(setup);
        Some(target)
    } else {
        None
    };

    if operation == DriverOperation::Recover {
        driver.set_recovery_exit(ExitStatus::exited(37).expect("recovery exit status"));
    }

    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let faults: Arc<dyn FaultInjector> = injector.clone();
    let opened = HostRuntimeService::open_with_fault_injector(
        &state_root,
        Arc::clone(&driver) as Arc<dyn RuntimeDriver>,
        faults,
    )
    .await;

    if matches!(
        operation,
        DriverOperation::Capability | DriverOperation::Recover
    ) {
        let error = opened.expect_err("open-time driver boundary must inject");
        assert_injected(&error, point);
    } else {
        let service = opened.expect("non-capability boundary opens runtime");
        let error = invoke_operation(&service, operation, &create, target.as_ref())
            .await
            .expect_err("selected driver boundary must inject");
        assert_injected(&error, point);
        drop(service);
    }
    assert!(injector.fired(), "fault point was not reached: {point}");

    let recovered =
        HostRuntimeService::open(&state_root, Arc::clone(&driver) as Arc<dyn RuntimeDriver>)
            .await
            .unwrap_or_else(|error| panic!("reopen after {point}: {error}"));
    if !matches!(
        operation,
        DriverOperation::Capability | DriverOperation::Recover
    ) {
        invoke_operation(&recovered, operation, &create, target.as_ref())
            .await
            .unwrap_or_else(|error| panic!("recover {point}: {error}"));
    }

    if operation == DriverOperation::Delete {
        let missing = recovered
            .state(StateRequest {
                target: target.as_ref().expect("delete target").clone(),
            })
            .await
            .expect_err("recovered delete must remove live state");
        assert_eq!(missing.code, ErrorCode::NotFound);
    }
    if operation == DriverOperation::Recover {
        let status = recovered
            .wait(WaitRequest {
                target: target.as_ref().expect("recovery target").clone(),
                timeout_ms: Some(0),
            })
            .await
            .expect("recovered init exit must be durably replayable");
        assert_eq!(
            status,
            ExitStatus::exited(37).expect("recovery exit status")
        );
    }
    if operation != DriverOperation::Capability {
        let call_count = driver
            .calls()
            .iter()
            .filter(|call| call_matches_operation(call, operation))
            .count();
        let expected = match stage {
            DriverBoundaryStage::BeforeCall => 1,
            DriverBoundaryStage::AfterCall => 2,
        };
        assert_eq!(call_count, expected, "{point}");
    }
    assert_no_transaction_files(&state_root);
}

const fn operation_requires_created_container(operation: DriverOperation) -> bool {
    matches!(
        operation,
        DriverOperation::Recover
            | DriverOperation::State
            | DriverOperation::Start
            | DriverOperation::Kill
            | DriverOperation::Delete
            | DriverOperation::Wait
            | DriverOperation::Exec
            | DriverOperation::SignalProcess
            | DriverOperation::WaitProcess
            | DriverOperation::Pause
            | DriverOperation::Resume
            | DriverOperation::Processes
            | DriverOperation::Update
            | DriverOperation::Stats
            | DriverOperation::ReadOutput
            | DriverOperation::WriteStdin
            | DriverOperation::CloseStdin
            | DriverOperation::Resize
            | DriverOperation::File
            | DriverOperation::Filesystem
            | DriverOperation::Checkpoint
            | DriverOperation::RestoreValidation
            | DriverOperation::Restore
    )
}

const fn call_matches_operation(call: &DriverCall, operation: DriverOperation) -> bool {
    matches!(
        (call, operation),
        (DriverCall::Recover(_), DriverOperation::Recover)
            | (DriverCall::Create(_), DriverOperation::Create)
            | (DriverCall::State(_), DriverOperation::State)
            | (DriverCall::Start(_), DriverOperation::Start)
            | (DriverCall::Kill(_), DriverOperation::Kill)
            | (DriverCall::Delete(_), DriverOperation::Delete)
            | (DriverCall::Wait(_), DriverOperation::Wait)
            | (DriverCall::Exec(_), DriverOperation::Exec)
            | (DriverCall::SignalProcess(_), DriverOperation::SignalProcess)
            | (DriverCall::WaitProcess(_), DriverOperation::WaitProcess)
            | (DriverCall::Pause(_), DriverOperation::Pause)
            | (DriverCall::Resume(_), DriverOperation::Resume)
            | (DriverCall::Processes(_), DriverOperation::Processes)
            | (DriverCall::Update(_), DriverOperation::Update)
            | (DriverCall::Stats(_), DriverOperation::Stats)
            | (DriverCall::ReadOutput(_), DriverOperation::ReadOutput)
            | (DriverCall::WriteStdin(_), DriverOperation::WriteStdin)
            | (DriverCall::CloseStdin(_), DriverOperation::CloseStdin)
            | (DriverCall::Resize(_), DriverOperation::Resize)
            | (DriverCall::File(_), DriverOperation::File)
            | (DriverCall::Filesystem(_), DriverOperation::Filesystem)
            | (DriverCall::Checkpoint(_), DriverOperation::Checkpoint)
            | (
                DriverCall::RestoreValidation(_),
                DriverOperation::RestoreValidation
            )
            | (DriverCall::Restore(_), DriverOperation::Restore)
    )
}

async fn invoke_operation(
    service: &HostRuntimeService,
    operation: DriverOperation,
    create: &CreateRequest,
    target: Option<&ContainerTarget>,
) -> Result<()> {
    match operation {
        DriverOperation::Capability | DriverOperation::Recover => Ok(()),
        DriverOperation::Create => {
            service.create(create.clone()).await?;
            Ok(())
        }
        DriverOperation::State => {
            service
                .state(StateRequest {
                    target: target.expect("state target").clone(),
                })
                .await?;
            Ok(())
        }
        DriverOperation::Start => {
            service
                .start(StartRequest {
                    context: OperationContext::new(operation_id("boundary-start")),
                    target: target.expect("start target").clone(),
                })
                .await?;
            Ok(())
        }
        DriverOperation::Kill => {
            service
                .kill(KillRequest {
                    context: OperationContext::new(operation_id("boundary-kill")),
                    target: target.expect("kill target").clone(),
                    signal: Signal::new(15).expect("signal"),
                    all: true,
                })
                .await?;
            Ok(())
        }
        DriverOperation::Delete => {
            service
                .delete(DeleteRequest {
                    context: OperationContext::new(operation_id("boundary-delete")),
                    target: target.expect("delete target").clone(),
                    mode: DeleteMode::StoppedOnly,
                })
                .await
        }
        DriverOperation::Wait => {
            service
                .wait(WaitRequest {
                    target: target.expect("wait target").clone(),
                    timeout_ms: Some(1_000),
                })
                .await?;
            Ok(())
        }
        DriverOperation::Exec => {
            service
                .exec(exec_request(
                    target.expect("exec target").clone(),
                    "boundary-exec",
                    "boundary-worker",
                ))
                .await?;
            Ok(())
        }
        DriverOperation::SignalProcess => {
            service
                .signal_process(SignalProcessRequest {
                    context: OperationContext::new(operation_id("boundary-signal-process")),
                    process: ProcessTarget {
                        container: target.expect("signal-process target").clone(),
                        process_id: ProcessId::new("boundary-worker").expect("process ID"),
                    },
                    signal: Signal::new(9).expect("signal"),
                })
                .await
        }
        DriverOperation::WaitProcess => {
            service
                .wait_process(WaitProcessRequest {
                    process: ProcessTarget {
                        container: target.expect("wait-process target").clone(),
                        process_id: ProcessId::new("boundary-worker").expect("process ID"),
                    },
                    timeout_ms: Some(1_000),
                })
                .await?;
            Ok(())
        }
        DriverOperation::Pause => {
            service
                .pause(ContainerOperationRequest {
                    context: OperationContext::new(operation_id("boundary-pause")),
                    target: target.expect("pause target").clone(),
                })
                .await?;
            Ok(())
        }
        DriverOperation::Resume => {
            service
                .resume(ContainerOperationRequest {
                    context: OperationContext::new(operation_id("boundary-resume")),
                    target: target.expect("resume target").clone(),
                })
                .await?;
            Ok(())
        }
        DriverOperation::Processes => {
            service
                .processes(ProcessesRequest {
                    target: target.expect("processes target").clone(),
                })
                .await?;
            Ok(())
        }
        DriverOperation::Update => {
            service
                .update(update_request(
                    target.expect("update target").clone(),
                    "boundary-update",
                ))
                .await?;
            Ok(())
        }
        DriverOperation::Stats => {
            service
                .stats(StatsRequest {
                    target: target.expect("stats target").clone(),
                })
                .await?;
            Ok(())
        }
        DriverOperation::ReadOutput => {
            service
                .read_output(ReadOutputRequest {
                    process: ProcessTarget {
                        container: target.expect("read-output target").clone(),
                        process_id: ProcessId::init(),
                    },
                    after_sequence: 0,
                    max_bytes: 1,
                    wait_timeout_ms: None,
                })
                .await?;
            Ok(())
        }
        DriverOperation::WriteStdin => {
            service
                .write_stdin(WriteStdinRequest {
                    context: OperationContext::new(operation_id("boundary-write-stdin")),
                    process: ProcessTarget {
                        container: target.expect("write-stdin target").clone(),
                        process_id: ProcessId::init(),
                    },
                    data: b"x".to_vec(),
                })
                .await
        }
        DriverOperation::CloseStdin => {
            service
                .close_stdin(CloseStdinRequest {
                    context: OperationContext::new(operation_id("boundary-close-stdin")),
                    process: ProcessTarget {
                        container: target.expect("close-stdin target").clone(),
                        process_id: ProcessId::init(),
                    },
                })
                .await
        }
        DriverOperation::Resize => {
            service
                .resize(ResizeRequest {
                    context: OperationContext::new(operation_id("boundary-resize")),
                    process: ProcessTarget {
                        container: target.expect("resize target").clone(),
                        process_id: ProcessId::init(),
                    },
                    size: TerminalSize {
                        width: 120,
                        height: 40,
                    },
                })
                .await
        }
        DriverOperation::File => {
            service
                .file(FileRequest {
                    target: target.expect("file target").clone(),
                    op: FileOp::Download,
                    path: "/fixture".to_string(),
                    data: None,
                    user: None,
                    context: None,
                })
                .await?;
            Ok(())
        }
        DriverOperation::Filesystem => {
            service
                .filesystem(FilesystemRequest {
                    target: target.expect("filesystem target").clone(),
                    op: FilesystemOp::Remove,
                    path: "/fixture".to_string(),
                    destination: None,
                    depth: 0,
                    user: None,
                    context: Some(OperationContext::new(operation_id("boundary-filesystem"))),
                })
                .await?;
            Ok(())
        }
        DriverOperation::Checkpoint => {
            let artifact = create
                .bundle
                .directory()
                .parent()
                .expect("checkpoint fixture root")
                .join("boundary-checkpoint.bin");
            service
                .checkpoint(
                    CheckpointRequest::new(
                        OperationContext::new(operation_id("boundary-checkpoint")),
                        target.expect("checkpoint target").clone(),
                        CheckpointArtifactPath::new(artifact).expect("checkpoint artifact path"),
                    )
                    .expect("checkpoint request"),
                )
                .await?;
            Ok(())
        }
        DriverOperation::RestoreValidation | DriverOperation::Restore => {
            let source = target.expect("restore source target");
            let artifact = create
                .bundle
                .directory()
                .parent()
                .expect("restore fixture root")
                .join("boundary-restore.checkpoint");
            let checkpoint = service
                .checkpoint(
                    CheckpointRequest::new(
                        OperationContext::new(operation_id("boundary-restore-checkpoint")),
                        source.clone(),
                        CheckpointArtifactPath::new(artifact.clone())
                            .expect("restore checkpoint artifact path"),
                    )
                    .expect("restore checkpoint request"),
                )
                .await?;
            service
                .restore(
                    RestoreRequest::new(
                        OperationContext::new(operation_id("boundary-restore")),
                        container_id("boundary-restored"),
                        create.bundle.clone(),
                        CheckpointArtifactPath::new(artifact).expect("restore artifact path"),
                        create.isolation.clone(),
                        create.attachments.clone(),
                        checkpoint.reference().clone(),
                    )
                    .expect("restore request"),
                )
                .await?;
            Ok(())
        }
    }
}

fn assert_injected(error: &Error, point: FaultPoint) {
    assert_eq!(error.code, ErrorCode::Unavailable, "{point}");
    assert_eq!(
        error.operation.as_deref(),
        Some("fault-injection"),
        "{point}"
    );
    assert!(error.retryable, "{point}");
    assert!(error.message.contains(&point.to_string()), "{point}");
}

fn assert_no_transaction_files(root: &Path) {
    if !root.exists() {
        return;
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).expect("inspect state directory") {
            let entry = entry.expect("state directory entry");
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                assert!(
                    !entry.file_name().to_string_lossy().ends_with(".next"),
                    "stale transaction file after recovery: {}",
                    path.display()
                );
            }
        }
    }
}
