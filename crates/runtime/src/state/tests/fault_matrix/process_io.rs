use a3s_oci_sdk::{
    CloseStdinRequest, ProcessTarget, ResizeRequest, TerminalSize, WriteStdinRequest,
};

use crate::state::ProcessIoPreparation;

use super::process::prepare_running_for_process;
use super::*;

#[derive(Debug, Clone, Copy)]
enum ProcessIoKind {
    WriteStdin,
    CloseStdin,
    Resize,
}

pub(super) async fn exercise_process_io_success(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("process-io-success-create");
    let target = prepare_running_for_process(&fixture.root, &create).await;
    let kind = process_io_kind(point);
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open process-I/O success store");
    let error = drive_success(&store, &target, kind)
        .await
        .expect_err("process-I/O success checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen process-I/O success store");
    drive_success(&recovered, &target, kind)
        .await
        .unwrap_or_else(|error| panic!("recover process-I/O success after {point}: {error}"));
    drive_success(&recovered, &target, kind)
        .await
        .expect("replay recovered process-I/O success");
    assert_init_unclaimed(&recovered, &target).await;
    assert_consistent_layout(recovered.root());
}

pub(super) async fn exercise_process_io_failure(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("process-io-failure-create");
    let target = prepare_running_for_process(&fixture.root, &create).await;
    let kind = process_io_kind(point);
    let failure = terminal_failure(kind.operation_name());
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open process-I/O failure store");
    let error = drive_failure(&store, &target, kind, &failure)
        .await
        .expect_err("process-I/O failure checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen process-I/O failure store");
    drive_failure(&recovered, &target, kind, &failure)
        .await
        .unwrap_or_else(|error| panic!("recover process-I/O failure after {point}: {error}"));
    assert_init_unclaimed(&recovered, &target).await;
    assert_consistent_layout(recovered.root());
}

impl ProcessIoKind {
    const fn operation_name(self) -> &'static str {
        match self {
            Self::WriteStdin => "write-stdin",
            Self::CloseStdin => "close-stdin",
            Self::Resize => "resize",
        }
    }
}

fn process_io_kind(point: FaultPoint) -> ProcessIoKind {
    let mutation = match point {
        FaultPoint::DurableFile { mutation, .. }
        | FaultPoint::DurableDirectory { mutation, .. } => mutation,
        FaultPoint::DriverBoundary { .. } => {
            panic!("process-I/O durable scenario received driver point {point}")
        }
    };
    match mutation {
        DurableMutation::PrepareWriteStdinOperation
        | DurableMutation::ClaimWriteStdinOperation
        | DurableMutation::CompleteWriteStdinRecord
        | DurableMutation::CompleteWriteStdinOperation
        | DurableMutation::ReleaseFailedWriteStdinClaim
        | DurableMutation::RecordWriteStdinFailure => ProcessIoKind::WriteStdin,
        DurableMutation::PrepareCloseStdinOperation
        | DurableMutation::ClaimCloseStdinOperation
        | DurableMutation::CompleteCloseStdinRecord
        | DurableMutation::CompleteCloseStdinOperation
        | DurableMutation::ReleaseFailedCloseStdinClaim
        | DurableMutation::RecordCloseStdinFailure => ProcessIoKind::CloseStdin,
        DurableMutation::PrepareResizeOperation
        | DurableMutation::ClaimResizeOperation
        | DurableMutation::CompleteResizeRecord
        | DurableMutation::CompleteResizeOperation
        | DurableMutation::ReleaseFailedResizeClaim
        | DurableMutation::RecordResizeFailure => ProcessIoKind::Resize,
        _ => panic!("non-process-I/O mutation routed to process-I/O scenario: {mutation:?}"),
    }
}

async fn drive_success(
    store: &DurableStateStore,
    target: &ContainerTarget,
    kind: ProcessIoKind,
) -> a3s_oci_sdk::Result<()> {
    let process = ProcessTarget {
        container: target.clone(),
        process_id: ProcessId::init(),
    };
    match kind {
        ProcessIoKind::WriteStdin => {
            let request = WriteStdinRequest {
                context: OperationContext::new(operation_id("process-io-success-write")),
                process,
                data: b"input".to_vec(),
            };
            match store.prepare_write_stdin(&request).await? {
                ProcessIoPreparation::Prepared(_) | ProcessIoPreparation::Resume(_) => {
                    store
                        .complete_write_stdin(&request.context.operation_id)
                        .await
                }
                ProcessIoPreparation::Replayed => Ok(()),
            }
        }
        ProcessIoKind::CloseStdin => {
            let request = CloseStdinRequest {
                context: OperationContext::new(operation_id("process-io-success-close")),
                process,
            };
            match store.prepare_close_stdin(&request).await? {
                ProcessIoPreparation::Prepared(_) | ProcessIoPreparation::Resume(_) => {
                    store
                        .complete_close_stdin(&request.context.operation_id)
                        .await
                }
                ProcessIoPreparation::Replayed => Ok(()),
            }
        }
        ProcessIoKind::Resize => {
            let request = ResizeRequest {
                context: OperationContext::new(operation_id("process-io-success-resize")),
                process,
                size: TerminalSize {
                    width: 120,
                    height: 40,
                },
            };
            match store.prepare_resize(&request).await? {
                ProcessIoPreparation::Prepared(_) | ProcessIoPreparation::Resume(_) => {
                    store.complete_resize(&request.context.operation_id).await
                }
                ProcessIoPreparation::Replayed => Ok(()),
            }
        }
    }
}

async fn drive_failure(
    store: &DurableStateStore,
    target: &ContainerTarget,
    kind: ProcessIoKind,
    failure: &Error,
) -> a3s_oci_sdk::Result<()> {
    let process = ProcessTarget {
        container: target.clone(),
        process_id: ProcessId::init(),
    };
    match kind {
        ProcessIoKind::WriteStdin => {
            let request = WriteStdinRequest {
                context: OperationContext::new(operation_id("process-io-failure-write")),
                process,
                data: b"input".to_vec(),
            };
            match store.prepare_write_stdin(&request).await {
                Ok(ProcessIoPreparation::Prepared(_)) | Ok(ProcessIoPreparation::Resume(_)) => {
                    store
                        .fail_operation(&request.context.operation_id, failure)
                        .await?;
                }
                Ok(ProcessIoPreparation::Replayed) => return unexpected_success(kind),
                Err(error) if error == *failure => return Ok(()),
                Err(error) => return Err(error),
            }
            expect_failure(store.prepare_write_stdin(&request).await, failure)
        }
        ProcessIoKind::CloseStdin => {
            let request = CloseStdinRequest {
                context: OperationContext::new(operation_id("process-io-failure-close")),
                process,
            };
            match store.prepare_close_stdin(&request).await {
                Ok(ProcessIoPreparation::Prepared(_)) | Ok(ProcessIoPreparation::Resume(_)) => {
                    store
                        .fail_operation(&request.context.operation_id, failure)
                        .await?;
                }
                Ok(ProcessIoPreparation::Replayed) => return unexpected_success(kind),
                Err(error) if error == *failure => return Ok(()),
                Err(error) => return Err(error),
            }
            expect_failure(store.prepare_close_stdin(&request).await, failure)
        }
        ProcessIoKind::Resize => {
            let request = ResizeRequest {
                context: OperationContext::new(operation_id("process-io-failure-resize")),
                process,
                size: TerminalSize {
                    width: 120,
                    height: 40,
                },
            };
            match store.prepare_resize(&request).await {
                Ok(ProcessIoPreparation::Prepared(_)) | Ok(ProcessIoPreparation::Resume(_)) => {
                    store
                        .fail_operation(&request.context.operation_id, failure)
                        .await?;
                }
                Ok(ProcessIoPreparation::Replayed) => return unexpected_success(kind),
                Err(error) if error == *failure => return Ok(()),
                Err(error) => return Err(error),
            }
            expect_failure(store.prepare_resize(&request).await, failure)
        }
    }
}

fn unexpected_success(kind: ProcessIoKind) -> a3s_oci_sdk::Result<()> {
    Err(Error::new(
        ErrorCode::Conflict,
        format!(
            "failed {} operation unexpectedly replayed success",
            kind.operation_name()
        ),
    )
    .for_operation("drive-failed-process-io"))
}

async fn assert_init_unclaimed(store: &DurableStateStore, target: &ContainerTarget) {
    let container = store
        .load_stored_container(&target.id)
        .await
        .expect("load process-I/O container state");
    assert!(
        container.init_io_operations.is_empty(),
        "process-I/O operation retained its init-process claim"
    );
}
