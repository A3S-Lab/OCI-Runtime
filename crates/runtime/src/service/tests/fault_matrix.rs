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
        12,
        "update the host/driver fault contract when the registry changes"
    );
    for point in registry {
        exercise_driver_boundary(point).await;
    }
}

async fn exercise_driver_boundary(point: FaultPoint) {
    let FaultPoint::DriverBoundary { operation, stage } = point else {
        panic!("driver registry contained non-driver point {point}");
    };
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let driver = Arc::new(RecordingDriver::supported());
    let create = create_request(&bundle_directory, "boundary-create");

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
        if matches!(operation, DriverOperation::Kill | DriverOperation::Delete) {
            setup
                .start(StartRequest {
                    context: OperationContext::new(operation_id("boundary-setup-start")),
                    target: target.clone(),
                })
                .await
                .expect("start setup container");
        }
        if operation == DriverOperation::Delete {
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
        drop(setup);
        Some(target)
    } else {
        None
    };

    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let faults: Arc<dyn FaultInjector> = injector.clone();
    let opened = HostRuntimeService::open_with_fault_injector(
        &state_root,
        Arc::clone(&driver) as Arc<dyn RuntimeDriver>,
        faults,
    )
    .await;

    if operation == DriverOperation::Capability {
        let error = opened.expect_err("capability boundary must inject");
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
    if operation != DriverOperation::Capability {
        invoke_operation(&recovered, operation, &create, target.as_ref())
            .await
            .unwrap_or_else(|error| panic!("recover {point}: {error}"));
    }

    if operation == DriverOperation::Delete {
        let missing = recovered
            .state(StateRequest {
                target: target.expect("delete target"),
            })
            .await
            .expect_err("recovered delete must remove live state");
        assert_eq!(missing.code, ErrorCode::NotFound);
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
        DriverOperation::State
            | DriverOperation::Start
            | DriverOperation::Kill
            | DriverOperation::Delete
    )
}

const fn call_matches_operation(call: &DriverCall, operation: DriverOperation) -> bool {
    matches!(
        (call, operation),
        (DriverCall::Create(_), DriverOperation::Create)
            | (DriverCall::State(_), DriverOperation::State)
            | (DriverCall::Start(_), DriverOperation::Start)
            | (DriverCall::Kill(_), DriverOperation::Kill)
            | (DriverCall::Delete(_), DriverOperation::Delete)
    )
}

async fn invoke_operation(
    service: &HostRuntimeService,
    operation: DriverOperation,
    create: &CreateRequest,
    target: Option<&ContainerTarget>,
) -> Result<()> {
    match operation {
        DriverOperation::Capability => Ok(()),
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
