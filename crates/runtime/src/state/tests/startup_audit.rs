use std::fs;
use std::sync::Arc;

use a3s_oci_core::DriverKind;
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{Error, ErrorCode, Generation};

use crate::fault::testing::RecordingFaultInjector;
use crate::fault::{DurableMutation, FaultInjector, FaultPoint, FileCommitStage};

use super::{
    create_request, operation_id, state_root, DurableStateStore, RecordOperationPreparation,
};

#[tokio::test]
async fn startup_rejects_an_unexpected_root_entry() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = state_root(&temporary);
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    drop(store);
    fs::write(root.join("foreign-state.json"), b"{}\n").expect("write foreign state");

    let error = DurableStateStore::open(&root)
        .await
        .expect_err("startup must reject an unexpected root entry");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(error.operation.as_deref(), Some("audit-state-root"));
}

#[tokio::test]
async fn startup_rejects_a_generation_record_bound_to_another_filename() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle = temporary.path().join("bundle");
    fs::create_dir(&bundle).expect("bundle directory");
    let root = state_root(&temporary);
    let request = create_request(&bundle, "audit-container", "audit-create");
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    drop(store);
    fs::copy(
        root.join("generations/audit-container.json"),
        root.join("generations/forged-container.json"),
    )
    .expect("copy mismatched generation record");

    let error = DurableStateStore::open(&root)
        .await
        .expect_err("startup must reject a mismatched generation filename");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(error.operation.as_deref(), Some("audit-generation-state"));
}

#[tokio::test]
async fn startup_rejects_an_operation_record_bound_to_another_filename() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle = temporary.path().join("bundle");
    fs::create_dir(&bundle).expect("bundle directory");
    let root = state_root(&temporary);
    let request = create_request(&bundle, "audit-container", "audit-create");
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    drop(store);
    fs::copy(
        root.join("operations/audit-create.json"),
        root.join("operations/forged-operation.json"),
    )
    .expect("copy mismatched operation record");

    let error = DurableStateStore::open(&root)
        .await
        .expect_err("startup must reject a mismatched operation filename");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(error.operation.as_deref(), Some("load-operation"));
}

#[tokio::test]
async fn startup_rejects_an_operation_without_an_allocated_generation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle = temporary.path().join("bundle");
    fs::create_dir(&bundle).expect("bundle directory");
    let root = state_root(&temporary);
    let request = create_request(&bundle, "audit-container", "audit-create");
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    drop(store);

    let source = root.join("operations/audit-create.json");
    let mut operation: serde_json::Value =
        serde_json::from_slice(&fs::read(&source).expect("read Create operation"))
            .expect("decode Create operation");
    operation["operationId"] = serde_json::json!("orphan-create");
    operation["containerId"] = serde_json::json!("orphan-container");
    fs::write(
        root.join("operations/orphan-create.json"),
        serde_json::to_vec_pretty(&operation).expect("encode orphan operation"),
    )
    .expect("write orphan operation");

    let error = DurableStateStore::open(&root)
        .await
        .expect_err("startup must reject an operation without a generation fence");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(error.operation.as_deref(), Some("audit-operation-state"));
}

#[tokio::test]
async fn startup_rejects_two_create_operations_for_one_generation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle = temporary.path().join("bundle");
    fs::create_dir(&bundle).expect("bundle directory");
    let root = state_root(&temporary);
    let request = create_request(&bundle, "audit-container", "audit-create");
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    drop(store);

    let source = root.join("operations/audit-create.json");
    let mut operation: serde_json::Value =
        serde_json::from_slice(&fs::read(&source).expect("read Create operation"))
            .expect("decode Create operation");
    operation["operationId"] = serde_json::json!("duplicate-create");
    fs::write(
        root.join("operations/duplicate-create.json"),
        serde_json::to_vec_pretty(&operation).expect("encode duplicate Create operation"),
    )
    .expect("write duplicate Create operation");

    let error = DurableStateStore::open(&root)
        .await
        .expect_err("startup must reject duplicate Create ownership");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(error.operation.as_deref(), Some("audit-operation-state"));
}

#[tokio::test]
async fn startup_rejects_a_live_container_without_its_create_operation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle = temporary.path().join("bundle");
    fs::create_dir(&bundle).expect("bundle directory");
    let root = state_root(&temporary);
    let request = create_request(&bundle, "audit-container", "audit-create");
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    store
        .complete_create(&request.context.operation_id, 4_242)
        .await
        .expect("complete create");
    drop(store);
    fs::remove_file(root.join("operations/audit-create.json"))
        .expect("remove owning Create operation");

    let error = DurableStateStore::open(&root)
        .await
        .expect_err("startup must reject an ownerless live container");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(error.operation.as_deref(), Some("audit-container-state"));
}

#[tokio::test]
async fn startup_rejects_a_live_container_below_its_generation_fence() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle = temporary.path().join("bundle");
    fs::create_dir(&bundle).expect("bundle directory");
    let root = state_root(&temporary);
    let request = create_request(&bundle, "audit-container", "audit-create");
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    store
        .complete_create(&request.context.operation_id, 4_242)
        .await
        .expect("complete create");
    drop(store);

    let generation_path = root.join("generations/audit-container.json");
    let mut generation: serde_json::Value =
        serde_json::from_slice(&fs::read(&generation_path).expect("read generation record"))
            .expect("decode generation record");
    generation["lastGeneration"] = serde_json::json!(2);
    fs::write(
        &generation_path,
        serde_json::to_vec_pretty(&generation).expect("encode advanced generation record"),
    )
    .expect("write advanced generation record");

    let error = DurableStateStore::open(&root)
        .await
        .expect_err("startup must reject a live container below its generation fence");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(error.operation.as_deref(), Some("audit-container-state"));
}

#[tokio::test]
async fn startup_rejects_a_quarantine_directory_without_an_operation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = state_root(&temporary);
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    drop(store);
    fs::create_dir(root.join("quarantine/orphan-delete.deleted"))
        .expect("create orphan quarantine directory");

    let error = DurableStateStore::open(&root)
        .await
        .expect_err("startup must reject unowned quarantine state");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(error.operation.as_deref(), Some("audit-quarantine-state"));
}

#[tokio::test]
async fn startup_rejects_quarantine_owned_by_another_container() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle = temporary.path().join("bundle");
    fs::create_dir(&bundle).expect("bundle directory");
    let root = state_root(&temporary);
    let request = create_request(&bundle, "failed-container", "failed-create");
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    let failure = Error::new(ErrorCode::FailedPrecondition, "terminal create failure")
        .for_operation("create");
    store
        .fail_operation(&request.context.operation_id, &failure)
        .await
        .expect("quarantine failed create");
    drop(store);

    let operation_path = root.join("operations/failed-create.json");
    let mut operation: serde_json::Value =
        serde_json::from_slice(&fs::read(&operation_path).expect("read failed Create operation"))
            .expect("decode failed Create operation");
    operation["containerId"] = serde_json::Value::String("forged-container".to_string());
    fs::write(
        &operation_path,
        serde_json::to_vec_pretty(&operation).expect("encode forged Create operation"),
    )
    .expect("write forged Create operation");
    let source_generation = root.join("generations/failed-container.json");
    let mut generation: serde_json::Value = serde_json::from_slice(
        &fs::read(&source_generation).expect("read failed-container generation"),
    )
    .expect("decode failed-container generation");
    generation["id"] = serde_json::json!("forged-container");
    fs::write(
        root.join("generations/forged-container.json"),
        serde_json::to_vec_pretty(&generation).expect("encode forged-container generation"),
    )
    .expect("write forged-container generation");

    let error = DurableStateStore::open(&root)
        .await
        .expect_err("startup must reject a quarantine owner mismatch");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(error.operation.as_deref(), Some("audit-quarantine-state"));
}

#[tokio::test]
async fn startup_rejects_the_same_generation_live_and_quarantined() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle = temporary.path().join("bundle");
    fs::create_dir(&bundle).expect("bundle directory");
    let root = state_root(&temporary);
    let request = create_request(&bundle, "failed-container", "failed-create");
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    let failure = Error::new(ErrorCode::FailedPrecondition, "terminal create failure")
        .for_operation("create");
    store
        .fail_operation(&request.context.operation_id, &failure)
        .await
        .expect("quarantine failed create");
    drop(store);

    let quarantined = root.join("quarantine/failed-create.failed-create");
    let live = root.join("containers/failed-container");
    fs::create_dir(&live).expect("recreate duplicate live directory");
    fs::copy(quarantined.join("config.json"), live.join("config.json"))
        .expect("copy duplicate configuration");
    fs::copy(quarantined.join("record.json"), live.join("record.json"))
        .expect("copy duplicate record");

    let error = DurableStateStore::open(&root)
        .await
        .expect_err("startup must reject a duplicated live generation");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(error.operation.as_deref(), Some("audit-quarantine-state"));
}

#[tokio::test]
async fn startup_rejects_an_unexpected_quarantined_process_entry() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle = temporary.path().join("bundle");
    fs::create_dir(&bundle).expect("bundle directory");
    let root = state_root(&temporary);
    let request = create_request(&bundle, "failed-container", "failed-create");
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    let failure = Error::new(ErrorCode::FailedPrecondition, "terminal create failure")
        .for_operation("create");
    store
        .fail_operation(&request.context.operation_id, &failure)
        .await
        .expect("quarantine failed create");
    drop(store);

    let processes = root.join("quarantine/failed-create.failed-create/processes");
    fs::create_dir(&processes).expect("create quarantined process directory");
    fs::write(processes.join("foreign-state"), b"foreign\n")
        .expect("write unexpected quarantined process entry");

    let error = DurableStateStore::open(&root)
        .await
        .expect_err("startup must reject an unexpected quarantined process entry");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(error.operation.as_deref(), Some("audit-process-state"));
}

#[tokio::test]
async fn startup_rejects_an_unclaimed_event_record() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle = temporary.path().join("bundle");
    fs::create_dir(&bundle).expect("bundle directory");
    let root = state_root(&temporary);
    let request = create_request(&bundle, "audit-container", "audit-create");
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    drop(store);
    let claim = fs::read_dir(root.join("events/keys"))
        .expect("read event claims")
        .next()
        .expect("creating event claim")
        .expect("read creating event claim")
        .path();
    fs::remove_file(claim).expect("remove creating event claim");

    let error = DurableStateStore::open(&root)
        .await
        .expect_err("startup must reject an unclaimed event record");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(error.operation.as_deref(), Some("audit-runtime-events"));
}

#[tokio::test]
async fn startup_preserves_a_recoverable_prepared_create_without_live_state() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle = temporary.path().join("bundle");
    fs::create_dir(&bundle).expect("bundle directory");
    let root = state_root(&temporary);
    let request = create_request(&bundle, "recoverable-container", "recoverable-create");
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    fs::remove_dir_all(root.join("containers/recoverable-container"))
        .expect("simulate interruption before live record commit");
    drop(store);

    let reopened = DurableStateStore::open(&root)
        .await
        .expect("prepared create remains recoverable");
    let RecordOperationPreparation::Resume(record) = reopened
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("rebuild prepared create")
    else {
        panic!("prepared create must resume");
    };
    assert_eq!(record.generation, Generation(1));
    assert_eq!(*record.state.status(), ContainerState::Creating);
    assert_eq!(
        reopened
            .load_operation(&operation_id("recoverable-create"))
            .await
            .expect("retained operation")
            .operation_id,
        operation_id("recoverable-create")
    );
}

#[tokio::test]
async fn startup_preserves_a_failed_create_until_its_quarantine_move_replays() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle = temporary.path().join("bundle");
    fs::create_dir(&bundle).expect("bundle directory");
    let root = state_root(&temporary);
    let request = create_request(&bundle, "failed-container", "failed-create");
    let point = FaultPoint::DurableFile {
        mutation: DurableMutation::RecordCreateFailure,
        stage: FileCommitStage::ParentDirectorySynced,
    };
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let faults: Arc<dyn FaultInjector> = injector.clone();
    let store = DurableStateStore::open_with_fault_injector(&root, faults)
        .await
        .expect("initialize state root");
    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    let failure = Error::new(ErrorCode::FailedPrecondition, "terminal create failure")
        .for_operation("create");

    store
        .fail_operation(&request.context.operation_id, &failure)
        .await
        .expect_err("failure journal checkpoint must inject");
    assert!(injector.fired());
    drop(store);

    let reopened = DurableStateStore::open(&root)
        .await
        .expect("failed create remains recoverable at startup");
    let replayed = reopened
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect_err("failed create must replay its terminal error");
    assert_eq!(replayed, failure);
    assert!(!root.join("containers/failed-container").exists());
    assert!(root.join("quarantine/failed-create.failed-create").is_dir());
}
