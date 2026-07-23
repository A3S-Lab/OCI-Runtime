use std::path::{Path, PathBuf};

use a3s_oci_core::DriverKind;
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerId, ContainerTarget, CreateRequest, ErrorCode, Generation, IsolationRequest,
    OciBundle, OperationContext, OperationId, ProcessIo,
};
use tempfile::TempDir;

use super::{CreatePreparation, DurableStateStore};

const TEST_CONFIG: &str = concat!(
    "{\n",
    "  \"ociVersion\": \"1.3.0\",\n",
    "  \"root\": {\"path\": \"rootfs\", \"readonly\": true},\n",
    "  \"annotations\": {\"dev.a3s.test\": \"durable-state\"}\n",
    "}\n",
);

fn identifier<T>(value: &str, constructor: impl FnOnce(String) -> a3s_oci_sdk::Result<T>) -> T {
    constructor(value.to_string()).unwrap_or_else(|error| panic!("valid test identifier: {error}"))
}

fn container_id(value: &str) -> ContainerId {
    identifier(value, ContainerId::new)
}

fn operation_id(value: &str) -> OperationId {
    identifier(value, OperationId::new)
}

fn create_request(bundle_directory: &Path, container: &str, operation: &str) -> CreateRequest {
    let bundle = OciBundle::from_json(bundle_directory.to_path_buf(), TEST_CONFIG)
        .expect("valid test OCI bundle");
    CreateRequest {
        context: OperationContext::new(operation_id(operation)),
        id: container_id(container),
        bundle,
        isolation: IsolationRequest::DedicatedVm,
        io: ProcessIo::default(),
    }
}

fn state_root(temporary: &TempDir) -> PathBuf {
    temporary.path().join("state")
}

#[tokio::test]
async fn initializes_and_exclusively_locks_an_absolute_root() {
    let relative_error = DurableStateStore::open(Path::new("relative-state"))
        .await
        .expect_err("relative state roots must be rejected");
    assert_eq!(relative_error.code, ErrorCode::InvalidArgument);

    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = state_root(&temporary);
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");

    assert_eq!(
        std::fs::canonicalize(&root).expect("canonical state root"),
        store.root()
    );
    for entry in [
        ".lock",
        "root.json",
        "containers",
        "generations",
        "operations",
        "quarantine",
    ] {
        assert!(store.root().join(entry).exists(), "{entry} must exist");
    }

    let lock_error = DurableStateStore::open(&root)
        .await
        .expect_err("a state root must have exactly one writer");
    assert_eq!(lock_error.code, ErrorCode::Conflict);

    drop(store);
    DurableStateStore::open(&root)
        .await
        .expect("the root lock must be released with the store");
}

#[tokio::test]
async fn create_is_durable_idempotent_and_generation_fenced() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let request = create_request(&bundle_directory, "container-1", "create-1");
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");

    let prepared = store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    let CreatePreparation::Prepared(prepared) = prepared else {
        panic!("first create must prepare a new operation");
    };
    assert_eq!(prepared.generation, Generation(1));
    assert_eq!(*prepared.state.status(), ContainerState::Creating);
    assert_eq!(*prepared.state.pid(), None);

    let resumed = store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("resume prepared create");
    assert_eq!(resumed, CreatePreparation::Resume(prepared.clone()));

    let completed = store
        .complete_create(&request.context.operation_id, 4_242)
        .await
        .expect("complete create");
    assert_eq!(*completed.state.status(), ContainerState::Created);
    assert_eq!(*completed.state.pid(), Some(4_242));

    let replayed = store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("replay completed create");
    assert_eq!(replayed, CreatePreparation::Replayed(completed.clone()));

    let exact = ContainerTarget::exact(request.id.clone(), Generation(1));
    assert_eq!(
        store.state(&exact).await.expect("load exact generation"),
        completed
    );
    let stale_error = store
        .state(&ContainerTarget::exact(request.id.clone(), Generation(2)))
        .await
        .expect_err("a mismatched generation must be rejected");
    assert_eq!(stale_error.code, ErrorCode::Conflict);

    let durable_bundle = store.bundle(&exact).await.expect("load bundle snapshot");
    assert_eq!(durable_bundle.config_json(), TEST_CONFIG);
    assert_eq!(
        durable_bundle.config_digest(),
        request.bundle.config_digest()
    );
    assert_eq!(durable_bundle.directory(), bundle_directory);

    drop(store);
    let reopened = DurableStateStore::open(&root)
        .await
        .expect("reopen durable state");
    assert_eq!(
        reopened
            .state(&ContainerTarget::current(request.id))
            .await
            .expect("state must survive reopen"),
        completed
    );
}

#[tokio::test]
async fn operation_id_cannot_be_reused_for_a_different_request() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let first = create_request(&bundle_directory, "container-1", "shared-operation");
    let second = create_request(&bundle_directory, "container-2", "shared-operation");
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");

    store
        .prepare_create(&first, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare first request");
    let error = store
        .prepare_create(&second, DriverKind::LibkrunWhpx)
        .await
        .expect_err("operation IDs are globally idempotent");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("different request"));
    assert!(!store.root().join("containers").join("container-2").exists());
}

#[tokio::test]
async fn expired_deadline_and_invalid_pid_do_not_commit_state() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let mut request = create_request(&bundle_directory, "container-1", "create-1");
    request.context.deadline_unix_ms = Some(1);
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");

    let deadline_error = store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect_err("expired operation must fail before mutation");
    assert_eq!(deadline_error.code, ErrorCode::DeadlineExceeded);
    assert_eq!(
        std::fs::read_dir(store.root().join("operations"))
            .expect("operations directory")
            .count(),
        0
    );
    assert_eq!(
        std::fs::read_dir(store.root().join("containers"))
            .expect("containers directory")
            .count(),
        0
    );

    request.context.deadline_unix_ms = None;
    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare valid create");
    let pid_error = store
        .complete_create(&request.context.operation_id, 0)
        .await
        .expect_err("invalid PID must not commit create");
    assert_eq!(pid_error.code, ErrorCode::InvalidArgument);
    assert_eq!(
        *store
            .state(&ContainerTarget::current(request.id))
            .await
            .expect("prepared state remains readable")
            .state
            .status(),
        ContainerState::Creating
    );
}
