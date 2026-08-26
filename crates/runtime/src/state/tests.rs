use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::AgentInheritedDescriptorSchema;
use a3s_oci_core::DriverKind;
use a3s_oci_sdk::oci_spec::runtime::{ContainerState, LinuxResources, Process};
use a3s_oci_sdk::{
    CloseStdinRequest, ContainerId, ContainerOperationRequest, ContainerTarget, CreateAttachments,
    CreateRequest, DeleteMode, DeleteRequest, Error, ErrorCode, ExecRequest, ExitStatus,
    Generation, IoMode, IsolationRequest, KillRequest, OciBundle, OperationContext, OperationId,
    ProcessId, ProcessIo, ProcessTarget, Signal, SignalProcessRequest, StartRequest, UpdateRequest,
    WaitProcessRequest, WriteStdinRequest,
};
use tempfile::TempDir;

use super::{
    DurableStateStore, ProcessOperationPreparation, ProcessWaitPreparation,
    RecordOperationPreparation, SignalProcessPreparation,
};
use crate::DriverState;

mod events;
mod fault_matrix;
#[cfg(unix)]
mod filesystem_security;
mod recovery;
mod startup_audit;
#[cfg(windows)]
mod windows_filesystem_security;

const TEST_CONFIG: &str = concat!(
    "{\n",
    "  \"ociVersion\": \"1.3.0\",\n",
    "  \"process\": {\n",
    "    \"terminal\": false,\n",
    "    \"user\": {\"uid\": 0, \"gid\": 0},\n",
    "    \"args\": [\"/bin/true\"],\n",
    "    \"cwd\": \"/\"\n",
    "  },\n",
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
    create_request_with_config(bundle_directory, container, operation, TEST_CONFIG)
}

fn create_request_with_config(
    bundle_directory: &Path,
    container: &str,
    operation: &str,
    config: &str,
) -> CreateRequest {
    let bundle = OciBundle::from_json(bundle_directory.to_path_buf(), config)
        .expect("valid test OCI bundle");
    CreateRequest {
        context: OperationContext::new(operation_id(operation)),
        id: container_id(container),
        attachments: CreateAttachments::from_bundle(&bundle, ProcessIo::default())
            .expect("valid attachment contract"),
        bundle,
        isolation: IsolationRequest::DedicatedVm,
    }
}

fn state_root(temporary: &TempDir) -> PathBuf {
    temporary.path().join("state")
}

async fn create_container(store: &DurableStateStore, request: &CreateRequest) {
    store
        .prepare_create(request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    store
        .complete_create(&request.context.operation_id, 4_242)
        .await
        .expect("complete create");
}

#[tokio::test]
async fn replays_legacy_v1_operation_journal_with_its_original_fingerprint() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let request = create_request(
        &bundle_directory,
        "legacy-operation-container",
        "legacy-operation-create",
    );
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");

    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare current operation journal");
    let mut operation = store
        .load_operation(&request.context.operation_id)
        .await
        .expect("load current operation journal");
    operation.schema_version = super::model::OPERATION_SCHEMA_VERSION_V1.to_string();
    operation.request_digest = super::create::create_request_digest(&request, None)
        .expect("legacy request fingerprints")
        .legacy()
        .to_string();
    tokio::fs::write(
        store.operation_path(&request.context.operation_id),
        serde_json::to_vec_pretty(&operation).expect("encode legacy operation journal"),
    )
    .await
    .expect("write legacy operation journal");

    assert!(matches!(
        store
            .prepare_create(&request, DriverKind::LibkrunWhpx)
            .await
            .expect("resume legacy operation journal"),
        RecordOperationPreparation::Resume(_)
    ));
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
        "events",
    ] {
        assert!(store.root().join(entry).exists(), "{entry} must exist");
    }
    assert!(store.root().join("events/records").is_dir());
    assert!(store.root().join("events/keys").is_dir());

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
    let RecordOperationPreparation::Prepared(prepared) = prepared else {
        panic!("first create must prepare a new operation");
    };
    assert_eq!(prepared.generation, Generation(1));
    assert_eq!(*prepared.state.status(), ContainerState::Creating);
    assert_eq!(*prepared.state.pid(), None);
    let attachment_digest = request.attachments.digest().expect("attachment evidence");
    assert_eq!(
        prepared.attachments_digest.as_deref(),
        Some(attachment_digest.as_str())
    );

    let resumed = store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("resume prepared create");
    assert_eq!(
        resumed,
        RecordOperationPreparation::Resume(prepared.clone())
    );

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
    assert_eq!(
        replayed,
        RecordOperationPreparation::Replayed(completed.clone())
    );

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
async fn attachment_contract_is_fingerprinted_and_revalidated_after_reopen() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let request = create_request(
        &bundle_directory,
        "attachment-container",
        "attachment-create",
    );
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare attachment create");
    let created = store
        .complete_create(&request.context.operation_id, 4_242)
        .await
        .expect("complete attachment create");
    let expected_digest = request.attachments.digest().expect("attachment digest");
    assert_eq!(
        created.attachments_digest.as_deref(),
        Some(expected_digest.as_str())
    );
    drop(store);

    let reopened = DurableStateStore::open(&root)
        .await
        .expect("reopen state root");
    assert_eq!(
        reopened
            .prepare_create(&request, DriverKind::LibkrunWhpx)
            .await
            .expect("replay exact attachment contract"),
        RecordOperationPreparation::Replayed(created)
    );

    let mut changed = request.clone();
    changed.attachments = changed.attachments.with_process_io(ProcessIo {
        stdin: IoMode::Pipe,
        stdout: IoMode::Capture,
        stderr: IoMode::Capture,
        terminal_size: None,
    });
    let error = reopened
        .prepare_create(&changed, DriverKind::LibkrunWhpx)
        .await
        .expect_err("same operation ID cannot change attachment I/O");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("different request"));
}

#[tokio::test]
async fn durable_attachment_tampering_fails_closed_after_reopen() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let request = create_request(
        &bundle_directory,
        "tampered-attachment-container",
        "tampered-attachment-create",
    );
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    create_container(&store, &request).await;
    drop(store);

    let record_path = root
        .join("containers")
        .join(request.id.as_str())
        .join("record.json");
    let mut stored: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&record_path).expect("read durable container record"),
    )
    .expect("decode durable container record");
    stored["record"]["attachments_digest"] =
        serde_json::Value::String(format!("sha256:{}", "f".repeat(64)));
    std::fs::write(
        &record_path,
        serde_json::to_vec_pretty(&stored).expect("encode tampered record"),
    )
    .expect("write tampered durable record");

    let error = DurableStateStore::open(&root)
        .await
        .expect_err("startup audit must reject tampered attachment evidence");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("attachment digest"));
}

#[tokio::test]
async fn descriptor_bearing_create_is_durable_and_replays_after_reopen() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let request = create_request(
        &bundle_directory,
        "descriptor-container",
        "descriptor-create",
    );
    let schema = AgentInheritedDescriptorSchema::a3s_box_control_v1();
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    let prepared = store
        .prepare_create_with_inherited_descriptors(&request, DriverKind::NativeLinux, Some(&schema))
        .await
        .expect("prepare descriptor create");
    assert!(matches!(prepared, RecordOperationPreparation::Prepared(_)));
    let created = store
        .complete_create(&request.context.operation_id, 4_242)
        .await
        .expect("complete descriptor create");
    drop(store);

    let reopened = DurableStateStore::open(&root)
        .await
        .expect("reopen state root");
    let equivalent_schema = AgentInheritedDescriptorSchema::a3s_box_control_v1();
    assert_eq!(
        reopened
            .prepare_create_with_inherited_descriptors(
                &request,
                DriverKind::NativeLinux,
                Some(&equivalent_schema),
            )
            .await
            .expect("replay descriptor create"),
        RecordOperationPreparation::Replayed(created)
    );
    let error = reopened
        .prepare_create_with_inherited_descriptors(&request, DriverKind::NativeLinux, None)
        .await
        .expect_err("retry without descriptors must conflict");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
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

#[tokio::test]
async fn core_lifecycle_is_idempotent_and_generation_safe() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let create = create_request(&bundle_directory, "container-1", "create-1");
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    create_container(&store, &create).await;
    let target = ContainerTarget::exact(create.id.clone(), Generation(1));

    let duplicate_create = create_request(
        &bundle_directory,
        "container-1",
        "create-duplicate-container-id",
    );
    let duplicate_error = store
        .prepare_create(&duplicate_create, DriverKind::LibkrunWhpx)
        .await
        .expect_err("a live container ID must remain unique on the host");
    assert_eq!(duplicate_error.code, ErrorCode::AlreadyExists);
    assert!(!store
        .root()
        .join("operations")
        .join("create-duplicate-container-id.json")
        .exists());

    let start = StartRequest {
        context: OperationContext::new(operation_id("start-1")),
        target: target.clone(),
    };
    assert!(matches!(
        store.prepare_start(&start).await.expect("prepare start"),
        RecordOperationPreparation::Prepared(_)
    ));
    let missing_running_pid = store
        .complete_start(&start.context.operation_id, ContainerState::Running, None)
        .await
        .expect_err("a running Linux container must retain its PID");
    assert_eq!(missing_running_pid.code, ErrorCode::InvalidArgument);
    assert_eq!(
        *store
            .state(&target)
            .await
            .expect("invalid start completion leaves created state")
            .state
            .status(),
        ContainerState::Created
    );
    let running = store
        .complete_start(
            &start.context.operation_id,
            ContainerState::Running,
            Some(4_242),
        )
        .await
        .expect("complete start");
    assert_eq!(*running.state.status(), ContainerState::Running);
    assert_eq!(
        store.prepare_start(&start).await.expect("replay start"),
        RecordOperationPreparation::Replayed(running.clone())
    );

    let duplicate_start = StartRequest {
        context: OperationContext::new(operation_id("start-2")),
        target: target.clone(),
    };
    let start_error = store
        .prepare_start(&duplicate_start)
        .await
        .expect_err("running containers cannot be started again");
    assert_eq!(start_error.code, ErrorCode::FailedPrecondition);
    assert!(!store
        .root()
        .join("operations")
        .join("start-2.json")
        .exists());
    assert_eq!(
        store
            .state(&target)
            .await
            .expect("running state is unchanged"),
        running
    );

    let kill = KillRequest {
        context: OperationContext::new(operation_id("kill-1")),
        target: target.clone(),
        signal: Signal::new(15).expect("signal"),
        all: false,
    };
    assert!(matches!(
        store.prepare_kill(&kill).await.expect("prepare kill"),
        RecordOperationPreparation::Prepared(_)
    ));
    let stopped = store
        .complete_kill(&kill.context.operation_id, ContainerState::Stopped, None)
        .await
        .expect("complete kill");
    assert_eq!(*stopped.state.status(), ContainerState::Stopped);
    assert_eq!(*stopped.state.pid(), None);
    assert_eq!(
        store.prepare_kill(&kill).await.expect("replay kill"),
        RecordOperationPreparation::Replayed(stopped.clone())
    );

    let stopped_kill = KillRequest {
        context: OperationContext::new(operation_id("kill-stopped")),
        target: target.clone(),
        signal: Signal::new(9).expect("signal"),
        all: false,
    };
    let kill_error = store
        .prepare_kill(&stopped_kill)
        .await
        .expect_err("stopped containers cannot be signaled");
    assert_eq!(kill_error.code, ErrorCode::FailedPrecondition);
    assert!(!store
        .root()
        .join("operations")
        .join("kill-stopped.json")
        .exists());
    assert_eq!(
        store
            .state(&target)
            .await
            .expect("stopped state is unchanged"),
        stopped
    );

    let delete = DeleteRequest {
        context: OperationContext::new(operation_id("delete-1")),
        target,
        mode: DeleteMode::StoppedOnly,
    };
    assert!(matches!(
        store.prepare_delete(&delete).await.expect("prepare delete"),
        super::DeletePreparation::Prepared(_)
    ));
    store
        .complete_delete(&delete.context.operation_id)
        .await
        .expect("complete delete");
    assert_eq!(
        store.prepare_delete(&delete).await.expect("replay delete"),
        super::DeletePreparation::Replayed
    );
    let missing = store
        .state(&ContainerTarget::current(create.id.clone()))
        .await
        .expect_err("deleted container must not have state");
    assert_eq!(missing.code, ErrorCode::NotFound);

    let recreate = create_request(&bundle_directory, "container-1", "create-2");
    let RecordOperationPreparation::Prepared(recreated) = store
        .prepare_create(&recreate, DriverKind::LibkrunWhpx)
        .await
        .expect("container ID may be reused after delete")
    else {
        panic!("recreate must allocate a new generation");
    };
    assert_eq!(recreated.generation, Generation(2));
}

#[tokio::test]
async fn init_io_claims_are_disjoint_from_start_and_each_other() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let create = create_request(&bundle_directory, "io-start-container", "io-start-create");
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    create_container(&store, &create).await;
    let target = ContainerTarget::exact(create.id, Generation(1));
    let process = ProcessTarget {
        container: target.clone(),
        process_id: ProcessId::init(),
    };
    let write = WriteStdinRequest {
        context: OperationContext::new(operation_id("io-before-start-write")),
        process: process.clone(),
        data: vec![0x5a; 64 * 1024],
    };
    let close = CloseStdinRequest {
        context: OperationContext::new(operation_id("io-before-start-close")),
        process,
    };

    assert!(matches!(
        store
            .prepare_write_stdin(&write)
            .await
            .expect("prepare created-state stdin write"),
        super::ProcessIoPreparation::Prepared(_)
    ));
    assert!(matches!(
        store
            .prepare_close_stdin(&close)
            .await
            .expect("prepare concurrent created-state stdin close"),
        super::ProcessIoPreparation::Prepared(_)
    ));

    let start = StartRequest {
        context: OperationContext::new(operation_id("io-concurrent-start")),
        target,
    };
    assert!(matches!(
        store
            .prepare_start(&start)
            .await
            .expect("start must not conflict with init I/O"),
        RecordOperationPreparation::Prepared(_)
    ));

    store
        .complete_write_stdin(&write.context.operation_id)
        .await
        .expect("complete stdin write while start remains claimed");
    let after_write = store
        .load_stored_container(&start.target.id)
        .await
        .expect("load concurrent state");
    assert_eq!(
        after_write.active_operation.as_ref(),
        Some(&start.context.operation_id),
        "stdin completion must preserve the lifecycle claim"
    );
    assert_eq!(after_write.init_io_operations.len(), 1);

    store
        .complete_close_stdin(&close.context.operation_id)
        .await
        .expect("complete stdin close");
    let after_close = store
        .load_stored_container(&start.target.id)
        .await
        .expect("load released I/O state");
    assert!(after_close.init_io_operations.is_empty());
    assert_eq!(
        after_close.active_operation.as_ref(),
        Some(&start.context.operation_id)
    );

    store
        .complete_start(
            &start.context.operation_id,
            ContainerState::Running,
            Some(4_242),
        )
        .await
        .expect("complete start after concurrent I/O");
}

#[tokio::test]
async fn legacy_init_io_claim_migrates_when_start_arrives_after_reopen() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let create = create_request(
        &bundle_directory,
        "legacy-io-start-container",
        "legacy-io-start-create",
    );
    let root = state_root(&temporary);
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    create_container(&store, &create).await;
    let target = ContainerTarget::exact(create.id, Generation(1));
    let write = WriteStdinRequest {
        context: OperationContext::new(operation_id("legacy-io-before-start-write")),
        process: ProcessTarget {
            container: target.clone(),
            process_id: ProcessId::init(),
        },
        data: b"input-before-start".to_vec(),
    };
    assert!(matches!(
        store
            .prepare_write_stdin(&write)
            .await
            .expect("prepare stdin write"),
        super::ProcessIoPreparation::Prepared(_)
    ));

    let record_path = store
        .container_directory(&target.id)
        .join(super::CONTAINER_RECORD_FILE);
    let mut legacy = store
        .load_stored_container(&target.id)
        .await
        .expect("load prepared stdin state");
    assert!(legacy
        .init_io_operations
        .remove(&write.context.operation_id));
    legacy.active_operation = Some(write.context.operation_id.clone());
    std::fs::write(
        &record_path,
        serde_json::to_vec_pretty(&legacy).expect("encode legacy container record"),
    )
    .expect("write legacy container record");
    drop(store);

    let reopened = DurableStateStore::open(&root)
        .await
        .expect("reopen legacy state root");
    let start = StartRequest {
        context: OperationContext::new(operation_id("legacy-io-direct-start")),
        target,
    };
    assert!(matches!(
        reopened
            .prepare_start(&start)
            .await
            .expect("start must migrate the old init I/O claim"),
        RecordOperationPreparation::Prepared(_)
    ));
    let migrated = reopened
        .load_stored_container(&start.target.id)
        .await
        .expect("load migrated container record");
    assert_eq!(
        migrated.active_operation.as_ref(),
        Some(&start.context.operation_id)
    );
    assert_eq!(
        migrated.init_io_operations,
        std::collections::BTreeSet::from([write.context.operation_id.clone()])
    );

    reopened
        .complete_write_stdin(&write.context.operation_id)
        .await
        .expect("complete migrated stdin operation");
    let after_write = reopened
        .load_stored_container(&start.target.id)
        .await
        .expect("load state after migrated stdin completion");
    assert!(after_write.init_io_operations.is_empty());
    assert_eq!(
        after_write.active_operation.as_ref(),
        Some(&start.context.operation_id),
        "old stdin completion must preserve the newer start claim"
    );
    reopened
        .complete_start(
            &start.context.operation_id,
            ContainerState::Running,
            Some(4_242),
        )
        .await
        .expect("complete start after old stdin migration");
}

#[tokio::test]
async fn delete_retry_waits_for_every_init_io_claim_to_finish() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let create = create_request(&bundle_directory, "delete-io-container", "delete-io-create");
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    create_container(&store, &create).await;
    let target = ContainerTarget::exact(create.id, Generation(1));
    let write = WriteStdinRequest {
        context: OperationContext::new(operation_id("delete-io-write")),
        process: ProcessTarget {
            container: target.clone(),
            process_id: ProcessId::init(),
        },
        data: b"pending-input".to_vec(),
    };
    store
        .prepare_write_stdin(&write)
        .await
        .expect("prepare pending stdin write");

    let delete = DeleteRequest {
        context: OperationContext::new(operation_id("delete-after-io")),
        target,
        mode: DeleteMode::Force,
    };
    let first = store
        .prepare_delete(&delete)
        .await
        .expect_err("delete must wait for pending init I/O");
    assert_eq!(first.code, ErrorCode::Conflict);
    assert!(first.retryable);

    store
        .complete_write_stdin(&write.context.operation_id)
        .await
        .expect("complete pending stdin write");
    assert!(matches!(
        store
            .prepare_delete(&delete)
            .await
            .expect("same delete identity resumes after I/O completion"),
        super::DeletePreparation::Prepared(_)
    ));
    store
        .complete_delete(&delete.context.operation_id)
        .await
        .expect("complete delete after I/O drain");
}

#[tokio::test]
async fn freezer_state_is_durable_idempotent_and_generation_fenced() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let create = create_request(&bundle_directory, "freezer-container", "freezer-create");
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    create_container(&store, &create).await;
    let target = ContainerTarget::exact(create.id.clone(), Generation(1));
    let start = StartRequest {
        context: OperationContext::new(operation_id("freezer-start")),
        target: target.clone(),
    };
    store.prepare_start(&start).await.expect("prepare start");
    store
        .complete_start(
            &start.context.operation_id,
            ContainerState::Running,
            Some(4_242),
        )
        .await
        .expect("complete start");

    let pause = ContainerOperationRequest {
        context: OperationContext::new(operation_id("freezer-pause")),
        target: target.clone(),
    };
    assert!(matches!(
        store.prepare_pause(&pause).await.expect("prepare pause"),
        RecordOperationPreparation::Prepared(_)
    ));
    let paused = store
        .complete_pause(
            &pause.context.operation_id,
            ContainerState::Running,
            Some(4_242),
            true,
        )
        .await
        .expect("complete pause");
    assert!(paused.is_paused());
    assert_eq!(
        store.prepare_pause(&pause).await.expect("replay pause"),
        RecordOperationPreparation::Replayed(paused.clone())
    );
    assert!(store
        .state(&target)
        .await
        .expect("load paused state")
        .is_paused());

    let resume = ContainerOperationRequest {
        context: OperationContext::new(operation_id("freezer-resume")),
        target: target.clone(),
    };
    assert!(matches!(
        store.prepare_resume(&resume).await.expect("prepare resume"),
        RecordOperationPreparation::Prepared(_)
    ));
    let running = store
        .complete_resume(
            &resume.context.operation_id,
            ContainerState::Running,
            Some(4_242),
            false,
        )
        .await
        .expect("complete resume");
    assert!(!running.is_paused());
    assert_eq!(
        store.prepare_resume(&resume).await.expect("replay resume"),
        RecordOperationPreparation::Replayed(running)
    );

    let stale = ContainerOperationRequest {
        context: OperationContext::new(operation_id("freezer-stale")),
        target: ContainerTarget::exact(create.id, Generation(2)),
    };
    assert_eq!(
        store
            .prepare_pause(&stale)
            .await
            .expect_err("stale freezer generation must fail")
            .code,
        ErrorCode::Conflict
    );
}

#[tokio::test]
async fn recreated_paused_running_process_rebinds_all_completed_setup_journals() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let create = create_request(
        &bundle_directory,
        "paused-recovery-container",
        "paused-recovery-create",
    );
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    create_container(&store, &create).await;
    let target = ContainerTarget::exact(create.id.clone(), Generation(1));
    let start = StartRequest {
        context: OperationContext::new(operation_id("paused-recovery-start")),
        target: target.clone(),
    };
    store.prepare_start(&start).await.expect("prepare start");
    store
        .complete_start(
            &start.context.operation_id,
            ContainerState::Running,
            Some(4_242),
        )
        .await
        .expect("complete start");
    let pause = ContainerOperationRequest {
        context: OperationContext::new(operation_id("paused-recovery-pause")),
        target: target.clone(),
    };
    store.prepare_pause(&pause).await.expect("prepare pause");
    store
        .complete_pause(
            &pause.context.operation_id,
            ContainerState::Running,
            Some(4_242),
            true,
        )
        .await
        .expect("complete pause");

    let replacement = DriverState::running(5_151)
        .and_then(|state| state.with_paused(true))
        .expect("paused replacement state");
    let recovered = store
        .observe_recreated_paused_running_process(&target, replacement)
        .await
        .expect("rebind paused process");
    assert_eq!(*recovered.state.pid(), Some(5_151));
    assert!(recovered.is_paused());

    let RecordOperationPreparation::Replayed(created) = store
        .prepare_create(&create, DriverKind::LibkrunWhpx)
        .await
        .expect("replay rebound Create")
    else {
        panic!("Create must replay");
    };
    assert_eq!(*created.state.pid(), Some(5_151));
    assert_eq!(*created.state.status(), ContainerState::Created);
    assert!(!created.is_paused());

    let RecordOperationPreparation::Replayed(started) = store
        .prepare_start(&start)
        .await
        .expect("replay rebound Start")
    else {
        panic!("Start must replay");
    };
    assert_eq!(*started.state.pid(), Some(5_151));
    assert_eq!(*started.state.status(), ContainerState::Running);
    assert!(!started.is_paused());

    let RecordOperationPreparation::Replayed(paused) = store
        .prepare_pause(&pause)
        .await
        .expect("replay rebound Pause")
    else {
        panic!("Pause must replay");
    };
    assert_eq!(*paused.state.pid(), Some(5_151));
    assert!(paused.is_paused());
}

#[tokio::test]
async fn created_container_can_be_killed_before_start_and_force_deleted() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let create = create_request(&bundle_directory, "container-1", "create-1");
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    create_container(&store, &create).await;
    let target = ContainerTarget::exact(create.id.clone(), Generation(1));

    let stopped_only = DeleteRequest {
        context: OperationContext::new(operation_id("delete-stopped-only")),
        target: target.clone(),
        mode: DeleteMode::StoppedOnly,
    };
    let error = store
        .prepare_delete(&stopped_only)
        .await
        .expect_err("OCI delete must reject a created container");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(!store
        .root()
        .join("operations")
        .join("delete-stopped-only.json")
        .exists());
    assert_eq!(
        *store
            .state(&target)
            .await
            .expect("created state is unchanged")
            .state
            .status(),
        ContainerState::Created
    );

    let kill = KillRequest {
        context: OperationContext::new(operation_id("kill-created")),
        target: target.clone(),
        signal: Signal::new(9).expect("signal"),
        all: false,
    };
    store.prepare_kill(&kill).await.expect("prepare kill");
    let stopped = store
        .complete_kill(&kill.context.operation_id, ContainerState::Stopped, None)
        .await
        .expect("created init may exit before start");
    assert_eq!(*stopped.state.status(), ContainerState::Stopped);

    let force = DeleteRequest {
        context: OperationContext::new(operation_id("delete-force")),
        target,
        mode: DeleteMode::Force,
    };
    store
        .prepare_delete(&force)
        .await
        .expect("prepare force delete");
    store
        .complete_delete(&force.context.operation_id)
        .await
        .expect("complete force delete");
}

#[tokio::test]
async fn start_revalidates_durable_process_before_journaling() {
    const NO_PROCESS: &str = "{\"ociVersion\":\"1.3.0\",\"root\":{\"path\":\"rootfs\"}}";

    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let create =
        create_request_with_config(&bundle_directory, "container-1", "create-1", NO_PROCESS);
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    create_container(&store, &create).await;
    let start = StartRequest {
        context: OperationContext::new(operation_id("start-without-process")),
        target: ContainerTarget::exact(create.id, Generation(1)),
    };

    let error = store
        .prepare_start(&start)
        .await
        .expect_err("start requires a durable process");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(!store
        .root()
        .join("operations")
        .join("start-without-process.json")
        .exists());
}

#[tokio::test]
async fn completed_operation_replays_after_its_deadline_and_delete_move_recovers() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let mut create = create_request(&bundle_directory, "container-1", "create-1");
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    create_container(&store, &create).await;

    create.context.deadline_unix_ms = Some(1);
    assert!(matches!(
        store
            .prepare_create(&create, DriverKind::LibkrunWhpx)
            .await
            .expect("completed work replays after its deadline"),
        RecordOperationPreparation::Replayed(_)
    ));

    let target = ContainerTarget::exact(create.id, Generation(1));
    let kill = KillRequest {
        context: OperationContext::new(operation_id("kill-1")),
        target: target.clone(),
        signal: Signal::new(9).expect("signal"),
        all: false,
    };
    store.prepare_kill(&kill).await.expect("prepare kill");
    store
        .complete_kill(&kill.context.operation_id, ContainerState::Stopped, None)
        .await
        .expect("complete kill");
    let delete = DeleteRequest {
        context: OperationContext::new(operation_id("delete-crash")),
        target,
        mode: DeleteMode::StoppedOnly,
    };
    store.prepare_delete(&delete).await.expect("prepare delete");
    std::fs::rename(
        store.root().join("containers").join("container-1"),
        store.root().join("quarantine").join("delete-crash.deleted"),
    )
    .expect("simulate crash after durable directory move");

    let recreate = create_request(
        &bundle_directory,
        "container-1",
        "create-after-delete-crash",
    );
    let RecordOperationPreparation::Prepared(recreated) = store
        .prepare_create(&recreate, DriverKind::LibkrunWhpx)
        .await
        .expect("ID reuse may occur before delete journal recovery")
    else {
        panic!("recreate must prepare a new generation");
    };
    assert_eq!(recreated.generation, Generation(2));
    assert_eq!(
        store
            .prepare_delete(&delete)
            .await
            .expect("prepared delete reconciles its tombstone"),
        super::DeletePreparation::Replayed
    );
}

#[tokio::test]
async fn prepared_create_rebuilds_missing_durable_records_after_a_crash() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let request = create_request(&bundle_directory, "container-1", "create-recover");
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");

    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    std::fs::remove_dir_all(store.root().join("containers").join("container-1"))
        .expect("simulate crash before durable create record");

    let recovered = store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("rebuild prepared create");
    let RecordOperationPreparation::Resume(recovered) = recovered else {
        panic!("recovered create must resume the original operation");
    };
    assert_eq!(recovered.generation, Generation(1));
    assert_eq!(*recovered.state.status(), ContainerState::Creating);
    assert_eq!(
        store
            .bundle(&ContainerTarget::exact(request.id, Generation(1)))
            .await
            .expect("recovered bundle")
            .config_json(),
        TEST_CONFIG
    );
}

#[tokio::test]
async fn failed_create_replays_its_exact_error_and_finishes_quarantine() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let request = create_request(&bundle_directory, "container-1", "create-failed");
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    let failure =
        Error::new(ErrorCode::FailedPrecondition, "driver rejected create").for_operation("create");
    store
        .fail_operation(&request.context.operation_id, &failure)
        .await
        .expect("journal failed create");

    let tombstone = store
        .root()
        .join("quarantine")
        .join("create-failed.failed-create");
    let live = store.root().join("containers").join("container-1");
    std::fs::rename(&tombstone, &live)
        .expect("simulate crash after failure journal and before quarantine");

    assert_eq!(
        store
            .prepare_create(&request, DriverKind::LibkrunWhpx)
            .await
            .expect_err("failed operation must replay"),
        failure
    );
    assert!(!live.exists());
    assert!(tombstone.exists());
}

#[tokio::test]
async fn state_observation_commits_start_and_kill_after_host_crashes() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let create = create_request(&bundle_directory, "container-1", "create-1");
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    create_container(&store, &create).await;
    let target = ContainerTarget::exact(create.id, Generation(1));

    let start = StartRequest {
        context: OperationContext::new(operation_id("start-crash")),
        target: target.clone(),
    };
    store.prepare_start(&start).await.expect("prepare start");
    let running = store
        .observe_state(&target, ContainerState::Running, Some(4_242))
        .await
        .expect("reconcile driver start");
    assert_eq!(*running.state.status(), ContainerState::Running);
    assert_eq!(
        store.prepare_start(&start).await.expect("replay start"),
        RecordOperationPreparation::Replayed(running)
    );

    let kill = KillRequest {
        context: OperationContext::new(operation_id("kill-crash")),
        target: target.clone(),
        signal: Signal::new(9).expect("signal"),
        all: false,
    };
    store.prepare_kill(&kill).await.expect("prepare kill");
    let stopped = store
        .observe_state(&target, ContainerState::Stopped, None)
        .await
        .expect("reconcile driver kill");
    assert_eq!(*stopped.state.status(), ContainerState::Stopped);
    assert_eq!(
        store.prepare_kill(&kill).await.expect("replay kill"),
        RecordOperationPreparation::Replayed(stopped)
    );
}
