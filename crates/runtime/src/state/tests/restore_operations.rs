use a3s_oci_core::HostPlatform;
use a3s_oci_sdk::{
    CheckpointArtifactPath, CheckpointCompatibility, CheckpointDigest, CheckpointFormat,
    CheckpointReference, ContainerRecord, RestoreRequest, RuntimeArtifact,
};

use crate::state::model::{
    StoredOperationKind, StoredOperationRequest, StoredOperationStatus, OPERATION_SCHEMA_VERSION,
};
use crate::state::{RestoreOperationLookup, RestoreOperationPreparation};

use super::*;

struct RestoreFixture {
    temporary: TempDir,
    store: DurableStateStore,
    create: CreateRequest,
    source: ContainerRecord,
}

async fn restore_fixture() -> RestoreFixture {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("open restore state store");
    let create = create_request(
        &bundle_directory,
        "restore-state-source",
        "restore-state-source-create",
    );
    create_container(&store, &create).await;
    let target = ContainerTarget::exact(create.id.clone(), Generation(1));
    let start = StartRequest {
        context: OperationContext::new(operation_id("restore-state-source-start")),
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
        context: OperationContext::new(operation_id("restore-state-source-pause")),
        target,
    };
    store.prepare_pause(&pause).await.expect("prepare pause");
    let source = store
        .complete_pause(
            &pause.context.operation_id,
            ContainerState::Running,
            Some(4_242),
            true,
        )
        .await
        .expect("complete pause");
    RestoreFixture {
        temporary,
        store,
        create,
        source,
    }
}

fn restore_request(
    fixture: &RestoreFixture,
    id: &str,
    operation: &str,
    file_name: &str,
) -> RestoreRequest {
    RestoreRequest::new(
        OperationContext::new(operation_id(operation)),
        container_id(id),
        fixture.create.bundle.clone(),
        CheckpointArtifactPath::new(fixture.temporary.path().join(file_name))
            .expect("restore artifact path"),
        fixture.create.isolation.clone(),
        fixture.create.attachments.clone(),
        checkpoint_reference(&fixture.source),
    )
    .expect("restore request")
}

fn checkpoint_reference(source: &ContainerRecord) -> CheckpointReference {
    let compatibility = CheckpointCompatibility::new(
        source.driver,
        source.isolation,
        HostPlatform::Windows,
        "x86_64",
        RuntimeArtifact::new("restore-state-test", "1.0.0", digest('a').to_string(), None)
            .expect("runtime artifact"),
        digest('b'),
        CheckpointFormat::new("restore-state-test", 1).expect("checkpoint format"),
    )
    .expect("checkpoint compatibility");
    CheckpointReference::new(source, compatibility, digest('c'), 4_096)
        .expect("checkpoint reference")
}

fn digest(symbol: char) -> CheckpointDigest {
    CheckpointDigest::new(format!("sha256:{}", symbol.to_string().repeat(64)))
        .expect("checkpoint digest")
}

#[tokio::test]
async fn restore_v5_journal_replays_one_exact_paused_running_generation() {
    let fixture = restore_fixture().await;
    let request = restore_request(
        &fixture,
        "restore-state-target",
        "restore-state-operation",
        "state.checkpoint",
    );
    assert!(matches!(
        fixture
            .store
            .lookup_restore(&request)
            .await
            .expect("lookup new restore"),
        RestoreOperationLookup::Pending
    ));
    let RestoreOperationPreparation::Prepared(prepared) = fixture
        .store
        .prepare_restore(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare restore")
    else {
        panic!("new restore must allocate a generation")
    };
    assert_eq!(*prepared.state.status(), ContainerState::Creating);
    assert_eq!(prepared.generation, Generation(1));

    let operation = fixture
        .store
        .load_operation(&request.context().operation_id)
        .await
        .expect("load restore journal");
    assert_eq!(operation.schema_version, OPERATION_SCHEMA_VERSION);
    assert_eq!(operation.kind, StoredOperationKind::Restore);
    assert_eq!(
        operation.request,
        Some(StoredOperationRequest::Restore(Box::new(request.clone())))
    );
    assert!(matches!(operation.outcome, StoredOperationStatus::Prepared));

    let original_response = fixture
        .store
        .complete_restore(&request.context().operation_id, 5_151)
        .await
        .expect("complete restore");
    assert_eq!(
        *original_response.restored().state.status(),
        ContainerState::Running
    );
    assert_eq!(*original_response.restored().state.pid(), Some(5_151));
    assert!(original_response.restored().is_paused());
    assert_eq!(original_response.restored().generation, Generation(1));
    let target = ContainerTarget::exact(request.id().clone(), Generation(1));
    let replacement = DriverState::running(5_252)
        .and_then(|state| state.with_paused(true))
        .expect("replacement paused state");
    fixture
        .store
        .observe_recreated_paused_running_process(&target, replacement)
        .await
        .expect("rebind restored process");
    let RestoreOperationLookup::Replayed(replayed) = fixture
        .store
        .lookup_restore(&request)
        .await
        .expect("lookup completed restore")
    else {
        panic!("completed restore must replay")
    };
    assert_eq!(*replayed.restored().state.pid(), Some(5_252));
    assert_eq!(replayed.reference(), original_response.reference());
    let response = *replayed;

    let changed = restore_request(
        &fixture,
        "restore-state-target",
        "restore-state-operation",
        "changed.checkpoint",
    );
    let error = fixture
        .store
        .lookup_restore(&changed)
        .await
        .expect_err("same operation ID with changed artifact must fail");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);

    let root = state_root(&fixture.temporary);
    drop(fixture.store);
    let reopened = DurableStateStore::open(root)
        .await
        .expect("reopen completed restore state");
    let RestoreOperationLookup::Replayed(reopened_response) = reopened
        .lookup_restore(&request)
        .await
        .expect("replay restore after reopen")
    else {
        panic!("reopened restore must replay")
    };
    assert_eq!(*reopened_response, response);
    let stored = reopened
        .load_stored_container(request.id())
        .await
        .expect("load restored container");
    assert!(stored.active_operation.is_none());
    assert!(stored.record.is_paused());
}

#[tokio::test]
async fn startup_rejects_restore_request_drift_inside_the_v5_journal() {
    let fixture = restore_fixture().await;
    let request = restore_request(
        &fixture,
        "restore-state-corrupt",
        "restore-state-corrupt-operation",
        "original.checkpoint",
    );
    fixture
        .store
        .prepare_restore(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare restore");
    fixture
        .store
        .complete_restore(&request.context().operation_id, 5_151)
        .await
        .expect("complete restore");
    let mut operation = fixture
        .store
        .load_operation(&request.context().operation_id)
        .await
        .expect("load restore journal");
    let changed = restore_request(
        &fixture,
        "restore-state-corrupt",
        "restore-state-corrupt-operation",
        "changed.checkpoint",
    );
    operation.request = Some(StoredOperationRequest::Restore(Box::new(changed)));
    let operation_path = fixture
        .store
        .operation_path(&request.context().operation_id);
    let root = state_root(&fixture.temporary);
    drop(fixture.store);
    tokio::fs::write(
        operation_path,
        serde_json::to_vec(&operation).expect("encode corrupt restore journal"),
    )
    .await
    .expect("write corrupt restore journal");

    let error = DurableStateStore::open(root)
        .await
        .expect_err("restore request drift must fail startup audit");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("durable identity"));
}

#[tokio::test]
async fn failed_restore_quarantines_its_generation_and_allows_exact_id_reuse() {
    let fixture = restore_fixture().await;
    let request = restore_request(
        &fixture,
        "restore-state-failure",
        "restore-state-failure-operation",
        "failure.checkpoint",
    );
    fixture
        .store
        .prepare_restore(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare failed restore");
    let failure = Error::new(ErrorCode::FailedPrecondition, "terminal restore failure")
        .for_operation("restore");
    fixture
        .store
        .fail_operation(&request.context().operation_id, &failure)
        .await
        .expect("record failed restore");
    let replay = fixture
        .store
        .lookup_restore(&request)
        .await
        .expect_err("failed restore must replay");
    assert_eq!(replay, failure);
    assert!(!fixture.store.container_directory(request.id()).exists());
    assert!(fixture
        .store
        .failed_restore_tombstone(&request.context().operation_id)
        .is_dir());

    let retry = restore_request(
        &fixture,
        "restore-state-failure",
        "restore-state-after-failure",
        "failure.checkpoint",
    );
    let RestoreOperationPreparation::Prepared(prepared) = fixture
        .store
        .prepare_restore(&retry, DriverKind::LibkrunWhpx)
        .await
        .expect("reuse ID after failed restore")
    else {
        panic!("new restore operation must allocate generation 2")
    };
    assert_eq!(prepared.generation, Generation(2));
    let restored = fixture
        .store
        .complete_restore(&retry.context().operation_id, 5_152)
        .await
        .expect("complete replacement restore");
    assert_eq!(restored.restored().generation, Generation(2));
    assert!(restored.restored().is_paused());
}
