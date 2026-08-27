use a3s_oci_core::{DriverKind, HostPlatform};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    CheckpointArtifactPath, CheckpointCompatibility, CheckpointDigest, CheckpointFormat,
    CheckpointReference, ContainerRecord, OperationContext, RestoreRequest, RestoreResponse,
    RuntimeArtifact,
};

use crate::state::{RestoreOperationLookup, RestoreOperationPreparation};

use super::checkpoint::prepare_paused_source;
use super::*;

#[tokio::test]
async fn recreated_restored_pid_and_journal_repair_survive_commit_faults() {
    for stage in FileCommitStage::ALL {
        exercise_restored_pid_rebind(FaultPoint::DurableFile {
            mutation: DurableMutation::CompleteRestoreOperation,
            stage,
        })
        .await;
    }
}

pub(super) async fn exercise_restore_success(point: FaultPoint, recover_claim: bool) {
    let fixture = Fixture::new();
    let create = fixture.create("restore-success-source-create");
    let source = prepare_paused_source(&fixture.root, &create).await;
    let request = restore_request(
        &fixture,
        &create,
        &source,
        "fault-restored",
        "restore-success",
        "success.checkpoint",
    );
    if recover_claim {
        prepare_restored_record_without_outcome(&fixture.root, &request).await;
    }

    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open restore success store");
    let error = drive_success(&store, &request)
        .await
        .expect_err("restore success commit must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen restore success store");
    let response = drive_success(&recovered, &request)
        .await
        .unwrap_or_else(|error| panic!("recover restore after {point}: {error}"));
    let replay = drive_success(&recovered, &request)
        .await
        .expect("replay recovered restore");
    assert_eq!(replay, response, "{point}");
    assert_eq!(
        response.reference(),
        request.reference().expect("reference")
    );
    assert_eq!(*response.restored().state.status(), ContainerState::Running);
    assert_eq!(*response.restored().state.pid(), Some(5_151));
    assert!(response.restored().is_paused());
    assert!(response.restored().generation.0 > 0, "{point}");
    assert_container_unclaimed_and_paused(
        &recovered,
        &ContainerTarget::exact(request.id().clone(), response.restored().generation),
    )
    .await;
    assert_consistent_layout(recovered.root());
}

async fn exercise_restored_pid_rebind(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("restore-rebind-source-create");
    let source = prepare_paused_source(&fixture.root, &create).await;
    let request = restore_request(
        &fixture,
        &create,
        &source,
        "fault-restore-rebind",
        "restore-rebind",
        "rebind.checkpoint",
    );
    let setup = DurableStateStore::open(&fixture.root)
        .await
        .expect("open restore rebind setup");
    drive_success(&setup, &request)
        .await
        .expect("complete original restore");
    let target = ContainerTarget::exact(request.id().clone(), a3s_oci_sdk::Generation(1));
    setup
        .observe_recreated_paused_running_process(
            &target,
            DriverState::running(5_252)
                .and_then(|state| state.with_paused(true))
                .expect("replacement paused state"),
        )
        .await
        .expect("store replacement restore PID");
    drop(setup);

    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let injected = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open restore rebind fault store");
    let error = injected
        .lookup_restore(&request)
        .await
        .expect_err("restore response repair must inject");
    assert_injected(&error, point, &injector);
    drop(injected);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen restore rebind store");
    let RestoreOperationLookup::Replayed(response) = recovered
        .lookup_restore(&request)
        .await
        .unwrap_or_else(|error| panic!("repair restored PID after {point}: {error}"))
    else {
        panic!("completed restore did not replay after {point}")
    };
    assert_eq!(*response.restored().state.pid(), Some(5_252), "{point}");
    assert_eq!(
        recovered
            .lookup_restore(&request)
            .await
            .expect("replay repaired restore"),
        RestoreOperationLookup::Replayed(response),
        "{point}"
    );
    assert_consistent_layout(recovered.root());
}

pub(super) async fn exercise_restore_failure(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("restore-failure-source-create");
    let source = prepare_paused_source(&fixture.root, &create).await;
    let request = restore_request(
        &fixture,
        &create,
        &source,
        "fault-restore-failure",
        "restore-failure",
        "failure.checkpoint",
    );
    let failure = terminal_failure("restore");
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open restore failure store");
    let error = drive_failure(&store, &request, &failure)
        .await
        .expect_err("restore failure commit must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen restore failure store");
    drive_failure(&recovered, &request, &failure)
        .await
        .unwrap_or_else(|error| panic!("recover restore failure after {point}: {error}"));
    let missing = recovered
        .state(&ContainerTarget::current(request.id().clone()))
        .await
        .expect_err("failed restore generation must be quarantined");
    assert_eq!(missing.code, ErrorCode::NotFound, "{point}");
    assert_consistent_layout(recovered.root());
}

fn restore_request(
    fixture: &Fixture,
    create: &CreateRequest,
    source: &ContainerRecord,
    id: &str,
    operation: &str,
    file_name: &str,
) -> RestoreRequest {
    RestoreRequest::new(
        OperationContext::new(operation_id(operation)),
        container_id(id),
        create.bundle.clone(),
        CheckpointArtifactPath::new(fixture._temporary.path().join(file_name))
            .expect("restore artifact path"),
        create.isolation.clone(),
        create.attachments.clone(),
        checkpoint_reference(source),
    )
    .expect("restore request")
}

fn checkpoint_reference(source: &ContainerRecord) -> CheckpointReference {
    let compatibility = CheckpointCompatibility::new(
        source.driver,
        source.isolation,
        HostPlatform::Windows,
        "x86_64",
        RuntimeArtifact::new(
            "fault-matrix-runtime",
            "1.0.0",
            digest('a').to_string(),
            None,
        )
        .expect("runtime artifact"),
        digest('b'),
        CheckpointFormat::new("fault-matrix", 1).expect("checkpoint format"),
    )
    .expect("checkpoint compatibility");
    CheckpointReference::new(source, compatibility, digest('c'), 4_096)
        .expect("checkpoint reference")
}

fn digest(symbol: char) -> CheckpointDigest {
    CheckpointDigest::new(format!("sha256:{}", symbol.to_string().repeat(64)))
        .expect("checkpoint digest")
}

async fn drive_success(
    store: &DurableStateStore,
    request: &RestoreRequest,
) -> a3s_oci_sdk::Result<RestoreResponse> {
    match store.lookup_restore(request).await? {
        RestoreOperationLookup::Replayed(response) => Ok(*response),
        RestoreOperationLookup::Pending => {
            match store
                .prepare_restore(request, DriverKind::LibkrunWhpx)
                .await?
            {
                RestoreOperationPreparation::Prepared(_)
                | RestoreOperationPreparation::Resume(_) => {
                    store
                        .complete_restore(&request.context().operation_id, 5_151)
                        .await
                }
                RestoreOperationPreparation::Replayed(response) => Ok(*response),
            }
        }
    }
}

async fn drive_failure(
    store: &DurableStateStore,
    request: &RestoreRequest,
    failure: &Error,
) -> a3s_oci_sdk::Result<()> {
    match store.lookup_restore(request).await {
        Ok(RestoreOperationLookup::Pending) => {}
        Ok(RestoreOperationLookup::Replayed(_)) => {
            panic!("failed restore unexpectedly replayed success")
        }
        Err(error) if error == *failure => return Ok(()),
        Err(error) => return Err(error),
    }
    match store
        .prepare_restore(request, DriverKind::LibkrunWhpx)
        .await
    {
        Ok(RestoreOperationPreparation::Prepared(_))
        | Ok(RestoreOperationPreparation::Resume(_)) => {
            store
                .fail_operation(&request.context().operation_id, failure)
                .await?;
        }
        Ok(RestoreOperationPreparation::Replayed(_)) => {
            panic!("failed restore unexpectedly replayed success")
        }
        Err(error) if error == *failure => return Ok(()),
        Err(error) => return Err(error),
    }
    expect_failure(store.lookup_restore(request).await, failure)
}

async fn prepare_restored_record_without_outcome(root: &Path, request: &RestoreRequest) {
    let setup_point = FaultPoint::DurableFile {
        mutation: DurableMutation::CompleteRestoreOperation,
        stage: FileCommitStage::TemporaryFileCreated,
    };
    let injector = Arc::new(RecordingFaultInjector::fail_once(setup_point));
    let store = open_injected(root, injector.clone())
        .await
        .expect("open restore-claim setup");
    let error = drive_success(&store, request)
        .await
        .expect_err("interrupt restore outcome");
    assert_injected(&error, setup_point, &injector);
}

async fn assert_container_unclaimed_and_paused(
    store: &DurableStateStore,
    target: &ContainerTarget,
) {
    let stored = store
        .load_stored_container(&target.id)
        .await
        .expect("load restored container");
    assert!(stored.active_operation.is_none());
    assert!(stored.record.is_paused());
}
