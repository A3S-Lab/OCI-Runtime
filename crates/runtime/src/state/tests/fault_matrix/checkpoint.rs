use a3s_oci_core::{DriverKind, HostPlatform};
use a3s_oci_sdk::{
    CheckpointArtifactPath, CheckpointCompatibility, CheckpointDigest, CheckpointFormat,
    CheckpointReference, CheckpointRequest, CheckpointResponse, ContainerOperationRequest,
    OperationContext, RuntimeArtifact,
};

use crate::state::CheckpointOperationPreparation;

use super::*;

pub(super) async fn exercise_checkpoint_success(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("checkpoint-success-create");
    let source = prepare_paused_source(&fixture.root, &create).await;
    let request = checkpoint_request(
        &fixture,
        &source,
        "checkpoint-success",
        "success.checkpoint",
    );
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open checkpoint success store");
    let error = drive_success(&store, &request)
        .await
        .expect_err("checkpoint success commit must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen checkpoint success store");
    let response = drive_success(&recovered, &request)
        .await
        .unwrap_or_else(|error| panic!("recover checkpoint after {point}: {error}"));
    let replay = drive_success(&recovered, &request)
        .await
        .expect("replay recovered checkpoint");
    assert_eq!(replay, response, "{point}");
    assert_eq!(response.source(), &source, "{point}");
    assert_container_unclaimed_and_paused(&recovered, request.target()).await;
    assert_consistent_layout(recovered.root());
}

pub(super) async fn exercise_checkpoint_failure(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("checkpoint-failure-create");
    let source = prepare_paused_source(&fixture.root, &create).await;
    let request = checkpoint_request(
        &fixture,
        &source,
        "checkpoint-failure",
        "failure.checkpoint",
    );
    let failure = terminal_failure("checkpoint");
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open checkpoint failure store");
    let error = drive_failure(&store, &request, &failure)
        .await
        .expect_err("checkpoint failure commit must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen checkpoint failure store");
    drive_failure(&recovered, &request, &failure)
        .await
        .unwrap_or_else(|error| panic!("recover checkpoint failure after {point}: {error}"));
    assert_container_unclaimed_and_paused(&recovered, request.target()).await;
    assert_consistent_layout(recovered.root());
}

async fn prepare_paused_source(root: &Path, create: &CreateRequest) -> ContainerRecord {
    let target = prepare_running_for_freezer(root, create).await;
    let store = DurableStateStore::open(root)
        .await
        .expect("open checkpoint source store");
    drive_pause(
        &store,
        &ContainerOperationRequest {
            context: OperationContext::new(operation_id("checkpoint-source-pause")),
            target,
        },
    )
    .await
    .expect("pause checkpoint source")
}

fn checkpoint_request(
    fixture: &Fixture,
    source: &ContainerRecord,
    operation: &str,
    file_name: &str,
) -> CheckpointRequest {
    CheckpointRequest::new(
        OperationContext::new(operation_id(operation)),
        ContainerTarget::exact(container_id(source.state.id()), source.generation),
        CheckpointArtifactPath::new(fixture._temporary.path().join(file_name))
            .expect("checkpoint artifact path"),
    )
    .expect("checkpoint request")
}

async fn drive_success(
    store: &DurableStateStore,
    request: &CheckpointRequest,
) -> a3s_oci_sdk::Result<CheckpointResponse> {
    match store.prepare_checkpoint(request).await? {
        CheckpointOperationPreparation::Prepared(source)
        | CheckpointOperationPreparation::Resume(source) => {
            let response = checkpoint_response(source)?;
            store
                .complete_checkpoint(&request.context().operation_id, response)
                .await
        }
        CheckpointOperationPreparation::Replayed(response) => Ok(*response),
    }
}

async fn drive_failure(
    store: &DurableStateStore,
    request: &CheckpointRequest,
    failure: &Error,
) -> a3s_oci_sdk::Result<()> {
    match store.prepare_checkpoint(request).await {
        Ok(CheckpointOperationPreparation::Prepared(_))
        | Ok(CheckpointOperationPreparation::Resume(_)) => {
            store
                .fail_operation(&request.context().operation_id, failure)
                .await?;
        }
        Ok(CheckpointOperationPreparation::Replayed(_)) => {
            panic!("failed checkpoint unexpectedly replayed success")
        }
        Err(error) if error == *failure => return Ok(()),
        Err(error) => return Err(error),
    }
    expect_failure(store.prepare_checkpoint(request).await, failure)
}

fn checkpoint_response(source: ContainerRecord) -> a3s_oci_sdk::Result<CheckpointResponse> {
    let platform = match source.driver {
        DriverKind::NativeLinux | DriverKind::LibkrunKvm => HostPlatform::Linux,
        DriverKind::LibkrunHvf => HostPlatform::Macos,
        DriverKind::LibkrunWhpx => HostPlatform::Windows,
    };
    let compatibility = CheckpointCompatibility::new(
        source.driver,
        source.isolation,
        platform,
        "x86_64",
        RuntimeArtifact::new(
            "fault-matrix-runtime",
            "1.0.0",
            digest('a').to_string(),
            None,
        )?,
        digest('b'),
        CheckpointFormat::new("fault-matrix", 1)?,
    )?;
    let reference = CheckpointReference::new(&source, compatibility, digest('c'), 4_096)?;
    CheckpointResponse::new(source, reference)
}

fn digest(symbol: char) -> CheckpointDigest {
    CheckpointDigest::new(format!("sha256:{}", symbol.to_string().repeat(64)))
        .expect("checkpoint digest")
}

async fn assert_container_unclaimed_and_paused(
    store: &DurableStateStore,
    target: &ContainerTarget,
) {
    let stored = store
        .load_stored_container(&target.id)
        .await
        .expect("load checkpoint source");
    assert!(stored.active_operation.is_none());
    assert!(stored.record.is_paused());
}
