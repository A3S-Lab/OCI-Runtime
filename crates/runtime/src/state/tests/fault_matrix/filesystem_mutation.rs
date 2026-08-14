use a3s_oci_sdk::{
    FileOp, FileRequest, FileResponse, FilesystemOp, FilesystemRequest, FilesystemResponse,
};

use crate::state::FilesystemMutationPreparation;

use super::*;

#[derive(Debug, Clone, Copy)]
enum MutationKind {
    File,
    Filesystem,
}

pub(super) async fn exercise_filesystem_mutation_success(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("filesystem-mutation-success-create");
    let target = prepare_running_for_freezer(&fixture.root, &create).await;
    let kind = mutation_kind(point);
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open filesystem-mutation success store");
    let error = drive_success(&store, &target, kind)
        .await
        .expect_err("filesystem-mutation success checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen filesystem-mutation success store");
    drive_success(&recovered, &target, kind)
        .await
        .unwrap_or_else(|error| panic!("recover filesystem mutation after {point}: {error}"));
    drive_success(&recovered, &target, kind)
        .await
        .expect("replay recovered filesystem mutation");
    assert_container_unclaimed(&recovered, &target).await;
    assert_consistent_layout(recovered.root());
}

pub(super) async fn exercise_filesystem_mutation_failure(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("filesystem-mutation-failure-create");
    let target = prepare_running_for_freezer(&fixture.root, &create).await;
    let kind = mutation_kind(point);
    let failure = terminal_failure(kind.operation_name());
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open filesystem-mutation failure store");
    let error = drive_failure(&store, &target, kind, &failure)
        .await
        .expect_err("filesystem-mutation failure checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen filesystem-mutation failure store");
    drive_failure(&recovered, &target, kind, &failure)
        .await
        .unwrap_or_else(|error| panic!("recover filesystem failure after {point}: {error}"));
    assert_container_unclaimed(&recovered, &target).await;
    assert_consistent_layout(recovered.root());
}

impl MutationKind {
    const fn operation_name(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Filesystem => "filesystem",
        }
    }
}

fn mutation_kind(point: FaultPoint) -> MutationKind {
    let mutation = match point {
        FaultPoint::DurableFile { mutation, .. }
        | FaultPoint::DurableDirectory { mutation, .. } => mutation,
        FaultPoint::DriverBoundary { .. } => {
            panic!("filesystem durable scenario received driver point {point}")
        }
    };
    match mutation {
        DurableMutation::PrepareFileOperation
        | DurableMutation::ClaimFileOperation
        | DurableMutation::CompleteFileContainer
        | DurableMutation::CompleteFileOperation
        | DurableMutation::ReleaseFailedFileClaim
        | DurableMutation::RecordFileFailure => MutationKind::File,
        DurableMutation::PrepareFilesystemOperation
        | DurableMutation::ClaimFilesystemOperation
        | DurableMutation::CompleteFilesystemContainer
        | DurableMutation::CompleteFilesystemOperation
        | DurableMutation::ReleaseFailedFilesystemClaim
        | DurableMutation::RecordFilesystemFailure => MutationKind::Filesystem,
        _ => panic!("non-filesystem mutation routed to filesystem scenario: {mutation:?}"),
    }
}

async fn drive_success(
    store: &DurableStateStore,
    target: &ContainerTarget,
    kind: MutationKind,
) -> a3s_oci_sdk::Result<()> {
    match kind {
        MutationKind::File => {
            let request = file_request(target, "filesystem-mutation-success-file");
            match store.prepare_file_mutation(&request).await? {
                FilesystemMutationPreparation::Prepared(exact)
                | FilesystemMutationPreparation::Resume(exact) => {
                    store
                        .complete_file_mutation(
                            &request.context.as_ref().expect("File context").operation_id,
                            FileResponse {
                                target: exact,
                                data: None,
                                size: 5,
                            },
                        )
                        .await?;
                    Ok(())
                }
                FilesystemMutationPreparation::Replayed(response) => {
                    if response.size != 5 {
                        panic!("replayed File response changed: {response:?}");
                    }
                    Ok(())
                }
            }
        }
        MutationKind::Filesystem => {
            let request = filesystem_request(target, "filesystem-mutation-success-filesystem");
            match store.prepare_filesystem_mutation(&request).await? {
                FilesystemMutationPreparation::Prepared(exact)
                | FilesystemMutationPreparation::Resume(exact) => {
                    store
                        .complete_filesystem_mutation(
                            &request
                                .context
                                .as_ref()
                                .expect("Filesystem context")
                                .operation_id,
                            FilesystemResponse {
                                target: exact,
                                entry: None,
                                entries: Vec::new(),
                            },
                        )
                        .await?;
                    Ok(())
                }
                FilesystemMutationPreparation::Replayed(response) => {
                    if response.entry.is_some() || !response.entries.is_empty() {
                        panic!("replayed Filesystem response changed: {response:?}");
                    }
                    Ok(())
                }
            }
        }
    }
}

async fn drive_failure(
    store: &DurableStateStore,
    target: &ContainerTarget,
    kind: MutationKind,
    failure: &Error,
) -> a3s_oci_sdk::Result<()> {
    match kind {
        MutationKind::File => {
            let request = file_request(target, "filesystem-mutation-failure-file");
            match store.prepare_file_mutation(&request).await {
                Ok(FilesystemMutationPreparation::Prepared(_))
                | Ok(FilesystemMutationPreparation::Resume(_)) => {
                    store
                        .fail_operation(
                            &request.context.as_ref().expect("File context").operation_id,
                            failure,
                        )
                        .await?;
                }
                Ok(FilesystemMutationPreparation::Replayed(_)) => {
                    panic!("failed File mutation unexpectedly replayed success")
                }
                Err(error) if error == *failure => return Ok(()),
                Err(error) => return Err(error),
            }
            expect_failure(store.prepare_file_mutation(&request).await, failure)
        }
        MutationKind::Filesystem => {
            let request = filesystem_request(target, "filesystem-mutation-failure-filesystem");
            match store.prepare_filesystem_mutation(&request).await {
                Ok(FilesystemMutationPreparation::Prepared(_))
                | Ok(FilesystemMutationPreparation::Resume(_)) => {
                    store
                        .fail_operation(
                            &request
                                .context
                                .as_ref()
                                .expect("Filesystem context")
                                .operation_id,
                            failure,
                        )
                        .await?;
                }
                Ok(FilesystemMutationPreparation::Replayed(_)) => {
                    panic!("failed Filesystem mutation unexpectedly replayed success")
                }
                Err(error) if error == *failure => return Ok(()),
                Err(error) => return Err(error),
            }
            expect_failure(store.prepare_filesystem_mutation(&request).await, failure)
        }
    }
}

fn file_request(target: &ContainerTarget, operation: &str) -> FileRequest {
    FileRequest {
        target: target.clone(),
        op: FileOp::Upload,
        path: "/tmp/durable-file".to_string(),
        data: Some("aGVsbG8=".to_string()),
        user: None,
        context: Some(OperationContext::new(operation_id(operation))),
    }
}

fn filesystem_request(target: &ContainerTarget, operation: &str) -> FilesystemRequest {
    FilesystemRequest {
        target: target.clone(),
        op: FilesystemOp::Remove,
        path: "/tmp/durable-file".to_string(),
        destination: None,
        depth: 0,
        user: None,
        context: Some(OperationContext::new(operation_id(operation))),
    }
}

async fn assert_container_unclaimed(store: &DurableStateStore, target: &ContainerTarget) {
    let stored = store
        .load_stored_container(&target.id)
        .await
        .expect("load filesystem-mutation container");
    assert!(
        stored.active_operation.is_none(),
        "filesystem mutation left an active container claim"
    );
}
