use a3s_oci_core::HostPlatform;
use a3s_oci_sdk::{
    CheckpointArtifactPath, CheckpointCompatibility, CheckpointDigest, CheckpointFormat,
    CheckpointReference, CheckpointRequest, CheckpointResponse, ContainerRecord, RuntimeArtifact,
};

use crate::state::model::{StoredOperationRequest, OPERATION_SCHEMA_VERSION};
use crate::state::{CheckpointOperationPreparation, ProcessIoPreparation};

use super::*;

async fn paused_fixture() -> (TempDir, DurableStateStore, ContainerRecord) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("open checkpoint store");
    let create = create_request(
        &bundle_directory,
        "checkpoint-state-container",
        "checkpoint-state-create",
    );
    create_container(&store, &create).await;
    let target = ContainerTarget::exact(create.id, Generation(1));
    let start = StartRequest {
        context: OperationContext::new(operation_id("checkpoint-state-start")),
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
        context: OperationContext::new(operation_id("checkpoint-state-pause")),
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
    (temporary, store, source)
}

fn checkpoint_request(
    temporary: &TempDir,
    source: &ContainerRecord,
    operation: &str,
    file_name: &str,
) -> CheckpointRequest {
    CheckpointRequest::new(
        OperationContext::new(operation_id(operation)),
        ContainerTarget::exact(container_id(source.state.id()), source.generation),
        CheckpointArtifactPath::new(temporary.path().join(file_name))
            .expect("checkpoint artifact path"),
    )
    .expect("checkpoint request")
}

fn checkpoint_response(source: ContainerRecord) -> CheckpointResponse {
    let compatibility = CheckpointCompatibility::new(
        source.driver,
        source.isolation,
        HostPlatform::Windows,
        "x86_64",
        RuntimeArtifact::new(
            "checkpoint-state-test",
            "1.0.0",
            digest('a').to_string(),
            None,
        )
        .expect("runtime artifact"),
        digest('b'),
        CheckpointFormat::new("checkpoint-state-test", 1).expect("checkpoint format"),
    )
    .expect("checkpoint compatibility");
    let reference = CheckpointReference::new(&source, compatibility, digest('c'), 4_096)
        .expect("checkpoint reference");
    CheckpointResponse::new(source, reference).expect("checkpoint response")
}

fn digest(symbol: char) -> CheckpointDigest {
    CheckpointDigest::new(format!("sha256:{}", symbol.to_string().repeat(64)))
        .expect("checkpoint digest")
}

#[tokio::test]
async fn checkpoint_claim_fences_new_process_io_until_the_response_is_durable() {
    let (temporary, store, source) = paused_fixture().await;
    let checkpoint = checkpoint_request(
        &temporary,
        &source,
        "checkpoint-state-save",
        "state.checkpoint",
    );
    let prepared = store
        .prepare_checkpoint(&checkpoint)
        .await
        .expect("prepare checkpoint");
    let CheckpointOperationPreparation::Prepared(prepared_source) = prepared else {
        panic!("new checkpoint must prepare")
    };

    let write = WriteStdinRequest {
        context: OperationContext::new(operation_id("checkpoint-state-write")),
        process: ProcessTarget {
            container: checkpoint.target().clone(),
            process_id: ProcessId::init(),
        },
        data: b"blocked".to_vec(),
    };
    let error = store
        .prepare_write_stdin(&write)
        .await
        .expect_err("checkpoint claim must fence process I/O");
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(error.retryable);

    store
        .complete_checkpoint(
            &checkpoint.context().operation_id,
            checkpoint_response(prepared_source),
        )
        .await
        .expect("complete checkpoint");
    assert!(matches!(
        store
            .prepare_write_stdin(&write)
            .await
            .expect("process I/O after checkpoint"),
        ProcessIoPreparation::Prepared(_)
    ));
    store
        .complete_write_stdin(&write.context.operation_id)
        .await
        .expect("complete process I/O");
}

#[tokio::test]
async fn checkpoint_refuses_an_existing_process_io_claim_before_writing_its_journal() {
    let (temporary, store, source) = paused_fixture().await;
    let checkpoint = checkpoint_request(
        &temporary,
        &source,
        "checkpoint-state-busy",
        "busy.checkpoint",
    );
    let write = WriteStdinRequest {
        context: OperationContext::new(operation_id("checkpoint-state-active-write")),
        process: ProcessTarget {
            container: checkpoint.target().clone(),
            process_id: ProcessId::init(),
        },
        data: b"active".to_vec(),
    };
    store
        .prepare_write_stdin(&write)
        .await
        .expect("prepare active process I/O");
    let error = store
        .prepare_checkpoint(&checkpoint)
        .await
        .expect_err("active process I/O must block checkpoint");
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(error.retryable);
    assert!(
        !tokio::fs::try_exists(store.operation_path(&checkpoint.context().operation_id))
            .await
            .expect("inspect checkpoint journal")
    );
    store
        .complete_write_stdin(&write.context.operation_id)
        .await
        .expect("complete active process I/O");
    let prepared = store
        .prepare_checkpoint(&checkpoint)
        .await
        .expect("checkpoint after process I/O");
    let CheckpointOperationPreparation::Prepared(prepared_source) = prepared else {
        panic!("checkpoint after process I/O must prepare")
    };
    store
        .complete_checkpoint(
            &checkpoint.context().operation_id,
            checkpoint_response(prepared_source),
        )
        .await
        .expect("complete checkpoint after process I/O");
}

#[tokio::test]
async fn startup_rejects_checkpoint_request_drift_inside_the_v4_journal() {
    let (temporary, store, source) = paused_fixture().await;
    let checkpoint = checkpoint_request(
        &temporary,
        &source,
        "checkpoint-state-corrupt",
        "original.checkpoint",
    );
    let prepared = store
        .prepare_checkpoint(&checkpoint)
        .await
        .expect("prepare checkpoint");
    let CheckpointOperationPreparation::Prepared(prepared_source) = prepared else {
        panic!("new checkpoint must prepare")
    };
    store
        .complete_checkpoint(
            &checkpoint.context().operation_id,
            checkpoint_response(prepared_source),
        )
        .await
        .expect("complete checkpoint");
    let mut operation = store
        .load_operation(&checkpoint.context().operation_id)
        .await
        .expect("load checkpoint journal");
    assert_eq!(operation.schema_version, OPERATION_SCHEMA_VERSION);
    let changed = checkpoint_request(
        &temporary,
        &source,
        "checkpoint-state-corrupt",
        "changed.checkpoint",
    );
    operation.request = Some(StoredOperationRequest::Checkpoint(changed));
    let operation_path = store.operation_path(&checkpoint.context().operation_id);
    drop(store);
    tokio::fs::write(
        operation_path,
        serde_json::to_vec(&operation).expect("encode corrupt checkpoint journal"),
    )
    .await
    .expect("write corrupt checkpoint journal");

    let error = DurableStateStore::open(state_root(&temporary))
        .await
        .expect_err("request drift must fail startup audit");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("durable identity"));
}
