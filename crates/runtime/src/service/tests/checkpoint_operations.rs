use super::*;

async fn checkpoint_fixture() -> (
    tempfile::TempDir,
    Arc<RecordingDriver>,
    HostRuntimeService,
    ContainerRecord,
) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::with_checkpoint_operations());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let mut create = create_request(&bundle_directory, "checkpoint-create");
    create.isolation = match driver.capability.isolation_classes[0] {
        IsolationClass::SharedHostKernel => IsolationRequest::SharedHostKernel,
        IsolationClass::DedicatedVm => IsolationRequest::DedicatedVm,
        IsolationClass::SharedGuestKernel => {
            panic!("checkpoint fixture does not use shared Guest isolation")
        }
    };
    let created = service.create(create.clone()).await.expect("create");
    let target = ContainerTarget::exact(create.id, created.generation);
    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("checkpoint-start")),
            target: target.clone(),
        })
        .await
        .expect("start");
    let paused = service
        .pause(ContainerOperationRequest {
            context: OperationContext::new(operation_id("checkpoint-pause")),
            target,
        })
        .await
        .expect("pause");
    assert!(paused.is_paused());
    (temporary, driver, service, paused)
}

fn request(source: &ContainerRecord, operation: &str, artifact_path: PathBuf) -> CheckpointRequest {
    CheckpointRequest::new(
        OperationContext::new(operation_id(operation)),
        ContainerTarget::exact(container_id(source.state.id()), source.generation),
        CheckpointArtifactPath::new(artifact_path).expect("checkpoint artifact path"),
    )
    .expect("checkpoint request")
}

#[tokio::test]
async fn checkpoint_publishes_and_replays_one_exact_immutable_reference() {
    let (temporary, driver, service, source) = checkpoint_fixture().await;
    let artifact_path = temporary.path().join("checkpoint.bin");
    let checkpoint = request(&source, "checkpoint-save", artifact_path.clone());

    let info = service.features().await.expect("configured features");
    assert!(info.operations.contains(&RuntimeOperation::Checkpoint));
    assert!(!info.operations.contains(&RuntimeOperation::Restore));
    let advertised = info
        .extensions
        .drivers()
        .iter()
        .find(|entry| entry.driver() == source.driver)
        .expect("checkpoint driver capability");
    assert!(
        advertised.supports_operation(RuntimeOperation::Checkpoint, RUNTIME_OPERATION_CONTRACT_V1)
    );
    assert!(
        !advertised.supports_operation(RuntimeOperation::Restore, RUNTIME_OPERATION_CONTRACT_V1)
    );

    let response = service
        .checkpoint(checkpoint.clone())
        .await
        .expect("checkpoint");
    assert_eq!(response.source(), &source);
    assert_eq!(response.reference().source(), checkpoint.target());
    assert_eq!(
        response.reference().compatibility().runtime_artifact(),
        info.extensions.artifact().expect("runtime artifact")
    );
    assert_eq!(
        response.reference().compatibility().platform(),
        HostPlatform::current()
    );
    assert_eq!(
        response.reference().compatibility().architecture(),
        std::env::consts::ARCH
    );
    let bytes = tokio::fs::read(&artifact_path)
        .await
        .expect("published checkpoint artifact");
    assert_eq!(
        response.reference().artifact_size_bytes(),
        u64::try_from(bytes.len()).expect("artifact size")
    );
    assert_eq!(
        response.reference().artifact_digest().as_str(),
        format!("sha256:{:x}", Sha256::digest(&bytes))
    );

    assert_eq!(
        service
            .checkpoint(checkpoint.clone())
            .await
            .expect("same-service checkpoint replay"),
        response
    );
    drop(service);
    let reopened = open_service(&temporary, Arc::clone(&driver)).await;
    assert_eq!(
        reopened
            .checkpoint(checkpoint.clone())
            .await
            .expect("reopened checkpoint replay"),
        response
    );
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Checkpoint(_)))
            .count(),
        1,
        "a committed checkpoint must never redispatch the driver"
    );

    let changed = request(
        &source,
        "checkpoint-save",
        temporary.path().join("different.bin"),
    );
    let error = reopened
        .checkpoint(changed)
        .await
        .expect_err("operation ID path drift must fail");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Checkpoint(_)))
            .count(),
        1
    );

    let resumed = reopened
        .resume(ContainerOperationRequest {
            context: OperationContext::new(operation_id("checkpoint-resume")),
            target: checkpoint.target().clone(),
        })
        .await
        .expect("explicit resume after checkpoint");
    assert!(!resumed.is_paused());
}

#[tokio::test]
async fn checkpoint_rejects_unpaused_sources_before_driver_dispatch() {
    let (temporary, driver, service, source) = checkpoint_fixture().await;
    let target = ContainerTarget::exact(container_id(source.state.id()), source.generation);
    service
        .resume(ContainerOperationRequest {
            context: OperationContext::new(operation_id("checkpoint-unpaused-resume")),
            target: target.clone(),
        })
        .await
        .expect("resume source");
    let checkpoint = request(
        &source,
        "checkpoint-unpaused",
        temporary.path().join("unpaused.bin"),
    );
    let error = service
        .checkpoint(checkpoint)
        .await
        .expect_err("unpaused checkpoint must fail");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(!driver
        .calls()
        .iter()
        .any(|call| matches!(call, DriverCall::Checkpoint(_))));
}

#[tokio::test]
async fn terminal_checkpoint_failure_is_durable_and_releases_the_source_claim() {
    let (temporary, driver, service, source) = checkpoint_fixture().await;
    let artifact_path = temporary.path().join("occupied.bin");
    tokio::fs::write(&artifact_path, b"caller-owned")
        .await
        .expect("pre-existing artifact");
    let checkpoint = request(&source, "checkpoint-occupied", artifact_path);

    let first = service
        .checkpoint(checkpoint.clone())
        .await
        .expect_err("pre-existing destination must fail");
    assert_eq!(first.code, ErrorCode::AlreadyExists);
    let replay = service
        .checkpoint(checkpoint.clone())
        .await
        .expect_err("terminal checkpoint failure must replay");
    assert_eq!(replay, first);
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Checkpoint(_)))
            .count(),
        1
    );

    let resumed = service
        .resume(ContainerOperationRequest {
            context: OperationContext::new(operation_id("checkpoint-failure-resume")),
            target: checkpoint.target().clone(),
        })
        .await
        .expect("checkpoint failure released source claim");
    assert!(!resumed.is_paused());
}
