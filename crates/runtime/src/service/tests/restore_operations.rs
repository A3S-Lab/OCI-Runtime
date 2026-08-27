use super::*;

struct RestoreFixture {
    temporary: tempfile::TempDir,
    driver: Arc<RecordingDriver>,
    service: HostRuntimeService,
    create: CreateRequest,
    reference: CheckpointReference,
    artifact_path: PathBuf,
    artifact_bytes: Vec<u8>,
}

async fn restore_fixture() -> RestoreFixture {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::with_restore_operations());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let mut create = create_request(&bundle_directory, "restore-source");
    create.isolation = match driver.capability.isolation_classes[0] {
        IsolationClass::SharedHostKernel => IsolationRequest::SharedHostKernel,
        IsolationClass::DedicatedVm => IsolationRequest::DedicatedVm,
        IsolationClass::SharedGuestKernel => {
            panic!("restore fixture does not use shared Guest isolation")
        }
    };
    let created = service.create(create.clone()).await.expect("create source");
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("restore-source-start")),
            target: target.clone(),
        })
        .await
        .expect("start source");
    service
        .pause(ContainerOperationRequest {
            context: OperationContext::new(operation_id("restore-source-pause")),
            target: target.clone(),
        })
        .await
        .expect("pause source");
    let artifact_path = temporary.path().join("restore-source.checkpoint");
    let checkpoint = CheckpointRequest::new(
        OperationContext::new(operation_id("restore-source-checkpoint")),
        target,
        CheckpointArtifactPath::new(artifact_path.clone()).expect("checkpoint path"),
    )
    .expect("checkpoint request");
    let checkpoint = service
        .checkpoint(checkpoint)
        .await
        .expect("checkpoint source");
    let artifact_bytes = tokio::fs::read(&artifact_path)
        .await
        .expect("checkpoint artifact");
    RestoreFixture {
        temporary,
        driver,
        service,
        create,
        reference: checkpoint.reference().clone(),
        artifact_path,
        artifact_bytes,
    }
}

fn request(fixture: &RestoreFixture, id: &str, operation: &str) -> RestoreRequest {
    RestoreRequest::new(
        OperationContext::new(operation_id(operation)),
        container_id(id),
        fixture.create.bundle.clone(),
        CheckpointArtifactPath::new(fixture.artifact_path.clone()).expect("restore path"),
        fixture.create.isolation.clone(),
        fixture.create.attachments.clone(),
        fixture.reference.clone(),
    )
    .expect("restore request")
}

#[tokio::test]
async fn restore_creates_and_replays_one_exact_paused_running_generation() {
    let fixture = restore_fixture().await;
    let restore = request(&fixture, "restored-container", "restore-save");
    let info = fixture.service.features().await.expect("runtime features");
    assert!(info.operations.contains(&RuntimeOperation::Checkpoint));
    assert!(info.operations.contains(&RuntimeOperation::Restore));
    let advertised = info
        .extensions
        .drivers()
        .iter()
        .find(|entry| entry.driver() == fixture.reference.compatibility().driver())
        .expect("restore driver capability");
    assert!(advertised.supports_operation(RuntimeOperation::Restore, RUNTIME_OPERATION_CONTRACT_V1));

    let response = fixture
        .service
        .restore(restore.clone())
        .await
        .expect("restore checkpoint");
    assert_eq!(response.reference(), &fixture.reference);
    assert_eq!(response.restored().state.id(), restore.id().as_str());
    assert_eq!(*response.restored().state.status(), ContainerState::Running);
    assert_eq!(*response.restored().state.pid(), Some(5_151));
    assert!(response.restored().is_paused());
    assert_eq!(response.restored().generation, Generation(1));
    assert_eq!(
        fixture
            .service
            .state(StateRequest {
                target: ContainerTarget::exact(
                    restore.id().clone(),
                    response.restored().generation,
                ),
            })
            .await
            .expect("restored state"),
        *response.restored()
    );
    let events = fixture
        .service
        .events(EventsRequest {
            container: Some(ContainerTarget::exact(
                restore.id().clone(),
                response.restored().generation,
            )),
            after_sequence: 0,
            limit: 16,
            wait_timeout_ms: None,
        })
        .await
        .expect("restore events");
    assert_eq!(
        events
            .events
            .iter()
            .map(|event| event.kind)
            .collect::<Vec<_>>(),
        [
            RuntimeEventKind::ContainerCreating,
            RuntimeEventKind::ContainerCreated,
            RuntimeEventKind::ContainerStarted,
            RuntimeEventKind::ContainerPaused,
        ]
    );

    assert_eq!(
        fixture
            .service
            .restore(restore.clone())
            .await
            .expect("same-service restore replay"),
        response
    );
    let changed = request(&fixture, "changed-restored-container", "restore-save");
    let error = fixture
        .service
        .restore(changed)
        .await
        .expect_err("changed restore request must fail");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);

    drop(fixture.service);
    let reopened = open_service(&fixture.temporary, Arc::clone(&fixture.driver)).await;
    assert_eq!(
        reopened
            .restore(restore.clone())
            .await
            .expect("reopened restore replay"),
        response
    );
    assert_eq!(
        fixture
            .driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Restore(_)))
            .count(),
        1,
        "committed restore must never redispatch the driver"
    );
    assert_eq!(
        fixture
            .driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::RestoreValidation(_)))
            .count(),
        1,
        "committed restore replay must not reopen the caller artifact"
    );
    assert_eq!(
        tokio::fs::read(&fixture.artifact_path)
            .await
            .expect("immutable artifact after restore"),
        fixture.artifact_bytes
    );

    let resumed = reopened
        .resume(ContainerOperationRequest {
            context: OperationContext::new(operation_id("restored-resume")),
            target: ContainerTarget::exact(restore.id().clone(), response.restored().generation),
        })
        .await
        .expect("explicit resume restored generation");
    assert!(!resumed.is_paused());
}

#[tokio::test]
async fn restore_validates_artifact_before_allocating_durable_lifecycle_state() {
    let fixture = restore_fixture().await;
    let restore = request(&fixture, "restore-tampered", "restore-tampered-operation");
    let mut tampered = fixture.artifact_bytes.clone();
    tampered[0] ^= 0x01;
    tokio::fs::write(&fixture.artifact_path, &tampered)
        .await
        .expect("tamper checkpoint artifact");

    let error = fixture
        .service
        .restore(restore.clone())
        .await
        .expect_err("tampered artifact must fail preflight");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    let missing = fixture
        .service
        .state(StateRequest {
            target: ContainerTarget::current(restore.id().clone()),
        })
        .await
        .expect_err("preflight failure must not reserve a generation");
    assert_eq!(missing.code, ErrorCode::NotFound);
    assert!(!fixture
        .driver
        .calls()
        .iter()
        .any(|call| matches!(call, DriverCall::Restore(_))));

    tokio::fs::write(&fixture.artifact_path, &fixture.artifact_bytes)
        .await
        .expect("repair checkpoint artifact");
    let restored = fixture
        .service
        .restore(restore)
        .await
        .expect("retry after read-only preflight failure");
    assert_eq!(restored.restored().generation, Generation(1));
}

#[tokio::test]
async fn terminal_restore_failure_is_replayed_and_quarantines_only_its_generation() {
    let fixture = restore_fixture().await;
    let restore = request(&fixture, "restore-failure", "restore-terminal-failure");
    fixture.driver.fail_next(
        "restore",
        Error::new(
            ErrorCode::FailedPrecondition,
            "recording restore terminal failure",
        )
        .for_operation("driver-restore"),
    );

    let first = fixture
        .service
        .restore(restore.clone())
        .await
        .expect_err("terminal restore must fail");
    let replay = fixture
        .service
        .restore(restore.clone())
        .await
        .expect_err("terminal restore failure must replay");
    assert_eq!(replay, first);
    assert_eq!(
        fixture
            .driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Restore(_)))
            .count(),
        1
    );
    assert_eq!(
        fixture
            .driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::RestoreValidation(_)))
            .count(),
        1
    );
    assert_eq!(
        tokio::fs::read(&fixture.artifact_path)
            .await
            .expect("caller artifact after failed restore"),
        fixture.artifact_bytes
    );

    let retry = request(&fixture, "restore-failure", "restore-after-failure");
    let restored = fixture
        .service
        .restore(retry)
        .await
        .expect("reuse ID after quarantined restore failure");
    assert_eq!(restored.restored().generation, Generation(2));
    assert!(restored.restored().is_paused());
}
