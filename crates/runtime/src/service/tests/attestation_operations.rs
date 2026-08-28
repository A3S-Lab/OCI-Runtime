use super::*;

fn request(target: ContainerTarget, operation: &str, byte: u8) -> TeeAttestationRequest {
    TeeAttestationRequest::new(
        OperationContext::new(operation_id(operation)),
        target,
        TeeReportData::new([byte; a3s_oci_sdk::TEE_REPORT_DATA_BYTES]),
    )
    .expect("TEE attestation request")
}

#[tokio::test]
async fn per_driver_tee_capability_routes_even_when_the_legacy_intersection_omits_it() {
    let temporary = tempfile::tempdir().expect("temporary state root");
    let tee_driver = Arc::new(RecordingDriver::with_attestation_operations());
    let mut shared_driver = RecordingDriver::shared_guest_supported();
    if shared_driver.capability.driver == tee_driver.capability.driver {
        shared_driver.capability.driver = DriverKind::LibkrunKvm;
    }
    let shared_driver = Arc::new(shared_driver);
    let drivers: Vec<Arc<dyn RuntimeDriver>> = vec![tee_driver.clone(), shared_driver];
    let service = HostRuntimeService::open_with_drivers(temporary.path().join("state"), drivers)
        .await
        .expect("open mixed-capability runtime");
    let info = service.features().await.expect("mixed feature report");
    assert!(!info.operations.contains(&RuntimeOperation::Attest));
    let advertised = info
        .extensions
        .drivers()
        .iter()
        .find(|entry| entry.driver() == tee_driver.capability.driver)
        .expect("TEE per-driver catalog entry");
    assert!(advertised.supports_operation(RuntimeOperation::Attest, RUNTIME_OPERATION_CONTRACT_V1));

    let create = tee_create_request(&temporary.path().join("tee-bundle"), "mixed-tee-create");
    let created = service
        .create(create.clone())
        .await
        .expect("mixed TEE create");
    let response = service
        .attest(request(
            ContainerTarget::exact(create.id, created.generation),
            "mixed-tee-attest",
            0x31,
        ))
        .await
        .expect("route per-driver attestation");
    assert_eq!(response.driver(), tee_driver.capability.driver);
}

#[tokio::test]
async fn a_service_without_any_tee_driver_rejects_before_source_lookup_or_journaling() {
    let temporary = tempfile::tempdir().expect("temporary state root");
    let service = HostRuntimeService::open(
        temporary.path().join("state"),
        Arc::new(RecordingDriver::supported()),
    )
    .await
    .expect("open non-TEE runtime");
    let error = service
        .attest(request(
            ContainerTarget::exact(container_id("missing-tee-source"), Generation(1)),
            "unsupported-tee-attest",
            0x19,
        ))
        .await
        .expect_err("unadvertised TEE attestation must fail");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(!temporary
        .path()
        .join("state")
        .join("operations")
        .join("unsupported-tee-attest.json")
        .exists());
}

#[tokio::test]
async fn service_open_rejects_durable_tee_capability_drift_before_recovery() {
    let temporary = tempfile::tempdir().expect("temporary state root");
    let state_root = temporary.path().join("state");
    let tee_driver = Arc::new(RecordingDriver::with_attestation_operations());
    let service = HostRuntimeService::open(&state_root, tee_driver)
        .await
        .expect("open TEE runtime");
    let create = tee_create_request(&temporary.path().join("tee-bundle"), "tee-drift-create");
    let created = service.create(create).await.expect("create TEE container");
    drop(service);

    let mut replacement = RecordingDriver::supported();
    replacement.capability.driver = created.driver;
    let replacement = Arc::new(replacement);
    let error = HostRuntimeService::open(
        &state_root,
        Arc::clone(&replacement) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect_err("a driver that withdrew TEE support must not recover the container");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains(created.state.id()));
    assert!(error.message.contains(AMD_SEV_SNP_LAUNCH_EXTENSION));
    assert!(!replacement
        .calls()
        .iter()
        .any(|call| matches!(call, DriverCall::Recover(_))));
}

#[tokio::test]
async fn tee_attestation_is_capability_gated_exact_and_durably_replayed() {
    let temporary = tempfile::tempdir().expect("temporary state root");
    let bundle = temporary.path().join("tee-bundle");
    let driver = Arc::new(RecordingDriver::with_attestation_operations());
    let service = HostRuntimeService::open(temporary.path().join("state"), driver.clone())
        .await
        .expect("open TEE runtime");
    let create = tee_create_request(&bundle, "tee-create");
    let created = service
        .create(create.clone())
        .await
        .expect("create TEE container");
    let target = ContainerTarget::exact(create.id.clone(), created.generation);

    let info = service.features().await.expect("TEE feature report");
    assert!(info.operations.contains(&RuntimeOperation::Attest));
    let advertised = info
        .extensions
        .drivers()
        .iter()
        .find(|entry| entry.driver() == created.driver)
        .expect("TEE driver capability");
    assert!(advertised.supports_operation(RuntimeOperation::Attest, RUNTIME_OPERATION_CONTRACT_V1));
    assert!(advertised.attachments().supports_extension(
        AMD_SEV_SNP_LAUNCH_EXTENSION,
        a3s_oci_sdk::TEE_LAUNCH_EXTENSION_VERSION
    ));

    let attest = request(target.clone(), "tee-attest", 0x5a);
    let first = service
        .attest(attest.clone())
        .await
        .expect("attest TEE container");
    assert_eq!(first.target(), &target);
    assert_eq!(first.report_data(), &attest.report_data);
    assert_eq!(first.launch().technology(), TeeTechnology::AmdSevSnp);
    assert_eq!(
        first.evidence().decode().expect("decode retained evidence"),
        attest.report_data.as_bytes()
    );

    let replayed = service
        .attest(attest.clone())
        .await
        .expect("replay attestation");
    assert_eq!(replayed, first);
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Attest(_)))
            .count(),
        1
    );
    drop(service);

    let reopened = HostRuntimeService::open(temporary.path().join("state"), driver.clone())
        .await
        .expect("reopen TEE runtime");
    assert_eq!(
        reopened
            .attest(attest.clone())
            .await
            .expect("reopen replay"),
        first
    );
    reopened
        .start(StartRequest {
            context: OperationContext::new(operation_id("start-after-attestation")),
            target: target.clone(),
        })
        .await
        .expect("start attested source");
    reopened
        .kill(KillRequest {
            context: OperationContext::new(operation_id("kill-after-attestation")),
            target: target.clone(),
            signal: Signal::new(15).expect("termination signal"),
            all: true,
        })
        .await
        .expect("stop attested source");
    drop(reopened);

    let stopped = HostRuntimeService::open(temporary.path().join("state"), driver.clone())
        .await
        .expect("reopen stopped TEE source");
    assert_eq!(
        stopped
            .attest(attest.clone())
            .await
            .expect("replay after source stopped"),
        first
    );
    stopped
        .delete(DeleteRequest {
            context: OperationContext::new(operation_id("delete-after-attestation")),
            target: target.clone(),
            mode: DeleteMode::StoppedOnly,
        })
        .await
        .expect("delete attested source");
    assert_eq!(
        stopped
            .attest(attest.clone())
            .await
            .expect("replay after source deletion"),
        first
    );
    drop(stopped);
    let after_delete = HostRuntimeService::open(temporary.path().join("state"), driver.clone())
        .await
        .expect("reopen after TEE source deletion");
    assert_eq!(
        after_delete
            .attest(attest.clone())
            .await
            .expect("reopen replay after source deletion"),
        first
    );
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Attest(_)))
            .count(),
        1
    );
    let mut drifted = attest;
    drifted.report_data = TeeReportData::new([0x6b; a3s_oci_sdk::TEE_REPORT_DATA_BYTES]);
    let error = after_delete
        .attest(drifted)
        .await
        .expect_err("operation ID drift must fail closed");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
}

#[tokio::test]
async fn non_tee_sources_and_terminal_driver_failures_do_not_leave_claims() {
    let temporary = tempfile::tempdir().expect("temporary state root");
    let driver = Arc::new(RecordingDriver::with_attestation_operations());
    let service = HostRuntimeService::open(temporary.path().join("state"), driver.clone())
        .await
        .expect("open TEE runtime");

    let normal = create_request(&temporary.path().join("normal-bundle"), "normal-create");
    let normal_created = service.create(normal.clone()).await.expect("normal create");
    let error = service
        .attest(request(
            ContainerTarget::exact(normal.id, normal_created.generation),
            "normal-attest",
            1,
        ))
        .await
        .expect_err("non-TEE source must fail");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(!temporary
        .path()
        .join("state/operations/normal-attest.json")
        .exists());

    let tee = tee_create_request(&temporary.path().join("tee-bundle"), "failed-tee-create");
    let created = service.create(tee.clone()).await.expect("TEE create");
    let target = ContainerTarget::exact(tee.id, created.generation);
    driver.fail_next(
        "attest",
        Error::new(
            ErrorCode::FailedPrecondition,
            "provider rejected report data",
        )
        .for_operation("driver-attest"),
    );
    let attest = request(target.clone(), "failed-tee-attest", 2);
    let first = service
        .attest(attest.clone())
        .await
        .expect_err("terminal provider failure");
    let replayed = service
        .attest(attest.clone())
        .await
        .expect_err("terminal failure replay");
    assert_eq!(replayed, first);

    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("start-after-attestation-failure")),
            target: target.clone(),
        })
        .await
        .expect("failure released the container claim");
    service
        .delete(DeleteRequest {
            context: OperationContext::new(operation_id("delete-after-attestation-failure")),
            target,
            mode: DeleteMode::Force,
        })
        .await
        .expect("delete after terminal attestation failure");
    assert_eq!(
        service
            .attest(attest)
            .await
            .expect_err("terminal failure replay after source deletion"),
        first
    );
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Attest(_)))
            .count(),
        1
    );
}
