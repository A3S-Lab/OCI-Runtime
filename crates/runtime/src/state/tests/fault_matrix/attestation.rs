use a3s_oci_sdk::{
    CreateAttachments, IsolationRequest, OciBundle, OperationContext, ProcessIo, RuntimeArtifact,
    TeeAttestationRequest, TeeAttestationResponse, TeeEvidence, TeeLaunchRequest, TeeMeasurement,
    TeeMode, TeeReportData, TeeSha256Digest, TeeTechnology, AMD_SEV_SNP_LAUNCH_EXTENSION,
    TEE_REPORT_DATA_BYTES,
};

use crate::state::AttestationOperationPreparation;

use super::*;

pub(super) async fn exercise_attestation_success(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = tee_create(&fixture, "attestation-success-create");
    let source = prepare_source(&fixture.root, &create).await;
    let request = attestation_request(&source, "attestation-success");
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open attestation success store");
    let error = drive_success(&store, &request)
        .await
        .expect_err("attestation success commit must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen attestation success store");
    let response = drive_success(&recovered, &request)
        .await
        .unwrap_or_else(|error| panic!("recover attestation after {point}: {error}"));
    assert_eq!(
        drive_success(&recovered, &request)
            .await
            .expect("replay recovered attestation"),
        response,
        "{point}"
    );
    assert_unclaimed(&recovered, &request.target).await;
    assert_consistent_layout(recovered.root());
}

pub(super) async fn exercise_attestation_failure(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = tee_create(&fixture, "attestation-failure-create");
    let source = prepare_source(&fixture.root, &create).await;
    let request = attestation_request(&source, "attestation-failure");
    let failure = terminal_failure("attest");
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open attestation failure store");
    let error = drive_failure(&store, &request, &failure)
        .await
        .expect_err("attestation failure commit must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen attestation failure store");
    drive_failure(&recovered, &request, &failure)
        .await
        .unwrap_or_else(|error| panic!("recover attestation failure after {point}: {error}"));
    assert_unclaimed(&recovered, &request.target).await;
    assert_consistent_layout(recovered.root());
}

fn tee_create(fixture: &Fixture, operation: &str) -> CreateRequest {
    let launch = TeeLaunchRequest::new(TeeTechnology::AmdSevSnp, TeeMode::Simulated);
    let mut configuration: serde_json::Value =
        serde_json::from_str(TEST_CONFIG).expect("TEE configuration fixture");
    configuration["annotations"][AMD_SEV_SNP_LAUNCH_EXTENSION] =
        serde_json::json!(launch.to_annotation_value().expect("TEE launch annotation"));
    let bundle = OciBundle::from_json(
        fixture.bundle.clone(),
        serde_json::to_string_pretty(&configuration).expect("encode TEE fixture"),
    )
    .expect("TEE bundle");
    CreateRequest {
        context: OperationContext::new(operation_id(operation)),
        id: container_id("fault-container"),
        attachments: CreateAttachments::from_bundle(&bundle, ProcessIo::default())
            .expect("base attachments")
            .attach_tee_launch(&bundle)
            .expect("TEE launch attachments"),
        bundle,
        isolation: IsolationRequest::DedicatedVm,
    }
}

async fn prepare_source(root: &Path, create: &CreateRequest) -> ContainerRecord {
    let store = DurableStateStore::open(root)
        .await
        .expect("open attestation source store");
    drive_create(&store, create)
        .await
        .expect("complete attestation source create")
}

fn attestation_request(source: &ContainerRecord, operation: &str) -> TeeAttestationRequest {
    TeeAttestationRequest::new(
        OperationContext::new(operation_id(operation)),
        ContainerTarget::exact(container_id(source.state.id()), source.generation),
        TeeReportData::new([0x4a; TEE_REPORT_DATA_BYTES]),
    )
    .expect("attestation request")
}

async fn drive_success(
    store: &DurableStateStore,
    request: &TeeAttestationRequest,
) -> a3s_oci_sdk::Result<TeeAttestationResponse> {
    match store.prepare_attestation(request).await? {
        AttestationOperationPreparation::Prepared(source)
        | AttestationOperationPreparation::Resume(source) => {
            let attachments_digest = source
                .record
                .attachments_digest
                .clone()
                .expect("TEE source attachment digest");
            let response = TeeAttestationResponse::new(
                request.target.clone(),
                source.launch,
                request.report_data,
                TeeSha256Digest::new(source.record.config_digest)?,
                TeeSha256Digest::new(attachments_digest)?,
                source.record.driver,
                RuntimeArtifact::new(
                    "fault-matrix-runtime",
                    "1.0.0",
                    format!("sha256:{}", "a".repeat(64)),
                    None,
                )?,
                TeeSha256Digest::new(format!("sha256:{}", "b".repeat(64)))?,
                TeeMeasurement::new(format!("sha384:{}", "c".repeat(96)))?,
                TeeEvidence::new(
                    "application/vnd.amd.sev-snp.report",
                    request.report_data.as_bytes().to_vec(),
                )?,
            )?;
            store
                .complete_attestation(&request.context.operation_id, response)
                .await
        }
        AttestationOperationPreparation::Replayed(response) => Ok(*response),
    }
}

async fn drive_failure(
    store: &DurableStateStore,
    request: &TeeAttestationRequest,
    failure: &Error,
) -> a3s_oci_sdk::Result<()> {
    match store.prepare_attestation(request).await {
        Ok(AttestationOperationPreparation::Prepared(_))
        | Ok(AttestationOperationPreparation::Resume(_)) => {
            store
                .fail_operation(&request.context.operation_id, failure)
                .await?;
        }
        Ok(AttestationOperationPreparation::Replayed(_)) => {
            panic!("failed attestation unexpectedly replayed success")
        }
        Err(error) if error == *failure => return Ok(()),
        Err(error) => return Err(error),
    }
    expect_failure(store.prepare_attestation(request).await, failure)
}

async fn assert_unclaimed(store: &DurableStateStore, target: &ContainerTarget) {
    let stored = store
        .load_stored_container(&target.id)
        .await
        .expect("load attestation source");
    assert!(stored.active_operation.is_none());
}
