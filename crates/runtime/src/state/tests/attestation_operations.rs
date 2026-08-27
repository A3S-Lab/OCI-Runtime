use a3s_oci_sdk::{
    ContainerRecord, EventsRequest, RuntimeArtifact, RuntimeEventKind, TeeAttestationRequest,
    TeeAttestationResponse, TeeEvidence, TeeLaunchRequest, TeeMeasurement, TeeMode, TeeReportData,
    TeeSha256Digest, TeeTechnology, AMD_SEV_SNP_LAUNCH_EXTENSION, TEE_REPORT_DATA_BYTES,
};

use crate::state::model::{StoredOperationStatus, OPERATION_SCHEMA_VERSION};
use crate::state::AttestationOperationPreparation;

use super::*;

async fn tee_fixture() -> (TempDir, DurableStateStore, ContainerRecord) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let launch = TeeLaunchRequest::new(TeeTechnology::AmdSevSnp, TeeMode::Simulated);
    let mut configuration: serde_json::Value =
        serde_json::from_str(TEST_CONFIG).expect("TEE configuration fixture");
    configuration["annotations"][AMD_SEV_SNP_LAUNCH_EXTENSION] =
        serde_json::json!(launch.to_annotation_value().expect("TEE launch annotation"));
    let bundle = OciBundle::from_json(
        bundle_directory,
        serde_json::to_string_pretty(&configuration).expect("encode TEE fixture"),
    )
    .expect("TEE bundle");
    let create = CreateRequest {
        context: OperationContext::new(operation_id("attestation-state-create")),
        id: container_id("attestation-state-container"),
        attachments: CreateAttachments::from_bundle(&bundle, ProcessIo::default())
            .expect("base attachments")
            .attach_tee_launch(&bundle)
            .expect("TEE launch attachments"),
        bundle,
        isolation: IsolationRequest::DedicatedVm,
    };
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("open TEE state store");
    create_container(&store, &create).await;
    let source = store
        .load_stored_container(&create.id)
        .await
        .expect("load TEE source")
        .record;
    (temporary, store, source)
}

fn attestation_request(source: &ContainerRecord, operation: &str) -> TeeAttestationRequest {
    TeeAttestationRequest::new(
        OperationContext::new(operation_id(operation)),
        ContainerTarget::exact(container_id(source.state.id()), source.generation),
        TeeReportData::new([0x5a; TEE_REPORT_DATA_BYTES]),
    )
    .expect("attestation request")
}

fn attestation_response(
    source: &ContainerRecord,
    request: &TeeAttestationRequest,
    config_digest: &str,
) -> TeeAttestationResponse {
    TeeAttestationResponse::new(
        request.target.clone(),
        TeeLaunchRequest::new(TeeTechnology::AmdSevSnp, TeeMode::Simulated),
        request.report_data,
        TeeSha256Digest::new(config_digest).expect("configuration digest"),
        TeeSha256Digest::new(
            source
                .attachments_digest
                .clone()
                .expect("attachment digest"),
        )
        .expect("attachment SHA-256 digest"),
        source.driver,
        RuntimeArtifact::new(
            "attestation-state-test",
            "1.0.0",
            format!("sha256:{}", "a".repeat(64)),
            None,
        )
        .expect("runtime artifact"),
        TeeSha256Digest::new(format!("sha256:{}", "b".repeat(64))).expect("driver build digest"),
        TeeMeasurement::new(format!("sha384:{}", "c".repeat(96))).expect("measurement"),
        TeeEvidence::new(
            "application/vnd.amd.sev-snp.report",
            request.report_data.as_bytes().to_vec(),
        )
        .expect("evidence"),
    )
    .expect("attestation response")
}

#[tokio::test]
async fn attestation_replays_exact_evidence_after_reopen_and_rejects_request_drift() {
    let (temporary, store, source) = tee_fixture().await;
    let request = attestation_request(&source, "attestation-state-report");
    let prepared = store
        .prepare_attestation(&request)
        .await
        .expect("prepare attestation");
    let AttestationOperationPreparation::Prepared(prepared_source) = prepared else {
        panic!("new attestation must prepare")
    };
    assert_eq!(prepared_source.record, source);
    let response = attestation_response(&source, &request, &source.config_digest);
    assert_eq!(
        store
            .complete_attestation(&request.context.operation_id, response.clone())
            .await
            .expect("complete attestation"),
        response
    );
    drop(store);

    let reopened = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("reopen TEE state store");
    assert!(matches!(
        reopened
            .prepare_attestation(&request)
            .await
            .expect("replay attestation"),
        AttestationOperationPreparation::Replayed(replayed) if *replayed == response
    ));

    let mut drifted = request.clone();
    drifted.report_data = TeeReportData::new([0x6b; TEE_REPORT_DATA_BYTES]);
    let error = reopened
        .prepare_attestation(&drifted)
        .await
        .expect_err("operation ID reuse with changed report data must fail");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);

    let events = reopened
        .events(&EventsRequest {
            container: Some(request.target.clone()),
            after_sequence: 0,
            limit: 32,
            wait_timeout_ms: None,
        })
        .await
        .expect("attestation events");
    let attested = events
        .events
        .iter()
        .find(|event| event.kind == RuntimeEventKind::ContainerAttested)
        .expect("durable attestation event");
    assert_eq!(
        attested.operation_id.as_ref(),
        Some(&request.context.operation_id)
    );
    assert_eq!(
        attested
            .attributes
            .get("evidence-digest")
            .map(String::as_str),
        Some(response.evidence().digest().as_str())
    );
}

#[tokio::test]
async fn startup_rejects_attestation_evidence_that_drifted_from_its_durable_source() {
    let (temporary, store, source) = tee_fixture().await;
    let request = attestation_request(&source, "attestation-state-tampered");
    store
        .prepare_attestation(&request)
        .await
        .expect("prepare attestation");
    store
        .complete_attestation(
            &request.context.operation_id,
            attestation_response(&source, &request, &source.config_digest),
        )
        .await
        .expect("complete attestation");

    let mut operation = store
        .load_operation(&request.context.operation_id)
        .await
        .expect("load attestation journal");
    assert_eq!(operation.schema_version, OPERATION_SCHEMA_VERSION);
    operation.outcome = StoredOperationStatus::SucceededAttestation {
        response: Box::new(attestation_response(
            &source,
            &request,
            &format!("sha256:{}", "f".repeat(64)),
        )),
    };
    let operation_path = store.operation_path(&request.context.operation_id);
    drop(store);
    tokio::fs::write(
        operation_path,
        serde_json::to_vec(&operation).expect("encode tampered attestation journal"),
    )
    .await
    .expect("write tampered attestation journal");

    let error = DurableStateStore::open(state_root(&temporary))
        .await
        .expect_err("source-binding drift must fail startup audit");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("invalid durable evidence"));
}
