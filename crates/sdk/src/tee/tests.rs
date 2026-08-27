use serde_json::json;

use super::*;
use crate::{ContainerId, Generation, OperationContext, OperationId};

fn target() -> ContainerTarget {
    ContainerTarget::exact(
        ContainerId::new("tee-container").expect("container ID"),
        Generation(7),
    )
}

#[test]
fn launch_annotation_is_canonical_and_technology_specific() {
    let launch = TeeLaunchRequest::new(TeeTechnology::AmdSevSnp, TeeMode::Hardware);
    let encoded = launch.to_annotation_value().expect("encode annotation");
    assert_eq!(
        TeeLaunchRequest::from_annotation_value(&encoded).unwrap(),
        launch
    );
    assert_eq!(
        launch.technology().extension_name(),
        AMD_SEV_SNP_LAUNCH_EXTENSION
    );

    let non_canonical = encoded.replace(",", ", ");
    assert!(TeeLaunchRequest::from_annotation_value(&non_canonical).is_err());
    assert!(TeeLaunchRequest::from_annotation_value(
        &json!({"schemaVersion": "unknown", "technology": "amd-sev-snp", "mode": "hardware"})
            .to_string()
    )
    .is_err());
}

#[test]
fn report_data_and_digests_reject_noncanonical_values() {
    let report_data = TeeReportData::new([0x5a; TEE_REPORT_DATA_BYTES]);
    let encoded = serde_json::to_string(&report_data).expect("serialize report data");
    assert_eq!(
        serde_json::from_str::<TeeReportData>(&encoded).unwrap(),
        report_data
    );
    assert!(serde_json::from_value::<TeeReportData>(json!("AA==")).is_err());
    assert!(TeeSha256Digest::new(format!("sha256:{}", "A".repeat(64))).is_err());
    assert!(TeeMeasurement::new(format!("sha384:{}", "0".repeat(95))).is_err());
}

#[test]
fn evidence_binds_bounded_payload_size_and_digest() {
    let evidence =
        TeeEvidence::new("application/vnd.amd.sev-snp.report", vec![1, 2, 3]).expect("evidence");
    assert_eq!(evidence.decode().unwrap(), vec![1, 2, 3]);
    assert_eq!(evidence.size_bytes(), 3);

    let mut value = serde_json::to_value(&evidence).expect("encode evidence");
    value["sizeBytes"] = json!(4);
    assert!(serde_json::from_value::<TeeEvidence>(value).is_err());
    assert!(TeeEvidence::new("Application/JSON", vec![1]).is_err());
    for media_type in ["/", "/json", "application/", "application/json/extra"] {
        assert!(TeeEvidence::new(media_type, vec![1]).is_err());
    }
    assert!(TeeEvidence::new(
        "application/octet-stream",
        vec![0; MAX_TEE_EVIDENCE_BYTES + 1]
    )
    .is_err());
}

#[test]
fn attestation_response_is_exactly_request_bound() {
    let request = TeeAttestationRequest::new(
        OperationContext::new(OperationId::new("attest-operation").unwrap()),
        target(),
        TeeReportData::new([9; TEE_REPORT_DATA_BYTES]),
    )
    .unwrap();
    let response = TeeAttestationResponse::new(
        target(),
        TeeLaunchRequest::new(TeeTechnology::AmdSevSnp, TeeMode::Simulated),
        request.report_data,
        TeeSha256Digest::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
        TeeSha256Digest::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
        DriverKind::LibkrunKvm,
        RuntimeArtifact::new(
            "a3s-oci-runtime",
            "0.3.1",
            format!("sha256:{}", "3".repeat(64)),
            None,
        )
        .unwrap(),
        TeeSha256Digest::new(format!("sha256:{}", "4".repeat(64))).unwrap(),
        TeeMeasurement::new(format!("sha384:{}", "5".repeat(96))).unwrap(),
        TeeEvidence::new("application/octet-stream", vec![6]).unwrap(),
    )
    .unwrap();
    response.validate_for_request(&request).unwrap();

    let mut changed = request;
    changed.report_data = TeeReportData::new([8; TEE_REPORT_DATA_BYTES]);
    assert!(response.validate_for_request(&changed).is_err());
}
