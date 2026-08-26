use a3s_oci_core::{DriverKind, IsolationClass};

use super::{
    RuntimeArtifact, RuntimeDriverCapabilities, RuntimeExtensions, RuntimeNegotiationRequest,
    RuntimeOperationCapability, RUNTIME_EXTENSIONS_SCHEMA_V1, RUNTIME_OPERATION_CONTRACT_V1,
};
use crate::{
    AttachmentCapabilities, ErrorCode, RuntimeFeatures, RuntimeInfo, RuntimeOperation,
    ATTACHMENT_SCHEMA_V1,
};

const NETWORK_EXTENSION: &str = "dev.a3s.network.tsi";

fn artifact() -> RuntimeArtifact {
    RuntimeArtifact::new(
        "a3s-oci-runtime",
        "0.2.0",
        format!("sha256:{}", "a".repeat(64)),
        Some("0123456789abcdef".to_string()),
    )
    .expect("valid artifact")
}

fn dedicated() -> RuntimeDriverCapabilities {
    RuntimeDriverCapabilities::new(
        DriverKind::LibkrunWhpx,
        vec![IsolationClass::DedicatedVm],
        [
            RuntimeOperation::Create,
            RuntimeOperation::State,
            RuntimeOperation::Start,
            RuntimeOperation::Kill,
            RuntimeOperation::Delete,
            RuntimeOperation::Wait,
        ]
        .map(RuntimeOperationCapability::v1)
        .to_vec(),
        AttachmentCapabilities::base_v1()
            .with_extension(NETWORK_EXTENSION, vec![2, 1])
            .expect("network extension"),
    )
    .expect("dedicated capabilities")
}

fn shared() -> RuntimeDriverCapabilities {
    RuntimeDriverCapabilities::new(
        DriverKind::LibkrunHvf,
        vec![IsolationClass::SharedGuestKernel],
        [
            RuntimeOperation::Create,
            RuntimeOperation::State,
            RuntimeOperation::Start,
            RuntimeOperation::Kill,
            RuntimeOperation::Delete,
        ]
        .map(RuntimeOperationCapability::v1)
        .to_vec(),
        AttachmentCapabilities::base_v1(),
    )
    .expect("shared capabilities")
}

#[test]
fn selects_only_the_driver_that_satisfies_exact_versions() {
    let catalog =
        RuntimeExtensions::new(artifact(), vec![shared(), dedicated()]).expect("canonical catalog");
    assert_eq!(catalog.schema_version(), RUNTIME_EXTENSIONS_SCHEMA_V1);
    assert_eq!(
        catalog
            .artifact()
            .expect("exact artifact")
            .source_revision(),
        Some("0123456789abcdef")
    );
    assert_eq!(catalog.drivers()[0].driver(), DriverKind::LibkrunHvf);

    let request = RuntimeNegotiationRequest::new(IsolationClass::DedicatedVm)
        .with_operation(RuntimeOperation::Wait, RUNTIME_OPERATION_CONTRACT_V1)
        .expect("operation requirement")
        .with_attachment_schema(ATTACHMENT_SCHEMA_V1)
        .expect("attachment schema requirement")
        .with_attachment_extension(NETWORK_EXTENSION, 2)
        .expect("extension requirement");
    let selected = catalog
        .negotiate(&request)
        .expect("select dedicated driver");
    assert_eq!(selected.driver(), DriverKind::LibkrunWhpx);

    let unavailable = RuntimeNegotiationRequest::new(IsolationClass::SharedGuestKernel)
        .with_operation(RuntimeOperation::Wait, RUNTIME_OPERATION_CONTRACT_V1)
        .expect("operation requirement");
    let error = catalog
        .negotiate(&unavailable)
        .expect_err("wait is not shared-driver qualified");
    assert_eq!(error.code, ErrorCode::Unsupported);
}

#[test]
fn catalog_round_trip_retains_canonical_artifact_and_driver_contracts() {
    let catalog =
        RuntimeExtensions::new(artifact(), vec![dedicated(), shared()]).expect("canonical catalog");
    let encoded = serde_json::to_vec(&catalog).expect("encode catalog");
    let decoded: RuntimeExtensions = serde_json::from_slice(&encoded).expect("decode catalog");
    assert_eq!(decoded, catalog);
    assert_eq!(
        decoded.drivers()[1].operations()[0].versions(),
        &[RUNTIME_OPERATION_CONTRACT_V1]
    );
}

#[test]
fn rejects_invalid_artifacts_ambiguous_isolation_and_legacy_negotiation() {
    let invalid = RuntimeArtifact::new("a3s-oci-runtime", "0.2.0", "sha256:ABCDEF", None)
        .expect_err("non-canonical digest must fail");
    assert_eq!(invalid.code, ErrorCode::InvalidArgument);

    let mut conflicting = shared();
    conflicting.isolation_classes = vec![IsolationClass::DedicatedVm];
    let ambiguous = RuntimeExtensions::new(artifact(), vec![dedicated(), conflicting])
        .expect_err("one isolation class cannot have two owners");
    assert_eq!(ambiguous.code, ErrorCode::InvalidArgument);

    let legacy = RuntimeExtensions::default();
    let error = legacy
        .negotiate(&RuntimeNegotiationRequest::new(IsolationClass::DedicatedVm))
        .expect_err("legacy peer has no exact contract");
    assert_eq!(error.code, ErrorCode::Unsupported);
}

#[test]
fn runtime_info_from_a_legacy_peer_defaults_to_no_extension_catalog() {
    let info = RuntimeInfo {
        oci: crate::oci_spec::runtime::Features::default(),
        drivers: RuntimeFeatures::current(Vec::new()),
        operations: vec![RuntimeOperation::Features],
        attachments: AttachmentCapabilities::base_v1(),
        extensions: RuntimeExtensions::default(),
    };
    let mut encoded = serde_json::to_value(info).expect("encode runtime info");
    encoded
        .as_object_mut()
        .expect("runtime info object")
        .remove("extensions");

    let decoded: RuntimeInfo = serde_json::from_value(encoded).expect("decode legacy info");
    assert!(decoded.extensions.artifact().is_none());
    assert!(decoded.extensions.drivers().is_empty());
}
