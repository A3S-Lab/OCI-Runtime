use std::collections::HashMap;
use std::path::PathBuf;

use oci_spec::runtime::{ContainerState, StateBuilder};
use serde_json::{json, Value};

use super::*;
use crate::{
    ContainerId, ContainerRecord, CreateAttachments, DriverKind, Generation, HostPlatform,
    IsolationClass, IsolationRequest, OciBundle, OperationContext, OperationId, ProcessIo,
    RuntimeArtifact, ValidateRequest, PAUSED_STATE_ANNOTATION,
};

fn digest(symbol: char) -> CheckpointDigest {
    CheckpointDigest::new(format!("sha256:{}", symbol.to_string().repeat(64)))
        .expect("canonical test digest")
}

fn bundle(label: &str, executable: &str) -> OciBundle {
    OciBundle::from_json(
        std::env::current_dir()
            .expect("current directory")
            .join(format!("checkpoint-{label}-bundle")),
        serde_json::to_string(&json!({
            "ociVersion": "1.3.0",
            "root": {"path": "rootfs"},
            "process": {
                "cwd": "/",
                "args": [executable],
                "user": {"uid": 0, "gid": 0}
            }
        }))
        .expect("checkpoint test configuration"),
    )
    .expect("checkpoint test bundle")
}

fn attachments(bundle: &OciBundle) -> CreateAttachments {
    CreateAttachments::from_bundle(bundle, ProcessIo::default()).expect("base attachments")
}

fn record(
    bundle: &OciBundle,
    attachments: &CreateAttachments,
    id: &str,
    generation: u64,
    paused: bool,
) -> ContainerRecord {
    let mut builder = StateBuilder::default()
        .version("1.3.0")
        .id(id)
        .status(ContainerState::Running)
        .pid(4_242)
        .bundle(bundle.directory().to_path_buf());
    if paused {
        builder = builder.annotations(HashMap::from([(
            PAUSED_STATE_ANNOTATION.to_string(),
            "true".to_string(),
        )]));
    }
    ContainerRecord {
        state: builder.build().expect("checkpoint test state"),
        generation: Generation(generation),
        driver: DriverKind::NativeLinux,
        isolation: IsolationClass::SharedHostKernel,
        guest_session: None,
        network_enforcement: None,
        config_digest: bundle.config_digest().to_string(),
        attachments_digest: Some(attachments.digest().expect("attachment digest")),
    }
}

fn compatibility() -> CheckpointCompatibility {
    CheckpointCompatibility::new(
        DriverKind::NativeLinux,
        IsolationClass::SharedHostKernel,
        HostPlatform::Linux,
        "x86_64",
        RuntimeArtifact::new(
            "a3s-oci-runtime",
            "0.1.0",
            digest('a').to_string(),
            Some("checkpoint-contract-test".to_string()),
        )
        .expect("runtime artifact"),
        digest('b'),
        CheckpointFormat::new("criu-archive", 1).expect("checkpoint format"),
    )
    .expect("native checkpoint compatibility")
}

fn reference(source: &ContainerRecord) -> CheckpointReference {
    CheckpointReference::new(source, compatibility(), digest('c'), 8_192)
        .expect("checkpoint reference")
}

fn context(label: &str) -> OperationContext {
    OperationContext::new(OperationId::new(label).expect("operation ID"))
}

fn artifact_path(label: &str) -> CheckpointArtifactPath {
    CheckpointArtifactPath::new(
        std::env::current_dir()
            .expect("current directory")
            .join(format!("{label}.checkpoint")),
    )
    .expect("absolute artifact path")
}

fn replace_field(value: &mut Value, old: &str, new: &str) {
    let object = value.as_object_mut().expect("JSON object");
    let field = object.remove(old).expect("source field");
    object.insert(new.to_string(), field);
}

#[test]
fn immutable_reference_round_trips_and_binds_the_paused_source() {
    let bundle = bundle("round-trip", "/bin/true");
    let attachments = attachments(&bundle);
    let source = record(&bundle, &attachments, "checkpoint-source", 7, true);
    let reference = reference(&source);

    assert_eq!(reference.schema_version(), CHECKPOINT_REFERENCE_SCHEMA_V1);
    assert_eq!(reference.source().generation, Some(Generation(7)));
    assert_eq!(
        reference.source_config_digest().as_str(),
        bundle.config_digest()
    );
    assert_eq!(
        reference.source_attachments_digest().as_str(),
        attachments.digest().expect("attachment digest")
    );
    assert_eq!(
        reference.compatibility().runtime_artifact().name(),
        "a3s-oci-runtime"
    );
    assert_eq!(
        reference.compatibility().driver_build_digest(),
        &digest('b')
    );
    assert_eq!(reference.artifact_digest(), &digest('c'));
    assert_eq!(reference.artifact_size_bytes(), 8_192);

    let encoded = serde_json::to_value(&reference).expect("encode reference");
    let decoded: CheckpointReference = serde_json::from_value(encoded).expect("decode reference");
    assert_eq!(decoded, reference);

    let request = CheckpointRequest::new(
        context("checkpoint-round-trip"),
        reference.source().clone(),
        artifact_path("round-trip"),
    )
    .expect("checkpoint request");
    let response = CheckpointResponse::new(source, reference).expect("checkpoint response");
    response
        .validate_for_request(&request)
        .expect("checkpoint response binding");
}

#[test]
fn checkpoint_scalar_types_reject_noncanonical_inputs() {
    assert!(CheckpointDigest::new(format!("sha256:{}", "A".repeat(64))).is_err());
    assert!(CheckpointDigest::new("sha256:1234").is_err());
    assert!(CheckpointFormat::new("CRIU", 1).is_err());
    assert!(CheckpointFormat::new("criu", 0).is_err());
    assert!(serde_json::from_value::<CheckpointFormat>(json!({
        "name": "criu",
        "version": 0
    }))
    .is_err());

    assert!(CheckpointArtifactPath::new(PathBuf::from("relative.checkpoint")).is_err());
    let escaping = std::env::current_dir()
        .expect("current directory")
        .join("checkpoints")
        .join("..")
        .join("artifact.checkpoint");
    assert!(CheckpointArtifactPath::new(escaping).is_err());
    let dotted = std::env::current_dir()
        .expect("current directory")
        .join(".")
        .join("artifact.checkpoint");
    assert!(CheckpointArtifactPath::new(dotted).is_err());
    let mut trailing = std::env::current_dir()
        .expect("current directory")
        .join("artifact.checkpoint");
    trailing.push("");
    assert!(CheckpointArtifactPath::new(trailing).is_err());
    let mut root = std::env::current_dir().expect("current directory");
    while let Some(parent) = root.parent() {
        root = parent.to_path_buf();
    }
    assert!(CheckpointArtifactPath::new(root).is_err());
}

#[test]
fn reference_creation_requires_a_matching_paused_source_stack() {
    let bundle = bundle("paused-source", "/bin/true");
    let attachments = attachments(&bundle);
    let running = record(&bundle, &attachments, "checkpoint-source", 7, false);
    assert!(CheckpointReference::new(&running, compatibility(), digest('c'), 1).is_err());

    let paused = record(&bundle, &attachments, "checkpoint-source", 7, true);
    let paused_reference = reference(&paused);
    assert!(RestoreResponse::new(paused.clone(), paused_reference).is_err());
    let vm_compatibility = CheckpointCompatibility::new(
        DriverKind::LibkrunKvm,
        IsolationClass::DedicatedVm,
        HostPlatform::Linux,
        "x86_64",
        RuntimeArtifact::new("a3s-oci-runtime", "0.1.0", digest('a').to_string(), None)
            .expect("runtime artifact"),
        digest('b'),
        CheckpointFormat::new("vm-snapshot", 1).expect("checkpoint format"),
    )
    .expect("VM checkpoint compatibility");
    assert!(CheckpointReference::new(&paused, vm_compatibility, digest('c'), 1).is_err());
}

#[test]
fn reference_deserialization_rejects_tampered_evidence() {
    let bundle = bundle("tamper", "/bin/true");
    let attachments = attachments(&bundle);
    let source = record(&bundle, &attachments, "checkpoint-source", 7, true);
    let canonical = serde_json::to_value(reference(&source)).expect("reference JSON");

    let mut tampered = Vec::new();
    let mut schema = canonical.clone();
    schema["schemaVersion"] = json!("a3s.oci.checkpoint-reference.v2");
    tampered.push(schema);
    let mut size = canonical.clone();
    size["artifactSizeBytes"] = json!(0);
    tampered.push(size);
    let mut generation = canonical.clone();
    generation["source"]["generation"] = json!(0);
    tampered.push(generation);
    let mut architecture = canonical.clone();
    architecture["compatibility"]["architecture"] = json!("X86_64");
    tampered.push(architecture);
    let mut host_digest = canonical.clone();
    host_digest["compatibility"]["runtimeArtifact"]["digest"] =
        json!(format!("sha256:{}", "A".repeat(64)));
    tampered.push(host_digest);
    let mut unknown = canonical;
    unknown["retentionPolicy"] = json!("forever");
    tampered.push(unknown);

    for value in tampered {
        assert!(serde_json::from_value::<CheckpointReference>(value).is_err());
    }
}

#[test]
fn legacy_requests_decode_only_to_fail_closed_validation() {
    let bundle = bundle("legacy", "/bin/true");
    let attachments = attachments(&bundle);
    let source = record(&bundle, &attachments, "checkpoint-source", 7, true);
    let reference = reference(&source);

    let checkpoint = CheckpointRequest::new(
        context("checkpoint-legacy"),
        reference.source().clone(),
        artifact_path("legacy-checkpoint"),
    )
    .expect("checkpoint request");
    let mut legacy_checkpoint = serde_json::to_value(checkpoint).expect("checkpoint JSON");
    replace_field(&mut legacy_checkpoint, "artifact_path", "directory");
    legacy_checkpoint
        .as_object_mut()
        .expect("checkpoint object")
        .remove("quiesce");
    legacy_checkpoint["leave_running"] = json!(false);
    let decoded: CheckpointRequest =
        serde_json::from_value(legacy_checkpoint).expect("decode legacy checkpoint");
    assert!(decoded.validate().is_err());

    let restore = RestoreRequest::new(
        context("restore-legacy"),
        ContainerId::new("restored-container").expect("container ID"),
        bundle,
        artifact_path("legacy-restore"),
        IsolationRequest::SharedHostKernel,
        attachments,
        reference,
    )
    .expect("restore request");
    let mut legacy_restore = serde_json::to_value(restore).expect("restore JSON");
    replace_field(&mut legacy_restore, "artifact_path", "checkpoint_directory");
    legacy_restore
        .as_object_mut()
        .expect("restore object")
        .remove("reference");
    let decoded: RestoreRequest =
        serde_json::from_value(legacy_restore).expect("decode legacy restore");
    assert!(decoded.validate().is_err());
}

#[test]
fn restore_requires_exact_config_and_response_correlation() {
    let source_bundle = bundle("restore", "/bin/true");
    let source_attachments = attachments(&source_bundle);
    let source = record(
        &source_bundle,
        &source_attachments,
        "checkpoint-source",
        7,
        true,
    );
    let reference = reference(&source);
    let restore_id = ContainerId::new("restored-container").expect("container ID");
    let request = RestoreRequest::new(
        context("restore-operation"),
        restore_id.clone(),
        source_bundle.clone(),
        artifact_path("restore"),
        IsolationRequest::SharedHostKernel,
        source_attachments.clone(),
        reference.clone(),
    )
    .expect("restore request");
    let restored = record(
        &source_bundle,
        &source_attachments,
        restore_id.as_str(),
        11,
        true,
    );
    let response = RestoreResponse::new(restored, reference.clone()).expect("restore response");
    response
        .validate_for_request(&request)
        .expect("restore response binding");

    let other_bundle = bundle("restore-other", "/bin/false");
    let other_attachments = attachments(&other_bundle);
    assert!(RestoreRequest::new(
        context("restore-config-mismatch"),
        restore_id,
        other_bundle,
        artifact_path("restore-other"),
        IsolationRequest::SharedHostKernel,
        other_attachments,
        reference.clone(),
    )
    .is_err());

    let wrong_id = record(
        &source_bundle,
        &source_attachments,
        "wrong-restored-container",
        11,
        true,
    );
    let wrong_response =
        RestoreResponse::new(wrong_id, reference.clone()).expect("locally valid response");
    assert!(wrong_response.validate_for_request(&request).is_err());

    let mut wrong_attachments = record(
        &source_bundle,
        &source_attachments,
        "restored-container",
        11,
        true,
    );
    wrong_attachments.attachments_digest = Some(digest('f').to_string());
    let wrong_response =
        RestoreResponse::new(wrong_attachments, reference).expect("canonical response evidence");
    assert!(wrong_response.validate_for_request(&request).is_err());
}
