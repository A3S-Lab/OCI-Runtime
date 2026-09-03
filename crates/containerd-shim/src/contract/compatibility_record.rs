use std::collections::BTreeSet;

use serde::Deserialize;

use super::{
    QualificationStatus, COMPATIBILITY_MATRIX, CONTRACT_VERSION, IDENTITY_ENCODING, RUNTIME_TYPE,
    TASK_API_SERVICE,
};

const RECORD: &str = include_str!("../../../../compat/containerd-runtime-v2.json");
const RECORD_SCHEMA_VERSION: &str = "a3s.oci.containerd-runtime-v2-compatibility.v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompatibilityRecord {
    schema_version: String,
    contract: RecordedContract,
    claims: Vec<RecordedClaim>,
    qualification_runs: Vec<QualificationRun>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedContract {
    version: u32,
    runtime_type: String,
    task_api: String,
    identity_encoding: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RecordedClaim {
    containerd: String,
    host: String,
    profile: String,
    status: RecordedQualificationStatus,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum RecordedQualificationStatus {
    DevelopmentQualified,
    NotQualified,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationRun {
    id: String,
    recorded_on: String,
    result: QualificationResult,
    claim_effect: ClaimEffect,
    source_commit: String,
    containerd: ContainerdRelease,
    host: QualificationHost,
    runtime_profile: RuntimeProfile,
    protocols: Protocols,
    artifacts: ArtifactSet,
    qualification: QualificationEvidence,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum QualificationResult {
    Passed,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ClaimEffect {
    SupportsDevelopmentClaim,
    ObservationOnly,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContainerdRelease {
    version: String,
    revision: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationHost {
    contract_host: String,
    distribution: String,
    kernel: String,
    architecture: String,
    environment: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeProfile {
    driver: String,
    isolation: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Protocols {
    sdk: ProtocolRange,
    agent: ProtocolRange,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolRange {
    minimum: u16,
    maximum: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactSet {
    cargo_lock_sha256: String,
    #[serde(default)]
    package: Option<PackageArtifact>,
    files: Vec<Artifact>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageArtifact {
    name: String,
    qualification_schema: String,
    qualification_report_sha256: String,
    qualification_report_size_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    role: String,
    name: String,
    sha256: String,
    size_bytes: Option<u64>,
    format: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationEvidence {
    test: String,
    passes: usize,
    duration_seconds: Vec<f64>,
    preflight_passed: bool,
    isolated_containerd: bool,
    default_containerd_preserved: bool,
    tasks_after: u64,
    containers_after: u64,
    temporary_roots_removed: Option<bool>,
    post_commit_resize_pty_forced_cleanup: bool,
    boundary_count: Option<u32>,
}

fn recorded_status(status: QualificationStatus) -> RecordedQualificationStatus {
    match status {
        QualificationStatus::DevelopmentQualified => {
            RecordedQualificationStatus::DevelopmentQualified
        }
        QualificationStatus::NotQualified => RecordedQualificationStatus::NotQualified,
    }
}

fn assert_nonempty(value: &str, field: &str) {
    assert!(!value.trim().is_empty(), "{field} must not be empty");
}

fn assert_lower_hex(value: &str, length: usize, field: &str) {
    assert_eq!(value.len(), length, "{field} must be {length} characters");
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{field} must contain lowercase hexadecimal characters"
    );
}

fn assert_iso_date(value: &str) {
    assert_eq!(value.len(), 10, "recorded_on must use YYYY-MM-DD");
    assert_eq!(&value[4..5], "-", "recorded_on must use YYYY-MM-DD");
    assert_eq!(&value[7..8], "-", "recorded_on must use YYYY-MM-DD");
    assert!(
        value
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit()),
        "recorded_on must use YYYY-MM-DD"
    );
}

#[test]
fn machine_readable_compatibility_record_is_complete_and_exact() {
    let record: CompatibilityRecord =
        serde_json::from_str(RECORD).expect("compatibility record must be valid JSON");

    assert_eq!(record.schema_version, RECORD_SCHEMA_VERSION);
    assert_eq!(record.contract.version, CONTRACT_VERSION);
    assert_eq!(record.contract.runtime_type, RUNTIME_TYPE);
    assert_eq!(record.contract.task_api, TASK_API_SERVICE);
    assert_eq!(record.contract.identity_encoding, IDENTITY_ENCODING);

    let expected_claims = COMPATIBILITY_MATRIX
        .iter()
        .map(|claim| RecordedClaim {
            containerd: claim.containerd.to_string(),
            host: claim.host.to_string(),
            profile: claim.profile.to_string(),
            status: recorded_status(claim.status),
        })
        .collect::<Vec<_>>();
    assert_eq!(record.claims, expected_claims);

    let required_roles = BTreeSet::from(["agent", "cli", "qualification-test", "shim"]);
    let mut run_ids = BTreeSet::new();
    let mut supported_claims = BTreeSet::new();

    for run in &record.qualification_runs {
        assert!(
            run_ids.insert(run.id.as_str()),
            "duplicate run id: {}",
            run.id
        );
        assert_iso_date(&run.recorded_on);
        assert_eq!(run.result, QualificationResult::Passed);
        assert_lower_hex(&run.source_commit, 40, "source_commit");
        assert_nonempty(&run.containerd.version, "containerd.version");
        if let Some(revision) = &run.containerd.revision {
            assert_lower_hex(revision, 40, "containerd.revision");
        }

        for (value, field) in [
            (&run.host.contract_host, "host.contract_host"),
            (&run.host.distribution, "host.distribution"),
            (&run.host.kernel, "host.kernel"),
            (&run.host.architecture, "host.architecture"),
            (&run.host.environment, "host.environment"),
            (&run.runtime_profile.driver, "runtime_profile.driver"),
            (&run.runtime_profile.isolation, "runtime_profile.isolation"),
        ] {
            assert_nonempty(value, field);
        }
        for (range, field) in [
            (&run.protocols.sdk, "protocols.sdk"),
            (&run.protocols.agent, "protocols.agent"),
        ] {
            assert!(range.minimum > 0, "{field}.minimum must be positive");
            assert!(
                range.minimum <= range.maximum,
                "{field}.minimum must not exceed maximum"
            );
        }

        assert_lower_hex(
            &run.artifacts.cargo_lock_sha256,
            64,
            "artifacts.cargo_lock_sha256",
        );
        if let Some(package) = &run.artifacts.package {
            assert_nonempty(&package.name, "artifacts.package.name");
            assert_nonempty(
                &package.qualification_schema,
                "artifacts.package.qualification_schema",
            );
            assert_lower_hex(
                &package.qualification_report_sha256,
                64,
                "artifacts.package.qualification_report_sha256",
            );
            assert!(
                package.qualification_report_size_bytes > 0,
                "artifacts.package.qualification_report_size_bytes must be positive"
            );
        }
        let mut artifact_names = BTreeSet::new();
        let mut artifact_roles = BTreeSet::new();
        for artifact in &run.artifacts.files {
            assert!(
                artifact_names.insert(artifact.name.as_str()),
                "duplicate artifact name in {}: {}",
                run.id,
                artifact.name
            );
            assert!(
                artifact_roles.insert(artifact.role.as_str()),
                "duplicate artifact role in {}: {}",
                run.id,
                artifact.role
            );
            assert_lower_hex(&artifact.sha256, 64, "artifact.sha256");
            if let Some(size_bytes) = artifact.size_bytes {
                assert!(size_bytes > 0, "artifact size must be positive");
            }
            if let Some(format) = &artifact.format {
                assert_nonempty(format, "artifact.format");
            }
        }
        assert_eq!(
            artifact_roles, required_roles,
            "artifact roles in {}",
            run.id
        );

        assert_eq!(
            run.qualification.test, "real_containerd_runtime_v2_qualification",
            "qualification test in {}",
            run.id
        );
        assert_eq!(
            run.qualification.passes,
            run.qualification.duration_seconds.len(),
            "pass count in {}",
            run.id
        );
        assert!(run.qualification.passes > 0, "{} has no passes", run.id);
        assert!(
            run.qualification
                .duration_seconds
                .iter()
                .all(|duration| duration.is_finite() && *duration > 0.0),
            "{} contains an invalid duration",
            run.id
        );
        assert!(
            run.qualification.preflight_passed,
            "{} failed preflight",
            run.id
        );
        assert!(
            run.qualification.isolated_containerd,
            "{} was not isolated",
            run.id
        );
        assert!(
            run.qualification.default_containerd_preserved,
            "{} changed the default containerd",
            run.id
        );
        assert_eq!(
            run.qualification.tasks_after, 0,
            "tasks leaked in {}",
            run.id
        );
        assert_eq!(
            run.qualification.containers_after, 0,
            "containers leaked in {}",
            run.id
        );
        if let Some(boundary_count) = run.qualification.boundary_count {
            assert!(boundary_count > 0, "boundary_count must be positive");
        }
        if run.qualification.post_commit_resize_pty_forced_cleanup {
            assert!(
                run.qualification.passes >= 3,
                "{} needs three passes for the ResizePty forced-cleanup gate",
                run.id
            );
            assert!(
                run.qualification.boundary_count.is_some(),
                "{} must retain its ResizePty boundary count",
                run.id
            );
        }

        let matching_development_claim = record.claims.iter().any(|claim| {
            claim.status == RecordedQualificationStatus::DevelopmentQualified
                && claim.containerd == run.containerd.version
                && claim.host == run.host.contract_host
                && claim.profile == run.runtime_profile.isolation
        });
        match run.claim_effect {
            ClaimEffect::SupportsDevelopmentClaim => {
                assert!(
                    matching_development_claim,
                    "{} does not match a development-qualified claim",
                    run.id
                );
                assert_eq!(run.qualification.temporary_roots_removed, Some(true));
                supported_claims.insert((
                    run.containerd.version.as_str(),
                    run.host.contract_host.as_str(),
                    run.runtime_profile.isolation.as_str(),
                ));
            }
            ClaimEffect::ObservationOnly => assert!(
                !matching_development_claim,
                "{} would accidentally promote a development-qualified claim",
                run.id
            ),
        }
    }

    let expected_supported_claims = record
        .claims
        .iter()
        .filter(|claim| claim.status == RecordedQualificationStatus::DevelopmentQualified)
        .map(|claim| {
            (
                claim.containerd.as_str(),
                claim.host.as_str(),
                claim.profile.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(supported_claims, expected_supported_claims);
    assert!(record.qualification_runs.iter().any(|run| {
        run.qualification.post_commit_resize_pty_forced_cleanup && run.qualification.passes >= 3
    }));

    for retained_run in [
        "2026-08-24-containerd-2.2.2-ubuntu-arm64",
        "2026-08-24-containerd-2.2.3-ubuntu-x86_64",
        "2026-08-28-containerd-2.2.1-wsl2-x86_64",
    ] {
        assert!(
            run_ids.contains(retained_run),
            "missing retained run: {retained_run}"
        );
    }
}
