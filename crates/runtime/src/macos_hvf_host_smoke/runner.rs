use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use a3s_oci_core::CapabilityStatus;
use a3s_oci_sdk::{ContainerId, OciBundle};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::cleanup;
use super::host::{self, HostServiceProcess};
use super::owner_death::OwnerDeathConfig;
use super::report::{
    canonical_git_revision, MacosHvfArtifactEvidence, MacosHvfHostServiceSmokeReport,
    MacosHvfPublicLifecycleEvidence,
};
use super::soak::SoakConfig;
use crate::unix_service::{validate_unix_socket_path, SERVICE_SOCKET_NAME};

pub const MIN_MACOS_HVF_HOST_SERVICE_SOAK_ITERATIONS: u32 = 25;
pub const MAX_MACOS_HVF_HOST_SERVICE_SOAK_ITERATIONS: u32 = 1_000;
const EVIDENCE_DIRECTORY_PREFIX: &str = "hvf-";
const SERVICE_DIRECTORY_NAME: &str = "s";

/// Inputs for one persistent public Host Service qualification run.
#[derive(Debug, Clone)]
pub struct MacosHvfHostServiceSmokeConfig {
    pub host_service_executable: PathBuf,
    pub shim: PathBuf,
    pub system_image_manifest: PathBuf,
    pub bundle: PathBuf,
    pub work_parent: PathBuf,
    pub iterations: u32,
    pub source_revision: Option<String>,
}

/// Exercise the complete public Apple Silicon Host Service product path.
pub async fn run(config: MacosHvfHostServiceSmokeConfig) -> MacosHvfHostServiceSmokeReport {
    let mut report =
        MacosHvfHostServiceSmokeReport::initial(config.work_parent.clone(), config.iterations);
    let prepared = match PreparedRun::open(config).await {
        Ok(prepared) => prepared,
        Err(reason) => {
            report.reason = Some(reason);
            return report;
        }
    };
    report.evidence_root = prepared.evidence_root.clone();
    report.artifacts = prepared.artifacts.clone();
    if let Err(reason) = persist_full_report(&report) {
        report.reason = Some(reason);
        return report;
    }

    if let Err(reason) = run_lifecycle_phase(&prepared, &mut report.lifecycle).await {
        report.lifecycle.reason = Some(reason.clone());
        report.reason = Some(format!("public lifecycle qualification failed: {reason}"));
        let phase = report.lifecycle.clone();
        persist_phase_and_report(&prepared, "lifecycle.json", &phase, &mut report);
        return report;
    }
    if !report.lifecycle.is_success() {
        let reason = "public lifecycle qualification returned incomplete evidence".to_string();
        report.lifecycle.reason = Some(reason.clone());
        report.reason = Some(reason);
        let phase = report.lifecycle.clone();
        persist_phase_and_report(&prepared, "lifecycle.json", &phase, &mut report);
        return report;
    }
    let phase = report.lifecycle.clone();
    persist_phase_and_report(&prepared, "lifecycle.json", &phase, &mut report);
    if report.reason.is_some() {
        return report;
    }

    let owner_root = prepared.evidence_root.join("owner-death");
    let owner_result = super::owner_death::run(
        OwnerDeathConfig {
            executable: &prepared.executable,
            service_root: &owner_root.join(SERVICE_DIRECTORY_NAME),
            shim: &prepared.shim,
            manifest: &prepared.manifest,
            source_bundle: &prepared.bundle,
            stdout: &owner_root.join("first.stdout.log"),
            stderr: &owner_root.join("first.stderr.log"),
            replacement_stdout: &owner_root.join("replacement.stdout.log"),
            replacement_stderr: &owner_root.join("replacement.stderr.log"),
            nonce: &format!("{}-owner", prepared.nonce),
        },
        &mut report.owner_death,
    )
    .await;
    if let Err(reason) = owner_result {
        report.owner_death.reason = Some(reason.clone());
        report.reason = Some(format!(
            "Host Service owner-death qualification failed: {reason}"
        ));
        let phase = report.owner_death.clone();
        persist_phase_and_report(&prepared, "owner-death.json", &phase, &mut report);
        return report;
    }
    if !report.owner_death.is_success() {
        let reason =
            "Host Service owner-death qualification returned incomplete evidence".to_string();
        report.owner_death.reason = Some(reason.clone());
        report.reason = Some(reason);
        let phase = report.owner_death.clone();
        persist_phase_and_report(&prepared, "owner-death.json", &phase, &mut report);
        return report;
    }
    let phase = report.owner_death.clone();
    persist_phase_and_report(&prepared, "owner-death.json", &phase, &mut report);
    if report.reason.is_some() {
        return report;
    }

    let soak_root = prepared.evidence_root.join("soak");
    let soak_result = super::soak::run(
        SoakConfig {
            executable: &prepared.executable,
            service_root: &soak_root.join(SERVICE_DIRECTORY_NAME),
            shim: &prepared.shim,
            manifest: &prepared.manifest,
            source_bundle: &prepared.bundle,
            stdout: &soak_root.join("host.stdout.log"),
            stderr: &soak_root.join("host.stderr.log"),
            nonce: &format!("{}-soak", prepared.nonce),
            iterations: prepared.iterations,
        },
        &mut report.soak,
    )
    .await;
    if let Err(reason) = soak_result {
        report.soak.reason = Some(reason.clone());
        report.reason = Some(format!("public Host Service soak failed: {reason}"));
        let phase = report.soak.clone();
        persist_phase_and_report(&prepared, "soak.json", &phase, &mut report);
        return report;
    }
    if !report.soak.is_success() {
        let reason = "public Host Service soak returned incomplete evidence".to_string();
        report.soak.reason = Some(reason.clone());
        report.reason = Some(reason);
        let phase = report.soak.clone();
        persist_phase_and_report(&prepared, "soak.json", &phase, &mut report);
        return report;
    }
    let phase = report.soak.clone();
    persist_phase_and_report(&prepared, "soak.json", &phase, &mut report);
    if report.reason.is_some() {
        return report;
    }

    report.status = CapabilityStatus::Available;
    if !report.is_success() {
        report.status = CapabilityStatus::Unavailable;
        report.reason =
            Some("public Host Service report failed its final completeness audit".into());
    }
    if let Err(reason) = persist_full_report(&report) {
        report.status = CapabilityStatus::Unavailable;
        report.reason = Some(reason);
    }
    report
}

struct PreparedRun {
    executable: PathBuf,
    shim: PathBuf,
    manifest: PathBuf,
    bundle: PathBuf,
    evidence_root: PathBuf,
    nonce: String,
    iterations: u32,
    artifacts: MacosHvfArtifactEvidence,
}

impl PreparedRun {
    async fn open(config: MacosHvfHostServiceSmokeConfig) -> Result<Self, String> {
        if !(MIN_MACOS_HVF_HOST_SERVICE_SOAK_ITERATIONS
            ..=MAX_MACOS_HVF_HOST_SERVICE_SOAK_ITERATIONS)
            .contains(&config.iterations)
        {
            return Err(format!(
                "public Host Service soak iterations must be in {}..={}",
                MIN_MACOS_HVF_HOST_SERVICE_SOAK_ITERATIONS,
                MAX_MACOS_HVF_HOST_SERVICE_SOAK_ITERATIONS
            ));
        }
        let work_parent =
            canonical_plain_directory(&config.work_parent, "qualification work parent")?;
        let executable = canonical_plain_file(
            &config.host_service_executable,
            "Host Service executable",
            true,
        )?;
        let shim = canonical_plain_file(&config.shim, "entitlement-signed libkrun shim", true)?;
        let manifest = canonical_plain_file(
            &config.system_image_manifest,
            "system-image manifest",
            false,
        )?;
        let bundle = canonical_plain_directory(&config.bundle, "source OCI bundle")?;
        let loaded = OciBundle::load(&bundle)
            .await
            .map_err(|error| format!("failed to validate source OCI bundle: {error}"))?;
        let source_revision = validate_source_revision(config.source_revision)?;
        let artifacts = MacosHvfArtifactEvidence {
            host_service_executable: executable.clone(),
            host_service_executable_sha256: sha256_file(&executable)?,
            shim: shim.clone(),
            shim_sha256: sha256_file(&shim)?,
            system_image_manifest: manifest.clone(),
            system_image_manifest_sha256: sha256_file(&manifest)?,
            source_bundle: bundle.clone(),
            source_bundle_config_digest: loaded.config_digest().to_string(),
            source_revision,
        };
        let nonce = unique_nonce()?;
        let evidence_root = qualification_evidence_root(&work_parent, &nonce);
        validate_qualification_socket_paths(&evidence_root)?;
        create_private_directory(&evidence_root)?;
        for name in ["lifecycle", "owner-death", "soak"] {
            let phase = evidence_root.join(name);
            create_private_directory(&phase)?;
            create_private_directory(&phase.join(SERVICE_DIRECTORY_NAME))?;
        }
        Ok(Self {
            executable,
            shim,
            manifest,
            bundle,
            evidence_root,
            nonce,
            iterations: config.iterations,
            artifacts,
        })
    }
}

async fn run_lifecycle_phase(
    prepared: &PreparedRun,
    evidence: &mut MacosHvfPublicLifecycleEvidence,
) -> Result<(), String> {
    let phase_root = prepared.evidence_root.join("lifecycle");
    let service_root = phase_root.join(SERVICE_DIRECTORY_NAME);
    let runtime_root = service_root.join("runtime");
    let endpoint_baseline = host::endpoint_inventory()?;
    let mut service = HostServiceProcess::spawn(
        &prepared.executable,
        &service_root,
        &prepared.shim,
        &prepared.manifest,
        &phase_root.join("host.stdout.log"),
        &phase_root.join("host.stderr.log"),
    )
    .await?;
    evidence.socket_private = true;
    let pid = service.pid()?;
    let client = match service.connect().await {
        Ok(client) => client,
        Err(error) => {
            service.emergency_stop().await;
            return Err(error);
        }
    };
    let descriptors_before = host::descriptor_inventory(pid)?;
    evidence.open_descriptors_before = u32::try_from(descriptors_before.len()).ok();
    let nonce = format!("{}-lifecycle", prepared.nonce);
    let outcome = super::lifecycle::run(
        &client,
        &prepared.bundle,
        &runtime_root,
        pid,
        &nonce,
        evidence,
    )
    .await;
    if outcome.is_err() {
        if let Ok(id) = ContainerId::new(format!("hvf-public-{nonce}")) {
            super::lifecycle::best_effort_delete(&client, &id, &nonce).await;
        }
    }
    let captured_processes = match &outcome {
        Ok(outcome) => outcome.vm_processes.clone(),
        Err(_) => host::process_descendants(pid).unwrap_or_default(),
    };
    let operation_result = outcome.map(|outcome| outcome.target);
    let descriptors_restored =
        host::wait_for_descriptor_inventory(pid, &descriptors_before).await?;
    let descriptors_after = host::descriptor_inventory(pid)?;
    evidence.open_descriptors_after = u32::try_from(descriptors_after.len()).ok();
    evidence.service_descriptor_inventory_restored = descriptors_restored;
    evidence.vm_processes_reaped = host::wait_for_processes_reaped(&captured_processes).await?;
    evidence.endpoint_inventory_restored =
        host::wait_for_endpoint_inventory(&endpoint_baseline).await?;
    let inventory = cleanup::inventory(&runtime_root)?;
    evidence.bundle_handoffs_clean = inventory.bundle_handoffs_clean;
    evidence.runtime_shares_clean = inventory.runtime_shares_clean;
    evidence.recovery_reports_clean = inventory.recovery_reports_clean;
    evidence.console_files_created =
        u32::try_from(inventory.console_files.len()).unwrap_or(u32::MAX);
    drop(client);
    evidence.service_exit_success = match service.terminate().await {
        Ok(success) => success,
        Err(error) => {
            service.emergency_stop().await;
            return Err(match operation_result {
                Ok(_) => error,
                Err(primary) => format!("{primary}; Host Service shutdown also failed: {error}"),
            });
        }
    };
    evidence.service_socket_removed = cleanup::socket_absent(&service_root)?;
    operation_result?;
    if !evidence.service_descriptor_inventory_restored
        || !evidence.vm_processes_reaped
        || !evidence.endpoint_inventory_restored
        || !evidence.bundle_handoffs_clean
        || !evidence.runtime_shares_clean
        || !evidence.recovery_reports_clean
        || !evidence.service_socket_removed
        || !evidence.service_exit_success
    {
        return Err("public lifecycle did not restore all Host Service cleanup baselines".into());
    }
    Ok(())
}

fn persist_phase_and_report<T: Serialize>(
    prepared: &PreparedRun,
    name: &str,
    phase: &T,
    report: &mut MacosHvfHostServiceSmokeReport,
) {
    let phase_result = atomic_write_json(&prepared.evidence_root.join(name), phase);
    let report_result = persist_full_report(report);
    if let Err(reason) = phase_result.and(report_result) {
        report.status = CapabilityStatus::Unavailable;
        report.reason = Some(reason);
        let _ = persist_full_report(report);
    }
}

fn persist_full_report(report: &MacosHvfHostServiceSmokeReport) -> Result<(), String> {
    atomic_write_json(&report.evidence_root.join("report.json"), report)
}

fn atomic_write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let mut encoded = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to encode {}: {error}", path.display()))?;
    encoded.push(b'\n');
    let pending = path.with_extension("json.pending");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&pending)
        .map_err(|error| format!("failed to create {}: {error}", pending.display()))?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("failed to persist {}: {error}", pending.display()))?;
    drop(file);
    std::fs::rename(&pending, path)
        .map_err(|error| format!("failed to publish {}: {error}", path.display()))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("report path has no parent: {}", path.display()))?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            format!(
                "failed to sync report directory {}: {error}",
                parent.display()
            )
        })
}

fn canonical_plain_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    canonical_plain_path(path, label, false, false)
}

fn canonical_plain_file(
    path: &Path,
    label: &str,
    require_executable: bool,
) -> Result<PathBuf, String> {
    canonical_plain_path(path, label, true, require_executable)
}

fn canonical_plain_path(
    path: &Path,
    label: &str,
    file: bool,
    require_executable: bool,
) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("{label} must be absolute: {}", path.display()));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    let kind_matches = if file {
        metadata.is_file()
    } else {
        metadata.is_dir()
    };
    // SAFETY: geteuid has no preconditions or failure result.
    let uid = unsafe { libc::geteuid() };
    if !kind_matches || metadata.file_type().is_symlink() || metadata.uid() != uid {
        return Err(format!(
            "{label} must be a plain same-UID {}: {}",
            if file { "file" } else { "directory" },
            path.display()
        ));
    }
    if require_executable && metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!("{label} is not executable: {}", path.display()));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| format!("failed to resolve {label} {}: {error}", path.display()))?;
    if canonical != path {
        return Err(format!(
            "{label} must use its canonical path: {} -> {}",
            path.display(),
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn create_private_directory(path: &Path) -> Result<(), String> {
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).map_err(|error| {
        format!(
            "failed to create private directory {}: {error}",
            path.display()
        )
    })?;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        format!(
            "failed to inspect private directory {}: {error}",
            path.display()
        )
    })?;
    // SAFETY: geteuid has no preconditions or failure result.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(format!(
            "private evidence directory contract failed: {}",
            path.display()
        ));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("failed to open {} for hashing: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("failed to hash {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_source_revision(revision: Option<String>) -> Result<String, String> {
    let revision = revision.ok_or_else(|| {
        "source revision is required for current-commit qualification".to_string()
    })?;
    if !canonical_git_revision(&revision) {
        return Err("source revision must be one canonical 40-character lowercase Git SHA".into());
    }
    Ok(revision)
}

fn unique_nonce() -> Result<String, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before the Unix epoch: {error}"))?
        .as_nanos();
    Ok(format!("{}-{nanos}", std::process::id()))
}

fn qualification_evidence_root(work_parent: &Path, nonce: &str) -> PathBuf {
    work_parent.join(format!("{EVIDENCE_DIRECTORY_PREFIX}{nonce}"))
}

fn validate_qualification_socket_paths(evidence_root: &Path) -> Result<(), String> {
    for phase in ["lifecycle", "owner-death", "soak"] {
        let socket = evidence_root
            .join(phase)
            .join(SERVICE_DIRECTORY_NAME)
            .join(SERVICE_SOCKET_NAME);
        validate_unix_socket_path(&socket, "macOS HVF qualification Host Service endpoint")
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        qualification_evidence_root, validate_qualification_socket_paths, validate_source_revision,
        MacosHvfHostServiceSmokeConfig, PreparedRun, MIN_MACOS_HVF_HOST_SERVICE_SOAK_ITERATIONS,
    };

    fn incomplete_config(work_parent: PathBuf) -> MacosHvfHostServiceSmokeConfig {
        MacosHvfHostServiceSmokeConfig {
            host_service_executable: PathBuf::from("/missing/a3s-oci"),
            shim: PathBuf::from("/missing/a3s-oci-krun-shim"),
            system_image_manifest: PathBuf::from("/missing/system-image.json"),
            bundle: PathBuf::from("/missing/bundle"),
            work_parent,
            iterations: MIN_MACOS_HVF_HOST_SERVICE_SOAK_ITERATIONS,
            source_revision: Some("a".repeat(40)),
        }
    }

    #[test]
    fn source_revision_requires_a_full_lowercase_git_sha() {
        assert_eq!(
            validate_source_revision(Some("a".repeat(40))).expect("full SHA"),
            "a".repeat(40)
        );
        for revision in [
            None,
            Some("a".repeat(39)),
            Some("A".repeat(40)),
            Some("g".repeat(40)),
        ] {
            assert!(validate_source_revision(revision).is_err());
        }
    }

    #[test]
    fn documented_work_parent_keeps_every_phase_socket_representable() {
        let root = qualification_evidence_root(
            PathBuf::from("/private/tmp/a3s-oci-hvf-host.XXXXXX").as_path(),
            "4294967295-9999999999999999999",
        );
        validate_qualification_socket_paths(&root)
            .expect("documented work parent must fit the longest generated socket path");
    }

    #[tokio::test]
    async fn invalid_iterations_fail_before_any_evidence_directory_is_created() {
        let temporary = tempfile::tempdir().expect("temporary parent");
        let parent = temporary.path().canonicalize().expect("canonical parent");
        let mut config = incomplete_config(parent.clone());
        config.iterations = MIN_MACOS_HVF_HOST_SERVICE_SOAK_ITERATIONS - 1;
        let error = PreparedRun::open(config)
            .await
            .err()
            .expect("invalid iterations must fail");
        assert!(error.contains("iterations"), "{error}");
        assert_eq!(std::fs::read_dir(&parent).expect("read parent").count(), 0);
    }

    #[tokio::test]
    async fn invalid_artifacts_fail_without_leaving_an_evidence_directory() {
        let temporary = tempfile::tempdir().expect("temporary parent");
        let parent = temporary.path().canonicalize().expect("canonical parent");
        let error = PreparedRun::open(incomplete_config(parent.clone()))
            .await
            .err()
            .expect("missing executable must fail");
        assert!(error.contains("Host Service executable"), "{error}");
        assert_eq!(std::fs::read_dir(&parent).expect("read parent").count(), 0);
    }
}
