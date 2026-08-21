use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use a3s_oci_sdk::OciBundle;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::report::{canonical_git_revision, LinuxKvmRecoveryArtifacts};
use crate::unix_service::validate_unix_socket_path;

pub(super) struct QualificationInputs {
    pub(super) host_service_executable: PathBuf,
    pub(super) shim: PathBuf,
    pub(super) system_image_manifest: PathBuf,
    pub(super) bundle: PathBuf,
    pub(super) work_parent: PathBuf,
    pub(super) source_revision: Option<String>,
}

pub(super) struct PreparedQualification {
    pub(super) executable: PathBuf,
    pub(super) shim: PathBuf,
    pub(super) manifest: PathBuf,
    pub(super) bundle: PathBuf,
    pub(super) service_root: PathBuf,
    pub(super) evidence_root: PathBuf,
    pub(super) nonce: String,
    pub(super) artifacts: LinuxKvmRecoveryArtifacts,
}

impl PreparedQualification {
    pub(super) async fn open(
        inputs: QualificationInputs,
        evidence_prefix: &str,
        endpoint_label: &str,
    ) -> Result<Self, String> {
        if !matches!(std::env::consts::ARCH, "x86_64" | "aarch64") {
            return Err(format!(
                "unsupported Linux KVM qualification architecture: {}",
                std::env::consts::ARCH
            ));
        }
        let work_parent = canonical_plain_directory(&inputs.work_parent, "work parent").await?;
        let executable = canonical_plain_file(
            &inputs.host_service_executable,
            "Host Service executable",
            true,
        )?;
        let shim = canonical_plain_file(&inputs.shim, "isolated libkrun shim", true)?;
        let manifest = canonical_plain_file(
            &inputs.system_image_manifest,
            "Linux KVM system-image manifest",
            false,
        )?;
        let bundle = canonical_plain_directory(&inputs.bundle, "source OCI bundle").await?;
        let loaded = OciBundle::load(&bundle)
            .await
            .map_err(|error| format!("failed to validate source OCI bundle: {error}"))?;
        let source_revision = inputs
            .source_revision
            .filter(|revision| canonical_git_revision(revision))
            .ok_or_else(|| "source revision must be 40 lowercase hexadecimal digits".to_string())?;
        let artifacts = LinuxKvmRecoveryArtifacts {
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
        let evidence_root = work_parent.join(format!("{evidence_prefix}-{nonce}"));
        let service_root = evidence_root.join("service");
        validate_unix_socket_path(&service_root.join("runtime.sock"), endpoint_label)
            .map_err(|error| error.to_string())?;
        create_private_directory(&evidence_root)?;
        create_private_directory(&service_root)?;
        Ok(Self {
            executable,
            shim,
            manifest,
            bundle,
            service_root,
            evidence_root,
            nonce,
            artifacts,
        })
    }
}

pub(super) fn persist_report<T: Serialize>(
    evidence_root: &Path,
    report: &T,
    label: &str,
) -> Result<(), String> {
    let encoded = serde_json::to_vec_pretty(report)
        .map_err(|error| format!("failed to encode {label}: {error}"))?;
    let path = evidence_root.join("report.json");
    let pending = evidence_root.join("report.json.pending");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&pending)
        .map_err(|error| format!("failed to create {label} pending file: {error}"))?;
    file.write_all(&encoded)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("failed to persist {label}: {error}"))?;
    drop(file);
    std::fs::rename(&pending, &path).map_err(|error| format!("failed to publish {label}: {error}"))
}

async fn canonical_plain_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{label} is not a plain directory: {}",
            path.display()
        ));
    }
    let canonical = tokio::fs::canonicalize(path)
        .await
        .map_err(|error| format!("failed to resolve {label} {}: {error}", path.display()))?;
    if canonical != path {
        return Err(format!(
            "{label} must be an absolute canonical path: {} -> {}",
            path.display(),
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn canonical_plain_file(path: &Path, label: &str, executable: bool) -> Result<PathBuf, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is not a plain file: {}", path.display()));
    }
    if executable && metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!("{label} is not executable: {}", path.display()));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| format!("failed to resolve {label} {}: {error}", path.display()))?;
    if canonical != path {
        return Err(format!(
            "{label} must be an absolute canonical path: {} -> {}",
            path.display(),
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn create_private_directory(path: &Path) -> Result<(), String> {
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|error| format!("failed to create {}: {error}", path.display()))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("failed to open {} for hashing: {error}", path.display()))?;
    let mut digest = Sha256::new();
    std::io::copy(&mut file, &mut digest)
        .map_err(|error| format!("failed to hash {}: {error}", path.display()))?;
    Ok(format!("{:x}", digest.finalize()))
}

fn unique_nonce() -> Result<String, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?
        .as_nanos();
    Ok(format!("{}-{nanos}", std::process::id()))
}
