use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use a3s_oci_sdk::{
    runtime_bundle_handoff_root, ContainerTarget, Error, ErrorCode, Generation, Result,
};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use super::HvfRuntimeDriverConfig;

pub(super) const CONSOLE_DIRECTORY: &str = "console";
pub(super) const RECOVERY_DIRECTORY: &str = "recovery";
pub(super) const RUNTIME_SHARE_DIRECTORY: &str = "shares";
pub(super) const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
pub(super) const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Debug)]
pub(super) struct PreparedHvfLayout {
    pub(super) shim: PathBuf,
    pub(super) runtime_root: PathBuf,
    pub(super) system_image_manifest: PathBuf,
    pub(super) system_image_manifest_sha256: String,
    pub(super) runtime_share_root: PathBuf,
    pub(super) console_directory: PathBuf,
    pub(super) recovery_directory: PathBuf,
}

impl PreparedHvfLayout {
    pub(super) async fn open(config: HvfRuntimeDriverConfig) -> Result<Self> {
        let runtime_root =
            ensure_private_directory(config.runtime_root, "HVF runtime root").await?;
        let shim = canonical_plain_file(&config.shim, "HVF libkrun shim", false).await?;
        let system_image_manifest = canonical_plain_file(
            &config.system_image_manifest,
            "HVF system-image manifest",
            false,
        )
        .await?;
        if system_image_manifest.starts_with(&runtime_root)
            || runtime_root.starts_with(&system_image_manifest)
        {
            return Err(path_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "immutable HVF system-image manifest must be outside writable runtime root {}: {}",
                    runtime_root.display(),
                    system_image_manifest.display()
                ),
            ));
        }
        let system_image_manifest_sha256 = sha256_path(&system_image_manifest).await?;

        let runtime_share_root = ensure_private_directory(
            runtime_root.join(RUNTIME_SHARE_DIRECTORY),
            "HVF runtime-share root",
        )
        .await?;
        let console_directory = ensure_private_directory(
            runtime_root.join(CONSOLE_DIRECTORY),
            "HVF console directory",
        )
        .await?;
        let recovery_directory = ensure_private_directory(
            runtime_root.join(RECOVERY_DIRECTORY),
            "HVF recovery directory",
        )
        .await?;
        ensure_private_directory(
            runtime_bundle_handoff_root(&runtime_root)?,
            "HVF bundle-handoff root",
        )
        .await?;

        Ok(Self {
            shim,
            runtime_root,
            system_image_manifest,
            system_image_manifest_sha256,
            runtime_share_root,
            console_directory,
            recovery_directory,
        })
    }
}

pub(super) fn validate_absolute_normalized_path(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(path_error(
            ErrorCode::InvalidArgument,
            format!(
                "{label} must be an absolute normalized path: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

pub(super) async fn ensure_private_directory(
    path: PathBuf,
    label: &'static str,
) -> Result<PathBuf> {
    validate_absolute_normalized_path(&path, label)?;
    match tokio::fs::symlink_metadata(&path).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = tokio::fs::DirBuilder::new();
            builder.mode(PRIVATE_DIRECTORY_MODE);
            builder.create(&path).await.map_err(|error| {
                path_error(
                    ErrorCode::PermissionDenied,
                    format!("failed to create {label} {}: {error}", path.display()),
                )
            })?;
        }
        Err(error) => {
            return Err(path_error(
                ErrorCode::PermissionDenied,
                format!("failed to inspect {label} {}: {error}", path.display()),
            ));
        }
    }
    canonical_private_directory(&path, label).await
}

pub(super) async fn canonical_private_directory(path: &Path, label: &str) -> Result<PathBuf> {
    validate_absolute_normalized_path(path, label)?;
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        path_error(
            ErrorCode::FailedPrecondition,
            format!("failed to inspect {label} {}: {error}", path.display()),
        )
    })?;
    if !is_private_directory(&metadata) {
        // SAFETY: geteuid has no preconditions or failure return.
        let effective_uid = unsafe { libc::geteuid() };
        return Err(path_error(
            ErrorCode::PermissionDenied,
            format!(
                "{label} {} must be a real directory owned by UID {effective_uid} with mode 0700",
                path.display()
            ),
        ));
    }
    let canonical = tokio::fs::canonicalize(path).await.map_err(|error| {
        path_error(
            ErrorCode::FailedPrecondition,
            format!("failed to resolve {label} {}: {error}", path.display()),
        )
    })?;
    if canonical != path {
        return Err(path_error(
            ErrorCode::FailedPrecondition,
            format!(
                "{label} resolves through an alias: {} -> {}",
                path.display(),
                canonical.display()
            ),
        ));
    }
    Ok(canonical)
}

pub(super) async fn canonical_plain_directory(path: &Path, label: &str) -> Result<PathBuf> {
    canonical_plain_path(path, label, false, true).await
}

pub(super) async fn canonical_plain_file(
    path: &Path,
    label: &str,
    require_same_uid: bool,
) -> Result<PathBuf> {
    canonical_plain_path(path, label, true, require_same_uid).await
}

async fn canonical_plain_path(
    path: &Path,
    label: &str,
    file: bool,
    require_same_uid: bool,
) -> Result<PathBuf> {
    validate_absolute_normalized_path(path, label)?;
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        path_error(
            ErrorCode::FailedPrecondition,
            format!("failed to inspect {label} {}: {error}", path.display()),
        )
    })?;
    let kind_matches = if file {
        metadata.is_file()
    } else {
        metadata.is_dir()
    };
    // SAFETY: geteuid has no preconditions or failure return.
    let effective_uid = unsafe { libc::geteuid() };
    if !kind_matches
        || metadata.file_type().is_symlink()
        || (require_same_uid && metadata.uid() != effective_uid)
    {
        return Err(path_error(
            ErrorCode::FailedPrecondition,
            format!(
                "{label} is not a plain {}{}: {}",
                if file { "file" } else { "directory" },
                if require_same_uid {
                    format!(" owned by UID {effective_uid}")
                } else {
                    String::new()
                },
                path.display()
            ),
        ));
    }
    let canonical = tokio::fs::canonicalize(path).await.map_err(|error| {
        path_error(
            ErrorCode::FailedPrecondition,
            format!("failed to resolve {label} {}: {error}", path.display()),
        )
    })?;
    if canonical != path {
        return Err(path_error(
            ErrorCode::FailedPrecondition,
            format!(
                "{label} resolves through an alias: {} -> {}",
                path.display(),
                canonical.display()
            ),
        ));
    }
    Ok(canonical)
}

pub(super) fn is_private_directory(metadata: &std::fs::Metadata) -> bool {
    // SAFETY: geteuid has no preconditions or failure return.
    let effective_uid = unsafe { libc::geteuid() };
    metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == effective_uid
        && metadata.mode() & 0o777 == PRIVATE_DIRECTORY_MODE
}

pub(super) fn is_private_file(metadata: &std::fs::Metadata) -> bool {
    // SAFETY: geteuid has no preconditions or failure return.
    let effective_uid = unsafe { libc::geteuid() };
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == effective_uid
        && metadata.mode() & 0o777 == PRIVATE_FILE_MODE
}

pub(super) async fn path_metadata(path: &Path) -> Result<Option<std::fs::Metadata>> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(path_error(
            ErrorCode::Internal,
            format!("failed to inspect {}: {error}", path.display()),
        )),
    }
}

pub(super) fn require_exact_generation(
    target: &ContainerTarget,
    operation: &'static str,
) -> Result<Generation> {
    target.generation.ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "HVF driver operation requires an exact generation for container {}",
                target.id
            ),
        )
        .for_operation(operation)
    })
}

pub(super) async fn ensure_exact_runtime_share_path(
    runtime_share_root: &Path,
    target: &ContainerTarget,
) -> Result<PathBuf> {
    let generation = require_exact_generation(target, "prepare-hvf-runtime-share")?;
    ensure_private_directory(
        runtime_share_root.join(target.id.as_str()),
        "HVF container-share directory",
    )
    .await?;
    ensure_private_directory(
        runtime_share_root
            .join(target.id.as_str())
            .join(generation.0.to_string()),
        "HVF generation-share directory",
    )
    .await
}

pub(super) async fn existing_exact_runtime_share_path(
    runtime_share_root: &Path,
    target: &ContainerTarget,
    operation: &'static str,
) -> Result<Option<PathBuf>> {
    let generation = require_exact_generation(target, operation)?;
    let configured_container = runtime_share_root.join(target.id.as_str());
    if path_metadata(&configured_container).await?.is_none() {
        return Ok(None);
    }
    let container =
        canonical_private_directory(&configured_container, "HVF container-share directory").await?;
    if container.parent() != Some(runtime_share_root) {
        return Err(path_error(
            ErrorCode::FailedPrecondition,
            format!(
                "HVF container share escaped protected root {}: {}",
                runtime_share_root.display(),
                container.display()
            ),
        ));
    }
    let configured_share = container.join(generation.0.to_string());
    if path_metadata(&configured_share).await?.is_none() {
        return Ok(None);
    }
    let share =
        canonical_private_directory(&configured_share, "HVF generation-share directory").await?;
    if share.parent() != Some(container.as_path()) {
        return Err(path_error(
            ErrorCode::FailedPrecondition,
            format!(
                "HVF generation share escaped container directory {}: {}",
                container.display(),
                share.display()
            ),
        ));
    }
    Ok(Some(share))
}

pub(super) async fn exact_runtime_share_path(
    runtime_share_root: &Path,
    target: &ContainerTarget,
) -> Result<PathBuf> {
    existing_exact_runtime_share_path(runtime_share_root, target, "resolve-hvf-runtime-share")
        .await?
        .ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "HVF exact-generation runtime share does not exist for container {} generation {:?}",
                    target.id, target.generation
                ),
            )
            .for_operation("resolve-hvf-runtime-share")
        })
}

pub(super) async fn remove_directory_if_empty(path: &Path) -> Result<()> {
    let Some(metadata) = path_metadata(path).await? else {
        return Ok(());
    };
    if !is_private_directory(&metadata) {
        return Err(path_error(
            ErrorCode::FailedPrecondition,
            format!(
                "refusing to remove a non-private directory: {}",
                path.display()
            ),
        ));
    }
    let mut entries = tokio::fs::read_dir(path).await.map_err(|error| {
        path_error(
            ErrorCode::Internal,
            format!("failed to enumerate {}: {error}", path.display()),
        )
    })?;
    if entries
        .next_entry()
        .await
        .map_err(|error| {
            path_error(
                ErrorCode::Internal,
                format!("failed to enumerate {}: {error}", path.display()),
            )
        })?
        .is_none()
    {
        tokio::fs::remove_dir(path).await.map_err(|error| {
            path_error(
                ErrorCode::Internal,
                format!(
                    "failed to remove empty directory {}: {error}",
                    path.display()
                ),
            )
        })?;
    }
    Ok(())
}

async fn sha256_path(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path).await.map_err(|error| {
        path_error(
            ErrorCode::FailedPrecondition,
            format!("failed to open {} for hashing: {error}", path.display()),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await.map_err(|error| {
            path_error(
                ErrorCode::FailedPrecondition,
                format!("failed to hash {}: {error}", path.display()),
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn path_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("open-hvf-runtime-driver")
}
