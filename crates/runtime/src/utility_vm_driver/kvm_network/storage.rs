use std::os::unix::fs::MetadataExt;
use std::path::Path;

use a3s_oci_agent_protocol::{AgentVmStorageAttachment, AgentVmStorageSourceIdentity};
use a3s_oci_sdk::{ErrorCode, Result, StorageAccessMode, StorageAttachment};
use serde_json::Value;

use super::{attachment_error, UtilityVmLaunchRequest};

pub(super) async fn prepare(
    request: &UtilityVmLaunchRequest<'_>,
    configuration: &Value,
    attachment: &StorageAttachment,
    attachment_digest: &str,
) -> Result<AgentVmStorageAttachment> {
    let mount = configuration
        .pointer(attachment.mount().json_pointer())
        .and_then(Value::as_object)
        .ok_or_else(|| {
            attachment_error(
                ErrorCode::InvalidArgument,
                format!(
                    "authorized KVM storage does not select an OCI mount object at {}",
                    attachment.mount().json_pointer()
                ),
            )
        })?;
    let source = mount.get("source").and_then(Value::as_str).ok_or_else(|| {
        attachment_error(
            ErrorCode::InvalidArgument,
            format!(
                "authorized KVM storage {} requires an OCI mount source",
                attachment.identity()
            ),
        )
    })?;
    let source_path = Path::new(source);
    if !source_path.is_absolute() {
        return Err(attachment_error(
            ErrorCode::Unsupported,
            format!(
                "KVM storage {} requires a caller-owned absolute raw-image source, received {source}",
                attachment.identity()
            ),
        ));
    }
    if paths_overlap(source_path, request.runtime_share)
        || paths_overlap(source_path, request.bundle.directory())
    {
        return Err(attachment_error(
            ErrorCode::FailedPrecondition,
            format!(
                "KVM storage image for {} must remain outside the runtime-owned bundle and share: {source}",
                attachment.identity()
            ),
        ));
    }
    let source_identity = verify_image(source_path, attachment.access_mode()).await?;
    AgentVmStorageAttachment::new(
        attachment.identity().clone(),
        attachment.mount().clone(),
        attachment.access_mode(),
        attachment.ownership(),
        attachment.cleanup(),
        source,
        source_identity,
        attachment_digest,
    )
}

async fn verify_image(
    source: &Path,
    access_mode: StorageAccessMode,
) -> Result<AgentVmStorageSourceIdentity> {
    let path_metadata = tokio::fs::symlink_metadata(source).await.map_err(|error| {
        attachment_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect authorized KVM storage image {}: {error}",
                source.display()
            ),
        )
    })?;
    if !path_metadata.is_file()
        || path_metadata.file_type().is_symlink()
        || path_metadata.nlink() != 1
    {
        return Err(attachment_error(
            ErrorCode::Unsupported,
            format!(
                "KVM storage transport requires a plain single-link raw image file: {}",
                source.display()
            ),
        ));
    }
    let canonical = tokio::fs::canonicalize(source).await.map_err(|error| {
        attachment_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to canonicalize authorized KVM storage image {}: {error}",
                source.display()
            ),
        )
    })?;
    if canonical != source {
        return Err(attachment_error(
            ErrorCode::FailedPrecondition,
            format!(
                "KVM storage image path must not traverse aliases or symbolic links: {}",
                source.display()
            ),
        ));
    }

    let mut options = tokio::fs::OpenOptions::new();
    options
        .read(true)
        .write(access_mode == StorageAccessMode::ReadWrite)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let image = options.open(source).await.map_err(|error| {
        attachment_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to open authorized KVM storage image {} with {access_mode:?} access: {error}",
                source.display()
            ),
        )
    })?;
    let opened = image.metadata().await.map_err(|error| {
        attachment_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect opened KVM storage image {}: {error}",
                source.display()
            ),
        )
    })?;
    if !opened.is_file()
        || opened.nlink() != 1
        || opened.dev() != path_metadata.dev()
        || opened.ino() != path_metadata.ino()
    {
        return Err(attachment_error(
            ErrorCode::Conflict,
            format!(
                "authorized KVM storage image changed while it was pinned: {}",
                source.display()
            ),
        ));
    }
    AgentVmStorageSourceIdentity::new(opened.dev(), opened.rdev(), opened.ino(), opened.len())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}
