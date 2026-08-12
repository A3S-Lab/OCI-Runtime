use std::path::{Component, Path, PathBuf};

use a3s_oci_agent_protocol::{GuestPath, AGENT_RUNTIME_SHARE_GUEST_ROOT};
use a3s_oci_sdk::{
    runtime_bundle_handoff_directory, runtime_bundle_handoff_root, ContainerId, ContainerTarget,
    Error, ErrorCode, OciBundle, OperationId, Result, RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::layout::{
    canonical_plain_directory, canonical_plain_file, canonical_private_directory,
    ensure_exact_runtime_share_path, is_private_file, path_metadata, remove_directory_if_empty,
    PRIVATE_FILE_MODE,
};
use crate::DriverCreateRequest;

const MARKER_FILE: &str = ".a3s-oci-bundle-handoff.json";
const PENDING_MARKER_FILE: &str = ".a3s-oci-bundle-handoff.pending";
const MARKER_SCHEMA: &str = "a3s.oci.bundle-handoff.v1";
const MAX_MARKER_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone)]
pub(super) struct BundleHandoffStore {
    runtime_root: PathBuf,
    runtime_share_root: PathBuf,
}

impl BundleHandoffStore {
    pub(super) fn new(runtime_root: PathBuf, runtime_share_root: PathBuf) -> Self {
        Self {
            runtime_root,
            runtime_share_root,
        }
    }

    pub(super) async fn prepare(&self, request: &DriverCreateRequest) -> Result<OciBundle> {
        let runtime_share =
            ensure_exact_runtime_share_path(&self.runtime_share_root, &request.target).await?;
        let destination = runtime_share.join(RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY);
        let source = runtime_bundle_handoff_directory(
            &self.runtime_root,
            &request.target.id,
            &request.context.operation_id,
        )?;

        if path_metadata(&destination).await?.is_some() {
            if path_metadata(&source).await?.is_some() {
                return Err(handoff_error(
                    ErrorCode::Conflict,
                    format!(
                        "both the HVF operation handoff and exact-generation bundle exist: {} and {}",
                        source.display(),
                        destination.display()
                    ),
                ));
            }
            let bundle = load_exact_bundle(&destination, &request.bundle).await?;
            ensure_marker(&runtime_share, &request.target, bundle.config_digest()).await?;
            cleanup_empty_source_parents(&source, &self.runtime_root)
                .await
                .map_err(|error| error.retryable(true))?;
            return Ok(bundle);
        }

        let source = canonical_private_directory(&source, "HVF operation bundle handoff").await?;
        validate_source_ancestry(
            &self.runtime_root,
            &source,
            &request.target.id,
            &request.context.operation_id,
        )
        .await?;
        let source_bundle = load_exact_bundle(&source, &request.bundle).await?;
        ensure_marker(
            &runtime_share,
            &request.target,
            source_bundle.config_digest(),
        )
        .await?;

        tokio::fs::rename(&source, &destination)
            .await
            .map_err(|error| {
                handoff_error(
                    ErrorCode::Unavailable,
                    format!(
                        "failed to atomically move HVF bundle handoff {} into {}: {error}",
                        source.display(),
                        destination.display()
                    ),
                )
                .retryable(true)
            })?;
        sync_directory(&runtime_share).await?;
        let bundle = load_exact_bundle(&destination, &source_bundle).await?;
        cleanup_empty_source_parents(&source, &self.runtime_root)
            .await
            .map_err(|error| error.retryable(true))?;
        Ok(bundle)
    }

    pub(super) async fn cleanup(&self, target: &ContainerTarget) -> Result<()> {
        let Some(runtime_share) = super::layout::existing_exact_runtime_share_path(
            &self.runtime_share_root,
            target,
            "cleanup-hvf-bundle-handoff",
        )
        .await?
        else {
            return Ok(());
        };

        let marker_path = runtime_share.join(MARKER_FILE);
        let bundle_path = runtime_share.join(RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY);
        match path_metadata(&marker_path).await? {
            Some(metadata) => {
                if !is_private_file(&metadata) {
                    return Err(handoff_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "HVF bundle-handoff marker is not a private plain file: {}",
                            marker_path.display()
                        ),
                    ));
                }
                let marker = read_marker(&marker_path).await?;
                if marker.target != *target {
                    return Err(handoff_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "HVF bundle-handoff marker targets {:?}, not {:?}",
                            marker.target, target
                        ),
                    ));
                }
                if path_metadata(&bundle_path).await?.is_some() {
                    let bundle = load_bundle_without_expected(&bundle_path).await?;
                    if bundle.config_digest() != marker.config_digest {
                        return Err(handoff_error(
                            ErrorCode::FailedPrecondition,
                            "runtime-owned HVF bundle no longer matches its handoff marker",
                        ));
                    }
                }
            }
            None if path_metadata(&bundle_path).await?.is_some() => {
                return Err(handoff_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "runtime-owned HVF bundle has no ownership marker: {}",
                        bundle_path.display()
                    ),
                ));
            }
            None => {}
        }

        // The exact-generation share is wholly runtime-owned. Removing it as
        // one verified subtree also clears the guest's empty `run` directory
        // and any one-time handoff residue after the VM has been reaped.
        tokio::fs::remove_dir_all(&runtime_share)
            .await
            .map_err(|error| {
                handoff_error(
                    ErrorCode::Internal,
                    format!(
                        "failed to remove exact-generation HVF share {}: {error}",
                        runtime_share.display()
                    ),
                )
            })?;
        if let Some(container_directory) = runtime_share.parent() {
            remove_directory_if_empty(container_directory).await?;
        }
        Ok(())
    }

    pub(super) async fn guest_bundle_path(
        &self,
        target: &ContainerTarget,
        bundle: &Path,
    ) -> Result<GuestPath> {
        let runtime_share =
            super::layout::exact_runtime_share_path(&self.runtime_share_root, target).await?;
        let bundle = canonical_private_directory(bundle, "runtime-owned HVF OCI bundle").await?;
        let relative = bundle.strip_prefix(&runtime_share).map_err(|error| {
            handoff_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "HVF OCI bundle must be contained by exact runtime share {}: {} ({error})",
                    runtime_share.display(),
                    bundle.display()
                ),
            )
        })?;
        let mut components = Vec::new();
        for component in relative.components() {
            let Component::Normal(component) = component else {
                return Err(handoff_error(
                    ErrorCode::InvalidArgument,
                    format!(
                        "HVF OCI bundle has a non-normal component: {}",
                        bundle.display()
                    ),
                ));
            };
            let component = component.to_str().ok_or_else(|| {
                handoff_error(
                    ErrorCode::InvalidArgument,
                    format!("HVF OCI bundle path is not Unicode: {}", bundle.display()),
                )
            })?;
            if component.contains(['/', '\\', '\0']) {
                return Err(handoff_error(
                    ErrorCode::InvalidArgument,
                    format!(
                        "HVF OCI bundle has an invalid guest component: {}",
                        bundle.display()
                    ),
                ));
            }
            components.push(component);
        }
        if components.is_empty() {
            return Err(handoff_error(
                ErrorCode::InvalidArgument,
                "HVF OCI bundle cannot be the runtime-share root itself",
            ));
        }
        GuestPath::new(format!(
            "{AGENT_RUNTIME_SHARE_GUEST_ROOT}/{}",
            components.join("/")
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BundleHandoffMarker {
    schema_version: String,
    target: ContainerTarget,
    config_digest: String,
}

async fn validate_source_ancestry(
    runtime_root: &Path,
    source: &Path,
    container_id: &ContainerId,
    operation_id: &OperationId,
) -> Result<()> {
    let expected = runtime_bundle_handoff_directory(runtime_root, container_id, operation_id)?;
    let expected = canonical_private_directory(&expected, "HVF operation bundle handoff").await?;
    if source != expected {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "HVF bundle handoff must use the exact operation path {}: {}",
                expected.display(),
                source.display()
            ),
        ));
    }
    let operation_directory = source.parent().ok_or_else(|| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            "HVF bundle handoff has no operation directory",
        )
    })?;
    let container_directory = operation_directory.parent().ok_or_else(|| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            "HVF bundle handoff has no container directory",
        )
    })?;
    let handoff_root = container_directory.parent().ok_or_else(|| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            "HVF bundle handoff has no protected root",
        )
    })?;
    let expected_root = canonical_private_directory(
        &runtime_bundle_handoff_root(runtime_root)?,
        "HVF bundle-handoff root",
    )
    .await?;
    if handoff_root != expected_root {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "HVF bundle handoff escaped protected root {}: {}",
                expected_root.display(),
                source.display()
            ),
        ));
    }
    for path in [container_directory, operation_directory] {
        canonical_private_directory(path, "HVF bundle-handoff ancestor").await?;
    }
    Ok(())
}

async fn load_exact_bundle(path: &Path, expected: &OciBundle) -> Result<OciBundle> {
    let bundle = load_bundle_without_expected(path).await?;
    if bundle.config_bytes() != expected.config_bytes()
        || bundle.config_digest() != expected.config_digest()
    {
        return Err(handoff_error(
            ErrorCode::Conflict,
            format!(
                "HVF bundle handoff configuration differs from durable digest {}",
                expected.config_digest()
            ),
        ));
    }
    Ok(bundle)
}

async fn load_bundle_without_expected(path: &Path) -> Result<OciBundle> {
    let directory = canonical_private_directory(path, "HVF portable OCI bundle").await?;
    let config = canonical_plain_file(
        &directory.join("config.json"),
        "HVF OCI configuration",
        true,
    )
    .await?;
    if config.parent() != Some(directory.as_path()) {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "HVF OCI configuration escaped bundle {}: {}",
                directory.display(),
                config.display()
            ),
        ));
    }
    let bundle = OciBundle::load(&directory).await?;
    validate_portable_bundle(&bundle).await?;
    Ok(bundle)
}

async fn validate_portable_bundle(bundle: &OciBundle) -> Result<()> {
    let root = bundle.spec().root().as_ref().ok_or_else(|| {
        handoff_error(
            ErrorCode::InvalidArgument,
            "HVF bundle handoff requires an OCI root filesystem",
        )
    })?;
    let root_path = root.path();
    if root_path.is_absolute()
        || root_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(handoff_error(
            ErrorCode::InvalidArgument,
            format!(
                "HVF bundle handoff requires a normalized relative root.path: {}",
                root_path.display()
            ),
        ));
    }
    let rootfs = canonical_plain_directory(
        &bundle.directory().join(root_path),
        "HVF portable bundle rootfs",
    )
    .await?;
    if rootfs == bundle.directory() || !rootfs.starts_with(bundle.directory()) {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "HVF portable rootfs escapes bundle {}: {}",
                bundle.directory().display(),
                rootfs.display()
            ),
        ));
    }
    for (index, mount) in bundle
        .spec()
        .mounts()
        .as_deref()
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        let is_bind = mount
            .options()
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|option| matches!(option.as_str(), "bind" | "rbind"));
        if !is_bind {
            continue;
        }
        let source = mount.source().as_ref().ok_or_else(|| {
            handoff_error(
                ErrorCode::InvalidArgument,
                format!("HVF portable bind mount {index} has no source"),
            )
        })?;
        if source.is_absolute()
            || source
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(handoff_error(
                ErrorCode::InvalidArgument,
                format!(
                    "HVF portable bind mount {index} requires a normalized relative source: {}",
                    source.display()
                ),
            ));
        }
    }
    Ok(())
}

async fn ensure_marker(
    runtime_share: &Path,
    target: &ContainerTarget,
    config_digest: &str,
) -> Result<()> {
    let marker_path = runtime_share.join(MARKER_FILE);
    let expected = BundleHandoffMarker {
        schema_version: MARKER_SCHEMA.to_string(),
        target: target.clone(),
        config_digest: config_digest.to_string(),
    };
    if path_metadata(&marker_path).await?.is_some() {
        let retained = read_marker(&marker_path).await?;
        if retained != expected {
            return Err(handoff_error(
                ErrorCode::Conflict,
                "existing HVF bundle-handoff marker differs from this create",
            ));
        }
        remove_private_file_if_present(&runtime_share.join(PENDING_MARKER_FILE)).await?;
        return Ok(());
    }

    let pending = runtime_share.join(PENDING_MARKER_FILE);
    remove_private_file_if_present(&pending).await?;
    let encoded = serde_json::to_vec(&expected).map_err(|error| {
        handoff_error(
            ErrorCode::Internal,
            format!("failed to encode HVF bundle-handoff marker: {error}"),
        )
    })?;
    if encoded.len() > MAX_MARKER_BYTES {
        return Err(handoff_error(
            ErrorCode::Internal,
            "HVF bundle-handoff marker exceeds its fixed bound",
        ));
    }
    let mut options = tokio::fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(&pending).await.map_err(|error| {
        handoff_error(
            ErrorCode::Internal,
            format!(
                "failed to create HVF bundle-handoff marker {}: {error}",
                pending.display()
            ),
        )
    })?;
    file.write_all(&encoded).await.map_err(|error| {
        handoff_error(
            ErrorCode::Internal,
            format!(
                "failed to write HVF bundle-handoff marker {}: {error}",
                pending.display()
            ),
        )
    })?;
    file.flush().await.map_err(|error| {
        handoff_error(
            ErrorCode::Internal,
            format!(
                "failed to flush HVF bundle-handoff marker {}: {error}",
                pending.display()
            ),
        )
    })?;
    file.sync_all().await.map_err(|error| {
        handoff_error(
            ErrorCode::Internal,
            format!(
                "failed to sync HVF bundle-handoff marker {}: {error}",
                pending.display()
            ),
        )
    })?;
    drop(file);
    tokio::fs::rename(&pending, &marker_path)
        .await
        .map_err(|error| {
            handoff_error(
                ErrorCode::Internal,
                format!(
                    "failed to commit HVF bundle-handoff marker {}: {error}",
                    marker_path.display()
                ),
            )
        })?;
    sync_directory(runtime_share).await
}

async fn read_marker(path: &Path) -> Result<BundleHandoffMarker> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect HVF bundle-handoff marker {}: {error}",
                path.display()
            ),
        )
    })?;
    if !is_private_file(&metadata) || metadata.len() > MAX_MARKER_BYTES as u64 {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "HVF bundle-handoff marker is not a bounded private file: {}",
                path.display()
            ),
        ));
    }
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    tokio::fs::File::open(path)
        .await
        .map_err(|error| {
            handoff_error(
                ErrorCode::FailedPrecondition,
                format!("failed to open HVF marker {}: {error}", path.display()),
            )
        })?
        .take((MAX_MARKER_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .await
        .map_err(|error| {
            handoff_error(
                ErrorCode::FailedPrecondition,
                format!("failed to read HVF marker {}: {error}", path.display()),
            )
        })?;
    let marker: BundleHandoffMarker = serde_json::from_slice(&encoded).map_err(|error| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "invalid HVF bundle-handoff marker {}: {error}",
                path.display()
            ),
        )
    })?;
    if marker.schema_version != MARKER_SCHEMA
        || marker.target.generation.is_none()
        || marker.config_digest.len() != 71
        || !marker.config_digest.starts_with("sha256:")
    {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            format!("invalid HVF bundle-handoff evidence: {}", path.display()),
        ));
    }
    Ok(marker)
}

async fn remove_private_file_if_present(path: &Path) -> Result<()> {
    let Some(metadata) = path_metadata(path).await? else {
        return Ok(());
    };
    if !is_private_file(&metadata) {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            format!("refusing to remove a non-private file: {}", path.display()),
        ));
    }
    tokio::fs::remove_file(path).await.map_err(|error| {
        handoff_error(
            ErrorCode::Internal,
            format!("failed to remove {}: {error}", path.display()),
        )
    })
}

async fn cleanup_empty_source_parents(source: &Path, runtime_root: &Path) -> Result<()> {
    let expected_root = canonical_private_directory(
        &runtime_bundle_handoff_root(runtime_root)?,
        "HVF bundle-handoff root",
    )
    .await?;
    let operation_directory = source.parent().ok_or_else(|| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            "HVF bundle handoff has no operation parent",
        )
    })?;
    let container_directory = operation_directory.parent().ok_or_else(|| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            "HVF bundle handoff has no container parent",
        )
    })?;
    if container_directory.parent() != Some(expected_root.as_path()) {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            "refusing to clean HVF handoff parents outside the protected root",
        ));
    }
    remove_directory_if_empty(operation_directory).await?;
    remove_directory_if_empty(container_directory).await
}

async fn sync_directory(path: &Path) -> Result<()> {
    tokio::fs::File::open(path)
        .await
        .map_err(|error| {
            handoff_error(
                ErrorCode::Internal,
                format!(
                    "failed to open directory {} for sync: {error}",
                    path.display()
                ),
            )
        })?
        .sync_all()
        .await
        .map_err(|error| {
            handoff_error(
                ErrorCode::Internal,
                format!("failed to sync directory {}: {error}", path.display()),
            )
        })
}

fn handoff_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("prepare-hvf-bundle-handoff")
}
