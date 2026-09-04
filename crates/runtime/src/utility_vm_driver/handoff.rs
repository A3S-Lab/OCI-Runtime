use std::io;
use std::path::{Component, Path, PathBuf};

use a3s_oci_agent_protocol::{GuestPath, AGENT_RUNTIME_SHARE_GUEST_ROOT};
use a3s_oci_sdk::{
    runtime_bundle_handoff_directory, runtime_bundle_handoff_root, ContainerId, ContainerTarget,
    Error, ErrorCode, GuestSessionAttachment, OciBundle, OperationId, Result,
    RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY,
};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

use super::atomic_publication;
use super::layout::{
    canonical_plain_directory, canonical_plain_file, canonical_private_directory,
    ensure_reusable_guest_session_root, ensure_runtime_share_paths, existing_runtime_share_paths,
    is_private_file, path_metadata, remove_directory_if_empty,
};
use super::session_marker;
use crate::DriverCreateRequest;

const MARKER_FILE: &str = ".a3s-oci-bundle-handoff.json";
const PENDING_MARKER_FILE: &str = ".a3s-oci-bundle-handoff.pending";
const STAGING_MARKER_PREFIX: &str = ".a3s-oci-bundle-handoff.pending.";
const MARKER_SCHEMA: &str = "a3s.oci.bundle-handoff.v1";
const MAX_MARKER_BYTES: usize = 4 * 1024;
const PUBLISH_ATTEMPTS: usize = atomic_publication::PUBLISH_ATTEMPTS;

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
        let guest_session = request.attachment_contract.guest_session();
        let source = runtime_bundle_handoff_directory(
            &self.runtime_root,
            &request.target.id,
            &request.context.operation_id,
        )?;

        let existing_runtime_share = existing_runtime_share_paths(
            &self.runtime_share_root,
            &request.target,
            guest_session,
            "prepare-utility-vm-bundle-handoff",
        )
        .await?;
        if let Some(paths) = existing_runtime_share.as_ref() {
            if let Some(session) = guest_session {
                session_marker::validate(&paths.mount_root, session).await?;
            }
            let destination = paths
                .container_share
                .join(RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY);
            if path_metadata(&destination).await?.is_some() {
                if path_metadata(&source).await?.is_some() {
                    return Err(handoff_error(
                        ErrorCode::Conflict,
                        format!(
                            "both the utility-VM operation handoff and exact-generation bundle exist: {} and {}",
                            source.display(),
                            destination.display()
                        ),
                    ));
                }
                let bundle = load_exact_bundle(&destination, &request.bundle).await?;
                ensure_marker(
                    &paths.container_share,
                    &request.target,
                    bundle.config_digest(),
                )
                .await?;
                cleanup_empty_source_parents(&source, &self.runtime_root)
                    .await
                    .map_err(|error| error.retryable(true))?;
                return Ok(bundle);
            }
        }

        // Validate the complete caller-owned handoff before creating any path
        // that will become visible to a guest. A missing, linked, insecure, or
        // drifted source must not leave an empty exact-generation share behind.
        let source =
            canonical_private_directory(&source, "utility-VM operation bundle handoff").await?;
        validate_source_ancestry(
            &self.runtime_root,
            &source,
            &request.target.id,
            &request.context.operation_id,
        )
        .await?;
        let source_bundle = load_exact_bundle(&source, &request.bundle).await?;
        let paths = match existing_runtime_share {
            Some(paths) => paths,
            None => {
                if let Some(session) = guest_session {
                    let session_root =
                        ensure_reusable_guest_session_root(&self.runtime_share_root, session)
                            .await?;
                    session_marker::ensure(&session_root, session).await?;
                }
                ensure_runtime_share_paths(&self.runtime_share_root, &request.target, guest_session)
                    .await?
            }
        };
        if let Some(session) = guest_session {
            session_marker::ensure(&paths.mount_root, session).await?;
        }
        let destination = paths
            .container_share
            .join(RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY);
        ensure_marker(
            &paths.container_share,
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
                        "failed to atomically move utility-VM bundle handoff {} into {}: {error}",
                        source.display(),
                        destination.display()
                    ),
                )
                .retryable(true)
            })?;
        sync_directory(&paths.container_share).await?;
        let bundle = load_exact_bundle(&destination, &source_bundle).await?;
        cleanup_empty_source_parents(&source, &self.runtime_root)
            .await
            .map_err(|error| error.retryable(true))?;
        Ok(bundle)
    }

    pub(super) async fn cleanup(
        &self,
        target: &ContainerTarget,
        guest_session: Option<&GuestSessionAttachment>,
        remove_empty_session: bool,
    ) -> Result<()> {
        let paths = existing_runtime_share_paths(
            &self.runtime_share_root,
            target,
            guest_session,
            "cleanup-utility-vm-bundle-handoff",
        )
        .await?;
        let Some(paths) = paths else {
            if remove_empty_session {
                if let Some(session) = guest_session {
                    self.cleanup_empty_session(session).await?;
                }
            }
            return Ok(());
        };

        if let Some(session) = guest_session {
            session_marker::validate(&paths.mount_root, session).await?;
        }
        let marker_path = paths.container_share.join(MARKER_FILE);
        let bundle_path = paths
            .container_share
            .join(RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY);
        match path_metadata(&marker_path).await? {
            Some(metadata) => {
                if !is_private_file(&metadata) {
                    return Err(handoff_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "utility-VM bundle-handoff marker is not a private plain file: {}",
                            marker_path.display()
                        ),
                    ));
                }
                let marker = read_marker(&marker_path).await?;
                if marker.target != *target {
                    return Err(handoff_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "utility-VM bundle-handoff marker targets {:?}, not {:?}",
                            marker.target, target
                        ),
                    ));
                }
                if path_metadata(&bundle_path).await?.is_some() {
                    let bundle = load_bundle_without_expected(&bundle_path).await?;
                    if bundle.config_digest() != marker.config_digest {
                        return Err(handoff_error(
                            ErrorCode::FailedPrecondition,
                            "runtime-owned utility-VM bundle no longer matches its handoff marker",
                        ));
                    }
                }
            }
            None if path_metadata(&bundle_path).await?.is_some() => {
                return Err(handoff_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "runtime-owned utility-VM bundle has no ownership marker: {}",
                        bundle_path.display()
                    ),
                ));
            }
            None => {}
        }

        // The exact-generation share is wholly runtime-owned. Removing it as
        // one verified subtree also clears the guest's empty `run` directory
        // and any one-time handoff residue after the VM has been reaped.
        tokio::fs::remove_dir_all(&paths.container_share)
            .await
            .map_err(|error| {
                handoff_error(
                    ErrorCode::Internal,
                    format!(
                        "failed to remove exact-generation utility-VM share {}: {error}",
                        paths.container_share.display()
                    ),
                )
            })?;
        if let Some(container_directory) = paths.container_share.parent() {
            remove_directory_if_empty(container_directory).await?;
        }
        if remove_empty_session {
            if let Some(session) = guest_session {
                let removed = session_marker::remove_if_empty(
                    &self.runtime_share_root,
                    &paths.mount_root,
                    session,
                )
                .await?;
                if !removed {
                    return Err(nonempty_session_error(session));
                }
            }
        }
        Ok(())
    }

    pub(super) async fn cleanup_empty_session(
        &self,
        guest_session: &GuestSessionAttachment,
    ) -> Result<()> {
        let Some(session_root) = super::layout::existing_reusable_guest_session_root(
            &self.runtime_share_root,
            guest_session,
        )
        .await?
        else {
            return Ok(());
        };
        if !session_marker::remove_if_empty(&self.runtime_share_root, &session_root, guest_session)
            .await?
        {
            return Err(nonempty_session_error(guest_session));
        }
        Ok(())
    }

    pub(super) async fn mount_root(
        &self,
        target: &ContainerTarget,
        guest_session: Option<&GuestSessionAttachment>,
    ) -> Result<PathBuf> {
        Ok(super::layout::exact_runtime_share_paths(
            &self.runtime_share_root,
            target,
            guest_session,
        )
        .await?
        .mount_root)
    }

    pub(super) async fn guest_bundle_path(
        &self,
        target: &ContainerTarget,
        bundle: &Path,
        guest_session: Option<&GuestSessionAttachment>,
    ) -> Result<GuestPath> {
        let paths = super::layout::exact_runtime_share_paths(
            &self.runtime_share_root,
            target,
            guest_session,
        )
        .await?;
        let bundle =
            canonical_private_directory(bundle, "runtime-owned utility-VM OCI bundle").await?;
        let relative = bundle.strip_prefix(&paths.mount_root).map_err(|error| {
            handoff_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "utility-VM OCI bundle must be contained by exact runtime share {}: {} ({error})",
                    paths.mount_root.display(),
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
                        "utility-VM OCI bundle has a non-normal component: {}",
                        bundle.display()
                    ),
                ));
            };
            let component = component.to_str().ok_or_else(|| {
                handoff_error(
                    ErrorCode::InvalidArgument,
                    format!(
                        "utility-VM OCI bundle path is not Unicode: {}",
                        bundle.display()
                    ),
                )
            })?;
            if component.contains(['/', '\\', '\0']) {
                return Err(handoff_error(
                    ErrorCode::InvalidArgument,
                    format!(
                        "utility-VM OCI bundle has an invalid guest component: {}",
                        bundle.display()
                    ),
                ));
            }
            components.push(component);
        }
        if components.is_empty() {
            return Err(handoff_error(
                ErrorCode::InvalidArgument,
                "utility-VM OCI bundle cannot be the runtime-share root itself",
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
    let expected =
        canonical_private_directory(&expected, "utility-VM operation bundle handoff").await?;
    if source != expected {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "utility-VM bundle handoff must use the exact operation path {}: {}",
                expected.display(),
                source.display()
            ),
        ));
    }
    let operation_directory = source.parent().ok_or_else(|| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            "utility-VM bundle handoff has no operation directory",
        )
    })?;
    let container_directory = operation_directory.parent().ok_or_else(|| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            "utility-VM bundle handoff has no container directory",
        )
    })?;
    let handoff_root = container_directory.parent().ok_or_else(|| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            "utility-VM bundle handoff has no protected root",
        )
    })?;
    let expected_root = canonical_private_directory(
        &runtime_bundle_handoff_root(runtime_root)?,
        "utility-VM bundle-handoff root",
    )
    .await?;
    if handoff_root != expected_root {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "utility-VM bundle handoff escaped protected root {}: {}",
                expected_root.display(),
                source.display()
            ),
        ));
    }
    for path in [container_directory, operation_directory] {
        canonical_private_directory(path, "utility-VM bundle-handoff ancestor").await?;
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
                "utility-VM bundle handoff configuration differs from durable digest {}",
                expected.config_digest()
            ),
        ));
    }
    Ok(bundle)
}

async fn load_bundle_without_expected(path: &Path) -> Result<OciBundle> {
    let directory = canonical_private_directory(path, "utility-VM portable OCI bundle").await?;
    let config = canonical_plain_file(
        &directory.join("config.json"),
        "utility-VM OCI configuration",
        true,
    )
    .await?;
    if config.parent() != Some(directory.as_path()) {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "utility-VM OCI configuration escaped bundle {}: {}",
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
            "utility-VM bundle handoff requires an OCI root filesystem",
        )
    })?;
    let root_path = root.path();
    if root_path.is_absolute()
        || (root_path != Path::new(".")
            && root_path
                .components()
                .any(|component| !matches!(component, Component::Normal(_))))
    {
        return Err(handoff_error(
            ErrorCode::InvalidArgument,
            format!(
                "utility-VM bundle handoff requires a normalized relative root.path: {}",
                root_path.display()
            ),
        ));
    }
    let rootfs = canonical_plain_directory(
        &bundle.directory().join(root_path),
        "utility-VM portable bundle rootfs",
    )
    .await?;
    if !rootfs.starts_with(bundle.directory()) {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "utility-VM portable rootfs escapes bundle {}: {}",
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
                format!("utility-VM portable bind mount {index} has no source"),
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
                    "utility-VM portable bind mount {index} requires a normalized relative source: {}",
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
    let pending = runtime_share.join(PENDING_MARKER_FILE);
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
                "existing utility-VM bundle-handoff marker differs from this create",
            ));
        }
        remove_matching_pending(&pending, &expected).await?;
        sync_directory(runtime_share).await?;
        return Ok(());
    }

    let encoded = serde_json::to_vec(&expected).map_err(|error| {
        handoff_error(
            ErrorCode::Internal,
            format!("failed to encode utility-VM bundle-handoff marker: {error}"),
        )
    })?;
    if encoded.len() > MAX_MARKER_BYTES {
        return Err(handoff_error(
            ErrorCode::Internal,
            "utility-VM bundle-handoff marker exceeds its fixed bound",
        ));
    }
    for attempt in 0..PUBLISH_ATTEMPTS {
        match create_or_reuse_pending(runtime_share, &pending, &encoded, &expected).await {
            Err(error) if error.retryable && attempt + 1 < PUBLISH_ATTEMPTS => continue,
            Err(error) => return Err(error),
            Ok(()) => {}
        }
        match publish_marker(runtime_share, &pending, &marker_path, &expected).await {
            Err(error) if error.retryable && attempt + 1 < PUBLISH_ATTEMPTS => continue,
            result => return result,
        }
    }
    Err(handoff_error(
        ErrorCode::Unavailable,
        "utility-VM bundle-handoff marker publication kept losing its concurrent owner",
    )
    .retryable(true))
}

async fn create_or_reuse_pending(
    runtime_share: &Path,
    pending: &Path,
    encoded: &[u8],
    expected: &BundleHandoffMarker,
) -> Result<()> {
    if path_metadata(pending).await?.is_some() {
        ensure_pending_matches(pending, expected).await?;
        return Ok(());
    }

    let staging = atomic_publication::create_complete_staging(
        runtime_share,
        pending,
        encoded,
        STAGING_MARKER_PREFIX,
    )
    .await
    .map_err(|error| {
        handoff_error(
            ErrorCode::Internal,
            format!(
                "failed to create utility-VM bundle-handoff marker staging file near {}: {error}",
                pending.display()
            ),
        )
    })?;
    match tokio::fs::hard_link(&staging, pending).await {
        Ok(()) => {
            atomic_publication::remove_file_if_present(&staging)
                .await
                .map_err(|error| {
                    handoff_error(
                        ErrorCode::Internal,
                        format!(
                            "failed to remove utility-VM bundle-handoff staging file {}: {error}",
                            staging.display()
                        ),
                    )
                })?;
            sync_directory(runtime_share).await
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let _ = atomic_publication::remove_file_if_present(&staging).await;
            ensure_pending_matches(pending, expected).await
        }
        Err(error) => {
            let _ = atomic_publication::remove_file_if_present(&staging).await;
            Err(handoff_error(
                ErrorCode::Internal,
                format!(
                    "failed to publish utility-VM bundle-handoff pending marker {}: {error}",
                    pending.display()
                ),
            ))
        }
    }
}

async fn ensure_pending_matches(pending: &Path, expected: &BundleHandoffMarker) -> Result<()> {
    match read_if_present(pending).await? {
        Some(retained) if retained == *expected => Ok(()),
        Some(_) => Err(marker_conflict(expected)),
        None => Err(handoff_error(
            ErrorCode::Unavailable,
            format!(
                "utility-VM bundle-handoff pending marker disappeared before adoption: {}",
                pending.display()
            ),
        )
        .retryable(true)),
    }
}

async fn publish_marker(
    runtime_share: &Path,
    pending: &Path,
    marker_path: &Path,
    expected: &BundleHandoffMarker,
) -> Result<()> {
    match tokio::fs::hard_link(pending, marker_path).await {
        Ok(()) => {
            let retained = read_marker(marker_path).await?;
            if retained != *expected {
                return Err(marker_conflict(expected));
            }
            remove_matching_pending(pending, expected).await?;
            sync_directory(runtime_share).await
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let retained = read_marker(marker_path).await?;
            if retained != *expected {
                return Err(marker_conflict(expected));
            }
            remove_matching_pending(pending, expected).await?;
            sync_directory(runtime_share).await
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match read_if_present(marker_path).await? {
                Some(retained) if retained == *expected => sync_directory(runtime_share).await,
                Some(_) => Err(marker_conflict(expected)),
                None => Err(handoff_error(
                    ErrorCode::Unavailable,
                    format!(
                        "utility-VM bundle-handoff pending marker disappeared before publication: {}",
                        pending.display()
                    ),
                )
                .retryable(true)),
            }
        }
        Err(error) => Err(handoff_error(
            ErrorCode::Internal,
            format!(
                "failed to commit utility-VM bundle-handoff marker {}: {error}",
                marker_path.display()
            ),
        )),
    }
}

async fn read_if_present(path: &Path) -> Result<Option<BundleHandoffMarker>> {
    let Some(initial_metadata) = path_metadata(path).await? else {
        return Ok(None);
    };
    match read_marker_bound(path, &initial_metadata).await {
        Ok(marker) => Ok(Some(marker)),
        Err(error) => match path_metadata(path).await? {
            None => Ok(None),
            Some(current_metadata)
                if !atomic_publication::same_file_identity(
                    &initial_metadata,
                    &current_metadata,
                ) =>
            {
                Err(handoff_error(
                    ErrorCode::Unavailable,
                    format!(
                        "utility-VM bundle-handoff marker changed while it was being read: {}",
                        path.display()
                    ),
                )
                .retryable(true))
            }
            Some(_) => Err(error),
        },
    }
}

async fn remove_matching_pending(pending: &Path, expected: &BundleHandoffMarker) -> Result<()> {
    if let Some(retained) = read_if_present(pending).await? {
        if retained != *expected {
            return Err(marker_conflict(expected));
        }
        remove_private_file_if_present(pending).await?;
    }
    Ok(())
}

fn marker_conflict(expected: &BundleHandoffMarker) -> Error {
    handoff_error(
        ErrorCode::Conflict,
        format!(
            "utility-VM bundle-handoff target {} generation {:?} has a different retained marker",
            expected.target.id, expected.target.generation
        ),
    )
}

async fn read_marker(path: &Path) -> Result<BundleHandoffMarker> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect utility-VM bundle-handoff marker {}: {error}",
                path.display()
            ),
        )
    })?;
    read_marker_bound(path, &metadata).await
}

async fn read_marker_bound(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<BundleHandoffMarker> {
    if !is_private_file(metadata) || metadata.len() > MAX_MARKER_BYTES as u64 {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "utility-VM bundle-handoff marker is not a bounded private file: {}",
                path.display()
            ),
        ));
    }
    let mut verified = crate::file_security::open_verified_regular_file(path)
        .await
        .map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidData {
                handoff_race_error(format!(
                    "utility-VM bundle-handoff marker changed while it was being opened: {} ({error})",
                    path.display()
                ))
            } else {
                handoff_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "failed to open utility-VM marker {}: {error}",
                        path.display()
                    ),
                )
            }
        })?;
    let opened_metadata = verified.file.metadata().await.map_err(|error| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect opened utility-VM bundle-handoff marker {}: {error}",
                path.display()
            ),
        )
    })?;
    if opened_metadata.len() != metadata.len()
        || !atomic_publication::same_file_identity(metadata, &opened_metadata)
    {
        return Err(handoff_error(
            ErrorCode::Unavailable,
            format!(
                "utility-VM bundle-handoff marker changed while it was being opened: {}",
                path.display()
            ),
        )
        .retryable(true));
    }
    if !is_private_file(&opened_metadata) || opened_metadata.len() > MAX_MARKER_BYTES as u64 {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "utility-VM bundle-handoff marker is not a bounded private file: {}",
                path.display()
            ),
        ));
    }
    let mut encoded = Vec::with_capacity(opened_metadata.len() as usize);
    (&mut verified.file)
        .take((MAX_MARKER_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .await
        .map_err(|error| {
            handoff_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to read utility-VM marker {}: {error}",
                    path.display()
                ),
            )
        })?;
    let final_metadata = verified.file.metadata().await.map_err(|error| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect utility-VM bundle-handoff marker after reading {}: {error}",
                path.display()
            ),
        )
    })?;
    if final_metadata.len() != opened_metadata.len()
        || encoded.len() != opened_metadata.len() as usize
        || !atomic_publication::same_file_identity(&opened_metadata, &final_metadata)
    {
        return Err(handoff_error(
            ErrorCode::Unavailable,
            format!(
                "utility-VM bundle-handoff marker changed while it was being read: {}",
                path.display()
            ),
        )
        .retryable(true));
    }
    if !is_private_file(&final_metadata) || final_metadata.len() > MAX_MARKER_BYTES as u64 {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "utility-VM bundle-handoff marker is not a bounded private file: {}",
                path.display()
            ),
        ));
    }
    verified
        .verify_unchanged(encoded.len() as u64)
        .await
        .map_err(|error| {
            handoff_race_error(format!(
                "utility-VM bundle-handoff marker changed while it was being read: {} ({error})",
                path.display()
            ))
        })?;
    verified
        .verify_path_unchanged(path)
        .await
        .map_err(|error| {
            handoff_race_error(format!(
                "utility-VM bundle-handoff marker path changed while it was being read: {} ({error})",
                path.display()
            ))
        })?;
    let marker: BundleHandoffMarker = serde_json::from_slice(&encoded).map_err(|error| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "invalid utility-VM bundle-handoff marker {}: {error}",
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
            format!(
                "invalid utility-VM bundle-handoff evidence: {}",
                path.display()
            ),
        ));
    }
    Ok(marker)
}

async fn remove_private_file_if_present(path: &Path) -> Result<()> {
    let Some(initial_metadata) = path_metadata(path).await? else {
        return Ok(());
    };
    remove_private_file_bound(path, &initial_metadata).await
}

async fn remove_private_file_bound(
    path: &Path,
    initial_metadata: &std::fs::Metadata,
) -> Result<()> {
    if !is_private_file(initial_metadata) {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            format!("refusing to remove a non-private file: {}", path.display()),
        ));
    }
    let verified = match crate::file_security::open_verified_regular_file(path).await {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            return Err(handoff_race_error(format!(
                "refusing to remove replaced utility-VM bundle-handoff marker {} ({error})",
                path.display()
            )))
        }
        Err(error) => {
            return Err(handoff_error(
                ErrorCode::Internal,
                format!(
                "failed to open utility-VM bundle-handoff marker {} for identity binding: {error}",
                path.display()
            ),
            ))
        }
    };
    let opened_metadata = verified.file.metadata().await.map_err(|error| {
        handoff_error(
            ErrorCode::Internal,
            format!(
                "failed to inspect opened utility-VM bundle-handoff marker {}: {error}",
                path.display()
            ),
        )
    })?;
    if !is_private_file(&opened_metadata)
        || opened_metadata.len() != initial_metadata.len()
        || !atomic_publication::same_file_identity(initial_metadata, &opened_metadata)
    {
        return Err(handoff_race_error(format!(
            "refusing to remove replaced utility-VM bundle-handoff marker {}",
            path.display()
        )));
    }
    verified
        .verify_path_unchanged(path)
        .await
        .map_err(|error| {
            handoff_race_error(format!(
                "refusing to remove changed utility-VM bundle-handoff marker {} ({error})",
                path.display()
            ))
        })?;
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(handoff_error(
            ErrorCode::Internal,
            format!("failed to remove {}: {error}", path.display()),
        )),
    }
}

async fn cleanup_empty_source_parents(source: &Path, runtime_root: &Path) -> Result<()> {
    let expected_root = canonical_private_directory(
        &runtime_bundle_handoff_root(runtime_root)?,
        "utility-VM bundle-handoff root",
    )
    .await?;
    let operation_directory = source.parent().ok_or_else(|| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            "utility-VM bundle handoff has no operation parent",
        )
    })?;
    let container_directory = operation_directory.parent().ok_or_else(|| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            "utility-VM bundle handoff has no container parent",
        )
    })?;
    if container_directory.parent() != Some(expected_root.as_path()) {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            "refusing to clean utility-VM handoff parents outside the protected root",
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
    Error::new(code, message).for_operation("prepare-utility-vm-bundle-handoff")
}

fn handoff_race_error(message: impl Into<String>) -> Error {
    handoff_error(ErrorCode::Unavailable, message).retryable(true)
}

fn nonempty_session_error(session: &GuestSessionAttachment) -> Error {
    handoff_error(
        ErrorCode::FailedPrecondition,
        format!(
            "reusable guest session {} generation {} still contains an untracked runtime-share entry",
            session.id(),
            session.generation()
        ),
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use a3s_oci_sdk::{ContainerId, ContainerTarget, ErrorCode, Generation};
    use tempfile::tempdir;
    use tokio::io::AsyncWriteExt;

    use super::super::layout::PRIVATE_FILE_MODE;
    use super::{
        ensure_marker, marker_conflict, publish_marker, read_marker, read_marker_bound,
        remove_private_file_bound, BundleHandoffMarker, MARKER_FILE, MARKER_SCHEMA,
        PENDING_MARKER_FILE,
    };

    fn target(id: &str, generation: u64) -> ContainerTarget {
        ContainerTarget::exact(
            ContainerId::new(id).expect("container ID"),
            Generation(generation),
        )
    }

    fn marker(target: ContainerTarget, digest: &str) -> BundleHandoffMarker {
        BundleHandoffMarker {
            schema_version: MARKER_SCHEMA.to_string(),
            target,
            config_digest: digest.to_string(),
        }
    }

    async fn write_private(path: &Path, bytes: &[u8]) {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .open(path)
            .await
            .expect("create private marker fixture");
        file.write_all(bytes).await.expect("write marker fixture");
        file.sync_all().await.expect("sync marker fixture");
    }

    #[tokio::test]
    async fn ensure_publishes_a_complete_marker_without_a_pending_alias() {
        let temporary = tempdir().expect("temporary marker root");
        let expected_target = target("handoff-marker", 1);
        let digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        ensure_marker(temporary.path(), &expected_target, digest)
            .await
            .expect("publish marker");

        let marker_path = temporary.path().join(MARKER_FILE);
        assert_eq!(
            read_marker(&marker_path).await.expect("read marker"),
            marker(expected_target, digest)
        );
        assert!(!temporary.path().join(PENDING_MARKER_FILE).exists());
    }

    #[tokio::test]
    async fn pending_contract_drift_is_rejected_without_overwrite() {
        let temporary = tempdir().expect("temporary marker root");
        let pending = temporary.path().join(PENDING_MARKER_FILE);
        let retained = serde_json::to_vec(&marker(
            target("handoff-marker", 2),
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        ))
        .expect("encode retained marker");
        write_private(&pending, &retained).await;

        let error = ensure_marker(
            temporary.path(),
            &target("handoff-marker", 1),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .await
        .expect_err("different pending marker must fail closed");
        assert_eq!(error.code, ErrorCode::Conflict);
        assert_eq!(
            tokio::fs::read(&pending).await.expect("read pending"),
            retained
        );
        assert!(!temporary.path().join(MARKER_FILE).exists());
    }

    #[tokio::test]
    async fn partial_pending_marker_is_rejected_without_replacement() {
        let temporary = tempdir().expect("temporary marker root");
        let pending = temporary.path().join(PENDING_MARKER_FILE);
        let retained = br#"{"schemaVersion":"a3s.oci.bundle-handoff.v1""#;
        write_private(&pending, retained).await;

        let error = ensure_marker(
            temporary.path(),
            &target("handoff-marker", 1),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .await
        .expect_err("partial pending marker must fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            tokio::fs::read(&pending).await.expect("read pending"),
            retained
        );
        assert!(!temporary.path().join(MARKER_FILE).exists());
    }

    #[tokio::test]
    async fn no_replace_publication_preserves_an_incumbent_marker() {
        let temporary = tempdir().expect("temporary marker root");
        let marker_path = temporary.path().join(MARKER_FILE);
        let pending = temporary.path().join(PENDING_MARKER_FILE);
        let expected = marker(
            target("handoff-marker", 1),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        );
        let incumbent = serde_json::to_vec(&marker(
            target("handoff-marker", 2),
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        ))
        .expect("encode incumbent");
        let candidate = serde_json::to_vec(&expected).expect("encode candidate");
        write_private(&marker_path, &incumbent).await;
        write_private(&pending, &candidate).await;

        let error = publish_marker(temporary.path(), &pending, &marker_path, &expected)
            .await
            .expect_err("occupied marker must not be replaced");
        assert_eq!(error, marker_conflict(&expected));
        assert_eq!(
            tokio::fs::read(&marker_path).await.expect("read incumbent"),
            incumbent
        );
        assert_eq!(
            tokio::fs::read(&pending).await.expect("read candidate"),
            candidate
        );
    }

    #[tokio::test]
    async fn marker_reader_rejects_a_replaced_path_before_open() {
        let temporary = tempdir().expect("temporary marker root");
        let path = temporary.path().join(MARKER_FILE);
        let retained = temporary.path().join("retained-original");
        let replacement = temporary.path().join("replacement");
        write_private(&path, b"original").await;
        let original_metadata = tokio::fs::symlink_metadata(&path)
            .await
            .expect("inspect original marker");
        tokio::fs::hard_link(&path, &retained)
            .await
            .expect("retain original marker identity");
        write_private(&replacement, b"replacement").await;
        tokio::fs::remove_file(&path)
            .await
            .expect("remove original marker path");
        tokio::fs::hard_link(&replacement, &path)
            .await
            .expect("install replacement marker path");

        let error = read_marker_bound(&path, &original_metadata)
            .await
            .expect_err("replacement marker must be rejected");
        assert!(error.retryable);
        assert_eq!(
            tokio::fs::read(&path)
                .await
                .expect("read replacement marker"),
            b"replacement"
        );
    }

    #[tokio::test]
    async fn marker_cleanup_rejects_a_replaced_path_without_deleting_it() {
        let temporary = tempdir().expect("temporary marker root");
        let path = temporary.path().join(PENDING_MARKER_FILE);
        let retained = temporary.path().join("retained-original");
        let replacement = temporary.path().join("replacement");
        write_private(&path, b"original").await;
        let original_metadata = tokio::fs::symlink_metadata(&path)
            .await
            .expect("inspect original marker");
        tokio::fs::hard_link(&path, &retained)
            .await
            .expect("retain original marker identity");
        write_private(&replacement, b"replacement").await;
        tokio::fs::remove_file(&path)
            .await
            .expect("remove original marker path");
        tokio::fs::hard_link(&replacement, &path)
            .await
            .expect("install replacement marker path");

        let error = remove_private_file_bound(&path, &original_metadata)
            .await
            .expect_err("replacement marker must not be deleted");
        assert!(error.retryable);
        assert_eq!(
            tokio::fs::read(&path)
                .await
                .expect("read replacement marker"),
            b"replacement"
        );
    }

    #[tokio::test]
    async fn marker_reader_rejects_a_final_component_symlink() {
        let temporary = tempdir().expect("temporary marker root");
        let victim = temporary.path().join("victim");
        let path = temporary.path().join(MARKER_FILE);
        write_private(&victim, b"victim").await;
        std::os::unix::fs::symlink(&victim, &path).expect("create marker symlink");

        let error = read_marker(&path)
            .await
            .expect_err("symlink marker must be rejected");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            tokio::fs::read(&victim).await.expect("read marker victim"),
            b"victim"
        );
    }

    #[tokio::test]
    async fn concurrent_ensure_calls_publish_one_complete_marker() {
        let temporary = tempdir().expect("temporary marker root");
        let expected_target = target("concurrent-handoff", 1);
        let digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        let mut calls = Vec::new();
        for _ in 0..16 {
            let root = temporary.path().to_path_buf();
            let target = expected_target.clone();
            calls.push(tokio::spawn(async move {
                ensure_marker(&root, &target, digest).await
            }));
        }
        for call in calls {
            call.await
                .expect("marker task must not panic")
                .expect("concurrent marker ensure must succeed");
        }

        assert_eq!(
            read_marker(&temporary.path().join(MARKER_FILE))
                .await
                .expect("read concurrent marker"),
            marker(expected_target, digest)
        );
        let mut entries = tokio::fs::read_dir(temporary.path())
            .await
            .expect("enumerate marker root");
        let mut names = Vec::new();
        while let Some(entry) = entries.next_entry().await.expect("read marker entry") {
            names.push(entry.file_name());
        }
        assert_eq!(names, vec![std::ffi::OsString::from(MARKER_FILE)]);
    }
}
