use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use a3s_oci_sdk::{
    runtime_bundle_handoff_root, ContainerTarget, Error, ErrorCode, Generation,
    GuestSessionAttachment, Result,
};

pub(super) const CONSOLE_DIRECTORY: &str = "console";
pub(super) const RECOVERY_DIRECTORY: &str = "recovery";
pub(super) const RUNTIME_SHARE_DIRECTORY: &str = "shares";
pub(super) const REUSABLE_GUEST_SESSION_DIRECTORY: &str = ".guest-sessions";
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const BOOTSTRAP_DIRECTORY: &str = "bootstrap";
pub(super) const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
pub(super) const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UtilityVmBootstrap {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    RuntimeShare,
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    PrivateEmptyRoot,
}

#[derive(Debug)]
pub(crate) struct PreparedUtilityVmLayout {
    pub(crate) shim: PathBuf,
    pub(crate) runtime_root: PathBuf,
    pub(crate) system_image_manifest: PathBuf,
    pub(crate) system_image_manifest_sha256: String,
    pub(crate) runtime_share_root: PathBuf,
    pub(crate) console_directory: PathBuf,
    pub(crate) recovery_directory: PathBuf,
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub(crate) bootstrap_root: PathBuf,
}

impl PreparedUtilityVmLayout {
    pub(crate) async fn open(
        shim: PathBuf,
        runtime_root: PathBuf,
        system_image_manifest: PathBuf,
        bootstrap: UtilityVmBootstrap,
    ) -> Result<Self> {
        let runtime_root =
            ensure_private_directory(runtime_root, "utility-VM runtime root").await?;
        let shim = canonical_plain_file(&shim, "utility-VM libkrun shim", false).await?;
        let system_image_manifest = canonical_plain_file(
            &system_image_manifest,
            "utility-VM system-image manifest",
            false,
        )
        .await?;
        if system_image_manifest.starts_with(&runtime_root)
            || runtime_root.starts_with(&system_image_manifest)
        {
            return Err(path_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "immutable utility-VM system-image manifest must be outside writable runtime root {}: {}",
                    runtime_root.display(),
                    system_image_manifest.display()
                ),
            ));
        }
        let system_image_manifest_sha256 = sha256_path(&system_image_manifest).await?;

        let runtime_share_root = ensure_private_directory(
            runtime_root.join(RUNTIME_SHARE_DIRECTORY),
            "utility-VM runtime-share root",
        )
        .await?;
        let console_directory = ensure_private_directory(
            runtime_root.join(CONSOLE_DIRECTORY),
            "utility-VM console directory",
        )
        .await?;
        let recovery_directory = ensure_private_directory(
            runtime_root.join(RECOVERY_DIRECTORY),
            "utility-VM recovery directory",
        )
        .await?;
        ensure_private_directory(
            runtime_bundle_handoff_root(&runtime_root)?,
            "utility-VM bundle-handoff root",
        )
        .await?;
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let UtilityVmBootstrap::RuntimeShare = bootstrap;
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        let bootstrap_root = match bootstrap {
            UtilityVmBootstrap::PrivateEmptyRoot => {
                ensure_empty_private_directory(
                    runtime_root.join(BOOTSTRAP_DIRECTORY),
                    "utility-VM bootstrap root",
                )
                .await?
            }
        };

        Ok(Self {
            shim,
            runtime_root,
            system_image_manifest,
            system_image_manifest_sha256,
            runtime_share_root,
            console_directory,
            recovery_directory,
            #[cfg(all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            bootstrap_root,
        })
    }
}

pub(crate) fn validate_absolute_normalized_path(path: &Path, label: &str) -> Result<()> {
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

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
async fn ensure_empty_private_directory(path: PathBuf, label: &'static str) -> Result<PathBuf> {
    let directory = ensure_private_directory(path, label).await?;
    let mut entries = tokio::fs::read_dir(&directory).await.map_err(|error| {
        path_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to enumerate {label} {}: {error}",
                directory.display()
            ),
        )
    })?;
    if entries
        .next_entry()
        .await
        .map_err(|error| {
            path_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to enumerate {label} {}: {error}",
                    directory.display()
                ),
            )
        })?
        .is_some()
    {
        return Err(path_error(
            ErrorCode::FailedPrecondition,
            format!("{label} must remain empty: {}", directory.display()),
        ));
    }
    Ok(directory)
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
            match builder.create(&path).await {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(path_error(
                        ErrorCode::PermissionDenied,
                        format!("failed to create {label} {}: {error}", path.display()),
                    ));
                }
            }
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
                "utility-VM driver operation requires an exact generation for container {}",
                target.id
            ),
        )
        .for_operation(operation)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RuntimeSharePaths {
    pub(super) mount_root: PathBuf,
    pub(super) container_share: PathBuf,
}

pub(super) async fn ensure_runtime_share_paths(
    runtime_share_root: &Path,
    target: &ContainerTarget,
    guest_session: Option<&GuestSessionAttachment>,
) -> Result<RuntimeSharePaths> {
    let generation = require_exact_generation(target, "prepare-utility-vm-runtime-share")?;
    let container_parent = match guest_session {
        Some(session) => ensure_reusable_guest_session_root(runtime_share_root, session).await?,
        None => runtime_share_root.to_path_buf(),
    };
    let container = ensure_private_child(
        &container_parent,
        target.id.as_str(),
        "utility-VM container-share directory",
    )
    .await?;
    let container_share = ensure_private_child(
        &container,
        &generation.0.to_string(),
        "utility-VM generation-share directory",
    )
    .await?;
    Ok(RuntimeSharePaths {
        mount_root: guest_session.map_or_else(|| container_share.clone(), |_| container_parent),
        container_share,
    })
}

pub(super) async fn existing_runtime_share_paths(
    runtime_share_root: &Path,
    target: &ContainerTarget,
    guest_session: Option<&GuestSessionAttachment>,
    operation: &'static str,
) -> Result<Option<RuntimeSharePaths>> {
    let generation = require_exact_generation(target, operation)?;
    let container_parent = match guest_session {
        Some(session) => {
            let Some(session_root) =
                existing_reusable_guest_session_root(runtime_share_root, session).await?
            else {
                return Ok(None);
            };
            session_root
        }
        None => runtime_share_root.to_path_buf(),
    };
    let Some(container) = existing_private_child(
        &container_parent,
        target.id.as_str(),
        "utility-VM container-share directory",
    )
    .await?
    else {
        return Ok(None);
    };
    let Some(container_share) = existing_private_child(
        &container,
        &generation.0.to_string(),
        "utility-VM generation-share directory",
    )
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(RuntimeSharePaths {
        mount_root: guest_session.map_or_else(|| container_share.clone(), |_| container_parent),
        container_share,
    }))
}

pub(super) async fn exact_runtime_share_paths(
    runtime_share_root: &Path,
    target: &ContainerTarget,
    guest_session: Option<&GuestSessionAttachment>,
) -> Result<RuntimeSharePaths> {
    existing_runtime_share_paths(
        runtime_share_root,
        target,
        guest_session,
        "resolve-utility-vm-runtime-share",
    )
    .await?
    .ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "utility-VM exact-generation runtime share does not exist for container {} generation {:?}",
                    target.id, target.generation
                ),
            )
            .for_operation("resolve-utility-vm-runtime-share")
        })
}

pub(super) async fn ensure_reusable_guest_session_root(
    runtime_share_root: &Path,
    session: &GuestSessionAttachment,
) -> Result<PathBuf> {
    let session_root = ensure_private_child(
        runtime_share_root,
        REUSABLE_GUEST_SESSION_DIRECTORY,
        "utility-VM reusable-session root",
    )
    .await?;
    let session_id = ensure_private_child(
        &session_root,
        session.id().as_str(),
        "utility-VM reusable-session identity directory",
    )
    .await?;
    ensure_private_child(
        &session_id,
        &session.generation().get().to_string(),
        "utility-VM reusable-session generation directory",
    )
    .await
}

pub(super) async fn existing_reusable_guest_session_root(
    runtime_share_root: &Path,
    session: &GuestSessionAttachment,
) -> Result<Option<PathBuf>> {
    let Some(session_id_root) =
        existing_reusable_guest_session_identity_root(runtime_share_root, session).await?
    else {
        return Ok(None);
    };
    existing_private_child(
        &session_id_root,
        &session.generation().get().to_string(),
        "utility-VM reusable-session generation directory",
    )
    .await
}

/// Resolve the protected directory for a logical reusable-session identity,
/// without selecting an incarnation.  A replacement owner uses this to
/// detect any stale generation root before it can launch a new VM under the
/// same caller-issued identity.
pub(super) async fn existing_reusable_guest_session_identity_root(
    runtime_share_root: &Path,
    session: &GuestSessionAttachment,
) -> Result<Option<PathBuf>> {
    let Some(session_root) = existing_private_child(
        runtime_share_root,
        REUSABLE_GUEST_SESSION_DIRECTORY,
        "utility-VM reusable-session root",
    )
    .await?
    else {
        return Ok(None);
    };
    existing_private_child(
        &session_root,
        session.id().as_str(),
        "utility-VM reusable-session identity directory",
    )
    .await
}

async fn ensure_private_child(
    parent: &Path,
    component: &str,
    label: &'static str,
) -> Result<PathBuf> {
    let child = ensure_private_directory(parent.join(component), label).await?;
    ensure_direct_child(parent, &child, label)?;
    Ok(child)
}

async fn existing_private_child(
    parent: &Path,
    component: &str,
    label: &'static str,
) -> Result<Option<PathBuf>> {
    let configured = parent.join(component);
    if path_metadata(&configured).await?.is_none() {
        return Ok(None);
    }
    let child = canonical_private_directory(&configured, label).await?;
    ensure_direct_child(parent, &child, label)?;
    Ok(Some(child))
}

fn ensure_direct_child(parent: &Path, child: &Path, label: &str) -> Result<()> {
    if child.parent() != Some(parent) {
        return Err(path_error(
            ErrorCode::FailedPrecondition,
            format!(
                "{label} escaped protected parent {}: {}",
                parent.display(),
                child.display()
            ),
        ));
    }
    Ok(())
}

async fn sha256_path(path: &Path) -> Result<String> {
    crate::file_security::sha256_path(path, Some(64 * 1024))
        .await
        .map_err(|error| {
            path_error(
                ErrorCode::FailedPrecondition,
                format!("failed to securely hash {}: {error}", path.display()),
            )
        })
}

fn path_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("open-utility-vm-runtime-driver")
}
