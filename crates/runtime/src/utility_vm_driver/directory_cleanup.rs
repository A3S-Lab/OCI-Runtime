//! Identity-bound directory cleanup for Unix utility-VM runtime state.
//!
//! Cleanup resolves the final component without following links, compares the
//! opened directory with metadata captured before validation, and performs all
//! traversal through that handle. A concurrent pathname replacement therefore
//! cannot redirect deletion into a different subtree.

use std::io;
use std::path::Path;

use a3s_oci_sdk::{Error, ErrorCode, Result};
use cap_fs_ext::{DirExt, OsMetadataExt};
use cap_std::ambient_authority;
use cap_std::fs::Dir;

use super::layout::{
    is_private_directory, path_metadata, validate_absolute_normalized_path, PRIVATE_DIRECTORY_MODE,
};

pub(super) async fn remove_directory_if_empty(path: &Path) -> Result<()> {
    let Some(metadata) = path_metadata(path).await? else {
        return Ok(());
    };
    remove_directory_if_empty_bound(path, &metadata).await
}

/// Remove an empty private directory through an identity-bound, no-follow
/// directory handle. The initial metadata must be captured before any
/// validation that leads to cleanup; a pathname lookup performed only at the
/// end could otherwise delete a replacement directory.
pub(super) async fn remove_directory_if_empty_bound(
    path: &Path,
    initial_metadata: &std::fs::Metadata,
) -> Result<()> {
    validate_cleanup_path(path, "empty directory cleanup target")?;
    if !is_private_directory(initial_metadata) {
        return Err(cleanup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "refusing to remove a non-private directory: {}",
                path.display()
            ),
        ));
    }
    let expected_identity = DirectoryIdentity::from_std(initial_metadata);
    let display = path.to_path_buf();
    let path = display.clone();
    tokio::task::spawn_blocking(move || {
        let Some(directory) = open_bound_directory(&path, expected_identity)? else {
            return Ok(());
        };
        let mut entries = directory.entries().map_err(|error| {
            cleanup_error(
                ErrorCode::Internal,
                format!(
                    "failed to enumerate empty-directory cleanup target {}: {error}",
                    path.display()
                ),
            )
        })?;
        if entries
            .next()
            .transpose()
            .map_err(|error| {
                cleanup_error(
                    ErrorCode::Internal,
                    format!(
                        "failed to enumerate empty-directory cleanup target {}: {error}",
                        path.display()
                    ),
                )
            })?
            .is_some()
        {
            return Ok(());
        }
        drop(entries);
        match directory.remove_open_dir() {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => Ok(()),
            Err(error) => Err(cleanup_error(
                ErrorCode::Internal,
                format!(
                    "failed to remove empty directory {}: {error}",
                    path.display()
                ),
            )),
        }
    })
    .await
    .map_err(|error| {
        cleanup_error(
            ErrorCode::Internal,
            format!(
                "empty-directory cleanup task failed for {}: {error}",
                display.display()
            ),
        )
    })?
}

/// Remove a complete private directory subtree through one identity-bound,
/// no-follow directory handle. The opened handle remains the authority for
/// recursive traversal and final removal, so a concurrent replacement of the
/// final pathname cannot redirect deletion into the replacement subtree.
pub(super) async fn remove_directory_all_bound(
    path: &Path,
    initial_metadata: &std::fs::Metadata,
) -> Result<()> {
    validate_cleanup_path(path, "recursive directory cleanup target")?;
    if !is_private_directory(initial_metadata) {
        return Err(cleanup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "refusing to recursively remove a non-private directory: {}",
                path.display()
            ),
        ));
    }
    let expected_identity = DirectoryIdentity::from_std(initial_metadata);
    let display = path.to_path_buf();
    let path = display.clone();
    tokio::task::spawn_blocking(move || {
        let Some(directory) = open_bound_directory(&path, expected_identity)? else {
            return Ok(());
        };
        match directory.remove_open_dir_all() {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => Err(cleanup_error(
                ErrorCode::Unavailable,
                format!(
                    "directory remained non-empty during recursive cleanup {}: {error}",
                    path.display()
                ),
            )
            .retryable(true)),
            Err(error) => Err(cleanup_error(
                ErrorCode::Internal,
                format!(
                    "failed to recursively remove directory {}: {error}",
                    path.display()
                ),
            )),
        }
    })
    .await
    .map_err(|error| {
        cleanup_error(
            ErrorCode::Internal,
            format!(
                "recursive directory cleanup task failed for {}: {error}",
                display.display()
            ),
        )
    })?
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

impl DirectoryIdentity {
    fn from_std(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: std::os::unix::fs::MetadataExt::dev(metadata),
            inode: std::os::unix::fs::MetadataExt::ino(metadata),
        }
    }

    fn from_cap(metadata: &cap_std::fs::Metadata) -> Self {
        Self {
            device: OsMetadataExt::dev(metadata),
            inode: OsMetadataExt::ino(metadata),
        }
    }
}

fn is_private_cap_directory(metadata: &cap_std::fs::Metadata) -> bool {
    // SAFETY: geteuid has no preconditions or failure return.
    let effective_uid = unsafe { libc::geteuid() };
    metadata.is_dir()
        && !metadata.is_symlink()
        && OsMetadataExt::uid(metadata) == effective_uid
        && OsMetadataExt::mode(metadata) & 0o777 == PRIVATE_DIRECTORY_MODE
}

fn open_bound_directory(path: &Path, expected_identity: DirectoryIdentity) -> Result<Option<Dir>> {
    let parent_path = path.parent().ok_or_else(|| {
        cleanup_error(
            ErrorCode::InvalidArgument,
            format!("directory cleanup target has no parent: {}", path.display()),
        )
    })?;
    let name = path.file_name().ok_or_else(|| {
        cleanup_error(
            ErrorCode::InvalidArgument,
            format!(
                "directory cleanup target has no final component: {}",
                path.display()
            ),
        )
    })?;
    let parent = match Dir::open_ambient_dir(parent_path, ambient_authority()) {
        Ok(parent) => parent,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(cleanup_error(
                ErrorCode::Internal,
                format!(
                    "failed to open parent for directory cleanup target {}: {error}",
                    path.display()
                ),
            ));
        }
    };
    let directory = match parent.open_dir_nofollow(name) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(cleanup_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "directory cleanup target is not a plain directory: {}: {error}",
                    path.display()
                ),
            ));
        }
    };
    let metadata = directory.dir_metadata().map_err(|error| {
        cleanup_error(
            ErrorCode::Internal,
            format!(
                "failed to inspect opened directory cleanup target {}: {error}",
                path.display()
            ),
        )
    })?;
    if !is_private_cap_directory(&metadata) {
        return Err(cleanup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "directory cleanup target is no longer a private directory: {}",
                path.display()
            ),
        ));
    }
    if DirectoryIdentity::from_cap(&metadata) != expected_identity {
        return Err(cleanup_error(
            ErrorCode::Unavailable,
            format!(
                "directory cleanup target was replaced while being opened: {}",
                path.display()
            ),
        )
        .retryable(true));
    }
    Ok(Some(directory))
}

fn validate_cleanup_path(path: &Path, label: &str) -> Result<()> {
    validate_absolute_normalized_path(path, label)
        .map_err(|error| cleanup_error(error.code, error.message))
}

fn cleanup_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("cleanup-utility-vm-runtime-directory")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utility_vm_driver::layout::ensure_private_directory;

    #[tokio::test]
    async fn empty_directory_cleanup_accepts_concurrent_removal_after_identity_check() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let temporary_root = tokio::fs::canonicalize(temporary.path())
            .await
            .expect("canonical temporary directory");
        let directory = ensure_private_directory(
            temporary_root.join("concurrently-removed"),
            "concurrent cleanup fixture",
        )
        .await
        .expect("create private cleanup directory");
        let metadata = path_metadata(&directory)
            .await
            .expect("inspect cleanup directory")
            .expect("cleanup directory must exist before the race");
        assert!(is_private_directory(&metadata));

        tokio::fs::remove_dir(&directory)
            .await
            .expect("simulate concurrent parent cleanup");

        remove_directory_if_empty_bound(&directory, &metadata)
            .await
            .expect("concurrent removal is idempotent");
    }

    #[tokio::test]
    async fn empty_directory_cleanup_refuses_a_replacement() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let temporary_root = tokio::fs::canonicalize(temporary.path())
            .await
            .expect("canonical temporary directory");
        let directory = ensure_private_directory(
            temporary_root.join("empty-generation"),
            "empty replacement fixture",
        )
        .await
        .expect("create original directory");
        let metadata = path_metadata(&directory)
            .await
            .expect("inspect original directory")
            .expect("original directory must exist");
        let retained = temporary_root.join("empty-generation-old");
        tokio::fs::rename(&directory, &retained)
            .await
            .expect("retain original directory under a different name");
        let replacement = ensure_private_directory(directory.clone(), "empty replacement fixture")
            .await
            .expect("create replacement directory");
        tokio::fs::write(replacement.join("replacement-entry"), b"replacement")
            .await
            .expect("write replacement entry");

        let error = remove_directory_if_empty_bound(&directory, &metadata)
            .await
            .expect_err("replacement must not be removed");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(directory.join("replacement-entry").is_file());
        assert!(retained.is_dir());
    }

    #[tokio::test]
    async fn recursive_directory_cleanup_refuses_a_replacement() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let temporary_root = tokio::fs::canonicalize(temporary.path())
            .await
            .expect("canonical temporary directory");
        let directory = ensure_private_directory(
            temporary_root.join("generation"),
            "recursive replacement fixture",
        )
        .await
        .expect("create original directory");
        tokio::fs::write(directory.join("original-entry"), b"original")
            .await
            .expect("write original entry");
        let metadata = path_metadata(&directory)
            .await
            .expect("inspect original directory")
            .expect("original directory must exist");
        let retained = temporary_root.join("generation-old");
        tokio::fs::rename(&directory, &retained)
            .await
            .expect("retain original directory under a different name");
        let replacement =
            ensure_private_directory(directory.clone(), "recursive replacement fixture")
                .await
                .expect("create replacement directory");
        tokio::fs::write(replacement.join("replacement-entry"), b"replacement")
            .await
            .expect("write replacement entry");

        let error = remove_directory_all_bound(&directory, &metadata)
            .await
            .expect_err("replacement must not be removed");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(directory.join("replacement-entry").is_file());
        assert!(retained.join("original-entry").is_file());
    }

    #[tokio::test]
    async fn recursive_directory_cleanup_does_not_follow_symlink_entries() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let temporary_root = tokio::fs::canonicalize(temporary.path())
            .await
            .expect("canonical temporary directory");
        let outside =
            ensure_private_directory(temporary_root.join("outside"), "recursive symlink fixture")
                .await
                .expect("create outside directory");
        tokio::fs::write(outside.join("must-survive"), b"outside")
            .await
            .expect("write outside entry");
        let directory = ensure_private_directory(
            temporary_root.join("generation"),
            "recursive symlink fixture",
        )
        .await
        .expect("create generation directory");
        let nested =
            ensure_private_directory(directory.join("nested"), "recursive symlink fixture")
                .await
                .expect("create nested directory");
        tokio::fs::write(nested.join("entry"), b"nested")
            .await
            .expect("write nested entry");
        std::os::unix::fs::symlink(&outside, directory.join("outside-link"))
            .expect("create outside symlink");
        let metadata = path_metadata(&directory)
            .await
            .expect("inspect generation directory")
            .expect("generation directory must exist");

        remove_directory_all_bound(&directory, &metadata)
            .await
            .expect("remove exact generation subtree");
        assert!(!directory.exists());
        assert!(outside.join("must-survive").is_file());
    }

    #[tokio::test]
    async fn recursive_directory_cleanup_rejects_a_symlink_replacement() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let temporary_root = tokio::fs::canonicalize(temporary.path())
            .await
            .expect("canonical temporary directory");
        let victim = ensure_private_directory(
            temporary_root.join("victim"),
            "recursive symlink target fixture",
        )
        .await
        .expect("create victim directory");
        tokio::fs::write(victim.join("must-survive"), b"victim")
            .await
            .expect("write victim entry");
        let directory = ensure_private_directory(
            temporary_root.join("generation"),
            "recursive symlink replacement fixture",
        )
        .await
        .expect("create original directory");
        let metadata = path_metadata(&directory)
            .await
            .expect("inspect original directory")
            .expect("original directory must exist");
        let retained = temporary_root.join("generation-old");
        tokio::fs::rename(&directory, &retained)
            .await
            .expect("retain original directory under a different name");
        std::os::unix::fs::symlink(&victim, &directory)
            .expect("replace cleanup target with a directory symlink");

        let error = remove_directory_all_bound(&directory, &metadata)
            .await
            .expect_err("symlink replacement must be rejected");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(victim.join("must-survive").is_file());
        assert!(retained.is_dir());
    }
}
