//! Crash-safe, no-replace publication primitives for Unix utility-VM state.
//!
//! The files handled by this module are ownership evidence.  A fixed pending
//! file must never be written in place and a final marker must never be
//! replaced by a racing creator.  Callers still validate the decoded contract
//! at every race boundary; this module only owns the inode publication steps.

use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt;

use super::layout::PRIVATE_FILE_MODE;

pub(super) const STAGING_ATTEMPTS: usize = 8;
pub(super) const PUBLISH_ATTEMPTS: usize = 3;

/// Write a complete, synced private inode under a random staging name.
///
/// The caller publishes the returned inode with [`tokio::fs::hard_link`].
/// `hard_link` has no-replace semantics on the supported Unix filesystems, so
/// an existing authoritative name is never overwritten.
pub(super) async fn create_complete_staging(
    root: &Path,
    pending: &Path,
    encoded: &[u8],
    prefix: &str,
) -> io::Result<PathBuf> {
    if pending.parent() != Some(root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic publication paths do not share their protected root",
        ));
    }

    for _ in 0..STAGING_ATTEMPTS {
        let staging = staging_path(root, prefix)?;
        let mut options = tokio::fs::OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = match options.open(&staging).await {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };

        if let Err(error) = file.write_all(encoded).await {
            let _ = remove_file_if_present(&staging).await;
            return Err(error);
        }
        if let Err(error) = file.flush().await {
            let _ = remove_file_if_present(&staging).await;
            return Err(error);
        }
        if let Err(error) = file.sync_all().await {
            let _ = remove_file_if_present(&staging).await;
            return Err(error);
        }
        drop(file);
        return Ok(staging);
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to allocate a unique atomic publication staging file",
    ))
}

fn staging_path(root: &Path, prefix: &str) -> io::Result<PathBuf> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|error| io::Error::other(error.to_string()))?;
    let mut encoded = String::with_capacity(nonce.len() * 2);
    for byte in nonce {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(root.join(format!("{prefix}{}{encoded}", std::process::id())))
}

/// Remove a private staging inode, treating a concurrent removal as success.
pub(super) async fn remove_file_if_present(path: &Path) -> io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Return whether two metadata snapshots still refer to the same inode.
///
/// A reader can observe `ENOENT` after its initial `stat` when another owner
/// consumes a pending name.  Comparing device and inode lets callers
/// distinguish that race (including remove-and-recreate) from a malformed
/// file that must remain fail-closed.
pub(super) fn same_file_identity(first: &std::fs::Metadata, second: &std::fs::Metadata) -> bool {
    first.dev() == second.dev() && first.ino() == second.ino()
}

/// Open a retained runtime file without following a final-component symlink.
///
/// Callers must validate the returned handle's metadata and compare its
/// identity with a path snapshot taken before the open. Reads then stay on
/// the opened inode instead of resolving the path again.
pub(super) async fn open_readonly_nofollow(path: &Path) -> io::Result<tokio::fs::File> {
    let mut options = tokio::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    options.open(path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn readonly_open_rejects_a_final_component_symlink() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let target = temporary.path().join("target");
        let alias = temporary.path().join("alias");
        let file = tokio::fs::File::create(&target)
            .await
            .expect("create target file");
        file.sync_all().await.expect("sync target file");
        std::os::unix::fs::symlink(&target, &alias).expect("create marker symlink");

        let error = open_readonly_nofollow(&alias)
            .await
            .expect_err("no-follow open must reject a symlink");
        assert!(error.raw_os_error().is_some());
    }

    #[tokio::test]
    async fn file_identity_detects_remove_and_recreate() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("marker");
        let file = tokio::fs::File::create(&path)
            .await
            .expect("create first file");
        file.sync_all().await.expect("sync first file");
        let first = tokio::fs::symlink_metadata(&path)
            .await
            .expect("inspect first file");
        let retained_old = temporary.path().join("retained-old");
        tokio::fs::hard_link(&path, &retained_old)
            .await
            .expect("retain first inode");
        tokio::fs::remove_file(&path)
            .await
            .expect("remove first file");
        let file = tokio::fs::File::create(&path)
            .await
            .expect("create replacement file");
        file.sync_all().await.expect("sync replacement file");
        let replacement = tokio::fs::symlink_metadata(&path)
            .await
            .expect("inspect replacement file");

        assert!(!same_file_identity(&first, &replacement));
    }
}
