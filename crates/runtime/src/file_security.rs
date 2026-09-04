//! File-open primitives for runtime trust boundaries.
//!
//! A path check followed by a second path-based open is not an immutable
//! reference: another process can replace the final directory entry between
//! those operations.  Runtime-owned manifests and artifacts are therefore
//! opened with platform no-follow semantics, validated through the opened
//! handle, and revalidated after the complete read.

use std::io::{self, ErrorKind};
use std::path::Path;

use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

const HASH_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) struct VerifiedRegularFile {
    pub(crate) file: tokio::fs::File,
    size: u64,
    #[cfg(unix)]
    identity: UnixFileIdentity,
    #[cfg(windows)]
    identity: WindowsFileIdentity,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnixFileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowsFileIdentity {
    volume_serial_number: u32,
    file_index: u64,
}

/// Open a regular file without following a final-component link and bind the
/// returned handle to the path identity observed before opening it.
pub(crate) async fn open_verified_regular_file(path: &Path) -> io::Result<VerifiedRegularFile> {
    let path_metadata = tokio::fs::symlink_metadata(path).await?;
    if !is_plain_regular_file(&path_metadata) {
        return Err(invalid_file(format!(
            "path is not a regular non-link file: {}",
            path.display()
        )));
    }

    // Windows does not expose a stable file identity through the portable
    // Metadata API.  Pin an identity from a no-follow handle before opening
    // the handle that will be consumed.
    #[cfg(windows)]
    let expected_identity = {
        let identity_file = open_readonly_nofollow(path).await?;
        let identity_metadata = identity_file.metadata().await?;
        if !is_plain_regular_file(&identity_metadata) {
            return Err(invalid_file(format!(
                "identity handle is not a regular non-link file: {}",
                path.display()
            )));
        }
        windows_file_identity(&identity_file)?
    };

    let file = open_readonly_nofollow(path).await?;
    let opened_metadata = file.metadata().await?;
    if !is_plain_regular_file(&opened_metadata) {
        return Err(invalid_file(format!(
            "opened handle is not a regular non-link file: {}",
            path.display()
        )));
    }
    if opened_metadata.len() != path_metadata.len() {
        return Err(invalid_file(format!(
            "file size changed while it was being opened: {}",
            path.display()
        )));
    }

    #[cfg(unix)]
    let identity = {
        let path_identity = unix_file_identity(&path_metadata);
        let opened_identity = unix_file_identity(&opened_metadata);
        if path_identity != opened_identity {
            return Err(invalid_file(format!(
                "file was replaced while it was being opened: {}",
                path.display()
            )));
        }
        opened_identity
    };

    #[cfg(windows)]
    let identity = {
        let opened_identity = windows_file_identity(&file)?;
        if opened_identity != expected_identity {
            return Err(invalid_file(format!(
                "file was replaced while it was being opened: {}",
                path.display()
            )));
        }
        opened_identity
    };

    Ok(VerifiedRegularFile {
        file,
        size: opened_metadata.len(),
        #[cfg(unix)]
        identity,
        #[cfg(windows)]
        identity,
    })
}

impl VerifiedRegularFile {
    /// Verify that the opened inode remained a regular file with the same
    /// identity and size, and that exactly `bytes_read` bytes were consumed.
    pub(crate) async fn verify_unchanged(&self, bytes_read: u64) -> io::Result<()> {
        let metadata = self.file.metadata().await?;
        if !is_plain_regular_file(&metadata) {
            return Err(invalid_file("opened file changed type while it was read"));
        }
        if metadata.len() != self.size || bytes_read != self.size {
            return Err(invalid_file(format!(
                "opened file size changed while it was read (expected {}, observed {}, read {})",
                self.size,
                metadata.len(),
                bytes_read
            )));
        }

        #[cfg(unix)]
        if unix_file_identity(&metadata) != self.identity {
            return Err(invalid_file(
                "opened file identity changed while it was read",
            ));
        }

        #[cfg(windows)]
        if windows_file_identity(&self.file)? != self.identity {
            return Err(invalid_file(
                "opened file identity changed while it was read",
            ));
        }

        Ok(())
    }
}

/// Hash a previously verified regular file, enforcing an optional byte limit
/// and checking the handle again after the final read.
pub(crate) async fn sha256_verified_file(
    mut verified: VerifiedRegularFile,
    max_size: Option<u64>,
    path: &Path,
) -> io::Result<String> {
    if let Some(max_size) = max_size {
        if verified.size > max_size {
            return Err(invalid_file(format!(
                "file exceeds the {}-byte limit: {}",
                max_size,
                path.display()
            )));
        }
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    let mut size = 0_u64;
    loop {
        let read = verified.file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(read).map_err(|error| {
                invalid_file(format!(
                    "read length does not fit u64 for {}: {error}",
                    path.display()
                ))
            })?)
            .ok_or_else(|| {
                invalid_file(format!("read length overflowed u64 for {}", path.display()))
            })?;
        if let Some(max_size) = max_size {
            if size > max_size {
                return Err(invalid_file(format!(
                    "file exceeds the {}-byte limit: {}",
                    max_size,
                    path.display()
                )));
            }
        }
        hasher.update(&buffer[..read]);
    }
    verified.verify_unchanged(size).await?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// Open and hash a regular file through one immutable handle.
pub(crate) async fn sha256_path(path: &Path, max_size: Option<u64>) -> io::Result<String> {
    let verified = open_verified_regular_file(path).await?;
    sha256_verified_file(verified, max_size, path).await
}

fn invalid_file(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

fn is_plain_regular_file(metadata: &std::fs::Metadata) -> bool {
    metadata.is_file() && !metadata.file_type().is_symlink() && !is_reparse_point(metadata)
}

async fn open_readonly_nofollow(path: &Path) -> io::Result<tokio::fs::File> {
    #[cfg(unix)]
    {
        let mut options = tokio::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        return options.open(path).await;
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        let mut options = tokio::fs::OpenOptions::new();
        options
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        return options.open(path).await;
    }

    #[cfg(not(any(unix, windows)))]
    tokio::fs::File::open(path).await
}

#[cfg(unix)]
fn unix_file_identity(metadata: &std::fs::Metadata) -> UnixFileIdentity {
    use std::os::unix::fs::MetadataExt;

    UnixFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(windows)]
fn windows_file_identity(file: &tokio::fs::File) -> io::Result<WindowsFileIdentity> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: `file` owns a valid handle for the duration of this call and
    // the output pointer refers to writable storage of the exact structure.
    let succeeded =
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) };
    if succeeded == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the API returned success and initialized the complete struct.
    let information = unsafe { information.assume_init() };
    Ok(WindowsFileIdentity {
        volume_serial_number: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hashes_the_exact_regular_file() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("manifest");
        let bytes = b"immutable manifest";
        tokio::fs::write(&path, bytes)
            .await
            .expect("write manifest");

        let digest = sha256_path(&path, None).await.expect("hash manifest");
        assert_eq!(digest, format!("{:x}", Sha256::digest(bytes)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_a_final_component_symlink() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let target = temporary.path().join("target");
        let alias = temporary.path().join("alias");
        tokio::fs::write(&target, b"target")
            .await
            .expect("write target");
        symlink(&target, &alias).expect("create symlink");

        let error = sha256_path(&alias, None)
            .await
            .expect_err("symlink must fail closed");
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn rejects_a_file_that_grows_after_open() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("manifest");
        tokio::fs::write(&path, b"small")
            .await
            .expect("write manifest");
        let verified = open_verified_regular_file(&path)
            .await
            .expect("open verified manifest");
        tokio::fs::write(&path, b"larger manifest")
            .await
            .expect("replace manifest contents");

        let error = verified
            .verify_unchanged(5)
            .await
            .expect_err("size drift must fail closed");
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn enforces_a_bounded_manifest_size() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("manifest");
        tokio::fs::write(&path, b"0123456789")
            .await
            .expect("write manifest");

        let error = sha256_path(&path, Some(9))
            .await
            .expect_err("oversized manifest must fail closed");
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_handles_pin_distinct_file_identities() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let first_path = temporary.path().join("first");
        let second_path = temporary.path().join("second");
        tokio::fs::write(&first_path, b"first")
            .await
            .expect("write first file");
        tokio::fs::write(&second_path, b"second")
            .await
            .expect("write second file");

        let first = open_verified_regular_file(&first_path)
            .await
            .expect("open first file");
        let second = open_verified_regular_file(&second_path)
            .await
            .expect("open second file");
        assert_ne!(first.identity, second.identity);
    }
}
