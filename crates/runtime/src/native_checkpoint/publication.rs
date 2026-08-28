use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{CheckpointArtifactPath, ErrorCode, Result};

use super::artifact;
use super::{checkpoint_error, io_error};

#[derive(Debug)]
pub(super) struct ArtifactDestination {
    directory: File,
    directory_path: PathBuf,
    final_name: CString,
    final_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PublishOutcome {
    Published,
    AlreadyPublished,
}

impl ArtifactDestination {
    pub(super) async fn open(path: &CheckpointArtifactPath) -> Result<Self> {
        let final_path = path.as_path().to_path_buf();
        tokio::task::spawn_blocking(move || Self::open_blocking(final_path))
            .await
            .map_err(|error| {
                checkpoint_error(
                    ErrorCode::Internal,
                    format!("checkpoint destination open task failed: {error}"),
                )
            })?
    }

    pub(super) async fn ensure_absent(&self) -> Result<()> {
        let directory = clone_file(&self.directory, &self.directory_path)?;
        let final_name = self.final_name.clone();
        let final_path = self.final_path.clone();
        tokio::task::spawn_blocking(move || {
            if entry_exists(directory.as_raw_fd(), &final_name)? {
                Err(checkpoint_error(
                    ErrorCode::AlreadyExists,
                    format!(
                        "checkpoint artifact destination already exists: {}",
                        final_path.display()
                    ),
                ))
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|error| {
            checkpoint_error(
                ErrorCode::Internal,
                format!("checkpoint destination inspection task failed: {error}"),
            )
        })?
    }

    pub(super) async fn create_pending(
        &self,
        name: &str,
        publication_token: [u8; 32],
    ) -> Result<File> {
        let directory = clone_file(&self.directory, &self.directory_path)?;
        let pending = c_name(name)?;
        let display = self.directory_path.join(name);
        tokio::task::spawn_blocking(move || {
            let mut file = open_at(
                directory.as_raw_fd(),
                &pending,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
            .map_err(|error| io_error("create pending checkpoint artifact", &display, error))?;
            if let Err(error) = artifact::initialize_pending(&mut file, &publication_token) {
                drop(file);
                // SAFETY: this call follows a successful exclusive create of
                // this exact internal name in the retained directory.
                let _ = unsafe { libc::unlinkat(directory.as_raw_fd(), pending.as_ptr(), 0) };
                return Err(error);
            }
            Ok(file)
        })
        .await
        .map_err(|error| {
            checkpoint_error(
                ErrorCode::Internal,
                format!("pending checkpoint creation task failed: {error}"),
            )
        })?
    }

    pub(super) async fn open_pending(&self, name: &str) -> Result<Option<File>> {
        let directory = clone_file(&self.directory, &self.directory_path)?;
        let pending = c_name(name)?;
        let display = self.directory_path.join(name);
        tokio::task::spawn_blocking(move || {
            match open_at(
                directory.as_raw_fd(),
                &pending,
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
            ) {
                Ok(file) => Ok(Some(file)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(io_error(
                    "open pending checkpoint artifact",
                    &display,
                    error,
                )),
            }
        })
        .await
        .map_err(|error| {
            checkpoint_error(
                ErrorCode::Internal,
                format!("pending checkpoint open task failed: {error}"),
            )
        })?
    }

    pub(super) async fn open_final(&self) -> Result<Option<File>> {
        let directory = clone_file(&self.directory, &self.directory_path)?;
        let final_name = self.final_name.clone();
        let display = self.final_path.clone();
        tokio::task::spawn_blocking(move || {
            match open_at(
                directory.as_raw_fd(),
                &final_name,
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
            ) {
                Ok(file) => Ok(Some(file)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(io_error("open checkpoint artifact", &display, error)),
            }
        })
        .await
        .map_err(|error| {
            checkpoint_error(
                ErrorCode::Internal,
                format!("checkpoint artifact open task failed: {error}"),
            )
        })?
    }

    pub(super) async fn publish(&self, pending_name: &str) -> Result<PublishOutcome> {
        let directory = clone_file(&self.directory, &self.directory_path)?;
        let pending = c_name(pending_name)?;
        let final_name = self.final_name.clone();
        let final_path = self.final_path.clone();
        tokio::task::spawn_blocking(move || {
            let descriptor = directory.as_raw_fd();
            // SAFETY: both names are valid NUL-terminated components, and the
            // retained descriptor refers to the authorized parent directory.
            let linked = unsafe {
                libc::linkat(
                    descriptor,
                    pending.as_ptr(),
                    descriptor,
                    final_name.as_ptr(),
                    0,
                )
            };
            if linked == 0 {
                directory.sync_all().map_err(|error| {
                    io_error("sync published checkpoint directory", &final_path, error)
                })?;
                return Ok(PublishOutcome::Published);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(io_error("publish checkpoint artifact", &final_path, error));
            }
            let pending_file = open_at(
                descriptor,
                &pending,
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
            )
            .map_err(|error| io_error("reopen pending checkpoint artifact", &final_path, error))?;
            let final_file = open_at(
                descriptor,
                &final_name,
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
            )
            .map_err(|error| {
                io_error("open existing checkpoint destination", &final_path, error)
            })?;
            if same_file(&pending_file, &final_file)? {
                Ok(PublishOutcome::AlreadyPublished)
            } else {
                Err(checkpoint_error(
                    ErrorCode::AlreadyExists,
                    format!(
                        "checkpoint artifact destination was occupied by a different file: {}",
                        final_path.display()
                    ),
                ))
            }
        })
        .await
        .map_err(|error| {
            checkpoint_error(
                ErrorCode::Internal,
                format!("checkpoint artifact publication task failed: {error}"),
            )
        })?
    }

    pub(super) async fn remove_owned_pending(
        &self,
        name: &str,
        publication_token: [u8; 32],
    ) -> Result<()> {
        let directory = clone_file(&self.directory, &self.directory_path)?;
        let pending = c_name(name)?;
        let display = self.directory_path.join(name);
        tokio::task::spawn_blocking(move || {
            let descriptor = directory.as_raw_fd();
            let mut file = match open_at(
                descriptor,
                &pending,
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
            ) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => {
                    return Err(io_error(
                        "open pending checkpoint artifact for cleanup",
                        &display,
                        error,
                    ));
                }
            };
            if !artifact::owns_pending(&mut file, &publication_token)? {
                return Err(checkpoint_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "refusing to remove an unowned pending checkpoint artifact: {}",
                        display.display()
                    ),
                ));
            }
            drop(file);
            // SAFETY: `pending` is one validated internal component and the
            // retained descriptor pins the authorized directory.
            if unsafe { libc::unlinkat(descriptor, pending.as_ptr(), 0) } != 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::NotFound {
                    return Err(io_error(
                        "remove pending checkpoint artifact",
                        &display,
                        error,
                    ));
                }
            }
            directory.sync_all().map_err(|error| {
                io_error("sync checkpoint directory after cleanup", &display, error)
            })
        })
        .await
        .map_err(|error| {
            checkpoint_error(
                ErrorCode::Internal,
                format!("pending checkpoint cleanup task failed: {error}"),
            )
        })?
    }

    pub(super) async fn remove_created_pending(&self, name: &str) -> Result<()> {
        let directory = clone_file(&self.directory, &self.directory_path)?;
        let pending = c_name(name)?;
        let display = self.directory_path.join(name);
        tokio::task::spawn_blocking(move || {
            // SAFETY: callers use this only after their own successful
            // exclusive create of this exact internal component.
            if unsafe { libc::unlinkat(directory.as_raw_fd(), pending.as_ptr(), 0) } != 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::NotFound {
                    return Err(io_error(
                        "remove newly created pending checkpoint artifact",
                        &display,
                        error,
                    ));
                }
            }
            directory.sync_all().map_err(|error| {
                io_error("sync checkpoint directory after cleanup", &display, error)
            })
        })
        .await
        .map_err(|error| {
            checkpoint_error(
                ErrorCode::Internal,
                format!("created checkpoint cleanup task failed: {error}"),
            )
        })?
    }

    fn open_blocking(final_path: PathBuf) -> Result<Self> {
        let parent = final_path.parent().ok_or_else(|| {
            checkpoint_error(
                ErrorCode::InvalidArgument,
                "checkpoint artifact has no parent directory",
            )
        })?;
        let file_name = final_path.file_name().ok_or_else(|| {
            checkpoint_error(
                ErrorCode::InvalidArgument,
                "checkpoint artifact has no file name",
            )
        })?;
        let parent_c = path_c_string(parent)?;
        // SAFETY: `parent_c` is a valid C path and `open` returns a newly
        // owned descriptor on success.
        let descriptor = unsafe {
            libc::open(
                parent_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(io_error(
                "open checkpoint artifact parent",
                parent,
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: the successful `open` transferred one owned descriptor.
        let directory = unsafe { File::from_raw_fd(descriptor) };
        let metadata = directory
            .metadata()
            .map_err(|error| io_error("inspect checkpoint artifact parent", parent, error))?;
        if !metadata.is_dir() {
            return Err(checkpoint_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "checkpoint artifact parent is not a directory: {}",
                    parent.display()
                ),
            ));
        }
        Ok(Self {
            directory,
            directory_path: parent.to_path_buf(),
            final_name: os_c_string(file_name)?,
            final_path,
        })
    }
}

fn entry_exists(directory: RawFd, name: &CStr) -> Result<bool> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `metadata` points to writable storage and `name` is a valid
    // component relative to the retained directory descriptor.
    let result = unsafe {
        libc::fstatat(
            directory,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        Ok(true)
    } else {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(checkpoint_error(
                ErrorCode::Unavailable,
                format!("failed to inspect checkpoint destination entry: {error}"),
            ))
        }
    }
}

fn open_at(directory: RawFd, name: &CStr, flags: i32, mode: libc::mode_t) -> io::Result<File> {
    // SAFETY: `name` is NUL-terminated, `directory` is retained by the caller,
    // and a successful return transfers one new descriptor.
    let descriptor = unsafe { libc::openat(directory, name.as_ptr(), flags, mode) };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: the successful `openat` returned one owned descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn same_file(left: &File, right: &File) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let left = left.metadata().map_err(|error| {
        checkpoint_error(
            ErrorCode::Unavailable,
            format!("failed to inspect pending checkpoint identity: {error}"),
        )
    })?;
    let right = right.metadata().map_err(|error| {
        checkpoint_error(
            ErrorCode::Unavailable,
            format!("failed to inspect published checkpoint identity: {error}"),
        )
    })?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

fn clone_file(file: &File, display: &Path) -> Result<File> {
    file.try_clone()
        .map_err(|error| io_error("clone checkpoint directory handle", display, error))
}

fn c_name(name: &str) -> Result<CString> {
    if name.is_empty()
        || name.len() > 255
        || name.as_bytes().contains(&b'/')
        || matches!(name, "." | "..")
    {
        return Err(checkpoint_error(
            ErrorCode::Internal,
            "runtime generated an invalid pending checkpoint name",
        ));
    }
    CString::new(name).map_err(|_| {
        checkpoint_error(
            ErrorCode::Internal,
            "runtime generated a NUL-containing pending checkpoint name",
        )
    })
}

fn os_c_string(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| {
        checkpoint_error(
            ErrorCode::InvalidArgument,
            "checkpoint artifact file name contains NUL",
        )
    })
}

fn path_c_string(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        checkpoint_error(
            ErrorCode::InvalidArgument,
            format!("checkpoint path contains NUL: {}", path.display()),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom};

    use a3s_oci_sdk::CheckpointArtifactPath;
    use tempfile::tempdir;

    use super::*;
    use crate::native_checkpoint::artifact::encode_token;

    #[tokio::test]
    async fn hard_link_publication_never_replaces_an_existing_destination() {
        let temporary = tempdir().unwrap();
        let final_path = temporary.path().join("artifact.bin");
        let path = CheckpointArtifactPath::new(final_path.clone()).unwrap();
        let destination = ArtifactDestination::open(&path).await.unwrap();
        destination.ensure_absent().await.unwrap();
        let token = [3_u8; 32];
        let name = format!(".a3s-test-{}.pending", encode_token(&token));
        let mut pending = destination.create_pending(&name, token).await.unwrap();
        assert_eq!(
            destination.publish(&name).await.unwrap(),
            PublishOutcome::Published
        );
        assert_eq!(
            destination.publish(&name).await.unwrap(),
            PublishOutcome::AlreadyPublished
        );
        destination
            .remove_owned_pending(&name, token)
            .await
            .unwrap();
        assert!(final_path.exists());
        pending.seek(SeekFrom::Start(0)).unwrap();
    }

    #[tokio::test]
    async fn preexisting_destination_is_preserved() {
        let temporary = tempdir().unwrap();
        let final_path = temporary.path().join("artifact.bin");
        std::fs::write(&final_path, b"caller-owned").unwrap();
        let path = CheckpointArtifactPath::new(final_path.clone()).unwrap();
        let destination = ArtifactDestination::open(&path).await.unwrap();
        let error = destination.ensure_absent().await.unwrap_err();
        assert_eq!(error.code, ErrorCode::AlreadyExists);
        assert_eq!(std::fs::read(final_path).unwrap(), b"caller-owned");
    }
}
