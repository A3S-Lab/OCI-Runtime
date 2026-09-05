use std::fs::{self, File};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{Error, ErrorCode, Result};

/// An executor-owned executable retained across every child-process handoff.
///
/// A pathname is used only to locate the image.  Once opened, the exact inode
/// is retained and children are started through its procfs descriptor path.
/// This closes the validate-then-spawn replacement window for the Linux agent
/// executable without exposing a caller-controlled descriptor to the child
/// contract.
#[derive(Debug)]
pub(super) struct PinnedExecutable {
    canonical_path: PathBuf,
    command_path: PathBuf,
    _file: File,
}

impl PinnedExecutable {
    /// Open and bind one regular executable.
    pub(super) async fn open(path: &Path) -> Result<Self> {
        let requested_metadata = tokio::fs::metadata(path).await.map_err(|error| {
            executable_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to inspect Linux executor executable {}: {error}",
                    path.display()
                ),
            )
        })?;
        ensure_regular_file(&requested_metadata, path)?;

        let canonical_path = tokio::fs::canonicalize(path).await.map_err(|error| {
            executable_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to resolve Linux executor executable {}: {error}",
                    path.display()
                ),
            )
        })?;
        let canonical_metadata =
            tokio::fs::symlink_metadata(&canonical_path)
                .await
                .map_err(|error| {
                    executable_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "failed to inspect resolved Linux executor executable {}: {error}",
                            canonical_path.display()
                        ),
                    )
                })?;
        ensure_regular_file(&canonical_metadata, &canonical_path)?;

        let mut options = tokio::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let file = options
            .open(&canonical_path)
            .await
            .map_err(|error| {
                executable_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "failed to pin Linux executor executable {}: {error}",
                        canonical_path.display()
                    ),
                )
            })?
            .into_std()
            .await;
        let pinned_file = duplicate_private_descriptor(&file, &canonical_path)?;
        let file_metadata = pinned_file.metadata().map_err(|error| {
            executable_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to inspect pinned Linux executor executable {}: {error}",
                    canonical_path.display()
                ),
            )
        })?;
        ensure_regular_file(&file_metadata, &canonical_path)?;

        let requested_identity = FileIdentity::from_metadata(&requested_metadata);
        let canonical_identity = FileIdentity::from_metadata(&canonical_metadata);
        let identity = FileIdentity::from_metadata(&file_metadata);
        if requested_identity != identity || canonical_identity != identity {
            return Err(executable_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "Linux executor executable changed while it was being pinned: {}",
                    canonical_path.display()
                ),
            ));
        }

        let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", pinned_file.as_raw_fd()));
        Ok(Self {
            canonical_path,
            command_path: descriptor_path,
            _file: pinned_file,
        })
    }

    /// Descriptor-backed path for `Command::new`.
    pub(super) fn command_path(&self) -> &Path {
        &self.command_path
    }

    /// Duplicate the pinned descriptor for a detached child-process task.
    ///
    /// The executor normally owns the descriptor for its whole lifetime.  A
    /// recorded `exec` operation can outlive the request future, however, so
    /// its detached task must retain an independent descriptor until the
    /// child has been spawned and the result has been journalled.
    pub(super) fn duplicate_command_path(&self) -> Result<(PathBuf, File)> {
        let file = duplicate_private_descriptor(&self._file, &self.canonical_path)?;
        let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        Ok((descriptor_path, file))
    }

    /// Stable pathname used when an external tool must receive an argument.
    ///
    /// The descriptor namespace is private to this process.  External tools
    /// such as CRIU therefore receive the canonical spelling and own their
    /// subsequent verification boundary.
    pub(super) fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }
}

fn duplicate_private_descriptor(file: &File, path: &Path) -> Result<File> {
    // Keep the retained descriptor out of stdin/stdout/stderr. Command setup
    // is allowed to replace those descriptors before exec; a descriptor in
    // the private range remains stable until the procfs path is resolved.
    let descriptor = unsafe {
        libc::fcntl(
            file.as_raw_fd(),
            libc::F_DUPFD_CLOEXEC,
            super::fd_boundary::FIRST_PRIVATE_DESCRIPTOR as i32,
        )
    };
    if descriptor < 0 {
        return Err(executable_error(
            ErrorCode::Internal,
            format!(
                "failed to retain a private descriptor for Linux executor executable {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: F_DUPFD_CLOEXEC returned a fresh owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn ensure_regular_file(metadata: &fs::Metadata, path: &Path) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(executable_error(
            ErrorCode::FailedPrecondition,
            format!(
                "Linux executor executable must be a regular file: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

fn executable_error(code: ErrorCode, message: String) -> Error {
    Error::new(code, message).for_operation("pin-linux-executor-executable")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::symlink;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    use super::PinnedExecutable;

    #[tokio::test]
    async fn pins_and_executes_the_exact_current_image() {
        let executable = std::env::current_exe().expect("resolve test executable");
        let pinned = PinnedExecutable::open(&executable)
            .await
            .expect("pin test executable");
        assert!(pinned._file.as_raw_fd() >= 3);
        assert!(pinned.command_path().starts_with("/proc/self/fd/"));
        let mut command = Command::new(pinned.command_path());
        command
            .arg("--list")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // Exercise the same private-descriptor close-on-exec boundary used by
        // every executor child before the descriptor path is resolved.
        unsafe {
            command.pre_exec(super::super::fd_boundary::mark_private_descriptors_close_on_exec);
        }
        let status = command.status().expect("execute descriptor-pinned image");
        assert!(status.success());
    }

    #[tokio::test]
    async fn invocation_symlinks_are_bound_to_their_canonical_target() {
        let temporary = tempfile::tempdir().expect("create executable fixture");
        let executable = std::env::current_exe().expect("resolve test executable");
        let alias = temporary.path().join("agent-alias");
        symlink(&executable, &alias).expect("create invocation alias");

        let pinned = PinnedExecutable::open(&alias)
            .await
            .expect("pin executable behind invocation alias");
        assert_eq!(
            pinned.canonical_path(),
            executable.canonicalize().expect("canonicalize executable")
        );
    }

    #[tokio::test]
    async fn retained_descriptor_survives_path_replacement() {
        let temporary = tempfile::tempdir().expect("create replacement fixture");
        let path = temporary.path().join("agent");
        let original = b"original executable bytes";
        fs::write(&path, original).expect("write original fixture");
        let pinned = PinnedExecutable::open(&path)
            .await
            .expect("pin regular fixture");

        let replacement = path.with_file_name("agent-replacement");
        fs::rename(&path, &replacement).expect("move original fixture");
        fs::write(&path, b"replacement executable bytes").expect("write replacement fixture");

        assert_eq!(
            fs::read(pinned.command_path()).expect("read pinned descriptor"),
            original
        );
        // The retained descriptor remains usable even after its directory entry
        // is replaced because child execution uses the retained descriptor,
        // not the caller-controlled pathname.
    }
}
