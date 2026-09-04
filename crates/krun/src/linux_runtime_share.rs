use std::fs::{self, File, Metadata, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{Error, ErrorCode, Result};

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const RUNTIME_STATE_DIRECTORY: &str = "run";

/// Descriptor-pinned writable directory exported to one exact KVM generation.
#[derive(Debug)]
pub(crate) struct LinuxRuntimeShare {
    path: PathBuf,
    directory: File,
    identity: DirectoryIdentity,
    state_directory: File,
    state_identity: DirectoryIdentity,
}

impl LinuxRuntimeShare {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(share_error(format!(
                "Linux KVM runtime share must be absolute: {}",
                path.display()
            )));
        }
        let path_metadata = fs::symlink_metadata(path).map_err(|error| {
            share_error(format!(
                "failed to inspect Linux KVM runtime share {}: {error}",
                path.display()
            ))
        })?;
        ensure_private_directory(&path_metadata, path, "runtime share")?;
        let canonical = path.canonicalize().map_err(|error| {
            share_error(format!(
                "failed to canonicalize Linux KVM runtime share {}: {error}",
                path.display()
            ))
        })?;
        if canonical != path {
            return Err(share_error(format!(
                "Linux KVM runtime share must not traverse aliases or symbolic links: {}",
                path.display()
            )));
        }

        let directory = pin_directory(&canonical, "runtime share")?;
        let descriptor_metadata = directory.metadata().map_err(|error| {
            share_error(format!(
                "failed to inspect pinned Linux KVM runtime share {}: {error}",
                canonical.display()
            ))
        })?;
        ensure_private_directory(&descriptor_metadata, &canonical, "runtime share")?;
        let identity = DirectoryIdentity::from_metadata(&descriptor_metadata);
        if DirectoryIdentity::from_metadata(&path_metadata) != identity {
            return Err(share_error(format!(
                "Linux KVM runtime share changed while it was being pinned: {}",
                canonical.display()
            )));
        }

        let state = canonical.join(RUNTIME_STATE_DIRECTORY);
        let state_metadata = fs::symlink_metadata(&state).map_err(|error| {
            share_error(format!(
                "failed to inspect Linux KVM runtime-state directory {}: {error}",
                state.display()
            ))
        })?;
        ensure_private_directory(&state_metadata, &state, "runtime-state directory")?;
        let state_canonical = state.canonicalize().map_err(|error| {
            share_error(format!(
                "failed to canonicalize Linux KVM runtime-state directory {}: {error}",
                state.display()
            ))
        })?;
        if state_canonical != state || state_canonical.parent() != Some(canonical.as_path()) {
            return Err(share_error(format!(
                "Linux KVM runtime-state directory must remain directly inside the exact share: {}",
                state.display()
            )));
        }

        let state_directory = pin_directory(&state_canonical, "runtime-state directory")?;
        let state_descriptor_metadata = state_directory.metadata().map_err(|error| {
            share_error(format!(
                "failed to inspect pinned Linux KVM runtime-state directory {}: {error}",
                state_canonical.display()
            ))
        })?;
        ensure_private_directory(
            &state_descriptor_metadata,
            &state_canonical,
            "runtime-state directory",
        )?;
        let state_identity = DirectoryIdentity::from_metadata(&state_descriptor_metadata);
        let state_path_metadata = fs::symlink_metadata(&state_canonical).map_err(|error| {
            share_error(format!(
                "failed to re-inspect Linux KVM runtime-state directory {} after pinning: {error}",
                state_canonical.display()
            ))
        })?;
        ensure_private_directory(
            &state_path_metadata,
            &state_canonical,
            "runtime-state directory",
        )?;
        if DirectoryIdentity::from_metadata(&state_metadata) != state_identity
            || DirectoryIdentity::from_metadata(&state_path_metadata) != state_identity
        {
            return Err(share_error(format!(
                "Linux KVM runtime-state directory changed while it was being pinned: {}",
                state_canonical.display()
            )));
        }

        Ok(Self {
            path: canonical,
            directory,
            identity,
            state_directory,
            state_identity,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Stable procfs path backed by the retained directory descriptor.
    ///
    /// The final `/.` is required because libkrun opens the configured
    /// virtio-fs root with `O_PATH | O_NOFOLLOW`. Making the descriptor link
    /// an intermediate component preserves descriptor pinning while ensuring
    /// libkrun opens the referenced directory rather than the procfs symlink.
    pub(crate) fn pinned_path(&self) -> PathBuf {
        use std::os::fd::AsRawFd;

        PathBuf::from(format!("/proc/self/fd/{}/.", self.directory.as_raw_fd()))
    }

    pub(crate) fn reverify(&self) -> Result<()> {
        let path_metadata = fs::symlink_metadata(&self.path).map_err(|error| {
            share_error(format!(
                "failed to re-inspect Linux KVM runtime share {}: {error}",
                self.path.display()
            ))
        })?;
        ensure_private_directory(&path_metadata, &self.path, "runtime share")?;
        let descriptor_metadata = self.directory.metadata().map_err(|error| {
            share_error(format!(
                "failed to re-inspect pinned Linux KVM runtime share {}: {error}",
                self.path.display()
            ))
        })?;
        ensure_private_directory(&descriptor_metadata, &self.path, "runtime share")?;
        if DirectoryIdentity::from_metadata(&path_metadata) != self.identity
            || DirectoryIdentity::from_metadata(&descriptor_metadata) != self.identity
        {
            return Err(share_error(format!(
                "Linux KVM runtime-share identity changed before VM entry: {}",
                self.path.display()
            )));
        }

        let state = self.path.join(RUNTIME_STATE_DIRECTORY);
        let state_metadata = fs::symlink_metadata(&state).map_err(|error| {
            share_error(format!(
                "failed to re-inspect Linux KVM runtime-state directory {}: {error}",
                state.display()
            ))
        })?;
        ensure_private_directory(&state_metadata, &state, "runtime-state directory")?;
        let state_descriptor_metadata = self.state_directory.metadata().map_err(|error| {
            share_error(format!(
                "failed to re-inspect pinned Linux KVM runtime-state directory {}: {error}",
                state.display()
            ))
        })?;
        ensure_private_directory(
            &state_descriptor_metadata,
            &state,
            "runtime-state directory",
        )?;
        if DirectoryIdentity::from_metadata(&state_metadata) != self.state_identity
            || DirectoryIdentity::from_metadata(&state_descriptor_metadata) != self.state_identity
        {
            return Err(share_error(format!(
                "Linux KVM runtime-state identity changed before VM entry: {}",
                state.display()
            )));
        }
        Ok(())
    }
}

fn pin_directory(path: &Path, label: &str) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            share_error(format!(
                "failed to pin Linux KVM {label} {}: {error}",
                path.display()
            ))
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

impl DirectoryIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

fn ensure_private_directory(metadata: &Metadata, path: &Path, label: &str) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(share_error(format!(
            "Linux KVM {label} must be a real directory, not a symbolic link: {}",
            path.display()
        )));
    }
    // SAFETY: geteuid has no arguments and cannot fail.
    let effective_user_id = unsafe { libc::geteuid() };
    if metadata.uid() != effective_user_id {
        return Err(share_error(format!(
            "Linux KVM {label} {} is owned by UID {}, expected {effective_user_id}",
            path.display(),
            metadata.uid()
        )));
    }
    if metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE {
        return Err(share_error(format!(
            "Linux KVM {label} {} has mode {:03o}, expected {PRIVATE_DIRECTORY_MODE:03o}",
            path.display(),
            metadata.mode() & 0o777
        )));
    }
    Ok(())
}

fn share_error(message: String) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message)
        .for_operation("verify-linux-kvm-runtime-share")
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::fs;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use super::LinuxRuntimeShare;

    fn private_directory(path: &std::path::Path) {
        fs::create_dir(path).expect("create private directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("protect private directory");
    }

    fn runtime_share(root: &std::path::Path) -> std::path::PathBuf {
        let share = root.join("generation");
        private_directory(&share);
        private_directory(&share.join("run"));
        share
    }

    #[test]
    fn pins_one_private_generation_and_state_directory() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let share = runtime_share(temporary.path());
        let pinned = LinuxRuntimeShare::open(&share).expect("pin runtime share");

        assert_eq!(pinned.path(), share);
        assert!(pinned.pinned_path().starts_with("/proc/self/fd/"));
        assert!(pinned.pinned_path().to_string_lossy().ends_with("/."));
        let path = CString::new(pinned.pinned_path().as_os_str().as_bytes())
            .expect("descriptor path must not contain NUL");
        // SAFETY: `path` is a live NUL-terminated string and the returned
        // descriptor is checked before ownership is transferred to `File`.
        let descriptor = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                path.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        assert!(descriptor >= 0, "open pinned virtio-fs root");
        // SAFETY: `descriptor` was returned as an owned descriptor above.
        let descriptor = unsafe { fs::File::from_raw_fd(descriptor) };
        assert!(
            descriptor
                .metadata()
                .expect("inspect pinned virtio-fs root")
                .is_dir(),
            "libkrun-compatible pinned path must resolve to the directory"
        );
        pinned.reverify().expect("reverify runtime share");
    }

    #[test]
    fn rejects_public_or_symbolic_generation_paths() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let public = temporary.path().join("public");
        fs::create_dir(&public).expect("create public directory");
        private_directory(&public.join("run"));
        assert!(LinuxRuntimeShare::open(&public).is_err());

        let share = runtime_share(temporary.path());
        let alias = temporary.path().join("alias");
        symlink(&share, &alias).expect("create share symlink");
        assert!(LinuxRuntimeShare::open(&alias).is_err());
    }

    #[test]
    fn detects_path_replacement_before_vm_entry() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let share = runtime_share(temporary.path());
        let pinned = LinuxRuntimeShare::open(&share).expect("pin runtime share");
        let displaced = temporary.path().join("displaced");
        fs::rename(&share, &displaced).expect("displace pinned share");
        let _replacement = runtime_share(temporary.path());

        assert!(pinned.reverify().is_err());
    }

    #[test]
    fn detects_runtime_state_replacement_before_vm_entry() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let share = runtime_share(temporary.path());
        let pinned = LinuxRuntimeShare::open(&share).expect("pin runtime share");
        let state = share.join("run");
        let displaced = share.join("run.displaced");
        fs::rename(&state, &displaced).expect("displace pinned runtime state");
        private_directory(&state);

        assert!(pinned.reverify().is_err());
    }
}
