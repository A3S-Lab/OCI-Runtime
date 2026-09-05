use std::fs::{self, File, Metadata, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{Error, ErrorCode, Result};

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const RUNTIME_STATE_DIRECTORY: &str = "run";

/// A same-UID macOS runtime share pinned to one directory descriptor.
///
/// libkrun accepts a path for virtio-fs, so the shim passes a stable
/// descriptor-backed path and retains the descriptor until VM entry.  The
/// directory entry and descriptor are checked again at every native trust
/// boundary to detect replacement, permission, and type changes.
#[derive(Debug)]
pub(crate) struct MacosRuntimeShare {
    path: PathBuf,
    directory: File,
    identity: DirectoryIdentity,
    state_directory: Option<File>,
    state_identity: Option<DirectoryIdentity>,
}

impl MacosRuntimeShare {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(share_error(format!(
                "macOS HVF runtime share must be absolute: {}",
                path.display()
            )));
        }

        let input_metadata = fs::symlink_metadata(path).map_err(|error| {
            share_error(format!(
                "failed to inspect writable runtime share {}: {error}",
                path.display()
            ))
        })?;
        ensure_private_directory(&input_metadata, path, "runtime share")?;

        // Canonicalization preserves the existing `/tmp` -> `/private/tmp`
        // compatibility while ensuring the retained descriptor is opened at a
        // concrete path.  The identity checks below close the race between the
        // initial inspection and this resolution.
        let canonical = path.canonicalize().map_err(|error| {
            share_error(format!(
                "failed to canonicalize writable runtime share {}: {error}",
                path.display()
            ))
        })?;
        let directory = pin_directory(&canonical, "runtime share")?;
        let descriptor_metadata = directory.metadata().map_err(|error| {
            share_error(format!(
                "failed to inspect pinned writable runtime share {}: {error}",
                canonical.display()
            ))
        })?;
        ensure_private_directory(&descriptor_metadata, &canonical, "runtime share")?;
        let identity = DirectoryIdentity::from_metadata(&descriptor_metadata);
        let canonical_metadata = fs::symlink_metadata(&canonical).map_err(|error| {
            share_error(format!(
                "failed to re-inspect writable runtime share {} after pinning: {error}",
                canonical.display()
            ))
        })?;
        ensure_private_directory(&canonical_metadata, &canonical, "runtime share")?;
        if DirectoryIdentity::from_metadata(&input_metadata) != identity
            || DirectoryIdentity::from_metadata(&canonical_metadata) != identity
        {
            return Err(share_error(format!(
                "writable runtime share changed while its descriptor was being pinned: {}",
                canonical.display()
            )));
        }

        Ok(Self {
            path: canonical,
            directory,
            identity,
            state_directory: None,
            state_identity: None,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Return the kernel identity captured when this generation share was
    /// opened.  The isolated worker receives this value across the process
    /// boundary and must prove that it reopened the same directory rather
    /// than a replacement at the same pathname.
    pub(crate) const fn identity(&self) -> (u64, u64) {
        (self.identity.device, self.identity.inode)
    }

    /// Return the kernel identity captured for the required `run/` state
    /// directory, when that child has been pinned by `require_state_directory`.
    pub(crate) fn state_identity(&self) -> Option<(u64, u64)> {
        self.state_identity
            .map(|identity| (identity.device, identity.inode))
    }

    pub(crate) fn verify_identity(&self, expected: (u64, u64)) -> Result<()> {
        if self.identity() != expected {
            return Err(share_error(format!(
                "macOS HVF runtime share identity changed across the worker handoff: expected device {} inode {}, found device {} inode {}",
                expected.0,
                expected.1,
                self.identity.device,
                self.identity.inode,
            )));
        }
        Ok(())
    }

    pub(crate) fn verify_state_identity(&self, expected: (u64, u64)) -> Result<()> {
        let actual = self.state_identity().ok_or_else(|| {
            share_error(
                "macOS HVF runtime-state identity is unavailable across the worker handoff"
                    .to_string(),
            )
        })?;
        if actual != expected {
            return Err(share_error(format!(
                "macOS HVF runtime-state identity changed across the worker handoff: expected device {} inode {}, found device {} inode {}",
                expected.0,
                expected.1,
                actual.0,
                actual.1,
            )));
        }
        Ok(())
    }

    /// Return the macOS fdesc path backed by the retained directory
    /// descriptor.
    ///
    /// Unlike Linux `/proc/self/fd`, Darwin's `/dev/fd` entries duplicate the
    /// referenced descriptor directly and are not symlink path components.
    /// Keeping the entry as the final component is therefore portable across
    /// supported macOS releases while still pinning the exact directory
    /// retained by this object.
    pub(crate) fn pinned_path(&self) -> PathBuf {
        PathBuf::from(format!("/dev/fd/{}", self.directory.as_raw_fd()))
    }

    /// Duplicate the retained directory descriptor for host-side operations.
    ///
    /// Callers should use this instead of reopening [`Self::pinned_path`]
    /// when they need descriptor-relative access; the duplicate remains bound
    /// to the same directory even if the public pathname is replaced.
    pub(crate) fn duplicate_directory(&self) -> std::io::Result<File> {
        self.directory.try_clone()
    }

    /// Pin the required `run` child used for guest-agent state.
    pub(crate) fn require_state_directory(&mut self) -> Result<()> {
        if self.state_directory.is_some() {
            return self.reverify_state_directory();
        }

        let state = self.path.join(RUNTIME_STATE_DIRECTORY);
        let path_metadata = fs::symlink_metadata(&state).map_err(|error| {
            share_error(format!(
                "failed to inspect writable runtime-state directory {}: {error}",
                state.display()
            ))
        })?;
        ensure_private_directory(&path_metadata, &state, "runtime-state directory")?;
        let canonical = state.canonicalize().map_err(|error| {
            share_error(format!(
                "failed to canonicalize writable runtime-state directory {}: {error}",
                state.display()
            ))
        })?;
        if canonical != state || canonical.parent() != Some(self.path.as_path()) {
            return Err(share_error(format!(
                "runtime-state directory must remain directly inside the exact writable share: {}",
                state.display()
            )));
        }

        let directory = pin_directory(&canonical, "runtime-state directory")?;
        let descriptor_metadata = directory.metadata().map_err(|error| {
            share_error(format!(
                "failed to inspect pinned runtime-state directory {}: {error}",
                canonical.display()
            ))
        })?;
        ensure_private_directory(&descriptor_metadata, &canonical, "runtime-state directory")?;
        let identity = DirectoryIdentity::from_metadata(&descriptor_metadata);
        if DirectoryIdentity::from_metadata(&path_metadata) != identity {
            return Err(share_error(format!(
                "runtime-state directory changed while its descriptor was being pinned: {}",
                canonical.display()
            )));
        }

        self.state_directory = Some(directory);
        self.state_identity = Some(identity);
        Ok(())
    }

    /// Recheck both the path and all retained directory descriptors before a
    /// native libkrun operation can expose the share to a guest.
    pub(crate) fn reverify(&self) -> Result<()> {
        self.verify_root_directory()?;
        if self.state_directory.is_some() {
            self.reverify_state_directory()?;
        }
        Ok(())
    }

    fn verify_root_directory(&self) -> Result<()> {
        verify_pinned_directory(
            &self.path,
            &self.directory,
            self.identity,
            "runtime share",
            "VM entry",
        )
    }

    fn reverify_state_directory(&self) -> Result<()> {
        let directory = self.state_directory.as_ref().ok_or_else(|| {
            share_error("runtime-state directory has not been pinned".to_string())
        })?;
        let identity = self.state_identity.ok_or_else(|| {
            share_error("runtime-state directory identity is unavailable".to_string())
        })?;
        let state = self.path.join(RUNTIME_STATE_DIRECTORY);
        verify_pinned_directory(
            &state,
            directory,
            identity,
            "runtime-state directory",
            "VM entry",
        )
    }
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

fn pin_directory(path: &Path, label: &str) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW_ANY)
        .open(path)
        .map_err(|error| {
            share_error(format!(
                "failed to pin macOS {label} {}: {error}",
                path.display()
            ))
        })
}

fn verify_pinned_directory(
    path: &Path,
    directory: &File,
    identity: DirectoryIdentity,
    label: &str,
    boundary: &str,
) -> Result<()> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        share_error(format!(
            "failed to re-inspect macOS {label} {}: {error}",
            path.display()
        ))
    })?;
    ensure_private_directory(&path_metadata, path, label)?;
    let descriptor_metadata = directory.metadata().map_err(|error| {
        share_error(format!(
            "failed to re-inspect pinned macOS {label} {}: {error}",
            path.display()
        ))
    })?;
    ensure_private_directory(&descriptor_metadata, path, label)?;
    if DirectoryIdentity::from_metadata(&path_metadata) != identity
        || DirectoryIdentity::from_metadata(&descriptor_metadata) != identity
    {
        return Err(share_error(format!(
            "macOS {label} identity changed before {boundary}: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_private_directory(metadata: &Metadata, path: &Path, label: &str) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(share_error(format!(
            "writable {label} must be a real directory, not a symlink: {}",
            path.display()
        )));
    }

    // SAFETY: geteuid has no arguments and cannot fail.
    let effective_user_id = unsafe { libc::geteuid() };
    if metadata.uid() != effective_user_id {
        return Err(share_error(format!(
            "macOS {label} {} is owned by UID {}, expected {effective_user_id}",
            path.display(),
            metadata.uid()
        )));
    }
    if metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE {
        return Err(share_error(format!(
            "macOS {label} {} has mode {:03o}, expected {PRIVATE_DIRECTORY_MODE:03o}",
            path.display(),
            metadata.mode() & 0o777
        )));
    }
    Ok(())
}

fn share_error(message: String) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message).for_operation("verify-macos-runtime-share")
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::fs;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use super::MacosRuntimeShare;

    fn private_directory(path: &std::path::Path) {
        fs::create_dir(path).expect("create private directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("protect private directory");
    }

    fn runtime_share(root: &std::path::Path) -> std::path::PathBuf {
        let share = root.join("generation");
        private_directory(&share);
        share
    }

    #[test]
    fn pins_private_generation_and_exposes_descriptor_path() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let share = runtime_share(temporary.path());
        let pinned = MacosRuntimeShare::open(&share).expect("pin runtime share");

        assert_eq!(pinned.path(), share.canonicalize().unwrap());
        assert!(pinned.pinned_path().starts_with("/dev/fd/"));
        assert!(!pinned.pinned_path().to_string_lossy().ends_with("/."));
        let path = CString::new(pinned.pinned_path().as_os_str().as_bytes())
            .expect("descriptor path must not contain NUL");
        // `/dev/fd/<n>` is a kernel descriptor namespace on macOS rather than
        // a user-controlled filesystem link. The fdesc implementation opens
        // the retained directory directly; appending `/.` is not supported
        // consistently by current macOS runners. libkrun likewise opens the
        // supplied root with ordinary read-only/no-follow flags, so do not add
        // `O_DIRECTORY` here (Darwin can report `ENOTDIR` for that fdesc form).
        // SAFETY: `path` is a live NUL-terminated path. The descriptor is
        // checked before ownership is transferred to `File`.
        let descriptor = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(
            descriptor >= 0,
            "open descriptor-backed runtime share: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: `descriptor` was returned as an owned descriptor above.
        let descriptor = unsafe { fs::File::from_raw_fd(descriptor) };
        assert!(
            descriptor
                .metadata()
                .expect("inspect descriptor-backed runtime share")
                .is_dir(),
            "descriptor-backed path must resolve to the pinned directory"
        );
        pinned.reverify().expect("reverify runtime share");
    }

    #[test]
    fn rejects_relative_public_and_symbolic_generation_paths() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let public = temporary.path().join("public");
        fs::create_dir(&public).expect("create public directory");
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755))
            .expect("make directory public");
        assert!(MacosRuntimeShare::open(&public).is_err());

        let share = runtime_share(temporary.path());
        let alias = temporary.path().join("alias");
        symlink(&share, &alias).expect("create share symlink");
        assert!(MacosRuntimeShare::open(&alias).is_err());
        assert!(MacosRuntimeShare::open(std::path::Path::new("relative-share")).is_err());
    }

    #[test]
    fn detects_generation_replacement_before_vm_entry() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let share = runtime_share(temporary.path());
        let pinned = MacosRuntimeShare::open(&share).expect("pin runtime share");
        let displaced = temporary.path().join("displaced");
        fs::rename(&share, &displaced).expect("displace pinned share");
        let _replacement = runtime_share(temporary.path());

        assert!(pinned.reverify().is_err());
    }

    #[test]
    fn rejects_a_different_worker_handoff_identity() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let share = runtime_share(temporary.path());
        let original = MacosRuntimeShare::open(&share).expect("pin original runtime share");
        let identity = original.identity();

        original
            .verify_identity(identity)
            .expect("the captured identity must verify");
        let displaced = temporary.path().join("displaced");
        std::fs::rename(&share, &displaced).expect("displace original runtime share");
        let _replacement = runtime_share(temporary.path());
        let reopened = MacosRuntimeShare::open(&share).expect("open replacement runtime share");
        assert!(reopened.verify_identity(identity).is_err());
    }

    #[test]
    fn rejects_a_different_worker_handoff_state_identity() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let share = runtime_share(temporary.path());
        let state = share.join("run");
        private_directory(&state);
        let mut original = MacosRuntimeShare::open(&share).expect("pin original runtime share");
        original
            .require_state_directory()
            .expect("pin original runtime state");
        let identity = original
            .state_identity()
            .expect("state identity must be available");
        original
            .verify_state_identity(identity)
            .expect("the captured state identity must verify");

        let displaced = share.join("run.displaced");
        std::fs::rename(&state, &displaced).expect("displace original runtime state");
        private_directory(&state);
        let mut reopened = MacosRuntimeShare::open(&share).expect("open replacement runtime share");
        reopened
            .require_state_directory()
            .expect("pin replacement runtime state");
        assert!(reopened.verify_state_identity(identity).is_err());
    }

    #[test]
    fn detects_permission_drift_before_vm_entry() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let share = runtime_share(temporary.path());
        let pinned = MacosRuntimeShare::open(&share).expect("pin runtime share");
        fs::set_permissions(&share, fs::Permissions::from_mode(0o755))
            .expect("make runtime share public");

        assert!(pinned.reverify().is_err());
    }

    #[test]
    fn pins_and_rechecks_runtime_state_directory() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let share = runtime_share(temporary.path());
        let state = share.join("run");
        private_directory(&state);
        let mut pinned = MacosRuntimeShare::open(&share).expect("pin runtime share");
        pinned.require_state_directory().expect("pin runtime state");
        pinned.reverify().expect("reverify runtime state");

        let displaced = share.join("run.displaced");
        fs::rename(&state, &displaced).expect("displace runtime state");
        private_directory(&state);
        assert!(pinned.reverify().is_err());
    }
}
