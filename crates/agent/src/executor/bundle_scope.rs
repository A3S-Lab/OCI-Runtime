use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use a3s_oci_agent_protocol::GuestPath;
use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::executor_error;

pub(super) const UTILITY_VM_BUNDLE_FD: RawFd = 8;
pub(super) const UTILITY_VM_ROOTFS_FD: RawFd = 9;
const PROTECTED_DESCRIPTOR_MINIMUM: RawFd = 10;

/// Filesystem authority for bundle directories accepted by one executor.
#[derive(Debug)]
pub(super) enum BundleDirectoryScope {
    /// Native execution accepts bundles prepared outside the runtime state root.
    Unrestricted,
    /// A utility VM accepts only descriptor-resolved directories below its
    /// exact mounted share and outside the Agent's reserved state directory.
    UtilityVm {
        share_root: PathBuf,
        state_name: PathBuf,
        share: File,
    },
}

/// One exact utility-VM bundle retained independently of its directory entry.
#[derive(Debug)]
pub(super) struct PinnedBundleDirectory {
    descriptor: File,
}

/// One exact utility-VM rootfs prepared for the internal init process.
#[derive(Debug)]
pub(super) struct PinnedRootfsDirectory {
    descriptor: File,
}

impl BundleDirectoryScope {
    pub(super) const fn unrestricted() -> Self {
        Self::Unrestricted
    }

    /// Open the exact utility-VM share and its reserved runtime-state child.
    pub(super) async fn utility_vm(
        runtime_state_root: impl AsRef<Path>,
    ) -> Result<(PathBuf, Self)> {
        let state_root = runtime_state_root.as_ref();
        validate_absolute_normal_path(state_root, "utility-VM runtime-state root")?;
        let share_root = state_root.parent().ok_or_else(|| {
            scope_error(
                ErrorCode::InvalidArgument,
                format!(
                    "utility-VM runtime-state root has no mounted-share parent: {}",
                    state_root.display()
                ),
            )
        })?;
        let state_name = state_root.file_name().map(PathBuf::from).ok_or_else(|| {
            scope_error(
                ErrorCode::InvalidArgument,
                format!(
                    "utility-VM runtime-state root has no final component: {}",
                    state_root.display()
                ),
            )
        })?;
        let share = open_absolute_directory(share_root, "utility-VM runtime share")?;
        let state = openat2_beneath(
            share.as_raw_fd(),
            &state_name,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            "utility-VM runtime-state root",
            "validate-utility-vm-bundle-scope",
        )?
        .ok_or_else(|| {
            scope_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "utility-VM runtime-state root does not exist: {}",
                    state_root.display()
                ),
            )
        })?;
        drop(state);

        Ok((
            state_root.to_path_buf(),
            Self::UtilityVm {
                share_root: share_root.to_path_buf(),
                state_name,
                share,
            },
        ))
    }

    /// Pin a Guest-supplied bundle below the exact generation share.
    pub(super) fn pin(&self, guest_directory: &GuestPath) -> Result<Option<PinnedBundleDirectory>> {
        let Self::UtilityVm {
            share_root,
            state_name,
            share,
        } = self
        else {
            return Ok(None);
        };
        let supplied = guest_directory.to_path_buf();
        let relative = supplied.strip_prefix(share_root).map_err(|_| {
            scope_error(
                ErrorCode::PermissionDenied,
                format!(
                    "utility-VM guest bundle must be a strict descendant of the exact runtime share {}: {}",
                    share_root.display(),
                    supplied.display()
                ),
            )
        })?;
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(scope_error(
                ErrorCode::PermissionDenied,
                format!(
                    "utility-VM guest bundle must use a normalized path below the exact runtime share {}: {}",
                    share_root.display(),
                    supplied.display()
                ),
            ));
        }
        if relative == state_name || relative.starts_with(state_name) {
            return Err(scope_error(
                ErrorCode::PermissionDenied,
                format!(
                    "utility-VM guest bundle must not overlap Agent runtime state {}: {}",
                    share_root.join(state_name).display(),
                    supplied.display()
                ),
            ));
        }
        let bundle = openat2_beneath(
            share.as_raw_fd(),
            relative,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            "utility-VM guest bundle directory",
            "validate-utility-vm-bundle-scope",
        )?
        .ok_or_else(|| {
            scope_error(
                ErrorCode::InvalidArgument,
                format!(
                    "utility-VM guest bundle directory does not exist: {}",
                    supplied.display()
                ),
            )
        })?;
        Ok(Some(PinnedBundleDirectory {
            descriptor: protect_descriptor(
                &bundle,
                "utility-VM bundle",
                "validate-utility-vm-bundle-scope",
            )?,
        }))
    }
}

impl PinnedBundleDirectory {
    pub(super) fn install_in_child(&self) -> io::Result<()> {
        // SAFETY: the protected source descriptor is live and cannot collide
        // with the fixed destination. dup2 clears close-on-exec on success.
        if unsafe { libc::dup2(self.descriptor.as_raw_fd(), UTILITY_VM_BUNDLE_FD) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn prepare_rootfs_for_child(&self, rootfs: &File) -> Result<PinnedRootfsDirectory> {
        Ok(PinnedRootfsDirectory {
            descriptor: protect_descriptor(rootfs, "container rootfs", "run-container-init")?,
        })
    }

    pub(super) fn take_from_child() -> Result<Self> {
        // SAFETY: F_GETFD only inspects the live fixed descriptor.
        let flags = unsafe { libc::fcntl(UTILITY_VM_BUNDLE_FD, libc::F_GETFD) };
        if flags < 0 {
            return Err(path_error(
                ErrorCode::PermissionDenied,
                "run-container-init",
                format!(
                    "container-init did not inherit its fixed utility-VM bundle descriptor: {}",
                    io::Error::last_os_error()
                ),
            ));
        }
        // SAFETY: F_GETFD proved that the authenticated parent installed a
        // live descriptor. Ownership transfers to this internal init once.
        let descriptor = unsafe { File::from_raw_fd(UTILITY_VM_BUNDLE_FD) };
        // SAFETY: F_SETFD updates descriptor flags without touching memory.
        if unsafe {
            libc::fcntl(
                descriptor.as_raw_fd(),
                libc::F_SETFD,
                flags | libc::FD_CLOEXEC,
            )
        } < 0
        {
            return Err(path_error(
                ErrorCode::Internal,
                "run-container-init",
                format!(
                    "failed to protect the inherited utility-VM bundle descriptor: {}",
                    io::Error::last_os_error()
                ),
            ));
        }
        ensure_directory_descriptor(
            &descriptor,
            "inherited utility-VM bundle descriptor",
            "run-container-init",
        )?;
        Ok(Self { descriptor })
    }

    pub(super) fn open_relative(
        &self,
        relative: &Path,
        flags: libc::c_int,
        require_directory: bool,
        description: &str,
        operation: &'static str,
    ) -> Result<Option<File>> {
        validate_relative_normal_path(relative, description, operation)?;
        let flags = flags | libc::O_CLOEXEC;
        let flags = if require_directory {
            flags | libc::O_DIRECTORY
        } else {
            flags
        };
        let descriptor = openat2_beneath(
            self.descriptor.as_raw_fd(),
            relative,
            flags,
            description,
            operation,
        )?;
        if let Some(descriptor) = descriptor.as_ref() {
            if require_directory {
                ensure_directory_descriptor(descriptor, description, operation)?;
            }
        }
        Ok(descriptor)
    }

    /// Open the configured rootfs below this bundle, or duplicate the pinned
    /// bundle itself for the OCI-standard relative `root.path` value `.`.
    pub(super) fn open_rootfs(
        &self,
        relative: &Path,
        operation: &'static str,
    ) -> Result<Option<File>> {
        if relative.as_os_str().is_empty() {
            return protect_descriptor(&self.descriptor, "container rootfs", operation).map(Some);
        }
        self.open_relative(relative, libc::O_PATH, true, "container rootfs", operation)
    }

    #[cfg(test)]
    fn descriptor(&self) -> RawFd {
        self.descriptor.as_raw_fd()
    }
}

impl PinnedRootfsDirectory {
    pub(super) fn install_in_child(&self) -> io::Result<()> {
        // SAFETY: the source is protected above every fixed target and remains
        // live for this pre-exec callback.
        if unsafe { libc::dup2(self.descriptor.as_raw_fd(), UTILITY_VM_ROOTFS_FD) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn take_from_child() -> Result<File> {
        take_fixed_directory_descriptor(
            UTILITY_VM_ROOTFS_FD,
            "utility-VM rootfs",
            "run-container-init",
        )
    }
}

fn open_absolute_directory(path: &Path, description: &str) -> Result<File> {
    let path_c = path_cstring(path, description, "validate-utility-vm-bundle-scope")?;
    let mut how = std::mem::MaybeUninit::<libc::open_how>::zeroed();
    // SAFETY: zero is valid for every open_how field.
    let how = unsafe { how.assume_init_mut() };
    how.flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_SYMLINKS;
    // SAFETY: the path and initialized ABI structure remain live for the call.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path_c.as_ptr(),
            how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        return Err(scope_error(
            path_error_code(&error, true),
            format!("failed to open {description} {}: {error}", path.display()),
        ));
    }
    owned_descriptor(descriptor, description, "validate-utility-vm-bundle-scope")
}

fn openat2_beneath(
    directory: RawFd,
    path: &Path,
    flags: libc::c_int,
    description: &str,
    operation: &'static str,
) -> Result<Option<File>> {
    let path_c = path_cstring(path, description, operation)?;
    let mut how = std::mem::MaybeUninit::<libc::open_how>::zeroed();
    // SAFETY: zero is valid for every open_how field.
    let how = unsafe { how.assume_init_mut() };
    how.flags = flags as u64;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_SYMLINKS;
    // SAFETY: directory is live and both initialized inputs remain live.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory,
            path_c.as_ptr(),
            how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(path_error(
            path_error_code(&error, flags & libc::O_DIRECTORY != 0),
            operation,
            format!(
                "failed to open descriptor-confined {description} {}: {error}",
                path.display()
            ),
        ));
    }
    owned_descriptor(descriptor, description, operation).map(Some)
}

fn owned_descriptor(
    descriptor: libc::c_long,
    description: &str,
    operation: &'static str,
) -> Result<File> {
    let descriptor = RawFd::try_from(descriptor).map_err(|error| {
        path_error(
            ErrorCode::Internal,
            operation,
            format!("openat2 returned an invalid {description} descriptor: {error}"),
        )
    })?;
    // SAFETY: openat2 returned this fresh descriptor exactly once.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn protect_descriptor(
    descriptor: &File,
    description: &str,
    operation: &'static str,
) -> Result<File> {
    // SAFETY: descriptor is live. F_DUPFD_CLOEXEC creates one new descriptor
    // above every fixed child target used by the executor.
    let protected = unsafe {
        libc::fcntl(
            descriptor.as_raw_fd(),
            libc::F_DUPFD_CLOEXEC,
            PROTECTED_DESCRIPTOR_MINIMUM,
        )
    };
    if protected < 0 {
        return Err(path_error(
            ErrorCode::Internal,
            operation,
            format!(
                "failed to protect the {description} descriptor: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: F_DUPFD_CLOEXEC returned one fresh descriptor.
    Ok(unsafe { File::from_raw_fd(protected) })
}

fn take_fixed_directory_descriptor(
    fixed: RawFd,
    description: &str,
    operation: &'static str,
) -> Result<File> {
    // SAFETY: F_GETFD only inspects one numeric descriptor slot.
    let flags = unsafe { libc::fcntl(fixed, libc::F_GETFD) };
    if flags < 0 {
        return Err(path_error(
            ErrorCode::PermissionDenied,
            operation,
            format!(
                "container-init did not inherit its fixed {description} descriptor: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: F_GETFD proved this live descriptor is owned by internal init.
    let descriptor = unsafe { File::from_raw_fd(fixed) };
    // SAFETY: F_SETFD only updates the live descriptor flags.
    if unsafe { libc::fcntl(fixed, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(path_error(
            ErrorCode::Internal,
            operation,
            format!(
                "failed to protect the inherited {description} descriptor: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    ensure_directory_descriptor(&descriptor, description, operation)?;
    Ok(descriptor)
}

fn ensure_directory_descriptor(
    descriptor: &File,
    description: &str,
    operation: &'static str,
) -> Result<()> {
    let metadata = descriptor.metadata().map_err(|error| {
        path_error(
            ErrorCode::FailedPrecondition,
            operation,
            format!("failed to inspect {description}: {error}"),
        )
    })?;
    if metadata.is_dir() {
        Ok(())
    } else {
        Err(path_error(
            ErrorCode::PermissionDenied,
            operation,
            format!("{description} is not a directory"),
        ))
    }
}

fn validate_absolute_normal_path(path: &Path, description: &str) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(scope_error(
            ErrorCode::InvalidArgument,
            format!(
                "{description} must be a normalized absolute path: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn validate_relative_normal_path(
    path: &Path,
    description: &str,
    operation: &'static str,
) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(path_error(
            ErrorCode::PermissionDenied,
            operation,
            format!(
                "{description} must be a normalized relative path: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn path_cstring(path: &Path, description: &str, operation: &'static str) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|error| {
        path_error(
            ErrorCode::InvalidArgument,
            operation,
            format!("{description} contains a NUL byte: {error}"),
        )
    })
}

fn path_error_code(error: &io::Error, require_directory: bool) -> ErrorCode {
    match error.raw_os_error() {
        Some(libc::EXDEV) | Some(libc::ELOOP) => ErrorCode::PermissionDenied,
        Some(libc::ENOTDIR) if require_directory => ErrorCode::PermissionDenied,
        Some(libc::EACCES) | Some(libc::EPERM) => ErrorCode::PermissionDenied,
        _ => ErrorCode::FailedPrecondition,
    }
}

fn path_error(code: ErrorCode, operation: &'static str, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation(operation)
}

fn scope_error(code: ErrorCode, message: impl Into<String>) -> Error {
    executor_error(code, message).for_operation("validate-utility-vm-bundle-scope")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::fd::AsRawFd;

    use a3s_oci_agent_protocol::GuestPath;
    use a3s_oci_sdk::ErrorCode;
    use tempfile::tempdir;

    use super::BundleDirectoryScope;

    #[tokio::test]
    async fn utility_vm_scope_accepts_only_real_bundle_descendants_outside_state() {
        let temporary = tempdir().expect("temporary share");
        let share = temporary.path().join("share");
        let state = share.join("run");
        let bundle = share.join("bundles/workload");
        fs::create_dir_all(&state).expect("runtime state");
        fs::create_dir_all(&bundle).expect("bundle");
        let (_, scope) = BundleDirectoryScope::utility_vm(&state)
            .await
            .expect("utility VM scope");

        let pinned = scope
            .pin(&GuestPath::new(bundle.to_string_lossy()).expect("guest bundle"))
            .expect("real bundle descendant")
            .expect("utility VM pin");
        assert!(pinned.descriptor() >= 10);

        for rejected in [&share, &state] {
            let error = scope
                .pin(&GuestPath::new(rejected.to_string_lossy()).expect("rejected guest path"))
                .expect_err("reserved path must fail closed");
            assert_eq!(error.code, ErrorCode::PermissionDenied);
        }
    }

    #[tokio::test]
    async fn pinned_bundle_can_be_the_oci_rootfs_for_dot_path() {
        use std::os::unix::fs::MetadataExt;

        let temporary = tempdir().expect("temporary share");
        let share = temporary.path().join("share");
        let state = share.join("run");
        let bundle = share.join("bundle");
        fs::create_dir_all(&state).expect("runtime state");
        fs::create_dir(&bundle).expect("bundle");
        let (_, scope) = BundleDirectoryScope::utility_vm(&state)
            .await
            .expect("utility VM scope");
        let pinned = scope
            .pin(&GuestPath::new(bundle.to_string_lossy()).expect("guest bundle"))
            .expect("pin bundle")
            .expect("utility VM pin");

        let rootfs = pinned
            .open_rootfs(std::path::Path::new(""), "run-container-init")
            .expect("duplicate pinned bundle as rootfs")
            .expect("pinned rootfs");

        assert_eq!(
            rootfs.metadata().expect("rootfs metadata").ino(),
            fs::metadata(&bundle).expect("bundle metadata").ino()
        );
        assert_ne!(rootfs.as_raw_fd(), pinned.descriptor());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn utility_vm_scope_rejects_bundle_symlinks_and_external_directories() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().expect("temporary share");
        let share = temporary.path().join("share");
        let state = share.join("run");
        let external = temporary.path().join("external");
        let linked = share.join("linked");
        fs::create_dir_all(&state).expect("runtime state");
        fs::create_dir(&external).expect("external directory");
        symlink(&external, &linked).expect("linked bundle");
        let (_, scope) = BundleDirectoryScope::utility_vm(&state)
            .await
            .expect("utility VM scope");

        for rejected in [&external, &linked] {
            let error = scope
                .pin(&GuestPath::new(rejected.to_string_lossy()).expect("rejected guest path"))
                .expect_err("external or linked bundle must fail closed");
            assert_eq!(error.code, ErrorCode::PermissionDenied);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pinned_bundle_survives_a_directory_entry_swap_without_following_it() {
        use std::os::unix::fs::{symlink, MetadataExt};

        let temporary = tempdir().expect("temporary share");
        let share = temporary.path().join("share");
        let state = share.join("run");
        let bundle = share.join("bundle");
        let retained = share.join("retained");
        let external = temporary.path().join("external");
        fs::create_dir_all(&state).expect("runtime state");
        fs::create_dir_all(bundle.join("rootfs")).expect("bundle rootfs");
        fs::create_dir_all(external.join("rootfs")).expect("external rootfs");
        let expected_inode = fs::metadata(bundle.join("rootfs"))
            .expect("rootfs metadata")
            .ino();
        let (_, scope) = BundleDirectoryScope::utility_vm(&state)
            .await
            .expect("utility VM scope");
        let pinned = scope
            .pin(&GuestPath::new(bundle.to_string_lossy()).expect("guest bundle"))
            .expect("pin bundle")
            .expect("utility VM pin");

        fs::rename(&bundle, &retained).expect("move original bundle");
        symlink(&external, &bundle).expect("replace bundle with hostile link");
        let rootfs = pinned
            .open_relative(
                std::path::Path::new("rootfs"),
                libc::O_PATH,
                true,
                "test rootfs",
                "run-container-init",
            )
            .expect("open retained rootfs")
            .expect("retained rootfs exists");

        assert_eq!(
            rootfs.metadata().expect("retained metadata").ino(),
            expected_inode
        );
        assert_ne!(rootfs.as_raw_fd(), pinned.descriptor());
    }
}
