use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{ErrorCode, Result};

use super::types::TargetMetadata;
use super::{device_error, invalid, last_os_error};
pub(super) fn openat2_beneath(
    directory: libc::c_int,
    path: &Path,
    flags: libc::c_int,
    require_directory: bool,
) -> Result<Option<OwnedFd>> {
    let path = path_cstring(path, "descriptor-relative device target")?;
    let mut how = std::mem::MaybeUninit::<libc::open_how>::zeroed();
    // SAFETY: zero is a valid initialization for every field in open_how.
    let how = unsafe { how.assume_init_mut() };
    how.flags = flags as u64;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_SYMLINKS;
    // SAFETY: the directory descriptor is live, `path` is NUL-terminated, and
    // `how` is initialized for the exact kernel ABI size.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory,
            path.as_ptr(),
            how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        let errno = error.raw_os_error();
        return Err(device_error(
            if errno == Some(libc::EXDEV)
                || errno == Some(libc::ELOOP)
                // With O_DIRECTORY | O_NOFOLLOW, Linux may report ENOTDIR
                // instead of ELOOP for a final symlink. In a call that
                // requires a real directory, both outcomes are the same
                // descriptor-confinement policy violation.
                || (require_directory && errno == Some(libc::ENOTDIR))
            {
                ErrorCode::PermissionDenied
            } else {
                ErrorCode::FailedPrecondition
            },
            format!(
                "failed to open descriptor-relative device target {}: {error}",
                path.to_string_lossy()
            ),
        ));
    }
    let descriptor = libc::c_int::try_from(descriptor).map_err(|error| {
        device_error(
            ErrorCode::Internal,
            format!("openat2 returned an invalid descriptor: {error}"),
        )
    })?;
    // SAFETY: descriptor is freshly returned by openat2.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    if require_directory && metadata_for_fd(&descriptor)?.file_type != libc::S_IFDIR {
        return Err(device_error(
            ErrorCode::PermissionDenied,
            "descriptor-relative device target parent is not a directory",
        ));
    }
    Ok(Some(descriptor))
}

pub(super) fn metadata_for_fd(descriptor: &OwnedFd) -> Result<TargetMetadata> {
    metadata_for_raw_fd(descriptor.as_raw_fd())
}

pub(super) fn metadata_for_raw_fd(descriptor: RawFd) -> Result<TargetMetadata> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `descriptor` is live and metadata points to writable storage
    // for one stat result.
    if unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) } != 0 {
        return Err(last_os_error("inspect descriptor-relative device target"));
    }
    // SAFETY: fstat succeeded and initialized metadata.
    Ok(target_metadata_from_stat(unsafe {
        &metadata.assume_init()
    }))
}

pub(super) fn target_metadata_from_stat(metadata: &libc::stat) -> TargetMetadata {
    TargetMetadata {
        file_type: metadata.st_mode & libc::S_IFMT,
        dev: metadata.st_dev,
        rdev: metadata.st_rdev,
        ino: metadata.st_ino,
        mode: metadata.st_mode & 0o7777,
        uid: metadata.st_uid,
        gid: metadata.st_gid,
    }
}

pub(super) fn clone_device_mount(path: &Path) -> Result<OwnedFd> {
    let path = path_cstring(path, "prepared device source")?;
    // SAFETY: the path is NUL-terminated and open_tree does not retain it.
    // OPEN_TREE_CLONE returns a detached mount owned by the returned fd.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(last_os_error("clone prepared OCI device source mount"));
    }
    let descriptor = libc::c_int::try_from(descriptor).map_err(|error| {
        device_error(
            ErrorCode::Internal,
            format!("open_tree returned an invalid device mount descriptor: {error}"),
        )
    })?;
    // SAFETY: `descriptor` is a fresh owned descriptor returned by open_tree.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

pub(super) fn target_metadata_for_path(path: &Path) -> Result<TargetMetadata> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        device_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect device target {}: {error}",
                path.display()
            ),
        )
    })?;
    Ok(TargetMetadata {
        file_type: metadata.mode() & libc::S_IFMT,
        dev: metadata.dev(),
        rdev: metadata.rdev(),
        ino: metadata.ino(),
        mode: metadata.mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
    })
}

pub(super) fn attach_device_mount(
    source: &OwnedFd,
    target: &Path,
    container_path: &Path,
) -> Result<()> {
    let target_descriptor = open_path_descriptor(target)?;
    let empty = c"";
    let flags = libc::MOVE_MOUNT_F_EMPTY_PATH | libc::MOVE_MOUNT_T_EMPTY_PATH;
    // SAFETY: both descriptors are live detached/source and target mount
    // references, both empty paths are NUL-terminated, and the EMPTY_PATH
    // flags select the descriptors directly.
    let moved = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            source.as_raw_fd(),
            empty.as_ptr(),
            target_descriptor.as_raw_fd(),
            empty.as_ptr(),
            flags,
        )
    };
    if moved != 0 {
        return Err(last_os_error(format!(
            "attach prepared OCI device {}",
            container_path.display()
        )));
    }

    let target = path_cstring(target, "OCI device bind target")?;
    let null = std::ptr::null::<libc::c_char>();
    let null_data = std::ptr::null::<libc::c_void>();
    // SAFETY: the bind target was created and mounted by this operation.
    if unsafe {
        libc::mount(
            null,
            target.as_ptr(),
            null,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NOEXEC,
            null_data,
        )
    } != 0
    {
        return Err(last_os_error(format!(
            "apply safe bind flags to OCI device {}",
            container_path.display()
        )));
    }
    Ok(())
}

pub(super) fn open_path_descriptor(path: &Path) -> Result<OwnedFd> {
    let path = path_cstring(path, "OCI device bind target")?;
    // SAFETY: the target is NUL-terminated and open does not retain it.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(last_os_error("retain OCI device bind target"));
    }
    // SAFETY: `descriptor` is a fresh owned descriptor returned by open.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

pub(super) fn canonical_device_source_directory(path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        device_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect OCI device-source directory {}: {error}",
                path.display()
            ),
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(device_error(
            ErrorCode::PermissionDenied,
            format!(
                "OCI device-source directory is not a real directory: {}",
                path.display()
            ),
        ));
    }
    path.canonicalize().map_err(|error| {
        device_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to resolve OCI device-source directory {}: {error}",
                path.display()
            ),
        )
    })
}

pub(super) fn path_cstring(path: &Path, label: &str) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|error| {
        invalid(format!(
            "{label} path {} contains NUL: {error}",
            path.display()
        ))
    })
}
