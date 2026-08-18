use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use a3s_oci_sdk::{ErrorCode, Result};

use crate::OCI_LINUX_DEFAULT_DEVICE_NODES;

use super::{last_policy_error, policy_error, ROOTLESS_DEVICE_MOUNT_COUNT};

pub(super) fn open_rootless_device_sources() -> Result<Vec<OwnedFd>> {
    OCI_LINUX_DEFAULT_DEVICE_NODES
        .iter()
        .map(|device| {
            let path = std::ffi::CString::new(device.path).map_err(|error| {
                policy_error(
                    ErrorCode::Internal,
                    format!("fixed rootless device path contains NUL: {error}"),
                )
            })?;
            // SAFETY: every source is a fixed NUL-terminated safe-device path.
            // O_PATH retains its exact identity without opening it for I/O.
            let descriptor = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if descriptor < 0 {
                return Err(last_policy_error(
                    ErrorCode::FailedPrecondition,
                    "retain fixed rootless device source",
                ));
            }
            // SAFETY: open returned a fresh owned descriptor.
            let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
            verify_rootless_device_descriptor(
                &descriptor,
                device.major,
                device.minor,
                device.mode,
            )?;
            Ok(descriptor)
        })
        .collect()
}

pub(super) fn prepare_device_mounts(sources: &[OwnedFd]) -> Result<Vec<OwnedFd>> {
    if sources.len() != ROOTLESS_DEVICE_MOUNT_COUNT {
        return Err(policy_error(
            ErrorCode::Internal,
            "rootless device-policy helper lost its fixed source set",
        ));
    }
    sources
        .iter()
        .enumerate()
        .map(|(index, source)| clone_device_mount(source, index))
        .collect()
}

fn clone_device_mount(source: &OwnedFd, index: usize) -> Result<OwnedFd> {
    // This runs in the initial user and mount namespaces while the helper
    // still has effective-root mount authority. AT_EMPTY_PATH operates on the
    // exact O_PATH node retained during authenticated bootstrap; callers
    // cannot provide either a path or descriptor.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            source.as_raw_fd(),
            c"".as_ptr(),
            libc::OPEN_TREE_CLONE
                | libc::OPEN_TREE_CLOEXEC
                | u32::try_from(libc::AT_EMPTY_PATH).map_err(|error| {
                    policy_error(
                        ErrorCode::Internal,
                        format!("AT_EMPTY_PATH does not fit open_tree flags: {error}"),
                    )
                })?,
        )
    };
    if descriptor < 0 {
        return Err(last_policy_error(
            ErrorCode::PermissionDenied,
            &format!("clone fixed rootless device mount slot {index}"),
        ));
    }
    let descriptor = i32::try_from(descriptor).map_err(|error| {
        policy_error(
            ErrorCode::Internal,
            format!("open_tree returned an invalid device mount descriptor: {error}"),
        )
    })?;
    // SAFETY: open_tree returned a fresh detached mount descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

pub(super) fn verify_prepared_device_mounts(mounts: &[OwnedFd]) -> Result<()> {
    if mounts.len() != OCI_LINUX_DEFAULT_DEVICE_NODES.len() {
        return Err(policy_error(
            ErrorCode::PermissionDenied,
            format!(
                "received {} rootless device mounts; expected {}",
                mounts.len(),
                OCI_LINUX_DEFAULT_DEVICE_NODES.len()
            ),
        ));
    }
    for (mount, device) in mounts.iter().zip(OCI_LINUX_DEFAULT_DEVICE_NODES) {
        verify_rootless_device_descriptor(mount, device.major, device.minor, device.mode)?;
        verify_close_on_exec(mount)?;
    }
    Ok(())
}

pub(super) fn verify_rootless_device_descriptor(
    descriptor: &OwnedFd,
    major: u32,
    minor: u32,
    mode: u32,
) -> Result<()> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: descriptor is live and metadata points to writable stat storage.
    if unsafe { libc::fstat(descriptor.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        return Err(last_policy_error(
            ErrorCode::FailedPrecondition,
            "inspect fixed rootless device descriptor",
        ));
    }
    // SAFETY: fstat succeeded and initialized metadata.
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFCHR
        || libc::major(metadata.st_rdev) != major
        || libc::minor(metadata.st_rdev) != minor
        || metadata.st_mode & 0o7777 != mode
    {
        return Err(policy_error(
            ErrorCode::PermissionDenied,
            format!(
                "rootless device descriptor differs from fixed character device {major}:{minor} mode {mode:04o}"
            ),
        ));
    }
    Ok(())
}

fn verify_close_on_exec(descriptor: &OwnedFd) -> Result<()> {
    // SAFETY: descriptor is live and F_GETFD only reads descriptor flags.
    let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
    if flags >= 0 && flags & libc::FD_CLOEXEC != 0 {
        Ok(())
    } else {
        Err(last_policy_error(
            ErrorCode::PermissionDenied,
            "verify close-on-exec rootless device mount descriptor",
        ))
    }
}
