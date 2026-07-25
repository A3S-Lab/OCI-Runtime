use std::ffi::{CStr, CString};
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use a3s_oci_sdk::{Error, ErrorCode, Result};

pub(crate) const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
pub(crate) const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
pub(crate) const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
pub(crate) const MOUNT_ATTR_NOEXEC: u64 = 0x0000_0008;
pub(crate) const MOUNT_ATTR_NOATIME: u64 = 0x0000_0010;
const MOUNT_ATTR_STRICTATIME: u64 = 0x0000_0020;
pub(crate) const MOUNT_ATTR_ATIME: u64 = 0x0000_0070;
pub(crate) const MOUNT_ATTR_NODIRATIME: u64 = 0x0000_0080;
pub(crate) const MOUNT_ATTR_NOSYMFOLLOW: u64 = 0x0020_0000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RecursiveMountAttributes {
    pub(crate) attr_set: u64,
    pub(crate) attr_clr: u64,
}

#[repr(C)]
pub(super) struct MountAttr {
    pub(super) attr_set: u64,
    pub(super) attr_clr: u64,
    pub(super) propagation: u64,
    pub(super) userns_fd: u64,
}

pub(super) fn record_option(
    attributes: &mut Option<RecursiveMountAttributes>,
    option: &str,
) -> bool {
    let Some((clear, flag)) = option_attribute(option) else {
        return false;
    };
    let attributes = attributes.get_or_insert_with(RecursiveMountAttributes::default);
    if clear {
        attributes.attr_clr |= flag;
        attributes.attr_set &= !flag;
    } else {
        attributes.attr_set |= flag;
        attributes.attr_clr &= !flag;
    }
    if flag & MOUNT_ATTR_ATIME == flag {
        // mount_setattr treats access time as an enum. Selecting any recursive
        // atime mode therefore requires clearing the complete mode mask.
        attributes.attr_clr |= MOUNT_ATTR_ATIME;
    }
    true
}

pub(super) fn apply(
    index: usize,
    target: &CString,
    attributes: RecursiveMountAttributes,
) -> Result<()> {
    let target_fd = open_target(index, target)?;
    let kernel_attributes = MountAttr {
        attr_set: attributes.attr_set,
        attr_clr: attributes.attr_clr,
        propagation: 0,
        userns_fd: 0,
    };
    let empty_path = c"";
    let flags = libc::AT_EMPTY_PATH | libc::AT_RECURSIVE;

    // SAFETY: target_fd remains open, empty_path is NUL-terminated, and
    // kernel_attributes points to the version-0 mount_attr layout for the
    // complete syscall duration.
    let result = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            target_fd.as_raw_fd(),
            empty_path.as_ptr(),
            flags,
            &kernel_attributes as *const MountAttr,
            size_of::<MountAttr>(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(syscall_error(index, io::Error::last_os_error()))
    }
}

fn option_attribute(option: &str) -> Option<(bool, u64)> {
    match option {
        "rro" => Some((false, MOUNT_ATTR_RDONLY)),
        "rrw" => Some((true, MOUNT_ATTR_RDONLY)),
        "rnosuid" => Some((false, MOUNT_ATTR_NOSUID)),
        "rsuid" => Some((true, MOUNT_ATTR_NOSUID)),
        "rnodev" => Some((false, MOUNT_ATTR_NODEV)),
        "rdev" => Some((true, MOUNT_ATTR_NODEV)),
        "rnoexec" => Some((false, MOUNT_ATTR_NOEXEC)),
        "rexec" => Some((true, MOUNT_ATTR_NOEXEC)),
        "rnoatime" => Some((false, MOUNT_ATTR_NOATIME)),
        "ratime" => Some((true, MOUNT_ATTR_NOATIME)),
        "rnodiratime" => Some((false, MOUNT_ATTR_NODIRATIME)),
        "rdiratime" => Some((true, MOUNT_ATTR_NODIRATIME)),
        "rrelatime" => Some((false, 0)),
        "rnorelatime" => Some((true, 0)),
        "rstrictatime" => Some((false, MOUNT_ATTR_STRICTATIME)),
        "rnostrictatime" => Some((true, MOUNT_ATTR_STRICTATIME)),
        "rnosymfollow" => Some((false, MOUNT_ATTR_NOSYMFOLLOW)),
        "rsymfollow" => Some((true, MOUNT_ATTR_NOSYMFOLLOW)),
        _ => None,
    }
}

fn open_target(index: usize, target: &CStr) -> Result<OwnedFd> {
    // SAFETY: target is NUL-terminated and open does not retain the pointer.
    let descriptor = unsafe {
        libc::open(
            target.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(apply_error(
            ErrorCode::Internal,
            index,
            format!(
                "failed to open recursive-attribute target: {}",
                io::Error::last_os_error()
            ),
        ));
    }

    // SAFETY: descriptor is a newly owned successful open result.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    // SAFETY: zero is a valid initial representation for stat, and fstat
    // initializes it before it is inspected.
    let mut metadata: libc::stat = unsafe { zeroed() };
    // SAFETY: descriptor is live and metadata is writable.
    if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut metadata) } != 0 {
        return Err(apply_error(
            ErrorCode::Internal,
            index,
            format!(
                "failed to inspect recursive-attribute target: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    if metadata.st_mode & libc::S_IFMT == libc::S_IFLNK {
        return Err(apply_error(
            ErrorCode::PermissionDenied,
            index,
            "recursive mount attributes refuse a symbolic-link destination",
        ));
    }
    Ok(descriptor)
}

fn syscall_error(index: usize, error: io::Error) -> Error {
    let code = match error.raw_os_error() {
        Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL) => ErrorCode::Unsupported,
        Some(libc::EACCES | libc::EPERM) => ErrorCode::PermissionDenied,
        _ => ErrorCode::Internal,
    };
    apply_error(
        code,
        index,
        format!("mount_setattr recursive attributes failed: {error}"),
    )
}

fn apply_error(code: ErrorCode, index: usize, message: impl Into<String>) -> Error {
    Error::new(code, format!("mounts[{index}]: {}", message.into()))
        .for_operation("prepare-container-mounts")
}
