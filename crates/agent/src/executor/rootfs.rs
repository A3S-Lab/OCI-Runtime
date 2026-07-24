use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use a3s_oci_sdk::{Error, ErrorCode, Result};

const CURRENT_DIRECTORY: &[u8] = b".\0";
const ROOT_DIRECTORY: &[u8] = b"/\0";

pub(super) fn prepare_pivot(rootfs: &Path) -> Result<()> {
    let rootfs = path_cstring(rootfs)?;
    let null_path = std::ptr::null::<libc::c_char>();
    let null_data = std::ptr::null::<libc::c_void>();

    // SAFETY: every pathname is NUL-terminated and remains live for each
    // syscall. The null source, filesystem type, and data pointers are valid
    // for propagation and bind mount operations.
    unsafe {
        if libc::mount(
            null_path,
            ROOT_DIRECTORY.as_ptr().cast(),
            null_path,
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            null_data,
        ) != 0
        {
            return Err(last_os_error(
                "make the guest mount tree recursively private",
            ));
        }
        if libc::mount(
            rootfs.as_ptr(),
            rootfs.as_ptr(),
            null_path,
            (libc::MS_BIND | libc::MS_REC) as libc::c_ulong,
            null_data,
        ) != 0
        {
            return Err(last_os_error("bind the container rootfs onto itself"));
        }
    }
    Ok(())
}

pub(super) fn pivot_root(rootfs: &Path) -> Result<()> {
    let rootfs = path_cstring(rootfs)?;

    // SAFETY: every pathname is NUL-terminated and remains live for each
    // syscall. The rootfs was made a mount point by `prepare_pivot`.
    unsafe {
        if libc::chdir(rootfs.as_ptr()) != 0 {
            return Err(last_os_error("change to the container rootfs"));
        }
        if libc::syscall(
            libc::SYS_pivot_root,
            CURRENT_DIRECTORY.as_ptr().cast::<libc::c_char>(),
            CURRENT_DIRECTORY.as_ptr().cast::<libc::c_char>(),
        ) != 0
        {
            return Err(last_os_error("pivot into the container rootfs"));
        }
        if libc::umount2(CURRENT_DIRECTORY.as_ptr().cast(), libc::MNT_DETACH) != 0 {
            return Err(last_os_error("detach the previous root filesystem"));
        }
        if libc::chdir(ROOT_DIRECTORY.as_ptr().cast()) != 0 {
            return Err(last_os_error("change to the pivoted root directory"));
        }
    }
    Ok(())
}

pub(super) fn chroot(rootfs: &File) -> Result<()> {
    // SAFETY: the descriptor was opened on the validated rootfs directory
    // before namespace entry. The caller is the dedicated single-threaded init
    // process, and `.` resolves through the retained descriptor after fchdir.
    unsafe {
        if libc::fchdir(rootfs.as_raw_fd()) != 0 {
            return Err(last_os_error("change to the retained container rootfs"));
        }
        if libc::chroot(CURRENT_DIRECTORY.as_ptr().cast()) != 0 {
            return Err(last_os_error("chroot container rootfs"));
        }
        if libc::chdir(ROOT_DIRECTORY.as_ptr().cast()) != 0 {
            return Err(last_os_error("change to the chroot root directory"));
        }
    }
    Ok(())
}

fn path_cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|error| {
        rootfs_error(
            ErrorCode::InvalidArgument,
            format!("container rootfs contains a NUL byte: {error}"),
        )
    })
}

fn last_os_error(operation: &str) -> Error {
    rootfs_error(
        ErrorCode::Internal,
        format!("{operation} failed: {}", io::Error::last_os_error()),
    )
}

fn rootfs_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("prepare-container-rootfs")
}
