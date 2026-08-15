mod dev_symlink;
mod mask;

use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{Error, ErrorCode, Result};

const CURRENT_DIRECTORY: &[u8] = b".\0";
const ROOT_DIRECTORY: &[u8] = b"/\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RootfsPropagation {
    Private,
    Shared,
    Slave,
    Unbindable,
}

impl RootfsPropagation {
    pub(super) fn parse(value: &str) -> Result<Self> {
        match value {
            "private" => Ok(Self::Private),
            "shared" => Ok(Self::Shared),
            "slave" => Ok(Self::Slave),
            "unbindable" => Ok(Self::Unbindable),
            _ => Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("linux.rootfsPropagation contains unsupported mode `{value}`"),
            )
            .for_operation("plan-container-rootfs")),
        }
    }

    const fn preparation_flags(self) -> libc::c_ulong {
        match self {
            Self::Slave => libc::MS_SLAVE | libc::MS_REC,
            Self::Private | Self::Shared | Self::Unbindable => libc::MS_PRIVATE | libc::MS_REC,
        }
    }

    const fn final_flags(self) -> libc::c_ulong {
        match self {
            Self::Private => libc::MS_PRIVATE,
            Self::Shared => libc::MS_SHARED,
            Self::Slave => libc::MS_SLAVE,
            Self::Unbindable => libc::MS_UNBINDABLE,
        }
    }
}

pub(super) fn prepare_pivot(rootfs: &Path, propagation: Option<RootfsPropagation>) -> Result<()> {
    let rootfs = path_cstring(rootfs)?;
    let null_path = std::ptr::null::<libc::c_char>();
    let null_data = std::ptr::null::<libc::c_void>();
    let preparation_flags = propagation.map_or(libc::MS_REC | libc::MS_PRIVATE, |mode| {
        mode.preparation_flags()
    });

    // SAFETY: every pathname is NUL-terminated and remains live for each
    // syscall. The null source, filesystem type, and data pointers are valid
    // for propagation and bind mount operations.
    unsafe {
        if libc::mount(
            null_path,
            ROOT_DIRECTORY.as_ptr().cast(),
            null_path,
            preparation_flags,
            null_data,
        ) != 0
        {
            return Err(last_os_error("prepare the guest mount tree propagation"));
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

pub(super) fn finalize(
    propagation: Option<RootfsPropagation>,
    readonly_paths: &[PathBuf],
    masked_paths: &[PathBuf],
    root_readonly: bool,
) -> Result<()> {
    if let Some(propagation) = propagation {
        apply_root_propagation(propagation)?;
    }
    if !masked_paths.is_empty() {
        let source = mask::MaskSource::open(Path::new("/"))?;
        mask::apply(masked_paths, &source)?;
    }
    for path in readonly_paths {
        make_path_readonly(path)?;
    }
    if root_readonly {
        make_root_readonly()?;
    }
    Ok(())
}

pub(super) use dev_symlink::create_required_dev_symlinks;

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

fn apply_root_propagation(propagation: RootfsPropagation) -> Result<()> {
    mount_raw(
        None,
        Path::new("/"),
        None,
        propagation.final_flags(),
        None,
        "apply configured rootfs propagation",
    )
}

fn make_path_readonly(path: &Path) -> Result<()> {
    match fs::metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(rootfs_error(
                ErrorCode::Internal,
                format!(
                    "failed to inspect read-only container path {}: {error}",
                    path.display()
                ),
            ));
        }
    }
    mount_raw(
        Some(path),
        path,
        None,
        libc::MS_BIND | libc::MS_REC,
        None,
        "self-bind read-only container path",
    )?;
    remount_readonly(path, "remount container path read-only")?;
    verify_readonly(path, "container read-only path")
}

fn make_root_readonly() -> Result<()> {
    remount_readonly(Path::new("/"), "remount the container rootfs read-only")?;
    verify_readonly(Path::new("/"), "container rootfs")
}

fn remount_readonly(path: &Path, operation: &str) -> Result<()> {
    let preserved = statvfs_flags(path)?;
    mount_raw(
        None,
        path,
        None,
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | preserved,
        None,
        operation,
    )
}

fn statvfs_flags(path: &Path) -> Result<libc::c_ulong> {
    let path = path_cstring(path)?;
    let mut status = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `status` points to writable storage and `path` is a live,
    // NUL-terminated pathname. A successful call initializes `status`.
    if unsafe { libc::statvfs(path.as_ptr(), status.as_mut_ptr()) } != 0 {
        return Err(last_os_error("inspect existing mount flags"));
    }
    // SAFETY: the successful `statvfs` call initialized the structure.
    let status = unsafe { status.assume_init() };
    let mut flags = 0;
    if status.f_flag & libc::ST_NOSUID != 0 {
        flags |= libc::MS_NOSUID;
    }
    if status.f_flag & libc::ST_NODEV != 0 {
        flags |= libc::MS_NODEV;
    }
    if status.f_flag & libc::ST_NOEXEC != 0 {
        flags |= libc::MS_NOEXEC;
    }
    Ok(flags)
}

fn verify_readonly(path: &Path, description: &str) -> Result<()> {
    let path_c = path_cstring(path)?;
    let mut status = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `status` points to writable storage and `path_c` remains live.
    if unsafe { libc::statvfs(path_c.as_ptr(), status.as_mut_ptr()) } != 0 {
        return Err(last_os_error(&format!("verify {description}")));
    }
    // SAFETY: the successful `statvfs` call initialized the structure.
    let status = unsafe { status.assume_init() };
    if status.f_flag & libc::ST_RDONLY == 0 {
        return Err(rootfs_error(
            ErrorCode::Internal,
            format!("{description} is not read-only after enforcement"),
        ));
    }
    Ok(())
}

fn mount_raw(
    source: Option<&Path>,
    target: &Path,
    filesystem_type: Option<&Path>,
    flags: libc::c_ulong,
    data: Option<&[u8]>,
    operation: &str,
) -> Result<()> {
    let source = source.map(path_cstring).transpose()?;
    let target_c = path_cstring(target)?;
    let filesystem_type = filesystem_type.map(path_cstring).transpose()?;
    let data = match data {
        Some(data) => Some(CString::from_vec_with_nul(data.to_vec()).map_err(|error| {
            rootfs_error(
                ErrorCode::InvalidArgument,
                format!("rootfs mount data is not NUL-terminated: {error}"),
            )
        })?),
        None => None,
    };
    // SAFETY: every non-null pointer references a live NUL-terminated buffer
    // for the duration of the syscall.
    if unsafe {
        libc::mount(
            source
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            target_c.as_ptr(),
            filesystem_type
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            flags,
            data.as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr().cast()),
        )
    } != 0
    {
        Err(last_os_error(&format!(
            "{operation} at {}",
            target.display()
        )))
    } else {
        Ok(())
    }
}

fn path_cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|error| {
        rootfs_error(
            ErrorCode::InvalidArgument,
            format!("container rootfs path contains a NUL byte: {error}"),
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
