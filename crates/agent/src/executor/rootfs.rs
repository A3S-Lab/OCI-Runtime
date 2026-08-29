mod dev_symlink;
mod mask;

use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, ErrorKind};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
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

/// Rootfs mount retained across OCI mount setup and the create-hook barrier.
#[derive(Debug)]
pub(super) struct PreparedRootfsMount {
    path: PathBuf,
    _descriptor: Option<OwnedFd>,
}

impl PreparedRootfsMount {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

pub(super) fn prepare_pivot(
    rootfs: &Path,
    propagation: Option<RootfsPropagation>,
) -> Result<PreparedRootfsMount> {
    prepare_mount_tree_propagation(propagation)?;
    let rootfs_c = path_cstring(rootfs)?;
    let null_path = std::ptr::null::<libc::c_char>();
    let null_data = std::ptr::null::<libc::c_void>();

    // SAFETY: both rootfs pointers reference the same live NUL-terminated
    // pathname, and the remaining mount arguments are valid null pointers.
    if unsafe {
        libc::mount(
            rootfs_c.as_ptr(),
            rootfs_c.as_ptr(),
            null_path,
            (libc::MS_BIND | libc::MS_REC) as libc::c_ulong,
            null_data,
        )
    } != 0
    {
        return Err(last_os_error("bind the container rootfs onto itself"));
    }
    Ok(PreparedRootfsMount {
        path: rootfs.to_path_buf(),
        _descriptor: None,
    })
}

/// Clone a descriptor-confined rootfs into the current mount namespace.
///
/// A rootfs descriptor inherited across `unshare(CLONE_NEWNS)` still refers
/// to the source namespace's mount. Linux consequently rejects using its
/// `/proc/self/fd` magic link as a legacy mount target. Reopening and matching
/// the real entry in the current namespace, then cloning and attaching by
/// descriptor, preserves the pinned inode without a path-race window.
pub(super) fn prepare_descriptor_pinned_pivot(
    rootfs_mountpoint: &Path,
    retained_rootfs: &File,
    propagation: Option<RootfsPropagation>,
) -> Result<PreparedRootfsMount> {
    prepare_mount_tree_propagation(propagation)?;
    let current_rootfs = open_current_rootfs(rootfs_mountpoint)?;
    verify_same_rootfs(retained_rootfs, &current_rootfs, rootfs_mountpoint)?;
    let detached = clone_rootfs_mount(&current_rootfs)?;
    attach_rootfs_mount(&detached, &current_rootfs)?;
    let path = PathBuf::from(format!("/proc/self/fd/{}", detached.as_raw_fd()));
    if !path.is_dir() {
        return Err(rootfs_error(
            ErrorCode::FailedPrecondition,
            "descriptor-attached container rootfs is not reachable in the current mount namespace",
        ));
    }
    Ok(PreparedRootfsMount {
        path,
        _descriptor: Some(detached),
    })
}

fn prepare_mount_tree_propagation(propagation: Option<RootfsPropagation>) -> Result<()> {
    let flags = propagation.map_or(libc::MS_REC | libc::MS_PRIVATE, |mode| {
        mode.preparation_flags()
    });
    // SAFETY: propagation changes use one live root pathname and otherwise
    // null pointers, which mount(2) requires for this operation.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            ROOT_DIRECTORY.as_ptr().cast(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    } != 0
    {
        Err(last_os_error("prepare the guest mount tree propagation"))
    } else {
        Ok(())
    }
}

fn open_current_rootfs(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        return Err(rootfs_error(
            ErrorCode::InvalidArgument,
            format!(
                "descriptor-pinned container rootfs mount point must be absolute: {}",
                path.display()
            ),
        ));
    }
    let path_c = path_cstring(path)?;
    let mut how = std::mem::MaybeUninit::<libc::open_how>::zeroed();
    // SAFETY: zero is valid for every open_how field.
    let how = unsafe { how.assume_init_mut() };
    how.flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_SYMLINKS;
    // SAFETY: the pathname and initialized open_how remain live for the call.
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
        return Err(descriptor_mount_error(
            "reopen the descriptor-pinned container rootfs in the current mount namespace",
            io::Error::last_os_error(),
        ));
    }
    let descriptor = libc::c_int::try_from(descriptor).map_err(|error| {
        rootfs_error(
            ErrorCode::Internal,
            format!("openat2 returned an invalid container rootfs descriptor: {error}"),
        )
    })?;
    // SAFETY: openat2 returned this fresh descriptor exactly once.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn verify_same_rootfs(retained: &File, current: &File, path: &Path) -> Result<()> {
    let retained = retained.metadata().map_err(|error| {
        rootfs_error(
            ErrorCode::FailedPrecondition,
            format!("failed to inspect retained container rootfs: {error}"),
        )
    })?;
    let current = current.metadata().map_err(|error| {
        rootfs_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect current container rootfs {}: {error}",
                path.display()
            ),
        )
    })?;
    if retained.dev() == current.dev() && retained.ino() == current.ino() {
        Ok(())
    } else {
        Err(rootfs_error(
            ErrorCode::PermissionDenied,
            format!(
                "descriptor-pinned container rootfs changed before mount attachment: {}",
                path.display()
            ),
        ))
    }
}

fn clone_rootfs_mount(rootfs: &File) -> Result<OwnedFd> {
    let traversal_flags =
        u32::try_from(libc::AT_EMPTY_PATH | libc::AT_RECURSIVE).map_err(|error| {
            rootfs_error(
                ErrorCode::Internal,
                format!("rootfs open_tree traversal flags do not fit the kernel ABI: {error}"),
            )
        })?;
    let flags = libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC | traversal_flags;
    // SAFETY: rootfs is a live directory descriptor, the empty pathname is
    // NUL-terminated, and AT_EMPTY_PATH selects that exact descriptor.
    let descriptor =
        unsafe { libc::syscall(libc::SYS_open_tree, rootfs.as_raw_fd(), c"".as_ptr(), flags) };
    if descriptor < 0 {
        return Err(descriptor_mount_error(
            "clone the descriptor-pinned container rootfs mount",
            io::Error::last_os_error(),
        ));
    }
    let descriptor = libc::c_int::try_from(descriptor).map_err(|error| {
        rootfs_error(
            ErrorCode::Internal,
            format!("open_tree returned an invalid container rootfs descriptor: {error}"),
        )
    })?;
    // SAFETY: open_tree returned this fresh descriptor exactly once.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn attach_rootfs_mount(detached: &OwnedFd, destination: &File) -> Result<()> {
    let flags = libc::MOVE_MOUNT_F_EMPTY_PATH | libc::MOVE_MOUNT_T_EMPTY_PATH;
    // SAFETY: both descriptors are live, both paths are empty NUL-terminated
    // strings selected by the EMPTY_PATH flags, and move_mount retains none.
    let moved = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            detached.as_raw_fd(),
            c"".as_ptr(),
            destination.as_raw_fd(),
            c"".as_ptr(),
            flags,
        )
    };
    if moved == 0 {
        Ok(())
    } else {
        Err(descriptor_mount_error(
            "attach the descriptor-pinned container rootfs mount",
            io::Error::last_os_error(),
        ))
    }
}

fn descriptor_mount_error(operation: &str, error: io::Error) -> Error {
    let code = match error.raw_os_error() {
        Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL) => ErrorCode::Unsupported,
        Some(libc::EACCES | libc::EPERM | libc::ELOOP | libc::EXDEV) => ErrorCode::PermissionDenied,
        _ => ErrorCode::FailedPrecondition,
    };
    rootfs_error(code, format!("{operation} failed: {error}"))
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

pub(super) use dev_symlink::{
    create_required_dev_symlinks, create_required_dev_symlinks_from_root,
};

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
