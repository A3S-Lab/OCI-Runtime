use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::Path;

use a3s_oci_sdk::{ErrorCode, Result};

use super::mount_source::{
    attach_device_mount, clone_device_mount, metadata_for_fd, metadata_for_raw_fd, openat2_beneath,
    target_metadata_for_path,
};
use super::types::{PreparedConsoleSource, PreparedDeviceSources, TargetMetadata};
use super::{device_error, invalid};
pub(super) fn ensure_ptmx_link() -> Result<()> {
    let path = Path::new("/dev/ptmx");
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let target = fs::read_link(path).map_err(|error| {
                device_error(
                    ErrorCode::FailedPrecondition,
                    format!("failed to read the required /dev/ptmx link: {error}"),
                )
            })?;
            if target == Path::new("pts/ptmx") {
                return Ok(());
            }
            return Err(device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "/dev/ptmx must link to pts/ptmx, found {}",
                    target.display()
                ),
            ));
        }
        Ok(metadata) if metadata.file_type().is_char_device() => {
            let target = target_metadata_for_path(path)?;
            let source = target_metadata_for_path(Path::new("/dev/pts/ptmx"))?;
            if target.file_type == libc::S_IFCHR
                && target.dev == source.dev
                && target.ino == source.ino
                && target.rdev == source.rdev
            {
                return Ok(());
            }
            return Err(device_error(
                ErrorCode::FailedPrecondition,
                "/dev/ptmx is not bound to /dev/pts/ptmx",
            ));
        }
        Ok(_) => {
            return Err(device_error(
                ErrorCode::FailedPrecondition,
                "/dev/ptmx already exists and is neither the required symlink nor bind mount",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(device_error(
                ErrorCode::FailedPrecondition,
                format!("failed to inspect /dev/ptmx: {error}"),
            ));
        }
    }
    std::os::unix::fs::symlink("pts/ptmx", path).map_err(|error| {
        device_error(
            ErrorCode::PermissionDenied,
            format!("failed to create the required /dev/ptmx link: {error}"),
        )
    })
}

pub(super) fn verify_ptmx_from_root(rootfs: &File) -> Result<()> {
    let dev = openat2_beneath(
        rootfs.as_raw_fd(),
        Path::new("dev"),
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        true,
    )?
    .ok_or_else(|| {
        device_error(
            ErrorCode::FailedPrecondition,
            "joined mount namespace does not supply /dev",
        )
    })?;
    let path = c"ptmx";
    let mut target = [0_u8; 256];
    // SAFETY: dev is a descriptor-confined real directory beneath the
    // retained rootfs, path is a fixed NUL-terminated basename, and target is
    // writable for its length.
    let length = unsafe {
        libc::readlinkat(
            dev.as_raw_fd(),
            path.as_ptr(),
            target.as_mut_ptr().cast(),
            target.len(),
        )
    };
    if length >= 0 {
        let length = usize::try_from(length).map_err(|error| {
            device_error(
                ErrorCode::Internal,
                format!("/dev/ptmx link length is invalid: {error}"),
            )
        })?;
        if length < target.len() && &target[..length] == b"pts/ptmx" {
            return Ok(());
        }
        return Err(device_error(
            ErrorCode::FailedPrecondition,
            "joined /dev/ptmx does not link to pts/ptmx",
        ));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::EINVAL) {
        return Err(device_error(
            ErrorCode::FailedPrecondition,
            format!("failed to inspect joined /dev/ptmx: {error}"),
        ));
    }
    let ptmx = openat2_beneath(
        rootfs.as_raw_fd(),
        Path::new("dev/ptmx"),
        libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        false,
    )?
    .ok_or_else(|| {
        device_error(
            ErrorCode::FailedPrecondition,
            "joined mount namespace does not supply /dev/ptmx",
        )
    })?;
    let pts_ptmx = openat2_beneath(
        rootfs.as_raw_fd(),
        Path::new("dev/pts/ptmx"),
        libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        false,
    )?
    .ok_or_else(|| {
        device_error(
            ErrorCode::FailedPrecondition,
            "joined mount namespace does not supply /dev/pts/ptmx",
        )
    })?;
    let ptmx = metadata_for_fd(&ptmx)?;
    let pts_ptmx = metadata_for_fd(&pts_ptmx)?;
    if ptmx.file_type == libc::S_IFCHR
        && ptmx.dev == pts_ptmx.dev
        && ptmx.ino == pts_ptmx.ino
        && ptmx.rdev == pts_ptmx.rdev
    {
        Ok(())
    } else {
        Err(device_error(
            ErrorCode::FailedPrecondition,
            "joined /dev/ptmx is not bound to /dev/pts/ptmx",
        ))
    }
}

pub(super) fn prepare_console_source() -> Result<PreparedConsoleSource> {
    // SAFETY: stdin is a live descriptor inherited by the configured process
    // launcher; isatty has no pointer arguments.
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return Err(device_error(
            ErrorCode::FailedPrecondition,
            "terminal configuration requires stdin to be the allocated PTY slave",
        ));
    }
    let metadata = metadata_for_raw_fd(libc::STDIN_FILENO)?;
    verify_console_metadata(&metadata)?;
    let mount = clone_device_mount(Path::new("/proc/self/fd/0"))?;
    let cloned = metadata_for_fd(&mount)?;
    if cloned.file_type != metadata.file_type
        || cloned.dev != metadata.dev
        || cloned.ino != metadata.ino
        || cloned.rdev != metadata.rdev
    {
        return Err(device_error(
            ErrorCode::FailedPrecondition,
            "detached terminal mount does not match the allocated PTY slave",
        ));
    }
    Ok(PreparedConsoleSource { mount, metadata })
}

pub(super) fn bind_console_source(
    rootfs: &Path,
    source: &PreparedConsoleSource,
    prepared: &PreparedDeviceSources,
) -> Result<()> {
    let canonical_rootfs = rootfs.canonicalize().map_err(|error| {
        invalid(format!(
            "failed to resolve the container rootfs while binding /dev/console: {error}"
        ))
    })?;
    let parent = canonical_rootfs.join("dev");
    let canonical_parent = parent.canonicalize().map_err(|error| {
        invalid(format!(
            "failed to resolve the container /dev directory while binding console: {error}"
        ))
    })?;
    if canonical_parent != parent || !canonical_parent.starts_with(&canonical_rootfs) {
        return Err(device_error(
            ErrorCode::PermissionDenied,
            "container /dev directory escapes the retained rootfs",
        ));
    }
    let target = canonical_parent.join("console");
    let created = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&target)
    {
        Ok(target) => {
            drop(target);
            true
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(&target).map_err(|inspect| {
                device_error(
                    ErrorCode::FailedPrecondition,
                    format!("failed to inspect existing /dev/console target: {inspect}"),
                )
            })?;
            if metadata.file_type().is_symlink() || metadata.is_dir() {
                return Err(device_error(
                    ErrorCode::PermissionDenied,
                    "existing /dev/console target must be a non-symlink file",
                ));
            }
            false
        }
        Err(error) => {
            return Err(device_error(
                ErrorCode::FailedPrecondition,
                format!("failed to create /dev/console bind target: {error}"),
            ));
        }
    };
    if created {
        prepared.record_created_target(&target, Path::new("dev/console"))?;
    }
    attach_device_mount(&source.mount, &target, Path::new("/dev/console"))?;
    let bound = target_metadata_for_path(&target)?;
    if bound.file_type != source.metadata.file_type
        || bound.dev != source.metadata.dev
        || bound.ino != source.metadata.ino
        || bound.rdev != source.metadata.rdev
    {
        return Err(device_error(
            ErrorCode::FailedPrecondition,
            "bound /dev/console does not match the allocated PTY slave",
        ));
    }
    Ok(())
}

pub(super) fn verify_console_metadata(console: &TargetMetadata) -> Result<()> {
    let stdin = metadata_for_raw_fd(libc::STDIN_FILENO)?;
    if stdin.file_type != libc::S_IFCHR
        || console.file_type != libc::S_IFCHR
        || console.dev != stdin.dev
        || console.ino != stdin.ino
        || console.rdev != stdin.rdev
    {
        return Err(device_error(
            ErrorCode::FailedPrecondition,
            "/dev/console is not the configured process PTY slave",
        ));
    }
    Ok(())
}
