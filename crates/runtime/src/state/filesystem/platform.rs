use std::ffi::OsStr;
use std::io;
use std::path::Path;

use a3s_oci_sdk::{ErrorCode, Result};
use cap_std::fs::Dir;

#[cfg(unix)]
use cap_fs_ext::{DirExt, MetadataExt};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

#[cfg(unix)]
use super::run_blocking;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::MountIdentity;
use super::{io_error, state_error};

#[cfg(windows)]
pub(super) fn is_lock_contended(error: &io::Error) -> bool {
    use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION};

    error.kind() == io::ErrorKind::WouldBlock
        || error.raw_os_error().is_some_and(|code| {
            u32::try_from(code)
                .is_ok_and(|code| matches!(code, ERROR_LOCK_VIOLATION | ERROR_SHARING_VIOLATION))
        })
}

#[cfg(not(windows))]
pub(super) fn is_lock_contended(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
}

#[cfg(not(windows))]
pub(super) async fn create_ambient_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    tokio::fs::create_dir(path)
        .await
        .map_err(|error| io_error("create-state-directory", path, error))?;
    #[cfg(unix)]
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .await
        .map_err(|error| io_error("protect-state-directory", path, error))?;
    Ok(())
}

#[cfg(windows)]
pub(super) async fn create_ambient_private_directory(path: &Path) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::windows_security::create_private_directory(&path))
        .await
        .map_err(|error| {
            state_error(
                ErrorCode::Internal,
                "create-state-directory",
                format!("Windows state-directory task failed: {error}"),
            )
        })?
}

pub(super) async fn ensure_ambient_plain_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|error| io_error("inspect-state-directory", path, error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "inspect-state-directory",
            format!("{label} is not a plain directory: {}", path.display()),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

pub(super) async fn ambient_path_exists(path: &Path) -> Result<bool> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error("inspect-state-path", path, error)),
    }
}

#[cfg(unix)]
pub(super) fn atomic_replace_relative(
    parent: &Dir,
    source: &OsStr,
    destination: &OsStr,
    _source_display: &Path,
    destination_display: &Path,
) -> Result<()> {
    parent
        .rename(source, parent, destination)
        .map_err(|error| io_error("commit-state-file", destination_display, error))
}

#[cfg(windows)]
pub(super) fn atomic_replace_relative(
    _parent: &Dir,
    _source: &OsStr,
    _destination: &OsStr,
    source_display: &Path,
    destination_display: &Path,
) -> Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source = source_display
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination_display
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: both slices are NUL-terminated, live for the duration of the
    // call, and point to distinct immutable UTF-16 path buffers. The retained
    // capability parent prevents path replacement during the ambient API.
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(io_error(
            "commit-state-file",
            destination_display,
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn rename_directory_noreplace(
    source_parent: &Dir,
    source: &OsStr,
    destination_parent: &Dir,
    destination: &OsStr,
    _source_display: &Path,
    destination_display: &Path,
) -> Result<()> {
    let source = c_string(source, "state directory source", destination_display)?;
    let destination = c_string(
        destination,
        "state directory destination",
        destination_display,
    )?;
    // SAFETY: both names are NUL-terminated, the directory descriptors remain
    // live for the call, and RENAME_NOREPLACE prevents destination races.
    let result = unsafe {
        libc::renameat2(
            source_parent.as_raw_fd(),
            source.as_ptr(),
            destination_parent.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(io_error(
            "commit-state-directory",
            destination_display,
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn rename_directory_noreplace(
    source_parent: &Dir,
    source: &OsStr,
    destination_parent: &Dir,
    destination: &OsStr,
    _source_display: &Path,
    destination_display: &Path,
) -> Result<()> {
    let source = c_string(source, "state directory source", destination_display)?;
    let destination = c_string(
        destination,
        "state directory destination",
        destination_display,
    )?;
    // SAFETY: both names are NUL-terminated, the directory descriptors remain
    // live for the call, and RENAME_EXCL prevents destination races.
    let result = unsafe {
        libc::renameatx_np(
            source_parent.as_raw_fd(),
            source.as_ptr(),
            destination_parent.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result != 0 {
        return Err(io_error(
            "commit-state-directory",
            destination_display,
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn rename_directory_noreplace(
    _source_parent: &Dir,
    _source: &OsStr,
    _destination_parent: &Dir,
    _destination: &OsStr,
    source_display: &Path,
    destination_display: &Path,
) -> Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};

    let source = source_display
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination_display
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: both buffers are live and NUL-terminated. Omitting the replace
    // flag makes a concurrently created destination fail closed.
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(io_error(
            "commit-state-directory",
            destination_display,
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn verify_moved_directory(
    source: &Dir,
    destination_parent: &Dir,
    destination_name: &OsStr,
    destination_display: &Path,
) -> Result<()> {
    let destination = destination_parent
        .open_dir_nofollow(destination_name)
        .map_err(|error| io_error("verify-state-directory-move", destination_display, error))?;
    let source_metadata = source
        .dir_metadata()
        .map_err(|error| io_error("verify-state-directory-source", destination_display, error))?;
    let destination_metadata = destination.dir_metadata().map_err(|error| {
        io_error(
            "verify-state-directory-destination",
            destination_display,
            error,
        )
    })?;
    if source_metadata.dev() != destination_metadata.dev()
        || source_metadata.ino() != destination_metadata.ino()
    {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "verify-state-directory-move",
            format!(
                "moved durable directory identity changed during commit: {}",
                destination_display.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn c_string(value: &OsStr, label: &str, display: &Path) -> Result<std::ffi::CString> {
    std::ffi::CString::new(value.as_bytes()).map_err(|error| {
        state_error(
            ErrorCode::Internal,
            "encode-state-path",
            format!("{label} contains NUL: {}: {error}", display.display()),
        )
    })
}

pub(super) async fn sync_directory(directory: Dir, display: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd as _;

        let display = display.to_path_buf();
        run_blocking("sync-state-directory", move || {
            // cap-std may retain Linux directories through O_PATH. Reopen the
            // exact pinned directory descriptor with read access before
            // fsync; no ambient pathname is consulted.
            let descriptor = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    c".".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if descriptor < 0 {
                return Err(io_error(
                    "open-state-directory-for-sync",
                    &display,
                    io::Error::last_os_error(),
                ));
            }
            // SAFETY: openat returned a fresh owned descriptor.
            let file = unsafe { std::fs::File::from_raw_fd(descriptor) };
            file.sync_all()
                .map_err(|error| io_error("sync-state-directory", &display, error))
        })
        .await
    }
    #[cfg(not(unix))]
    {
        let _ = (directory, display);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(super) fn mount_identity(descriptor: std::os::fd::RawFd) -> io::Result<MountIdentity> {
    let mut stat = std::mem::MaybeUninit::<libc::statx>::zeroed();
    // SAFETY: `descriptor` is live and the output buffer is correctly sized
    // and writable. AT_EMPTY_PATH requests metadata for that descriptor.
    let result = unsafe {
        libc::statx(
            descriptor,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_NO_AUTOMOUNT,
            libc::STATX_MNT_ID,
            stat.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful statx initialized the output structure.
    let stat = unsafe { stat.assume_init() };
    if stat.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "statx did not report a mount identity",
        ));
    }
    Ok(stat.stx_mnt_id)
}

#[cfg(target_os = "macos")]
pub(super) fn mount_identity(descriptor: std::os::fd::RawFd) -> io::Result<MountIdentity> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: `descriptor` is live and the output buffer is correctly sized
    // and writable for fstatfs.
    let result = unsafe { libc::fstatfs(descriptor, stat.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatfs initialized `stat`; fsid_t is exactly two i32 values on
    // Apple platforms even though libc keeps the field private.
    let stat = unsafe { stat.assume_init() };
    let identity = unsafe { std::mem::transmute_copy::<libc::fsid_t, [i32; 2]>(&stat.f_fsid) };
    Ok(identity)
}
