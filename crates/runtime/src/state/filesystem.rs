use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use a3s_oci_sdk::{Error, ErrorCode, Result};
use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::model::{RuntimeRootMarker, ROOT_SCHEMA_VERSION};

const ROOT_MARKER_FILE: &str = "root.json";
const LOCK_FILE: &str = ".lock";
const MAX_STATE_FILE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct RootLock {
    _file: std::fs::File,
}

pub(super) async fn open_root(path: &Path) -> Result<(PathBuf, Arc<RootLock>)> {
    if !path.is_absolute() {
        return Err(state_error(
            ErrorCode::InvalidArgument,
            "open-state-root",
            format!("runtime state root must be absolute: {}", path.display()),
        ));
    }
    if path.to_str().is_none() {
        return Err(state_error(
            ErrorCode::InvalidArgument,
            "open-state-root",
            "runtime state root must be valid UTF-8",
        ));
    }

    let root = if path_exists(path).await? {
        ensure_plain_directory(path, "runtime state root").await?;
        tokio::fs::canonicalize(path)
            .await
            .map_err(|error| io_error("canonicalize-state-root", path, error))?
    } else {
        let parent = path.parent().ok_or_else(|| {
            state_error(
                ErrorCode::InvalidArgument,
                "open-state-root",
                format!("runtime state root has no parent: {}", path.display()),
            )
        })?;
        let name = path.file_name().ok_or_else(|| {
            state_error(
                ErrorCode::InvalidArgument,
                "open-state-root",
                format!(
                    "runtime state root has no final component: {}",
                    path.display()
                ),
            )
        })?;
        let parent = tokio::fs::canonicalize(parent)
            .await
            .map_err(|error| io_error("canonicalize-state-root-parent", parent, error))?;
        ensure_plain_directory(&parent, "runtime state root parent").await?;
        let candidate = parent.join(name);
        create_private_directory(&candidate).await?;
        tokio::fs::canonicalize(&candidate)
            .await
            .map_err(|error| io_error("canonicalize-state-root", &candidate, error))?
    };
    set_private_directory_permissions(&root).await?;

    let lock_path = root.join(LOCK_FILE);
    if path_exists(&lock_path).await? {
        ensure_plain_file(&lock_path, "runtime root lock").await?;
    }
    let root_lock = acquire_root_lock(lock_path.clone()).await?;
    set_private_file_permissions(&lock_path).await?;
    initialize_layout(&root).await?;
    Ok((root, Arc::new(root_lock)))
}

async fn initialize_layout(root: &Path) -> Result<()> {
    let marker_path = root.join(ROOT_MARKER_FILE);
    if path_exists(&marker_path).await? {
        ensure_plain_file(&marker_path, "runtime root marker").await?;
        let marker: RuntimeRootMarker = read_json(&marker_path).await?;
        if marker.schema_version != ROOT_SCHEMA_VERSION {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "open-state-root",
                format!(
                    "runtime root {} uses unsupported schema {}",
                    root.display(),
                    marker.schema_version
                ),
            ));
        }
    } else {
        let mut entries = tokio::fs::read_dir(root)
            .await
            .map_err(|error| io_error("inspect-state-root", root, error))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| io_error("inspect-state-root", root, error))?
        {
            if entry.file_name() != LOCK_FILE {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "open-state-root",
                    format!("uninitialized runtime root {} is not empty", root.display()),
                ));
            }
        }
        atomic_write_json(&marker_path, &RuntimeRootMarker::default()).await?;
    }

    for directory in ["containers", "generations", "operations", "quarantine"] {
        let path = root.join(directory);
        if path_exists(&path).await? {
            ensure_plain_directory(&path, directory).await?;
            set_private_directory_permissions(&path).await?;
        } else {
            create_private_directory(&path).await?;
        }
    }
    Ok(())
}

async fn acquire_root_lock(path: PathBuf) -> Result<RootLock> {
    tokio::task::spawn_blocking(move || {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| io_error("open-state-root-lock", &path, error))?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
            let contended = is_lock_contended(&error);
            let code = if contended {
                ErrorCode::Conflict
            } else {
                ErrorCode::Internal
            };
            state_error(
                code,
                "lock-state-root",
                format!(
                    "failed to acquire exclusive runtime root lock {}: {error}",
                    path.display()
                ),
            )
            .retryable(contended)
        })?;
        Ok(RootLock { _file: file })
    })
    .await
    .map_err(|error| {
        state_error(
            ErrorCode::Internal,
            "lock-state-root",
            format!("runtime root lock task failed: {error}"),
        )
    })?
}

#[cfg(windows)]
fn is_lock_contended(error: &io::Error) -> bool {
    use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION};

    error.kind() == io::ErrorKind::WouldBlock
        || error.raw_os_error().is_some_and(|code| {
            u32::try_from(code)
                .is_ok_and(|code| matches!(code, ERROR_LOCK_VIOLATION | ERROR_SHARING_VIOLATION))
        })
}

#[cfg(not(windows))]
fn is_lock_contended(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
}

#[cfg(not(windows))]
pub(super) async fn create_private_directory(path: &Path) -> Result<()> {
    tokio::fs::create_dir(path)
        .await
        .map_err(|error| io_error("create-state-directory", path, error))?;
    set_private_directory_permissions(path).await
}

#[cfg(unix)]
pub(super) async fn set_private_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .await
        .map_err(|error| io_error("protect-state-directory", path, error))
}

#[cfg(windows)]
pub(super) async fn create_private_directory(path: &Path) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || super::windows_security::create_private_directory(&path))
        .await
        .map_err(|error| {
            state_error(
                ErrorCode::Internal,
                "create-state-directory",
                format!("Windows state-directory task failed: {error}"),
            )
        })?
}

#[cfg(windows)]
pub(super) async fn set_private_directory_permissions(path: &Path) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || super::windows_security::protect_path(&path))
        .await
        .map_err(|error| {
            state_error(
                ErrorCode::Internal,
                "protect-state-directory",
                format!("Windows state-directory protection task failed: {error}"),
            )
        })?
}

#[cfg(all(not(unix), not(windows)))]
pub(super) async fn set_private_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

pub(super) async fn ensure_plain_directory(path: &Path, label: &str) -> Result<()> {
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

pub(super) async fn ensure_plain_file(path: &Path, label: &str) -> Result<()> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|error| io_error("inspect-state-file", path, error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "inspect-state-file",
            format!("{label} is not a plain file: {}", path.display()),
        ));
    }
    if metadata.len() > MAX_STATE_FILE_BYTES {
        return Err(state_error(
            ErrorCode::ResourceExhausted,
            "inspect-state-file",
            format!(
                "{label} exceeds {MAX_STATE_FILE_BYTES} bytes: {}",
                path.display()
            ),
        ));
    }
    set_private_file_permissions(path).await?;
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

pub(super) async fn path_exists(path: &Path) -> Result<bool> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error("inspect-state-path", path, error)),
    }
}

pub(super) async fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = read_bytes(path).await?;
    serde_json::from_slice(&bytes).map_err(|error| {
        state_error(
            ErrorCode::FailedPrecondition,
            "decode-state-file",
            format!("invalid durable state {}: {error}", path.display()),
        )
    })
}

pub(super) async fn read_utf8(path: &Path) -> Result<String> {
    let bytes = read_bytes(path).await?;
    String::from_utf8(bytes).map_err(|error| {
        state_error(
            ErrorCode::FailedPrecondition,
            "decode-state-file",
            format!("durable state {} is not UTF-8: {error}", path.display()),
        )
    })
}

async fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    ensure_plain_file(path, "durable state file").await?;
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|error| io_error("open-state-file", path, error))?;
    let mut bytes = Vec::new();
    file.take(MAX_STATE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| io_error("read-state-file", path, error))?;
    if bytes.len() as u64 > MAX_STATE_FILE_BYTES {
        return Err(state_error(
            ErrorCode::ResourceExhausted,
            "read-state-file",
            format!(
                "durable state exceeds {MAX_STATE_FILE_BYTES} bytes: {}",
                path.display()
            ),
        ));
    }
    Ok(bytes)
}

pub(super) async fn atomic_write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| {
        state_error(
            ErrorCode::Internal,
            "encode-state-file",
            format!("failed to encode durable state {}: {error}", path.display()),
        )
    })?;
    bytes.push(b'\n');
    atomic_write(path, &bytes).await
}

pub(super) async fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 > MAX_STATE_FILE_BYTES {
        return Err(state_error(
            ErrorCode::ResourceExhausted,
            "write-state-file",
            format!(
                "durable state exceeds {MAX_STATE_FILE_BYTES} bytes: {}",
                path.display()
            ),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        state_error(
            ErrorCode::Internal,
            "write-state-file",
            format!("durable state path has no parent: {}", path.display()),
        )
    })?;
    ensure_plain_directory(parent, "durable state parent").await?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            state_error(
                ErrorCode::Internal,
                "write-state-file",
                format!(
                    "durable state filename is not valid UTF-8: {}",
                    path.display()
                ),
            )
        })?;
    let temporary = parent.join(format!(".{file_name}.next"));
    if path_exists(&temporary).await? {
        ensure_plain_file(&temporary, "state transaction file").await?;
        tokio::fs::remove_file(&temporary)
            .await
            .map_err(|error| io_error("remove-stale-state-transaction", &temporary, error))?;
    }
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .await
        .map_err(|error| io_error("create-state-file", &temporary, error))?;
    set_private_file_permissions(&temporary).await?;
    file.write_all(bytes)
        .await
        .map_err(|error| io_error("write-state-file", &temporary, error))?;
    file.flush()
        .await
        .map_err(|error| io_error("flush-state-file", &temporary, error))?;
    file.sync_all()
        .await
        .map_err(|error| io_error("sync-state-file", &temporary, error))?;
    drop(file);
    atomic_replace(&temporary, path).await?;
    sync_parent(parent).await
}

pub(super) async fn atomic_move_directory(source: &Path, destination: &Path) -> Result<()> {
    ensure_plain_directory(source, "state transaction source").await?;
    if path_exists(destination).await? {
        return Err(state_error(
            ErrorCode::Conflict,
            "commit-state-directory",
            format!(
                "state transaction destination already exists: {}",
                destination.display()
            ),
        ));
    }
    let source_parent = source.parent().ok_or_else(|| {
        state_error(
            ErrorCode::Internal,
            "commit-state-directory",
            format!("state source has no parent: {}", source.display()),
        )
    })?;
    let destination_parent = destination.parent().ok_or_else(|| {
        state_error(
            ErrorCode::Internal,
            "commit-state-directory",
            format!("state destination has no parent: {}", destination.display()),
        )
    })?;
    ensure_plain_directory(source_parent, "state transaction source parent").await?;
    ensure_plain_directory(destination_parent, "state transaction destination parent").await?;
    move_directory(source, destination).await?;
    sync_parent(source_parent).await?;
    if source_parent != destination_parent {
        sync_parent(destination_parent).await?;
    }
    Ok(())
}

#[cfg(unix)]
async fn move_directory(source: &Path, destination: &Path) -> Result<()> {
    tokio::fs::rename(source, destination)
        .await
        .map_err(|error| io_error("commit-state-directory", destination, error))
}

#[cfg(windows)]
async fn move_directory(source: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};

    let source_wide = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination_wide = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: both path buffers are live, immutable, and NUL-terminated.
    let result = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(io_error(
            "commit-state-directory",
            destination,
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
async fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
    tokio::fs::rename(source, destination)
        .await
        .map_err(|error| io_error("commit-state-file", destination, error))
}

#[cfg(windows)]
async fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let destination_display = destination.display().to_string();
    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: both slices are NUL-terminated, live for the duration of the
    // call, and point to distinct immutable UTF-16 path buffers.
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
            Path::new(&destination_display),
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
async fn set_private_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .await
        .map_err(|error| io_error("protect-state-file", path, error))
}

#[cfg(not(unix))]
#[cfg(not(windows))]
async fn set_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
async fn set_private_file_permissions(path: &Path) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || super::windows_security::protect_path(&path))
        .await
        .map_err(|error| {
            state_error(
                ErrorCode::Internal,
                "protect-state-file",
                format!("Windows state-file protection task failed: {error}"),
            )
        })?
}

#[cfg(unix)]
async fn sync_parent(path: &Path) -> Result<()> {
    tokio::fs::File::open(path)
        .await
        .map_err(|error| io_error("open-state-directory", path, error))?
        .sync_all()
        .await
        .map_err(|error| io_error("sync-state-directory", path, error))
}

#[cfg(not(unix))]
async fn sync_parent(_path: &Path) -> Result<()> {
    Ok(())
}

pub(super) fn state_error(
    code: ErrorCode,
    operation: &'static str,
    message: impl Into<String>,
) -> Error {
    Error::new(code, message).for_operation(operation)
}

fn io_error(operation: &'static str, path: &Path, error: io::Error) -> Error {
    state_error(
        ErrorCode::Internal,
        operation,
        format!("{}: {error}", path.display()),
    )
}
