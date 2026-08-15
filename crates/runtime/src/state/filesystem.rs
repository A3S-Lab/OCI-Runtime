use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

mod platform;
mod transaction;

use a3s_oci_sdk::{Error, ErrorCode, Result};
use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use serde::de::DeserializeOwned;
use tokio::io::AsyncReadExt;

use crate::fault::{DurableMutation, FaultInjector};
#[cfg(unix)]
use cap_std::fs::{DirBuilder, DirBuilderExt, OpenOptionsExt, Permissions, PermissionsExt};
#[cfg(unix)]
use std::os::fd::AsRawFd;

use super::model::{RuntimeRootMarker, ROOT_SCHEMA_VERSION};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use platform::mount_identity;
use platform::{
    ambient_path_exists, create_ambient_private_directory, ensure_ambient_plain_directory,
    is_lock_contended,
};

const ROOT_MARKER_FILE: &str = "root.json";
const ROOT_MARKER_TRANSACTION_FILE: &str = ".root.json.next";
const LOCK_FILE: &str = ".lock";
// A durable File upload record contains the caller's exact base64 request.
// The public decoded payload limit is 32 MiB, whose canonical JSON encoding
// remains below this fixed bound.
const MAX_STATE_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct RootLock {
    _file: std::fs::File,
}

/// Capability root for every durable-state filesystem operation.
///
/// The display path is retained only for diagnostics and Windows DACL APIs.
/// All traversal, reads, enumeration, creation, replacement, and directory
/// moves start from the pinned directory handle.
#[derive(Debug, Clone)]
pub(super) struct StateFilesystem {
    display_root: Arc<PathBuf>,
    root: Arc<Dir>,
    root_device: u64,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    root_mount: MountIdentity,
}

#[cfg(target_os = "linux")]
type MountIdentity = u64;

#[cfg(target_os = "macos")]
type MountIdentity = [i32; 2];

pub(super) async fn open_root(
    path: &Path,
    faults: &dyn FaultInjector,
) -> Result<(Arc<StateFilesystem>, Arc<RootLock>)> {
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

    let root = if ambient_path_exists(path).await? {
        ensure_ambient_plain_directory(path, "runtime state root").await?;
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
        ensure_ambient_plain_directory(&parent, "runtime state root parent").await?;
        let candidate = parent.join(name);
        create_ambient_private_directory(&candidate).await?;
        tokio::fs::canonicalize(&candidate)
            .await
            .map_err(|error| io_error("canonicalize-state-root", &candidate, error))?
    };

    let filesystem = Arc::new(StateFilesystem::open(root).await?);
    filesystem
        .set_private_directory_permissions(filesystem.root())
        .await?;
    let root_lock = filesystem.acquire_root_lock().await?;
    initialize_layout(filesystem.as_ref(), faults).await?;
    Ok((filesystem, Arc::new(root_lock)))
}

impl StateFilesystem {
    async fn open(root: PathBuf) -> Result<Self> {
        let display = root.clone();
        run_blocking("open-state-root-capability", move || {
            let parent_path = root.parent().ok_or_else(|| {
                state_error(
                    ErrorCode::InvalidArgument,
                    "open-state-root-capability",
                    format!("runtime state root has no parent: {}", root.display()),
                )
            })?;
            let name = root.file_name().ok_or_else(|| {
                state_error(
                    ErrorCode::InvalidArgument,
                    "open-state-root-capability",
                    format!(
                        "runtime state root has no final component: {}",
                        root.display()
                    ),
                )
            })?;
            let parent = Dir::open_ambient_dir(parent_path, ambient_authority())
                .map_err(|error| io_error("open-state-root-parent", parent_path, error))?;
            let directory = parent.open_dir_nofollow(name).map_err(|error| {
                state_error(
                    ErrorCode::FailedPrecondition,
                    "open-state-root-capability",
                    format!(
                        "runtime state root is not a plain directory: {}: {error}",
                        root.display()
                    ),
                )
            })?;
            let metadata = directory
                .dir_metadata()
                .map_err(|error| io_error("inspect-state-root-capability", &root, error))?;
            if !metadata.is_dir() {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "open-state-root-capability",
                    format!("runtime state root is not a directory: {}", root.display()),
                ));
            }
            let root_device = metadata.dev();
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            let root_mount = mount_identity(directory.as_raw_fd())
                .map_err(|error| io_error("inspect-state-root-mount", &root, error))?;
            Ok(Self {
                display_root: Arc::new(root),
                root: Arc::new(directory),
                root_device,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                root_mount,
            })
        })
        .await
        .map_err(|error| {
            if error.operation.as_deref() == Some("open-state-root-capability") {
                error
            } else {
                state_error(
                    error.code,
                    "open-state-root-capability",
                    format!(
                        "failed to pin runtime state root {}: {}",
                        display.display(),
                        error
                    ),
                )
            }
        })
    }

    pub(super) fn root(&self) -> &Path {
        self.display_root.as_ref()
    }

    pub(super) async fn path_exists(&self, path: &Path) -> Result<bool> {
        let filesystem = self.clone();
        let path = path.to_path_buf();
        run_blocking("inspect-state-path", move || {
            let (parent, name) = filesystem.resolve_parent(&path, "durable state path")?;
            match parent.symlink_metadata(&name) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(io_error("inspect-state-path", &path, error)),
            }
        })
        .await
    }

    pub(super) async fn ensure_plain_directory(&self, path: &Path, label: &str) -> Result<()> {
        let filesystem = self.clone();
        let path = path.to_path_buf();
        let label = label.to_string();
        run_blocking("inspect-state-directory", move || {
            filesystem.resolve_directory(&path, &label).map(|_| ())
        })
        .await
    }

    pub(super) async fn ensure_plain_file(&self, path: &Path, label: &str) -> Result<()> {
        let filesystem = self.clone();
        let path = path.to_path_buf();
        let label = label.to_string();
        run_blocking("inspect-state-file", move || {
            let file = filesystem.open_plain_file(&path, &label)?;
            filesystem.protect_file(&file, &path)
        })
        .await
    }

    pub(super) async fn create_private_directory(&self, path: &Path) -> Result<()> {
        let filesystem = self.clone();
        let path = path.to_path_buf();
        run_blocking("create-state-directory", move || {
            let (parent, name) = filesystem.resolve_parent(&path, "state directory parent")?;
            #[cfg(unix)]
            {
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                parent
                    .create_dir_with(&name, &builder)
                    .map_err(|error| io_error("create-state-directory", &path, error))?;
            }
            #[cfg(windows)]
            crate::windows_security::create_private_directory(&path)?;
            #[cfg(all(not(unix), not(windows)))]
            parent
                .create_dir(&name)
                .map_err(|error| io_error("create-state-directory", &path, error))?;

            let directory = parent.open_dir_nofollow(&name).map_err(|error| {
                state_error(
                    ErrorCode::FailedPrecondition,
                    "create-state-directory",
                    format!(
                        "new durable state directory is not plain: {}: {error}",
                        path.display()
                    ),
                )
            })?;
            filesystem.verify_directory_location(&directory, &path)?;
            filesystem.protect_directory(&directory, &path)
        })
        .await
    }

    pub(super) async fn set_private_directory_permissions(&self, path: &Path) -> Result<()> {
        let filesystem = self.clone();
        let path = path.to_path_buf();
        run_blocking("protect-state-directory", move || {
            let directory = filesystem.resolve_directory(&path, "durable state directory")?;
            filesystem.protect_directory(&directory, &path)
        })
        .await
    }

    pub(super) async fn read_json<T>(&self, path: &Path) -> Result<T>
    where
        T: DeserializeOwned + Send + 'static,
    {
        let bytes = self.read_bytes(path).await?;
        serde_json::from_slice(&bytes).map_err(|error| {
            state_error(
                ErrorCode::FailedPrecondition,
                "decode-state-file",
                format!("invalid durable state {}: {error}", path.display()),
            )
        })
    }

    pub(super) async fn read_utf8(&self, path: &Path) -> Result<String> {
        let bytes = self.read_bytes(path).await?;
        String::from_utf8(bytes).map_err(|error| {
            state_error(
                ErrorCode::FailedPrecondition,
                "decode-state-file",
                format!("durable state {} is not UTF-8: {error}", path.display()),
            )
        })
    }

    async fn read_bytes(&self, path: &Path) -> Result<Vec<u8>> {
        let filesystem = self.clone();
        let display = path.to_path_buf();
        let open_path = display.clone();
        let file = run_blocking("open-state-file", move || {
            let file = filesystem.open_plain_file(&open_path, "durable state file")?;
            filesystem.protect_file(&file, &open_path)?;
            Ok(file.into_std())
        })
        .await?;
        let file = tokio::fs::File::from_std(file);
        let mut bytes = Vec::new();
        file.take(MAX_STATE_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|error| io_error("read-state-file", &display, error))?;
        if bytes.len() as u64 > MAX_STATE_FILE_BYTES {
            return Err(state_error(
                ErrorCode::ResourceExhausted,
                "read-state-file",
                format!(
                    "durable state exceeds {MAX_STATE_FILE_BYTES} bytes: {}",
                    display.display()
                ),
            ));
        }
        Ok(bytes)
    }

    pub(super) async fn read_directory(&self, path: &Path, label: &str) -> Result<Vec<OsString>> {
        let filesystem = self.clone();
        let path = path.to_path_buf();
        let label = label.to_string();
        run_blocking("read-state-directory", move || {
            let directory = filesystem.resolve_directory(&path, &label)?;
            let entries = directory
                .entries()
                .map_err(|error| io_error("open-state-directory", &path, error))?;
            entries
                .map(|entry| {
                    entry
                        .map(|entry| entry.file_name())
                        .map_err(|error| io_error("read-state-directory", &path, error))
                })
                .collect()
        })
        .await
    }

    fn open_plain_file(&self, path: &Path, label: &str) -> Result<cap_std::fs::File> {
        let (parent, name) = self.resolve_parent(path, "durable state file parent")?;
        self.open_plain_file_in_parent(&parent, &name, path, label)
    }

    fn open_plain_file_in_parent(
        &self,
        parent: &Dir,
        name: &OsStr,
        display: &Path,
        label: &str,
    ) -> Result<cap_std::fs::File> {
        let mut options = OpenOptions::new();
        options.read(true);
        options.follow(FollowSymlinks::No);
        let file = parent.open_with(name, &options).map_err(|error| {
            state_error(
                ErrorCode::FailedPrecondition,
                "inspect-state-file",
                format!(
                    "{label} is not a plain file: {}: {error}",
                    display.display()
                ),
            )
        })?;
        let metadata = file
            .metadata()
            .map_err(|error| io_error("inspect-state-file", display, error))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "inspect-state-file",
                format!("{label} is not a plain file: {}", display.display()),
            ));
        }
        if metadata.len() > MAX_STATE_FILE_BYTES {
            return Err(state_error(
                ErrorCode::ResourceExhausted,
                "inspect-state-file",
                format!(
                    "{label} exceeds {MAX_STATE_FILE_BYTES} bytes: {}",
                    display.display()
                ),
            ));
        }
        self.verify_file_location(&file, display)?;
        Ok(file)
    }

    fn resolve_parent(&self, path: &Path, label: &str) -> Result<(Dir, OsString)> {
        let relative = self.relative_path(path)?;
        let name = relative.file_name().ok_or_else(|| {
            state_error(
                ErrorCode::Internal,
                "resolve-state-path",
                format!("{label} has no final component: {}", path.display()),
            )
        })?;
        let parent = relative.parent().unwrap_or_else(|| Path::new(""));
        let parent_display = path.parent().unwrap_or_else(|| self.root());
        let directory = self.resolve_relative_directory(parent, parent_display, label)?;
        Ok((directory, name.to_os_string()))
    }

    fn resolve_directory(&self, path: &Path, label: &str) -> Result<Dir> {
        let relative = self.relative_path(path)?;
        self.resolve_relative_directory(&relative, path, label)
    }

    fn resolve_relative_directory(
        &self,
        relative: &Path,
        display: &Path,
        label: &str,
    ) -> Result<Dir> {
        let mut current = self
            .root
            .try_clone()
            .map_err(|error| io_error("clone-state-root-capability", self.root(), error))?;
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(state_error(
                    ErrorCode::Internal,
                    "resolve-state-directory",
                    format!(
                        "{label} contains a non-normal path component: {}",
                        display.display()
                    ),
                ));
            };
            current = current.open_dir_nofollow(name).map_err(|error| {
                state_error(
                    ErrorCode::FailedPrecondition,
                    "inspect-state-directory",
                    format!(
                        "{label} is not a plain directory: {}: {error}",
                        display.display()
                    ),
                )
            })?;
            self.verify_directory_location(&current, display)?;
        }
        Ok(current)
    }

    fn relative_path(&self, path: &Path) -> Result<PathBuf> {
        let relative = path.strip_prefix(self.root()).map_err(|_| {
            state_error(
                ErrorCode::Internal,
                "resolve-state-path",
                format!(
                    "durable state path is outside the pinned runtime root {}: {}",
                    self.root().display(),
                    path.display()
                ),
            )
        })?;
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(state_error(
                ErrorCode::Internal,
                "resolve-state-path",
                format!(
                    "durable state path is not normalized below the pinned runtime root: {}",
                    path.display()
                ),
            ));
        }
        Ok(relative.to_path_buf())
    }

    fn verify_directory_location(&self, directory: &Dir, display: &Path) -> Result<()> {
        let metadata = directory
            .dir_metadata()
            .map_err(|error| io_error("inspect-state-directory", display, error))?;
        if !metadata.is_dir() || metadata.dev() != self.root_device {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "inspect-state-directory",
                format!(
                    "durable state directory crossed the pinned runtime filesystem: {}",
                    display.display()
                ),
            ));
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if mount_identity(directory.as_raw_fd())
            .map_err(|error| io_error("inspect-state-directory-mount", display, error))?
            != self.root_mount
        {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "inspect-state-directory-mount",
                format!(
                    "durable state directory crossed a mount boundary below the pinned runtime root: {}",
                    display.display()
                ),
            ));
        }
        Ok(())
    }

    fn verify_file_location(&self, file: &cap_std::fs::File, display: &Path) -> Result<()> {
        let metadata = file
            .metadata()
            .map_err(|error| io_error("inspect-state-file", display, error))?;
        if metadata.dev() != self.root_device {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "inspect-state-file",
                format!(
                    "durable state file crossed the pinned runtime filesystem: {}",
                    display.display()
                ),
            ));
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if mount_identity(file.as_raw_fd())
            .map_err(|error| io_error("inspect-state-file-mount", display, error))?
            != self.root_mount
        {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "inspect-state-file-mount",
                format!(
                    "durable state file crossed a mount boundary below the pinned runtime root: {}",
                    display.display()
                ),
            ));
        }
        Ok(())
    }

    fn protect_directory(&self, directory: &Dir, display: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            directory
                .set_permissions(".", Permissions::from_mode(0o700))
                .map_err(|error| io_error("protect-state-directory", display, error))?;
        }
        #[cfg(windows)]
        {
            let _retained = directory;
            crate::windows_security::protect_path(display)?;
        }
        Ok(())
    }

    fn protect_file(&self, file: &cap_std::fs::File, display: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            file.set_permissions(Permissions::from_mode(0o600))
                .map_err(|error| io_error("protect-state-file", display, error))?;
        }
        #[cfg(windows)]
        {
            let _retained = file;
            crate::windows_security::protect_path(display)?;
        }
        Ok(())
    }

    async fn acquire_root_lock(&self) -> Result<RootLock> {
        let filesystem = self.clone();
        run_blocking("lock-state-root", move || {
            let path = filesystem.root().join(LOCK_FILE);
            let (parent, name) = filesystem.resolve_parent(&path, "runtime root lock parent")?;
            match parent.symlink_metadata(&name) {
                Ok(metadata) => {
                    if !metadata.is_file() || metadata.file_type().is_symlink() {
                        return Err(state_error(
                            ErrorCode::FailedPrecondition,
                            "open-state-root-lock",
                            format!("runtime root lock is not a plain file: {}", path.display()),
                        ));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(io_error("inspect-state-root-lock", &path, error));
                }
            }
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true);
            options.follow(FollowSymlinks::No);
            #[cfg(unix)]
            options.mode(0o600);
            let file = parent
                .open_with(&name, &options)
                .map_err(|error| io_error("open-state-root-lock", &path, error))?;
            filesystem.verify_file_location(&file, &path)?;
            filesystem.protect_file(&file, &path)?;
            let file = file.into_std();
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
    }
}

async fn initialize_layout(filesystem: &StateFilesystem, faults: &dyn FaultInjector) -> Result<()> {
    let root = filesystem.root();
    let marker_path = root.join(ROOT_MARKER_FILE);
    if filesystem.path_exists(&marker_path).await? {
        filesystem
            .ensure_plain_file(&marker_path, "runtime root marker")
            .await?;
        let marker: RuntimeRootMarker = filesystem.read_json(&marker_path).await?;
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
        for entry in filesystem
            .read_directory(root, "runtime state root")
            .await?
        {
            if entry != LOCK_FILE && entry != ROOT_MARKER_TRANSACTION_FILE {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "open-state-root",
                    format!("uninitialized runtime root {} is not empty", root.display()),
                ));
            }
        }
        filesystem
            .atomic_write_json(
                faults,
                DurableMutation::RuntimeRootMarker,
                &marker_path,
                &RuntimeRootMarker::default(),
            )
            .await?;
    }

    for directory in [
        "containers",
        "generations",
        "operations",
        "quarantine",
        "events",
    ] {
        let path = root.join(directory);
        if filesystem.path_exists(&path).await? {
            filesystem.ensure_plain_directory(&path, directory).await?;
            filesystem.set_private_directory_permissions(&path).await?;
        } else {
            filesystem.create_private_directory(&path).await?;
        }
    }
    for directory in ["records", "keys"] {
        let path = root.join("events").join(directory);
        if filesystem.path_exists(&path).await? {
            filesystem
                .ensure_plain_directory(&path, "runtime event directory")
                .await?;
            filesystem.set_private_directory_permissions(&path).await?;
        } else {
            filesystem.create_private_directory(&path).await?;
        }
    }
    Ok(())
}

async fn run_blocking<T, F>(operation: &'static str, work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(work).await.map_err(|error| {
        state_error(
            ErrorCode::Internal,
            operation,
            format!("durable state filesystem task failed: {error}"),
        )
    })?
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

#[cfg(all(test, unix))]
mod tests {
    use std::path::Path;

    use super::StateFilesystem;
    use cap_std::{ambient_authority, fs::Dir};

    #[tokio::test]
    async fn rejects_a_directory_handle_from_another_mount() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("state");
        std::fs::create_dir(&root).expect("state root");
        let filesystem = StateFilesystem::open(root).await.expect("pin state root");
        let foreign = Dir::open_ambient_dir("/dev", ambient_authority())
            .expect("open a different mounted filesystem");

        let error = filesystem
            .verify_directory_location(&foreign, Path::new("/dev"))
            .expect_err("a foreign mount must fail the state-root identity check");

        assert_eq!(error.code, a3s_oci_sdk::ErrorCode::FailedPrecondition);
    }
}
