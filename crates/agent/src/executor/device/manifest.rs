use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};

use a3s_oci_sdk::{Error, ErrorCode, Result};

use crate::executor::recovery::read_json_record;

use super::mount_source::{
    metadata_for_fd, openat2_beneath, path_cstring, target_metadata_from_stat,
};
use super::types::{
    DeviceRootfsRecord, DeviceTargetManifest, DeviceTargetRecord, PreparedDeviceSources,
    TargetMetadata,
};
use super::{device_error, last_os_error};

pub(super) const DEVICE_TARGETS_RECORD_NAME: &str = "device-targets.json";
pub(super) const DEVICE_TARGETS_SCHEMA_VERSION: &str = "a3s.oci.native-linux-device-targets.v2";
const DEVICE_TARGETS_SCHEMA_VERSION_V1: &str = "a3s.oci.native-linux-device-targets.v1";
const MAX_DEVICE_TARGETS_RECORD_BYTES: u64 = 64 * 1024;
const DEVICE_TARGET_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const DEVICE_TARGET_CLEANUP_POLL_INTERVAL: Duration = Duration::from_millis(10);
impl DeviceTargetRecord {
    pub(super) fn capture(relative_path: &Path, metadata: &fs::Metadata) -> Result<Self> {
        validate_device_target_relative_path(relative_path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "device bind target is not a regular file placeholder: {}",
                    relative_path.display()
                ),
            ));
        }
        Ok(Self {
            relative_path: relative_path.to_path_buf(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode: metadata.mode() & 0o7777,
            uid: metadata.uid(),
            gid: metadata.gid(),
        })
    }

    pub(super) fn capture_for_cleanup(
        relative_path: &Path,
        metadata: &fs::Metadata,
        target_host_owner: Option<(u32, u32)>,
    ) -> Result<Self> {
        let mut record = Self::capture(relative_path, metadata)?;
        if let Some((uid, gid)) = target_host_owner {
            // The placeholder is created after entering the container user
            // namespace, where its mapped ownership is reported as 0:0. The
            // supervisor later performs cleanup in the initial user namespace
            // and must compare against the corresponding host IDs.
            record.uid = uid;
            record.gid = gid;
        }
        Ok(record)
    }

    pub(super) fn matches(&self, metadata: &TargetMetadata) -> bool {
        metadata.file_type == libc::S_IFREG
            && metadata.dev == self.dev
            && metadata.ino == self.ino
            && metadata.mode == self.mode
            && metadata.uid == self.uid
            && metadata.gid == self.gid
    }
}

impl DeviceRootfsRecord {
    pub(super) fn capture(canonical_rootfs: &Path) -> Result<Self> {
        validate_device_rootfs_path(canonical_rootfs)?;
        let metadata = fs::symlink_metadata(canonical_rootfs).map_err(|error| {
            device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to inspect device target rootfs {}: {error}",
                    canonical_rootfs.display()
                ),
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                format!(
                    "device target rootfs is not a real directory: {}",
                    canonical_rootfs.display()
                ),
            ));
        }
        Ok(Self {
            canonical_path: canonical_rootfs.to_path_buf(),
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
}

impl PreparedDeviceSources {
    /// Bind the cleanup manifest to the exact retained rootfs before the
    /// supervised child enters its mount namespace.
    pub(in crate::executor) fn bind_rootfs(&self, rootfs: &Path) -> Result<()> {
        if self.sources.is_none() || self.manifest_path.is_none() {
            return Ok(());
        }
        let canonical_rootfs = rootfs.canonicalize().map_err(|error| {
            device_error(
                ErrorCode::InvalidArgument,
                format!(
                    "failed to resolve device target rootfs {}: {error}",
                    rootfs.display()
                ),
            )
        })?;
        let manifest = DeviceTargetManifest {
            schema_version: DEVICE_TARGETS_SCHEMA_VERSION.to_string(),
            rootfs: DeviceRootfsRecord::capture(&canonical_rootfs)?,
            targets: Vec::new(),
        };
        let mut retained = self.manifest.lock().map_err(|_| {
            device_error(
                ErrorCode::Internal,
                "prepared device target manifest state was poisoned",
            )
        })?;
        if retained.is_some() {
            return Err(device_error(
                ErrorCode::Conflict,
                "prepared device target rootfs was already bound",
            ));
        }
        let manifest_path = self.manifest_path.as_ref().ok_or_else(|| {
            device_error(
                ErrorCode::Internal,
                "prepared device target manifest path was not retained",
            )
        })?;
        write_device_target_manifest(manifest_path, &manifest)?;
        let manifest_file = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(manifest_path)
            .map_err(|error| manifest_persistence_error(manifest_path, error))?;
        let mut retained_file = self.manifest_file.lock().map_err(|_| {
            device_error(
                ErrorCode::Internal,
                "prepared device target manifest file state was poisoned",
            )
        })?;
        if retained_file.is_some() {
            return Err(device_error(
                ErrorCode::Conflict,
                "prepared device target manifest file was already opened",
            ));
        }
        *retained_file = Some(manifest_file);
        *retained = Some(manifest);
        Ok(())
    }

    pub(super) fn record_device_target(&self, record: DeviceTargetRecord) -> Result<()> {
        let Some(manifest_path) = &self.manifest_path else {
            return Err(device_error(
                ErrorCode::Internal,
                "prepared device target manifest path was not retained",
            ));
        };
        let mut retained = self.manifest.lock().map_err(|_| {
            device_error(
                ErrorCode::Internal,
                "prepared device target manifest state was poisoned",
            )
        })?;
        let manifest = retained.as_mut().ok_or_else(|| {
            device_error(
                ErrorCode::Internal,
                "prepared device target rootfs identity was not retained",
            )
        })?;
        if manifest
            .targets
            .iter()
            .any(|target| target.relative_path == record.relative_path)
        {
            return Err(device_error(
                ErrorCode::Conflict,
                format!(
                    "prepared device target was recorded twice: {}",
                    record.relative_path.display()
                ),
            ));
        }
        manifest.targets.push(record.clone());
        let write_result = self
            .manifest_file
            .lock()
            .map_err(|_| {
                device_error(
                    ErrorCode::Internal,
                    "prepared device target manifest file state was poisoned",
                )
            })?
            .as_mut()
            .ok_or_else(|| {
                device_error(
                    ErrorCode::Internal,
                    "prepared device target manifest file was not opened",
                )
            })
            .and_then(|file| overwrite_device_target_manifest(file, manifest_path, manifest));
        if let Err(error) = write_result {
            let removed = manifest.targets.pop();
            if removed.as_ref() != Some(&record) {
                return Err(device_error(
                    ErrorCode::Internal,
                    "prepared device target manifest rollback lost its last record",
                ));
            }
            return Err(error);
        }
        Ok(())
    }

    /// Persist a placeholder before it can become a device bind target.
    ///
    /// Callers invoke this only after creating `target` with `create_new`.
    /// Any inspection or persistence failure removes that untrusted-to-keep
    /// placeholder, so supervisor cleanup never depends on an unrecorded path.
    pub(super) fn record_created_target(&self, target: &Path, relative_path: &Path) -> Result<()> {
        let recorded = fs::symlink_metadata(target)
            .map_err(|error| {
                device_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "failed to inspect newly created OCI device bind target {}: {error}",
                        target.display()
                    ),
                )
            })
            .and_then(|metadata| {
                DeviceTargetRecord::capture_for_cleanup(
                    relative_path,
                    &metadata,
                    self.target_host_owner,
                )
            })
            .and_then(|record| self.record_device_target(record));
        let Err(error) = recorded else {
            return Ok(());
        };

        match fs::remove_file(target) {
            Ok(()) => Err(error),
            Err(rollback) if rollback.kind() == io::ErrorKind::NotFound => Err(error),
            Err(rollback) => Err(device_error(
                ErrorCode::Internal,
                format!(
                    "{error}; failed to roll back unrecorded OCI device placeholder {}: {rollback}",
                    target.display()
                ),
            )),
        }
    }
}

pub(in crate::executor) fn load_device_target_manifest(
    runtime_directory: &Path,
) -> Result<Option<DeviceTargetManifest>> {
    load_device_target_manifest_from(&runtime_directory.join(DEVICE_TARGETS_RECORD_NAME))
}

pub(super) fn load_device_target_manifest_from(
    path: &Path,
) -> Result<Option<DeviceTargetManifest>> {
    let value: serde_json::Value = match fs::symlink_metadata(path) {
        Ok(_) => read_json_record(path, MAX_DEVICE_TARGETS_RECORD_BYTES)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to inspect prepared OCI device target manifest {}: {error}",
                    path.display()
                ),
            ));
        }
    };
    let schema_version = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "prepared OCI device target manifest {} has no schema version",
                    path.display()
                ),
            )
        })?;
    if schema_version == DEVICE_TARGETS_SCHEMA_VERSION_V1 {
        return Err(device_error(
            ErrorCode::PermissionDenied,
            format!(
                "prepared OCI device target manifest {} uses legacy v1 absolute paths without a rootfs identity; refusing cleanup",
                path.display()
            ),
        ));
    }
    if schema_version != DEVICE_TARGETS_SCHEMA_VERSION {
        return Err(device_error(
            ErrorCode::FailedPrecondition,
            format!(
                "prepared OCI device target manifest {} has unsupported schema {schema_version}",
                path.display()
            ),
        ));
    }
    let manifest: DeviceTargetManifest = serde_json::from_value(value).map_err(|error| {
        device_error(
            ErrorCode::FailedPrecondition,
            format!(
                "prepared OCI device target manifest {} is invalid: {error}",
                path.display()
            ),
        )
    })?;
    validate_device_target_manifest(&manifest)?;
    Ok(Some(manifest))
}

pub(super) fn write_device_target_manifest(
    path: &Path,
    manifest: &DeviceTargetManifest,
) -> Result<()> {
    let encoded = encode_device_target_manifest(manifest)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            device_error(
                ErrorCode::InvalidArgument,
                format!(
                    "prepared OCI device target manifest has no UTF-8 filename: {}",
                    path.display()
                ),
            )
        })?;
    let pending = path.with_file_name(format!(".{name}.next"));
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let result = (|| -> io::Result<()> {
        let mut file = options.open(&pending)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        fs::rename(&pending, path)?;
        fs::File::open(path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "prepared device manifest has no parent",
            )
        })?)?
        .sync_all()
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&pending);
        return Err(manifest_persistence_error(path, error));
    }
    Ok(())
}

fn overwrite_device_target_manifest(
    file: &mut File,
    path: &Path,
    manifest: &DeviceTargetManifest,
) -> Result<()> {
    let encoded = encode_device_target_manifest(manifest)?;
    // The trusted launcher opens this supervisor-owned record before entering
    // a mapped user namespace. Updating through that retained descriptor keeps
    // the private runtime directory inaccessible to container credentials.
    let result = (|| -> io::Result<()> {
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&encoded)?;
        file.set_len(encoded.len() as u64)?;
        file.sync_all()
    })();
    result.map_err(|error| manifest_persistence_error(path, error))
}

fn encode_device_target_manifest(manifest: &DeviceTargetManifest) -> Result<Vec<u8>> {
    validate_device_target_manifest(manifest)?;
    let mut encoded = serde_json::to_vec_pretty(manifest).map_err(|error| {
        device_error(
            ErrorCode::Internal,
            format!("failed to encode prepared OCI device target manifest: {error}"),
        )
    })?;
    encoded.push(b'\n');
    if encoded.len() as u64 > MAX_DEVICE_TARGETS_RECORD_BYTES {
        return Err(device_error(
            ErrorCode::ResourceExhausted,
            "prepared OCI device target manifest exceeds its bounded size",
        ));
    }
    Ok(encoded)
}

fn manifest_persistence_error(path: &Path, error: io::Error) -> Error {
    device_error(
        match error.kind() {
            io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
            io::ErrorKind::AlreadyExists => ErrorCode::Conflict,
            _ => ErrorCode::Internal,
        },
        format!(
            "failed to persist prepared OCI device target manifest {}: {error}",
            path.display()
        ),
    )
}

fn validate_device_target_manifest(manifest: &DeviceTargetManifest) -> Result<()> {
    if manifest.schema_version != DEVICE_TARGETS_SCHEMA_VERSION {
        return Err(device_error(
            ErrorCode::FailedPrecondition,
            format!(
                "prepared OCI device target manifest has unsupported schema {}",
                manifest.schema_version
            ),
        ));
    }
    validate_device_rootfs_path(&manifest.rootfs.canonical_path)?;
    let mut paths = BTreeSet::new();
    for record in &manifest.targets {
        validate_device_target_relative_path(&record.relative_path)?;
        if record.mode > 0o7777 {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                format!(
                    "device bind target record has invalid mode for {}",
                    record.relative_path.display()
                ),
            ));
        }
        if !paths.insert(record.relative_path.clone()) {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                format!(
                    "device bind target record is duplicated: {}",
                    record.relative_path.display()
                ),
            ));
        }
    }
    Ok(())
}

pub(in crate::executor) fn cleanup_device_target_manifest(
    manifest: &DeviceTargetManifest,
) -> Result<()> {
    validate_device_target_manifest(manifest)?;
    let rootfs = open_device_rootfs(&manifest.rootfs)?;

    // Validate every target before the first unlink. Each target is opened
    // again immediately before mutation to close ordinary replacement races.
    for record in &manifest.targets {
        wait_for_recorded_target(&rootfs, &manifest.rootfs, record)?;
    }

    let mut failures = Vec::new();
    for record in manifest.targets.iter().rev() {
        if let Err(error) = cleanup_recorded_target(&rootfs, &manifest.rootfs, record) {
            failures.push(format!("{}: {error}", record.relative_path.display()));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(device_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to clean recorded OCI device targets: {}",
                failures.join("; ")
            ),
        ))
    }
}

fn cleanup_recorded_target(
    rootfs: &OwnedFd,
    rootfs_record: &DeviceRootfsRecord,
    record: &DeviceTargetRecord,
) -> Result<()> {
    if !wait_for_recorded_target(rootfs, rootfs_record, record)? {
        return Ok(());
    }
    let parent = open_device_target_parent(rootfs, &record.relative_path)?;
    let name = record
        .relative_path
        .file_name()
        .ok_or_else(|| device_error(ErrorCode::Internal, "device target has no filename"))?;
    let name = CString::new(name.as_bytes()).map_err(|error| {
        device_error(
            ErrorCode::PermissionDenied,
            format!("device target filename contains NUL: {error}"),
        )
    })?;
    let metadata = metadata_at(parent.as_raw_fd(), &name)?;
    let Some(metadata) = metadata else {
        return Ok(());
    };
    if !record.matches(&metadata) {
        return Err(device_error(
            ErrorCode::Conflict,
            format!(
                "device bind target changed immediately before cleanup: {}",
                rootfs_record
                    .canonical_path
                    .join(&record.relative_path)
                    .display()
            ),
        ));
    }
    // SAFETY: `parent` is a descriptor opened beneath the exact retained
    // rootfs and `name` is one validated normal path component.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(device_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to remove recorded OCI device target {}: {error}",
                rootfs_record
                    .canonical_path
                    .join(&record.relative_path)
                    .display()
            ),
        ));
    }
    Ok(())
}

fn validate_device_rootfs_path(path: &Path) -> Result<()> {
    if path == Path::new("/")
        || !path.is_absolute()
        || path.as_os_str().as_bytes().contains(&0)
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(device_error(
            ErrorCode::PermissionDenied,
            format!(
                "device target rootfs must be a normalized absolute non-root path: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn validate_device_target_relative_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.as_os_str().as_bytes().contains(&0)
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(device_error(
            ErrorCode::PermissionDenied,
            format!(
                "device bind target record must be relative and normalized: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn open_device_rootfs(record: &DeviceRootfsRecord) -> Result<OwnedFd> {
    validate_device_rootfs_path(&record.canonical_path)?;
    let observed_canonical = record.canonical_path.canonicalize().map_err(|error| {
        device_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to resolve recorded device target rootfs {}: {error}",
                record.canonical_path.display()
            ),
        )
    })?;
    if observed_canonical != record.canonical_path {
        return Err(device_error(
            ErrorCode::Conflict,
            format!(
                "recorded device target rootfs is no longer canonical: {}",
                record.canonical_path.display()
            ),
        ));
    }
    let path = path_cstring(&record.canonical_path, "recorded device target rootfs")?;
    // SAFETY: `path` is NUL-terminated and open does not retain the pointer.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(last_os_error(format!(
            "open recorded device target rootfs {}",
            record.canonical_path.display()
        )));
    }
    // SAFETY: `descriptor` is a fresh descriptor returned by open.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let metadata = metadata_for_fd(&descriptor)?;
    if metadata.file_type != libc::S_IFDIR
        || metadata.dev != record.dev
        || metadata.ino != record.ino
    {
        return Err(device_error(
            ErrorCode::Conflict,
            format!(
                "recorded device target rootfs identity changed before cleanup: {}",
                record.canonical_path.display()
            ),
        ));
    }
    Ok(descriptor)
}

fn wait_for_recorded_target(
    rootfs: &OwnedFd,
    rootfs_record: &DeviceRootfsRecord,
    record: &DeviceTargetRecord,
) -> Result<bool> {
    let deadline = Instant::now() + DEVICE_TARGET_CLEANUP_TIMEOUT;
    loop {
        match open_device_target(rootfs, &record.relative_path)? {
            None => return Ok(false),
            Some(target) => {
                let metadata = metadata_for_fd(&target)?;
                if record.matches(&metadata) {
                    return Ok(true);
                }
                if Instant::now() >= deadline {
                    return Err(device_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "device bind target never returned to its recorded placeholder before cleanup: {} (expected {}; observed {})",
                            rootfs_record
                                .canonical_path
                                .join(&record.relative_path)
                                .display(),
                            describe_device_metadata(
                                record.dev,
                                record.ino,
                                record.mode,
                                record.uid,
                                record.gid
                            ),
                            describe_target_metadata(&metadata),
                        ),
                    ));
                }
            }
        }
        sleep(DEVICE_TARGET_CLEANUP_POLL_INTERVAL);
    }
}

fn open_device_target(rootfs: &OwnedFd, relative_path: &Path) -> Result<Option<OwnedFd>> {
    validate_device_target_relative_path(relative_path)?;
    openat2_beneath(
        rootfs.as_raw_fd(),
        relative_path,
        libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        false,
    )
}

fn open_device_target_parent(rootfs: &OwnedFd, relative_path: &Path) -> Result<OwnedFd> {
    validate_device_target_relative_path(relative_path)?;
    let parent = relative_path.parent().unwrap_or_else(|| Path::new(""));
    if parent.as_os_str().is_empty() {
        // SAFETY: fcntl duplicates the live rootfs descriptor and returns a new
        // owned descriptor on success.
        let descriptor = unsafe { libc::fcntl(rootfs.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if descriptor < 0 {
            return Err(last_os_error("duplicate device target rootfs descriptor"));
        }
        // SAFETY: descriptor is freshly returned by F_DUPFD_CLOEXEC.
        return Ok(unsafe { OwnedFd::from_raw_fd(descriptor) });
    }
    openat2_beneath(
        rootfs.as_raw_fd(),
        parent,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        true,
    )?
    .ok_or_else(|| {
        device_error(
            ErrorCode::FailedPrecondition,
            format!("device target parent disappeared: {}", parent.display()),
        )
    })
}

fn metadata_at(directory: libc::c_int, name: &CString) -> Result<Option<TargetMetadata>> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `directory` is live, name is NUL-terminated, and metadata points
    // to writable storage for one stat result.
    if unsafe {
        libc::fstatat(
            directory,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(device_error(
            ErrorCode::FailedPrecondition,
            format!("failed to revalidate device target before cleanup: {error}"),
        ));
    }
    // SAFETY: fstatat succeeded and initialized metadata.
    Ok(Some(target_metadata_from_stat(unsafe {
        &metadata.assume_init()
    })))
}

fn describe_device_metadata(dev: u64, ino: u64, mode: u32, uid: u32, gid: u32) -> String {
    format!("dev={dev} ino={ino} mode={mode:04o} uid={uid} gid={gid}")
}

fn describe_target_metadata(metadata: &TargetMetadata) -> String {
    describe_device_metadata(
        metadata.dev,
        metadata.ino,
        metadata.mode,
        metadata.uid,
        metadata.gid,
    )
}
