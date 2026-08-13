use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread::sleep;
use std::time::{Duration, Instant};

use a3s_oci_sdk::oci_spec::runtime::{
    Linux, LinuxDevice, LinuxDeviceCgroup, LinuxDeviceType, LinuxResources,
};
use a3s_oci_sdk::{Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};

use super::mount::MountPlan;
use super::namespace::NamespacePlan;
use super::recovery::read_json_record;

const MAX_DEVICES: usize = 256;
const MAX_SCANNED_ROOTFS_ENTRIES: usize = 1_000_000;
const DEVICE_TARGETS_RECORD_NAME: &str = "device-targets.json";
const DEVICE_TARGETS_SCHEMA_VERSION: &str = "a3s.oci.native-linux-device-targets.v2";
const DEVICE_TARGETS_SCHEMA_VERSION_V1: &str = "a3s.oci.native-linux-device-targets.v1";
const MAX_DEVICE_TARGETS_RECORD_BYTES: u64 = 64 * 1024;
const DEVICE_TARGET_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const DEVICE_TARGET_CLEANUP_POLL_INTERVAL: Duration = Duration::from_millis(10);
const ROOTLESS_SAFE_DEVICES: [(&str, DeviceKind, u32, u32); 6] = [
    ("/dev/null", DeviceKind::Character, 1, 3),
    ("/dev/zero", DeviceKind::Character, 1, 5),
    ("/dev/full", DeviceKind::Character, 1, 7),
    ("/dev/random", DeviceKind::Character, 1, 8),
    ("/dev/urandom", DeviceKind::Character, 1, 9),
    ("/dev/tty", DeviceKind::Character, 5, 0),
];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DevicePlan {
    nodes: Vec<DeviceNode>,
    allow_access_masks: Vec<u8>,
    enforce_allowlist: bool,
}

#[derive(Debug)]
pub(super) struct LoadedDeviceProgram(OwnedFd);

#[derive(Debug)]
pub(super) struct PreparedDeviceSources {
    sources: Option<Vec<PreparedDeviceSource>>,
    verify_ownership: bool,
    manifest: Mutex<Option<DeviceTargetManifest>>,
    manifest_file: Mutex<Option<File>>,
    manifest_path: Option<PathBuf>,
}

#[derive(Debug)]
enum PreparedDeviceSource {
    DetachedMount(OwnedFd),
    RetainedNode(OwnedFd),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DeviceTargetRecord {
    relative_path: PathBuf,
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DeviceTargetManifest {
    schema_version: String,
    rootfs: DeviceRootfsRecord,
    targets: Vec<DeviceTargetRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeviceRootfsRecord {
    canonical_path: PathBuf,
    dev: u64,
    ino: u64,
}

impl DeviceTargetRecord {
    fn capture(relative_path: &Path, metadata: &fs::Metadata) -> Result<Self> {
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

    fn matches(&self, metadata: &TargetMetadata) -> bool {
        metadata.file_type == libc::S_IFREG
            && metadata.dev == self.dev
            && metadata.ino == self.ino
            && metadata.mode == self.mode
            && metadata.uid == self.uid
            && metadata.gid == self.gid
    }
}

impl DeviceRootfsRecord {
    fn capture(canonical_rootfs: &Path) -> Result<Self> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TargetMetadata {
    file_type: u32,
    dev: u64,
    rdev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeviceNode {
    path: PathBuf,
    kind: DeviceKind,
    major: u32,
    minor: u32,
    mode: u32,
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DeviceKind {
    Block,
    Character,
    Fifo,
}

impl DevicePlan {
    pub(super) fn from_linux(linux: Option<&Linux>, mounts: &[MountPlan]) -> Result<Self> {
        let Some(linux) = linux else {
            return Ok(Self {
                nodes: Vec::new(),
                allow_access_masks: Vec::new(),
                enforce_allowlist: false,
            });
        };
        let devices = linux.devices().as_deref().unwrap_or_default();
        let rules = linux
            .resources()
            .as_ref()
            .and_then(|resources| resources.devices().as_deref())
            .unwrap_or_default();
        if devices.len() > MAX_DEVICES {
            return Err(invalid(format!(
                "linux.devices contains {} entries; maximum is {MAX_DEVICES}",
                devices.len()
            )));
        }
        let nodes = devices
            .iter()
            .enumerate()
            .map(|(index, device)| DeviceNode::from_oci(index, device))
            .collect::<Result<Vec<_>>>()?;
        let mut unique_paths = BTreeSet::new();
        let mut unique_numbers = BTreeSet::new();
        for node in &nodes {
            if !unique_paths.insert(node.path.clone()) {
                return Err(invalid(format!(
                    "linux.devices contains duplicate path {}",
                    node.path.display()
                )));
            }
            if !unique_numbers.insert((node.kind, node.major, node.minor)) {
                return Err(invalid(format!(
                    "linux.devices contains duplicate {} {}:{}",
                    node.kind.description(),
                    node.major,
                    node.minor
                )));
            }
        }
        let allow_access_masks = validate_device_policy(&nodes, Some(rules))?;
        let enforce_allowlist = !nodes.is_empty() || !rules.is_empty();
        if enforce_allowlist {
            validate_bind_mounts_are_nodev(mounts)?;
        }
        Ok(Self {
            nodes,
            allow_access_masks,
            enforce_allowlist,
        })
    }

    pub(super) fn validate_rootfs(&self, rootfs: &Path) -> Result<()> {
        if !self.enforce_allowlist {
            return Ok(());
        }
        let allowed = self
            .nodes
            .iter()
            .map(|node| node.path.clone())
            .collect::<BTreeSet<_>>();
        let mut pending = vec![rootfs.to_path_buf()];
        let mut visited = 0_usize;
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory).map_err(|error| {
                device_error(
                    ErrorCode::InvalidArgument,
                    format!(
                        "failed to scan rootfs device nodes in {}: {error}",
                        directory.display()
                    ),
                )
            })? {
                let entry = entry.map_err(|error| {
                    device_error(
                        ErrorCode::InvalidArgument,
                        format!("failed to inspect a rootfs entry: {error}"),
                    )
                })?;
                let entry_path = entry.path();
                visited = visited.checked_add(1).ok_or_else(|| {
                    device_error(ErrorCode::ResourceExhausted, "rootfs entry count overflow")
                })?;
                if visited > MAX_SCANNED_ROOTFS_ENTRIES {
                    return Err(device_error(
                        ErrorCode::ResourceExhausted,
                        format!("rootfs device scan exceeds {MAX_SCANNED_ROOTFS_ENTRIES} entries"),
                    ));
                }
                let metadata = fs::symlink_metadata(&entry_path).map_err(|error| {
                    device_error(
                        ErrorCode::InvalidArgument,
                        format!(
                            "failed to inspect rootfs entry {}: {error}",
                            entry_path.display()
                        ),
                    )
                })?;
                let file_type = metadata.file_type();
                if file_type.is_dir() {
                    pending.push(entry_path);
                } else if file_type.is_char_device() || file_type.is_block_device() {
                    let relative = entry_path.strip_prefix(rootfs).map_err(|_| {
                        device_error(
                            ErrorCode::PermissionDenied,
                            "rootfs device scan escaped the retained root",
                        )
                    })?;
                    let container_path = Path::new("/").join(relative);
                    if !allowed.contains(&container_path) {
                        return Err(device_error(
                            ErrorCode::PermissionDenied,
                            format!(
                                "rootfs contains device node outside the OCI allowlist: {}",
                                container_path.display()
                            ),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn prepare_sources(
        &self,
        namespaces: &NamespacePlan,
        runtime_directory: &Path,
        rootless: bool,
    ) -> Result<PreparedDeviceSources> {
        if !namespaces.has_user() {
            return Ok(PreparedDeviceSources {
                sources: None,
                verify_ownership: true,
                manifest: Mutex::new(None),
                manifest_file: Mutex::new(None),
                manifest_path: None,
            });
        }
        if !namespaces.new_user() && !self.nodes.is_empty() {
            return Err(unsupported(
                "linux.devices",
                "devices in a joined user namespace require externally prepared mount sources",
            ));
        }
        if self.nodes.is_empty() {
            return Ok(PreparedDeviceSources {
                sources: Some(Vec::new()),
                verify_ownership: !rootless,
                manifest: Mutex::new(None),
                manifest_file: Mutex::new(None),
                manifest_path: None,
            });
        }

        if rootless {
            let mounts = self
                .nodes
                .iter()
                .enumerate()
                .map(|(index, node)| node.prepare_rootless_source(index))
                .collect::<Result<Vec<_>>>()?;
            return Ok(PreparedDeviceSources {
                sources: Some(mounts),
                verify_ownership: false,
                manifest: Mutex::new(None),
                manifest_file: Mutex::new(None),
                manifest_path: Some(runtime_directory.join(DEVICE_TARGETS_RECORD_NAME)),
            });
        }

        let directory = runtime_directory.join("devices");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&directory).map_err(|error| {
            device_error(
                ErrorCode::Conflict,
                format!(
                    "failed to create private device source directory {}: {error}",
                    directory.display()
                ),
            )
        })?;

        let prepared = self
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| node.prepare_source(index, &directory, namespaces))
            .collect::<Result<Vec<_>>>();
        match prepared {
            Ok(mounts) => Ok(PreparedDeviceSources {
                sources: Some(mounts),
                verify_ownership: true,
                manifest: Mutex::new(None),
                manifest_file: Mutex::new(None),
                manifest_path: Some(runtime_directory.join(DEVICE_TARGETS_RECORD_NAME)),
            }),
            Err(error) => {
                let _ = fs::remove_dir_all(&directory);
                Err(error)
            }
        }
    }

    pub(super) fn bind_prepared_sources(
        &self,
        rootfs: &Path,
        prepared: &PreparedDeviceSources,
    ) -> Result<()> {
        let Some(sources) = prepared.sources.as_ref() else {
            return Ok(());
        };
        if sources.len() != self.nodes.len() {
            return Err(device_error(
                ErrorCode::Internal,
                "prepared device source count does not match the OCI device plan",
            ));
        }
        for (node, source) in self.nodes.iter().zip(sources) {
            node.bind_source(rootfs, source, prepared.verify_ownership, prepared)?;
        }
        Ok(())
    }

    pub(super) fn create_all(&self) -> Result<()> {
        for node in &self.nodes {
            node.create()?;
        }
        Ok(())
    }

    pub(super) const fn uses_prepared_sources(prepared: &PreparedDeviceSources) -> bool {
        prepared.sources.is_some()
    }

    pub(super) fn requires_setup(&self) -> bool {
        self.enforce_allowlist
    }

    pub(super) fn update_from_resources(&self, resources: &LinuxResources) -> Result<Option<Self>> {
        let Some(rules) = resources.devices().as_deref() else {
            return Ok(None);
        };
        if rules.is_empty() {
            return Ok(Some(Self {
                nodes: self.nodes.clone(),
                allow_access_masks: Vec::new(),
                enforce_allowlist: false,
            }));
        }
        let allow_access_masks = validate_device_policy(&self.nodes, Some(rules))?;
        Ok(Some(Self {
            nodes: self.nodes.clone(),
            allow_access_masks,
            enforce_allowlist: !self.nodes.is_empty() || !rules.is_empty(),
        }))
    }

    pub(super) fn load_cgroup_device_program(&self) -> Result<Option<OwnedFd>> {
        if !self.enforce_allowlist {
            return Ok(None);
        }
        let program = build_cgroup_device_program(&self.nodes, &self.allow_access_masks)?;
        load_cgroup_device_program_fd(&program).map(Some)
    }

    pub(super) fn load_device_program(&self) -> Result<LoadedDeviceProgram> {
        self.validate_serialized_policy()?;
        let program = build_cgroup_device_program(&self.nodes, &self.allow_access_masks)?;
        load_cgroup_device_program_fd(&program).map(LoadedDeviceProgram)
    }

    fn has_rootless_safe_nodes(&self) -> bool {
        self.nodes.len() == ROOTLESS_SAFE_DEVICES.len()
            && self.nodes.iter().zip(ROOTLESS_SAFE_DEVICES).all(
                |(node, (path, kind, major, minor))| {
                    node.path == Path::new(path)
                        && node.kind == kind
                        && node.major == major
                        && node.minor == minor
                        && node.mode == 0o666
                        && node.uid == 0
                        && node.gid == 0
                },
            )
    }

    fn validate_serialized_policy(&self) -> Result<()> {
        if !self.enforce_allowlist
            || !self.has_rootless_safe_nodes()
            || self.nodes.len() != self.allow_access_masks.len()
            || self
                .allow_access_masks
                .iter()
                .any(|mask| *mask == 0 || *mask & !0b111 != 0)
        {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                "serialized rootless device policy is not a bounded active allowlist",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_rootless_device_set(&self) -> Result<()> {
        if !self.has_rootless_safe_nodes() {
            Err(device_error(
                ErrorCode::Unsupported,
                "rootless device policy requires the exact six-node A3S Box safe-device profile",
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn attach_loaded_cgroup_device_program(
        &self,
        cgroup_path: &Path,
        loaded: &OwnedFd,
    ) -> Result<()> {
        attach_loaded_cgroup_device_program(cgroup_path, loaded)
    }

    pub(super) fn replace_loaded_cgroup_device_program(
        &self,
        cgroup_path: &Path,
        loaded: &OwnedFd,
        replaced: &OwnedFd,
    ) -> Result<()> {
        replace_loaded_cgroup_device_program(cgroup_path, loaded, replaced)
    }

    pub(super) fn detach_loaded_cgroup_device_program(
        &self,
        cgroup_path: &Path,
        attached: &OwnedFd,
    ) -> Result<()> {
        detach_loaded_cgroup_device_program(cgroup_path, attached)
    }

    pub(super) fn install_cgroup_device_filter(
        &self,
        cgroup_path: &Path,
    ) -> Result<Option<OwnedFd>> {
        if !self.enforce_allowlist {
            return Ok(None);
        }
        let Some(loaded) = self.load_cgroup_device_program()? else {
            return Ok(None);
        };
        self.attach_loaded_cgroup_device_program(cgroup_path, &loaded)?;
        Ok(Some(loaded))
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.nodes.len()
    }
}

impl LoadedDeviceProgram {
    pub(super) fn attach_to_fd(&self, cgroup: RawFd) -> Result<()> {
        attach_cgroup_device_program_fd(cgroup, &self.0, None)
    }

    pub(super) fn replace_on_fd(
        &self,
        cgroup: RawFd,
        replaced: &LoadedDeviceProgram,
    ) -> Result<()> {
        attach_cgroup_device_program_fd(cgroup, &self.0, Some(&replaced.0))
    }

    pub(super) fn detach_from_fd(&self, cgroup: RawFd) -> Result<()> {
        detach_cgroup_device_program_fd(cgroup, &self.0)
    }
}

impl PreparedDeviceSources {
    /// Bind the cleanup manifest to the exact retained rootfs before the
    /// supervised child enters its mount namespace.
    pub(super) fn bind_rootfs(&self, rootfs: &Path) -> Result<()> {
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

    fn record_device_target(&self, record: DeviceTargetRecord) -> Result<()> {
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
}

pub(super) fn load_device_target_manifest(
    runtime_directory: &Path,
) -> Result<Option<DeviceTargetManifest>> {
    load_device_target_manifest_from(&runtime_directory.join(DEVICE_TARGETS_RECORD_NAME))
}

fn load_device_target_manifest_from(path: &Path) -> Result<Option<DeviceTargetManifest>> {
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

fn write_device_target_manifest(path: &Path, manifest: &DeviceTargetManifest) -> Result<()> {
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

pub(super) fn cleanup_device_target_manifest(manifest: &DeviceTargetManifest) -> Result<()> {
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

fn openat2_beneath(
    directory: libc::c_int,
    path: &Path,
    flags: libc::c_int,
    require_directory: bool,
) -> Result<Option<OwnedFd>> {
    let path = path_cstring(path, "descriptor-relative device target")?;
    let mut how = std::mem::MaybeUninit::<libc::open_how>::zeroed();
    // SAFETY: zero is a valid initialization for every field in open_how.
    let how = unsafe { how.assume_init_mut() };
    how.flags = flags as u64;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_SYMLINKS;
    // SAFETY: the directory descriptor is live, `path` is NUL-terminated, and
    // `how` is initialized for the exact kernel ABI size.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory,
            path.as_ptr(),
            how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(device_error(
            if error.raw_os_error() == Some(libc::EXDEV)
                || error.raw_os_error() == Some(libc::ELOOP)
            {
                ErrorCode::PermissionDenied
            } else {
                ErrorCode::FailedPrecondition
            },
            format!(
                "failed to open descriptor-relative device target {}: {error}",
                path.to_string_lossy()
            ),
        ));
    }
    let descriptor = libc::c_int::try_from(descriptor).map_err(|error| {
        device_error(
            ErrorCode::Internal,
            format!("openat2 returned an invalid descriptor: {error}"),
        )
    })?;
    // SAFETY: descriptor is freshly returned by openat2.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    if require_directory && metadata_for_fd(&descriptor)?.file_type != libc::S_IFDIR {
        return Err(device_error(
            ErrorCode::PermissionDenied,
            "descriptor-relative device target parent is not a directory",
        ));
    }
    Ok(Some(descriptor))
}

fn metadata_for_fd(descriptor: &OwnedFd) -> Result<TargetMetadata> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `descriptor` is live and metadata points to writable storage for
    // one stat result.
    if unsafe { libc::fstat(descriptor.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        return Err(last_os_error("inspect descriptor-relative device target"));
    }
    // SAFETY: fstat succeeded and initialized metadata.
    Ok(target_metadata_from_stat(unsafe {
        &metadata.assume_init()
    }))
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

fn target_metadata_from_stat(metadata: &libc::stat) -> TargetMetadata {
    TargetMetadata {
        file_type: metadata.st_mode & libc::S_IFMT,
        dev: metadata.st_dev,
        rdev: metadata.st_rdev,
        ino: metadata.st_ino,
        mode: metadata.st_mode & 0o7777,
        uid: metadata.st_uid,
        gid: metadata.st_gid,
    }
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

impl DeviceNode {
    fn from_oci(index: usize, device: &LinuxDevice) -> Result<Self> {
        let path = normalize_device_path(index, device.path())?;
        let kind = DeviceKind::from_oci(index, device.typ())?;
        let major = u32::try_from(device.major()).map_err(|_| {
            invalid(format!(
                "linux.devices[{index}].major must be a non-negative u32"
            ))
        })?;
        let minor = u32::try_from(device.minor()).map_err(|_| {
            invalid(format!(
                "linux.devices[{index}].minor must be a non-negative u32"
            ))
        })?;
        let mode = device.file_mode().unwrap_or(0o666);
        if mode > 0o7777 {
            return Err(invalid(format!(
                "linux.devices[{index}].fileMode exceeds POSIX permission and special bits"
            )));
        }
        Ok(Self {
            path,
            kind,
            major,
            minor,
            mode,
            uid: device.uid().unwrap_or(0),
            gid: device.gid().unwrap_or(0),
        })
    }

    fn prepare_source(
        &self,
        index: usize,
        directory: &Path,
        namespaces: &NamespacePlan,
    ) -> Result<PreparedDeviceSource> {
        let host_uid = namespaces.host_uid(self.uid).ok_or_else(|| {
            invalid(format!(
                "linux.devices[{index}].uid {} is not covered by linux.uidMappings",
                self.uid
            ))
        })?;
        let host_gid = namespaces.host_gid(self.gid).ok_or_else(|| {
            invalid(format!(
                "linux.devices[{index}].gid {} is not covered by linux.gidMappings",
                self.gid
            ))
        })?;
        let path = directory.join(format!("device-{index:04}"));
        let path_cstring = path_cstring(&path, "prepared device source")?;
        let file_type = self.file_type();
        let device = libc::makedev(self.major, self.minor);
        // SAFETY: the path is a live NUL-terminated string in an exclusive
        // runtime directory and the mode and device numbers were validated.
        if unsafe { libc::mknod(path_cstring.as_ptr(), file_type | self.mode, device) } != 0 {
            return Err(last_os_error(format!(
                "precreate OCI device source for {}",
                self.path.display()
            )));
        }
        // SAFETY: the source path remains live and is still owned exclusively
        // by this create operation.
        if unsafe { libc::chown(path_cstring.as_ptr(), host_uid, host_gid) } != 0 {
            return Err(last_os_error(format!(
                "set mapped ownership on OCI device source for {}",
                self.path.display()
            )));
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(self.mode)).map_err(|error| {
            device_error(
                ErrorCode::PermissionDenied,
                format!(
                    "failed to set mode on OCI device source for {}: {error}",
                    self.path.display()
                ),
            )
        })?;
        self.verify_at(&path, host_uid, host_gid)?;
        clone_device_mount(&path).map(PreparedDeviceSource::DetachedMount)
    }

    fn prepare_rootless_source(&self, index: usize) -> Result<PreparedDeviceSource> {
        if !is_rootless_safe_device(self) {
            return Err(unsupported(
                &format!("linux.devices[{index}].path"),
                "rootless device profiles support only the fixed A3S Box safe-device set",
            ));
        }
        let path = path_cstring(&self.path, "rootless device source")?;
        // SAFETY: path is NUL-terminated. O_PATH retains the exact node
        // identity without requiring read or write access.
        let descriptor = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(last_os_error(format!(
                "retain rootless device source {}",
                self.path.display()
            )));
        }
        // SAFETY: open returned a fresh owned descriptor.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        if !self.matches_source_metadata(&metadata_for_fd(&descriptor)?) {
            return Err(device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "rootless device source {} does not match the requested device",
                    self.path.display()
                ),
            ));
        }
        Ok(PreparedDeviceSource::RetainedNode(descriptor))
    }

    fn bind_source(
        &self,
        rootfs: &Path,
        source: &PreparedDeviceSource,
        verify_ownership: bool,
        prepared: &PreparedDeviceSources,
    ) -> Result<()> {
        let canonical_rootfs = rootfs.canonicalize().map_err(|error| {
            invalid(format!(
                "failed to resolve the container rootfs while binding {}: {error}",
                self.path.display()
            ))
        })?;
        let relative = self.path.strip_prefix("/").map_err(|error| {
            device_error(
                ErrorCode::Internal,
                format!("invalid normalized OCI device path: {error}"),
            )
        })?;
        let target = canonical_rootfs.join(relative);
        let parent = target.parent().ok_or_else(|| {
            device_error(
                ErrorCode::Internal,
                format!("OCI device path has no parent: {}", target.display()),
            )
        })?;
        let canonical_parent = parent.canonicalize().map_err(|error| {
            invalid(format!(
                "failed to resolve OCI device parent {}: {error}",
                parent.display()
            ))
        })?;
        if canonical_parent != canonical_rootfs && !canonical_parent.starts_with(&canonical_rootfs)
        {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                format!(
                    "OCI device path escapes the container rootfs: {}",
                    self.path.display()
                ),
            ));
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&target)
            .map_err(|error| {
                invalid(format!(
                    "failed to create OCI device bind target {}: {error}",
                    self.path.display()
                ))
            })?;
        let metadata = fs::symlink_metadata(&target).map_err(|error| {
            device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to inspect OCI device bind target {} after creation: {error}",
                    self.path.display()
                ),
            )
        })?;
        let record = DeviceTargetRecord::capture(relative, &metadata)?;
        if let Err(error) = prepared.record_device_target(record) {
            if let Err(rollback) = fs::remove_file(&target) {
                return Err(device_error(
                    ErrorCode::Internal,
                    format!(
                        "{error}; failed to roll back unrecorded OCI device placeholder {}: {rollback}",
                        target.display()
                    ),
                ));
            }
            return Err(error);
        }

        match source {
            PreparedDeviceSource::DetachedMount(source) => {
                attach_device_mount(source, &target, &self.path)?;
            }
            PreparedDeviceSource::RetainedNode(source) => {
                attach_retained_device(source, &target, &self.path)?;
            }
        }
        if verify_ownership {
            self.verify_at(&target, self.uid, self.gid)
        } else {
            self.verify_device_at(&target)
        }
    }

    fn create(&self) -> Result<()> {
        let parent = self.path.parent().ok_or_else(|| {
            invalid(format!(
                "device path has no parent: {}",
                self.path.display()
            ))
        })?;
        let metadata = fs::symlink_metadata(parent).map_err(|error| {
            device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "device parent directory {} is unavailable after mounts: {error}",
                    parent.display()
                ),
            )
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                format!(
                    "device parent is not a real directory: {}",
                    parent.display()
                ),
            ));
        }
        let path =
            std::ffi::CString::new(self.path.as_os_str().as_encoded_bytes()).map_err(|error| {
                invalid(format!(
                    "device path {} contains NUL: {error}",
                    self.path.display()
                ))
            })?;
        let file_type = self.file_type();
        let device = libc::makedev(self.major, self.minor);
        // SAFETY: the path is a live NUL-terminated string and the mode and
        // device numbers were fully validated.
        if unsafe { libc::mknod(path.as_ptr(), file_type | self.mode, device) } != 0 {
            return Err(last_os_error(format!(
                "create OCI device {}",
                self.path.display()
            )));
        }
        // SAFETY: the device path is still a live NUL-terminated string.
        if unsafe { libc::chown(path.as_ptr(), self.uid, self.gid) } != 0 {
            return Err(last_os_error(format!(
                "set ownership on OCI device {}",
                self.path.display()
            )));
        }
        fs::set_permissions(&self.path, fs::Permissions::from_mode(self.mode)).map_err(
            |error| {
                device_error(
                    ErrorCode::PermissionDenied,
                    format!(
                        "failed to set mode on OCI device {}: {error}",
                        self.path.display()
                    ),
                )
            },
        )?;
        self.verify_at(&self.path, self.uid, self.gid)
    }

    const fn file_type(&self) -> libc::mode_t {
        match self.kind {
            DeviceKind::Block => libc::S_IFBLK,
            DeviceKind::Character => libc::S_IFCHR,
            DeviceKind::Fifo => libc::S_IFIFO,
        }
    }

    fn verify_at(&self, path: &Path, uid: u32, gid: u32) -> Result<()> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to verify OCI device {}: {error}",
                    self.path.display()
                ),
            )
        })?;
        let file_type_matches = match self.kind {
            DeviceKind::Block => metadata.file_type().is_block_device(),
            DeviceKind::Character => metadata.file_type().is_char_device(),
            DeviceKind::Fifo => metadata.file_type().is_fifo(),
        };
        if !file_type_matches
            || libc::major(metadata.rdev()) != self.major
            || libc::minor(metadata.rdev()) != self.minor
            || metadata.mode() & 0o7777 != self.mode
            || metadata.uid() != uid
            || metadata.gid() != gid
        {
            return Err(device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "OCI device {} differs after enforcement",
                    self.path.display()
                ),
            ));
        }
        Ok(())
    }

    fn verify_device_at(&self, path: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to verify rootless OCI device {}: {error}",
                    self.path.display()
                ),
            )
        })?;
        let file_type_matches = match self.kind {
            DeviceKind::Block => metadata.file_type().is_block_device(),
            DeviceKind::Character => metadata.file_type().is_char_device(),
            DeviceKind::Fifo => metadata.file_type().is_fifo(),
        };
        if metadata.file_type().is_symlink()
            || !file_type_matches
            || libc::major(metadata.rdev()) != self.major
            || libc::minor(metadata.rdev()) != self.minor
            || metadata.mode() & 0o7777 != self.mode
        {
            return Err(device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "rootless OCI device {} differs after bind enforcement",
                    self.path.display()
                ),
            ));
        }
        Ok(())
    }

    fn matches_source_metadata(&self, metadata: &TargetMetadata) -> bool {
        metadata.file_type == self.file_type()
            && libc::major(metadata.rdev) == self.major
            && libc::minor(metadata.rdev) == self.minor
            && metadata.mode == self.mode
    }
}

fn is_rootless_safe_device(node: &DeviceNode) -> bool {
    node.mode == 0o666
        && node.uid == 0
        && node.gid == 0
        && ROOTLESS_SAFE_DEVICES
            .iter()
            .any(|(path, kind, major, minor)| {
                node.path == Path::new(path)
                    && node.kind == *kind
                    && node.major == *major
                    && node.minor == *minor
            })
}

impl DeviceKind {
    fn from_oci(index: usize, kind: LinuxDeviceType) -> Result<Self> {
        match kind {
            LinuxDeviceType::B => Ok(Self::Block),
            LinuxDeviceType::C | LinuxDeviceType::U => Ok(Self::Character),
            LinuxDeviceType::P => Ok(Self::Fifo),
            LinuxDeviceType::A => Err(invalid(format!(
                "linux.devices[{index}].type cannot create the wildcard device type"
            ))),
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Block => "block device",
            Self::Character => "character device",
            Self::Fifo => "FIFO",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct BpfInsn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

const BPF_ALU64: u32 = 0x07;
const BPF_MOV: u32 = 0xb0;
const BPF_AND: u32 = 0x50;
const BPF_RSH: u32 = 0x70;
const BPF_JNE: u32 = 0x50;
const BPF_EXIT: u32 = 0x90;
const BPF_REG_0: u8 = 0;
const BPF_REG_1: u8 = 1;
const BPF_REG_2: u8 = 2;
const BPF_REG_3: u8 = 3;
const BPF_REG_4: u8 = 4;
const BPF_REG_5: u8 = 5;
const BPF_PROG_LOAD: u32 = 5;
const BPF_PROG_ATTACH: u32 = 8;
const BPF_PROG_DETACH: u32 = 9;
const BPF_F_ALLOW_MULTI: u32 = 1 << 1;
const BPF_F_REPLACE: u32 = 1 << 2;
const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 15;
const BPF_CGROUP_DEVICE: u32 = 6;
const BPF_DEVCG_ACC_MKNOD: u32 = 1;
const BPF_DEVCG_ACC_READ: u32 = 2;
const BPF_DEVCG_ACC_WRITE: u32 = 4;
const BPF_DEVCG_DEV_BLOCK: u32 = 1;
const BPF_DEVCG_DEV_CHAR: u32 = 2;
const MAX_BPF_LOG_BYTES: usize = 64 * 1024;

#[repr(C)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

#[repr(C)]
struct BpfProgAttachAttr {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
    replace_bpf_fd: u32,
}

fn build_cgroup_device_program(
    nodes: &[DeviceNode],
    allow_access_masks: &[u8],
) -> Result<Vec<BpfInsn>> {
    if nodes.len() != allow_access_masks.len() {
        return Err(device_error(
            ErrorCode::Internal,
            "device access mask count does not match the OCI device node count",
        ));
    }

    let allow_rules = nodes
        .iter()
        .zip(allow_access_masks.iter().copied())
        .filter_map(|(node, access_mask)| match node.kind {
            DeviceKind::Block => Some((BPF_DEVCG_DEV_BLOCK, node.major, node.minor, access_mask)),
            DeviceKind::Character => {
                Some((BPF_DEVCG_DEV_CHAR, node.major, node.minor, access_mask))
            }
            DeviceKind::Fifo => None,
        })
        .collect::<Vec<_>>();

    if allow_rules.is_empty() {
        return Ok(vec![mov64_imm(BPF_REG_0, 0), exit_insn()]);
    }

    let mut program = vec![
        ldx_mem(libc::BPF_W, BPF_REG_2, BPF_REG_1, 0),
        alu32_imm(BPF_AND, BPF_REG_2, 0xFFFF),
        ldx_mem(libc::BPF_W, BPF_REG_3, BPF_REG_1, 0),
        alu32_imm(BPF_RSH, BPF_REG_3, 16),
        ldx_mem(libc::BPF_W, BPF_REG_4, BPF_REG_1, 4),
        ldx_mem(libc::BPF_W, BPF_REG_5, BPF_REG_1, 8),
    ];
    let mut rule_starts = Vec::with_capacity(allow_rules.len());
    let mut mismatch_jumps = Vec::with_capacity(allow_rules.len());

    for (device_type, major, minor, access_mask) in allow_rules {
        rule_starts.push(program.len());
        let mut rule_jumps = Vec::with_capacity(4);
        rule_jumps.push(push_jne_imm(&mut program, BPF_REG_2, device_type as i32));
        if access_mask != (BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE | BPF_DEVCG_ACC_MKNOD) as u8 {
            program.push(mov64_reg(BPF_REG_1, BPF_REG_3));
            program.push(alu32_imm(BPF_AND, BPF_REG_1, i32::from(access_mask)));
            rule_jumps.push(push_jne_reg(&mut program, BPF_REG_1, BPF_REG_3));
        }
        rule_jumps.push(push_jne_imm(&mut program, BPF_REG_4, major as i32));
        rule_jumps.push(push_jne_imm(&mut program, BPF_REG_5, minor as i32));
        program.push(mov64_imm(BPF_REG_0, 1));
        program.push(exit_insn());
        mismatch_jumps.push(rule_jumps);
    }

    let reject_start = program.len();
    program.push(mov64_imm(BPF_REG_0, 0));
    program.push(exit_insn());

    for (rule_index, rule_jumps) in mismatch_jumps.iter().enumerate() {
        let target = rule_starts
            .get(rule_index + 1)
            .copied()
            .unwrap_or(reject_start);
        for &jump_index in rule_jumps {
            let jump = program.get_mut(jump_index).ok_or_else(|| {
                device_error(
                    ErrorCode::Internal,
                    "cgroup device BPF program lost a patch target",
                )
            })?;
            let offset = target as isize - jump_index as isize - 1;
            jump.off = i16::try_from(offset).map_err(|error| {
                device_error(
                    ErrorCode::ResourceExhausted,
                    format!("cgroup device BPF program exceeds jump limits: {error}"),
                )
            })?;
        }
    }

    Ok(program)
}

fn attach_loaded_cgroup_device_program(cgroup_path: &Path, loaded: &OwnedFd) -> Result<()> {
    attach_cgroup_device_program(cgroup_path, loaded, None)
}

fn replace_loaded_cgroup_device_program(
    cgroup_path: &Path,
    loaded: &OwnedFd,
    replaced: &OwnedFd,
) -> Result<()> {
    attach_cgroup_device_program(cgroup_path, loaded, Some(replaced))
}

fn attach_cgroup_device_program(
    cgroup_path: &Path,
    loaded: &OwnedFd,
    replaced: Option<&OwnedFd>,
) -> Result<()> {
    let cgroup = open_cgroup_descriptor(cgroup_path)?;
    attach_cgroup_device_program_fd(cgroup.as_raw_fd(), loaded, replaced).map_err(|error| {
        Error::new(
            error.code,
            format!(
                "failed to attach cgroup device BPF program to {}: {}",
                cgroup_path.display(),
                error.message
            ),
        )
        .for_operation("enforce-container-devices")
        .retryable(error.retryable)
    })
}

fn attach_cgroup_device_program_fd(
    cgroup: RawFd,
    loaded: &OwnedFd,
    replaced: Option<&OwnedFd>,
) -> Result<()> {
    let mut attr = BpfProgAttachAttr {
        target_fd: cgroup as u32,
        attach_bpf_fd: loaded.as_raw_fd() as u32,
        attach_type: BPF_CGROUP_DEVICE,
        attach_flags: BPF_F_ALLOW_MULTI | if replaced.is_some() { BPF_F_REPLACE } else { 0 },
        replace_bpf_fd: replaced.map_or(0, |program| program.as_raw_fd() as u32),
    };
    // SAFETY: the cgroup and program descriptors are live owned fds and the
    // attribute struct matches the kernel layout for BPF_PROG_ATTACH.
    let attached = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_ATTACH,
            &mut attr as *mut _ as *mut libc::c_void,
            std::mem::size_of::<BpfProgAttachAttr>(),
        )
    };
    if attached != 0 {
        return Err(bpf_last_os_error(
            "failed to attach cgroup device BPF program",
        ));
    }
    Ok(())
}

fn detach_loaded_cgroup_device_program(cgroup_path: &Path, attached: &OwnedFd) -> Result<()> {
    let cgroup = open_cgroup_descriptor(cgroup_path)?;
    detach_cgroup_device_program_fd(cgroup.as_raw_fd(), attached).map_err(|error| {
        Error::new(
            error.code,
            format!(
                "failed to detach cgroup device BPF program from {}: {}",
                cgroup_path.display(),
                error.message
            ),
        )
        .for_operation("enforce-container-devices")
        .retryable(error.retryable)
    })
}

fn detach_cgroup_device_program_fd(cgroup: RawFd, attached: &OwnedFd) -> Result<()> {
    let mut attr = BpfProgAttachAttr {
        target_fd: cgroup as u32,
        attach_bpf_fd: attached.as_raw_fd() as u32,
        attach_type: BPF_CGROUP_DEVICE,
        attach_flags: 0,
        replace_bpf_fd: 0,
    };
    // SAFETY: the cgroup and program descriptors are live owned fds and the
    // attribute struct matches the kernel layout for BPF_PROG_DETACH.
    let detached = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_DETACH,
            &mut attr as *mut _ as *mut libc::c_void,
            std::mem::size_of::<BpfProgAttachAttr>(),
        )
    };
    if detached != 0 {
        return Err(bpf_last_os_error(
            "failed to detach cgroup device BPF program",
        ));
    }
    Ok(())
}

fn load_cgroup_device_program_fd(program: &[BpfInsn]) -> Result<OwnedFd> {
    let insn_cnt = u32::try_from(program.len()).map_err(|error| {
        device_error(
            ErrorCode::ResourceExhausted,
            format!("cgroup device BPF program exceeds the kernel instruction limit: {error}"),
        )
    })?;
    let license = c"GPL";
    let mut log = Vec::new();
    let mut with_log = false;
    loop {
        let mut attr = BpfProgLoadAttr {
            prog_type: BPF_PROG_TYPE_CGROUP_DEVICE,
            insn_cnt,
            insns: program.as_ptr() as u64,
            license: license.as_ptr() as u64,
            log_level: if with_log { 1 } else { 0 },
            log_size: log.len() as u32,
            log_buf: if with_log { log.as_mut_ptr() as u64 } else { 0 },
            kern_version: 0,
            prog_flags: 0,
            prog_name: [0; 16],
            prog_ifindex: 0,
            expected_attach_type: BPF_CGROUP_DEVICE,
        };
        // SAFETY: the attribute struct is fully initialized and the program
        // and license pointers stay live for the duration of the syscall.
        let loaded = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_PROG_LOAD,
                &mut attr as *mut _ as *mut libc::c_void,
                std::mem::size_of::<BpfProgLoadAttr>(),
            )
        };
        if loaded >= 0 {
            let fd = i32::try_from(loaded).map_err(|error| {
                device_error(
                    ErrorCode::Internal,
                    format!("BPF_PROG_LOAD returned an invalid descriptor: {error}"),
                )
            })?;
            // SAFETY: `fd` is a fresh owned descriptor returned by BPF_PROG_LOAD.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }

        let error = io::Error::last_os_error();
        if !with_log {
            bump_memlock_limit();
            log.resize(16 * 1024, 0);
            with_log = true;
            continue;
        }
        if error.raw_os_error() == Some(libc::ENOSPC) && log.len() < MAX_BPF_LOG_BYTES {
            let next = (log.len().max(16 * 1024) * 2).min(MAX_BPF_LOG_BYTES);
            log.resize(next, 0);
            continue;
        }
        return Err(bpf_load_failure(error, &log));
    }
}

fn open_cgroup_descriptor(path: &Path) -> Result<OwnedFd> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to open cgroup directory {}: {error}",
                    path.display()
                ),
            )
        })?;
    let raw = file.into_raw_fd();
    // SAFETY: `raw` is a live owned descriptor from OpenOptions.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn bump_memlock_limit() {
    let mut current = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: the pointed-to structure is valid and owned by this function.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &current) } == 0 {
        return;
    }
    // SAFETY: the pointed-to structure is valid and owned by this function.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut current) } != 0 {
        return;
    }
    current.rlim_cur = current.rlim_max;
    // SAFETY: the pointed-to structure is valid and owned by this function.
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &current) };
}

fn bpf_load_failure(error: io::Error, log: &[u8]) -> Error {
    let message = if let Some(verifier_log) = verifier_log(log) {
        format!("failed to load cgroup device BPF program: {error}: {verifier_log}")
    } else {
        format!("failed to load cgroup device BPF program: {error}")
    };
    device_error(bpf_error_code(&error), message)
}

fn bpf_last_os_error(message: impl Into<String>) -> Error {
    let error = io::Error::last_os_error();
    device_error(
        bpf_error_code(&error),
        format!("{}: {error}", message.into()),
    )
}

fn bpf_error_code(error: &io::Error) -> ErrorCode {
    match error.raw_os_error() {
        Some(code) if code == libc::EPERM || code == libc::EACCES => ErrorCode::PermissionDenied,
        Some(code) if code == libc::ENOMEM => ErrorCode::ResourceExhausted,
        Some(code)
            if code == libc::EINVAL
                || code == libc::EOPNOTSUPP
                || code == libc::ENOSYS
                || code == libc::ENOTSUP =>
        {
            ErrorCode::Unsupported
        }
        _ => ErrorCode::FailedPrecondition,
    }
}

fn verifier_log(log: &[u8]) -> Option<String> {
    let end = log.iter().rposition(|byte| *byte != 0)?;
    let log = String::from_utf8_lossy(&log[..=end]).trim().to_string();
    if log.is_empty() {
        None
    } else {
        Some(log)
    }
}

fn ldx_mem(size: u32, dst: u8, src: u8, off: i16) -> BpfInsn {
    BpfInsn {
        code: (libc::BPF_LDX | size | libc::BPF_MEM) as u8,
        regs: pack_regs(dst, src),
        off,
        imm: 0,
    }
}

fn alu32_imm(op: u32, dst: u8, imm: i32) -> BpfInsn {
    BpfInsn {
        code: (libc::BPF_ALU | op | libc::BPF_K) as u8,
        regs: pack_regs(dst, 0),
        off: 0,
        imm,
    }
}

fn mov64_reg(dst: u8, src: u8) -> BpfInsn {
    BpfInsn {
        code: (BPF_ALU64 | BPF_MOV | libc::BPF_X) as u8,
        regs: pack_regs(dst, src),
        off: 0,
        imm: 0,
    }
}

fn push_jne_imm(program: &mut Vec<BpfInsn>, dst: u8, imm: i32) -> usize {
    let index = program.len();
    program.push(BpfInsn {
        code: (libc::BPF_JMP | BPF_JNE | libc::BPF_K) as u8,
        regs: pack_regs(dst, 0),
        off: 0,
        imm,
    });
    index
}

fn push_jne_reg(program: &mut Vec<BpfInsn>, dst: u8, src: u8) -> usize {
    let index = program.len();
    program.push(BpfInsn {
        code: (libc::BPF_JMP | BPF_JNE | libc::BPF_X) as u8,
        regs: pack_regs(dst, src),
        off: 0,
        imm: 0,
    });
    index
}

fn mov64_imm(dst: u8, imm: i32) -> BpfInsn {
    BpfInsn {
        code: (BPF_ALU64 | BPF_MOV | libc::BPF_K) as u8,
        regs: pack_regs(dst, 0),
        off: 0,
        imm,
    }
}

fn exit_insn() -> BpfInsn {
    BpfInsn {
        code: (libc::BPF_JMP | BPF_EXIT) as u8,
        regs: 0,
        off: 0,
        imm: 0,
    }
}

fn pack_regs(dst: u8, src: u8) -> u8 {
    (dst & 0x0f) | ((src & 0x0f) << 4)
}

fn validate_device_policy(
    nodes: &[DeviceNode],
    rules: Option<&[LinuxDeviceCgroup]>,
) -> Result<Vec<u8>> {
    let rules = rules.unwrap_or_default();
    if nodes.is_empty() && rules.is_empty() {
        return Ok(Vec::new());
    }
    let Some(default_deny) = rules.first() else {
        return Err(unsupported(
            "linux.resources.devices",
            "explicit devices require a default-deny policy",
        ));
    };
    if default_deny.allow()
        || default_deny.typ().is_some()
        || default_deny.major().is_some()
        || default_deny.minor().is_some()
        || default_deny.access().as_deref() != Some("rwm")
    {
        return Err(unsupported(
            "linux.resources.devices[0]",
            "the supported policy starts with deny-all rwm",
        ));
    }
    if rules.len() != nodes.len() + 1 {
        return Err(unsupported(
            "linux.resources.devices",
            "the allow rules must exactly match the created device nodes",
        ));
    }
    let mut allow_access_masks = Vec::with_capacity(nodes.len());
    for (index, (node, rule)) in nodes.iter().zip(&rules[1..]).enumerate() {
        let expected_type = match node.kind {
            DeviceKind::Block => LinuxDeviceType::B,
            DeviceKind::Character => LinuxDeviceType::C,
            DeviceKind::Fifo => LinuxDeviceType::P,
        };
        let access_mask = parse_device_access_mask(
            &format!("linux.resources.devices[{}].access", index + 1),
            rule.access().as_deref(),
        )?;
        if !rule.allow()
            || rule.typ() != Some(expected_type)
            || rule.major() != Some(i64::from(node.major))
            || rule.minor() != Some(i64::from(node.minor))
        {
            return Err(unsupported(
                &format!("linux.resources.devices[{}]", index + 1),
                "the rule must allow a matching created device",
            ));
        }
        allow_access_masks.push(access_mask);
    }
    Ok(allow_access_masks)
}

fn parse_device_access_mask(field: &str, value: Option<&str>) -> Result<u8> {
    let Some(value) = value else {
        return Err(invalid(format!("{field} is required for allow rules")));
    };
    let mut mask = 0_u8;
    for access in value.chars() {
        match access {
            'r' => mask |= BPF_DEVCG_ACC_READ as u8,
            'w' => mask |= BPF_DEVCG_ACC_WRITE as u8,
            'm' => mask |= BPF_DEVCG_ACC_MKNOD as u8,
            _ => {
                return Err(invalid(format!(
                    "{field} must contain only `r`, `w`, and `m`"
                )));
            }
        }
    }
    if mask == 0 {
        return Err(invalid(format!(
            "{field} must not be empty for a device allow rule"
        )));
    }
    Ok(mask)
}

fn validate_bind_mounts_are_nodev(mounts: &[MountPlan]) -> Result<()> {
    if let Some(mount) = mounts
        .iter()
        .find(|mount| mount.bind && mount.flags & libc::MS_NODEV == 0)
    {
        Err(unsupported(
            &format!("mounts[{}].options", mount.index),
            "bind mounts must use nodev when an OCI device allowlist is active",
        ))
    } else {
        Ok(())
    }
}

fn clone_device_mount(path: &Path) -> Result<OwnedFd> {
    let path = path_cstring(path, "prepared device source")?;
    // SAFETY: the path is NUL-terminated and open_tree does not retain it.
    // OPEN_TREE_CLONE returns a detached mount owned by the returned fd.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(last_os_error("clone prepared OCI device source mount"));
    }
    let descriptor = libc::c_int::try_from(descriptor).map_err(|error| {
        device_error(
            ErrorCode::Internal,
            format!("open_tree returned an invalid device mount descriptor: {error}"),
        )
    })?;
    // SAFETY: `descriptor` is a fresh owned descriptor returned by open_tree.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn attach_device_mount(source: &OwnedFd, target: &Path, container_path: &Path) -> Result<()> {
    let target_descriptor = open_path_descriptor(target)?;
    let empty = c"";
    let flags = libc::MOVE_MOUNT_F_EMPTY_PATH | libc::MOVE_MOUNT_T_EMPTY_PATH;
    // SAFETY: both descriptors are live detached/source and target mount
    // references, both empty paths are NUL-terminated, and the EMPTY_PATH
    // flags select the descriptors directly.
    let moved = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            source.as_raw_fd(),
            empty.as_ptr(),
            target_descriptor.as_raw_fd(),
            empty.as_ptr(),
            flags,
        )
    };
    if moved != 0 {
        return Err(last_os_error(format!(
            "attach prepared OCI device {}",
            container_path.display()
        )));
    }

    let target = path_cstring(target, "OCI device bind target")?;
    let null = std::ptr::null::<libc::c_char>();
    let null_data = std::ptr::null::<libc::c_void>();
    // SAFETY: the bind target was created and mounted by this operation.
    if unsafe {
        libc::mount(
            null,
            target.as_ptr(),
            null,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NOEXEC,
            null_data,
        )
    } != 0
    {
        return Err(last_os_error(format!(
            "apply safe bind flags to OCI device {}",
            container_path.display()
        )));
    }
    Ok(())
}

fn attach_retained_device(source: &OwnedFd, target: &Path, container_path: &Path) -> Result<()> {
    let empty_path_flag = u32::try_from(libc::AT_EMPTY_PATH).map_err(|error| {
        device_error(
            ErrorCode::Internal,
            format!("AT_EMPTY_PATH does not fit the open_tree flags ABI: {error}"),
        )
    })?;
    // Clone the exact pre-namespace O_PATH reference after the launcher has
    // entered its private user and mount namespaces. Operating on the FD
    // directly avoids both host-path re-resolution and procfs magic-link bind
    // behavior, while OPEN_TREE_CLONE produces the detached mount required by
    // move_mount below.
    let empty = c"";
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            source.as_raw_fd(),
            empty.as_ptr(),
            libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC | empty_path_flag,
        )
    };
    if descriptor < 0 {
        return Err(last_os_error(format!(
            "clone retained OCI device {} mount",
            container_path.display()
        )));
    }
    let descriptor = libc::c_int::try_from(descriptor).map_err(|error| {
        device_error(
            ErrorCode::Internal,
            format!("open_tree returned an invalid retained device descriptor: {error}"),
        )
    })?;
    // SAFETY: open_tree returned a fresh detached mount descriptor.
    let detached = unsafe { OwnedFd::from_raw_fd(descriptor) };
    attach_device_mount(&detached, target, container_path)
}

fn open_path_descriptor(path: &Path) -> Result<OwnedFd> {
    let path = path_cstring(path, "OCI device bind target")?;
    // SAFETY: the target is NUL-terminated and open does not retain it.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(last_os_error("retain OCI device bind target"));
    }
    // SAFETY: `descriptor` is a fresh owned descriptor returned by open.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn path_cstring(path: &Path, label: &str) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|error| {
        invalid(format!(
            "{label} path {} contains NUL: {error}",
            path.display()
        ))
    })
}

fn normalize_device_path(index: usize, path: &Path) -> Result<PathBuf> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid(format!("linux.devices[{index}].path is not valid UTF-8")))?;
    if value.is_empty()
        || value.len() > 4_096
        || !value.starts_with('/')
        || value.ends_with('/')
        || value.as_bytes().contains(&0)
        || value.contains('\\')
        || value
            .trim_start_matches('/')
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(invalid(format!(
            "linux.devices[{index}].path must be a normalized absolute Linux path"
        )));
    }
    Ok(PathBuf::from(value))
}

fn invalid(message: impl Into<String>) -> Error {
    device_error(ErrorCode::InvalidArgument, message)
}

fn unsupported(field: &str, reason: &str) -> Error {
    device_error(ErrorCode::Unsupported, format!("{field}: {reason}"))
}

fn last_os_error(operation: impl Into<String>) -> Error {
    device_error(
        ErrorCode::PermissionDenied,
        format!(
            "failed to {}: {}",
            operation.into(),
            io::Error::last_os_error()
        ),
    )
}

fn device_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("configure-container-devices")
}

#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::PermissionsExt;

    use a3s_oci_sdk::oci_spec::runtime::{Linux, LinuxResources};
    use a3s_oci_sdk::ErrorCode;

    use super::{
        build_cgroup_device_program, cleanup_device_target_manifest, load_device_target_manifest,
        load_device_target_manifest_from, write_device_target_manifest, DeviceKind, DeviceNode,
        DevicePlan, DeviceTargetManifest, DeviceTargetRecord, PreparedDeviceSources, BPF_ALU64,
        BPF_DEVCG_ACC_READ, BPF_MOV, DEVICE_TARGETS_RECORD_NAME, DEVICE_TARGETS_SCHEMA_VERSION,
    };
    use crate::executor::mount;
    use crate::executor::namespace::NamespacePlan;
    use tempfile::tempdir;

    #[test]
    fn cleanup_device_target_removes_exact_placeholder_file() {
        let temporary = tempdir().expect("temporary device target directory");
        let path = temporary.path().join("null");
        std::fs::write(&path, b"placeholder").expect("placeholder file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("placeholder permissions");
        let metadata = std::fs::symlink_metadata(&path).expect("placeholder metadata");
        let record = DeviceTargetRecord::capture(std::path::Path::new("null"), &metadata)
            .expect("capture target");
        let manifest = DeviceTargetManifest {
            schema_version: DEVICE_TARGETS_SCHEMA_VERSION.to_string(),
            rootfs: super::DeviceRootfsRecord::capture(temporary.path()).expect("rootfs record"),
            targets: vec![record],
        };

        cleanup_device_target_manifest(&manifest).expect("cleanup exact placeholder");

        assert!(!path.exists());
    }

    #[test]
    fn cleanup_device_target_fails_closed_on_inode_drift() {
        let temporary = tempdir().expect("temporary device target directory");
        let path = temporary.path().join("null");
        std::fs::write(&path, b"placeholder").expect("placeholder file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("placeholder permissions");
        let metadata = std::fs::symlink_metadata(&path).expect("placeholder metadata");
        let record = DeviceTargetRecord::capture(std::path::Path::new("null"), &metadata)
            .expect("capture target");
        let manifest = DeviceTargetManifest {
            schema_version: DEVICE_TARGETS_SCHEMA_VERSION.to_string(),
            rootfs: super::DeviceRootfsRecord::capture(temporary.path()).expect("rootfs record"),
            targets: vec![record],
        };
        let replacement = temporary.path().join("null.replacement");
        std::fs::rename(&path, &replacement).expect("move original placeholder");
        std::fs::write(&path, b"replacement").expect("replacement file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("replacement permissions");

        let error = cleanup_device_target_manifest(&manifest).expect_err("fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(path.exists());
        assert!(replacement.exists());
    }

    #[test]
    fn cleanup_device_target_fails_closed_on_rootfs_inode_drift() {
        let temporary = tempdir().expect("temporary device target directory");
        let rootfs = temporary.path().join("rootfs");
        let retained_rootfs = temporary.path().join("rootfs.retained");
        std::fs::create_dir(&rootfs).expect("rootfs directory");
        let path = rootfs.join("null");
        std::fs::write(&path, b"placeholder").expect("placeholder file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("placeholder permissions");
        let metadata = std::fs::symlink_metadata(&path).expect("placeholder metadata");
        let record = DeviceTargetRecord::capture(std::path::Path::new("null"), &metadata)
            .expect("capture target");
        let manifest = DeviceTargetManifest {
            schema_version: DEVICE_TARGETS_SCHEMA_VERSION.to_string(),
            rootfs: super::DeviceRootfsRecord::capture(&rootfs).expect("rootfs record"),
            targets: vec![record],
        };

        std::fs::rename(&rootfs, &retained_rootfs).expect("move recorded rootfs");
        std::fs::create_dir(&rootfs).expect("replacement rootfs");
        std::fs::write(rootfs.join("null"), b"replacement").expect("replacement target");

        let error = cleanup_device_target_manifest(&manifest).expect_err("fail closed");
        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(error.message.contains("rootfs identity changed"));
        assert_eq!(
            std::fs::read(retained_rootfs.join("null")).expect("retained placeholder"),
            b"placeholder"
        );
        assert_eq!(
            std::fs::read(rootfs.join("null")).expect("replacement target"),
            b"replacement"
        );
    }

    #[test]
    fn cleanup_device_target_rejects_symlink_parent_and_traversal() {
        let temporary = tempdir().expect("temporary device target directory");
        let rootfs = temporary.path().join("rootfs");
        let external = temporary.path().join("external");
        std::fs::create_dir_all(rootfs.join("dev")).expect("rootfs device directory");
        std::fs::create_dir(&external).expect("external directory");
        let path = rootfs.join("dev/null");
        std::fs::write(&path, b"placeholder").expect("placeholder file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("placeholder permissions");
        let metadata = std::fs::symlink_metadata(&path).expect("placeholder metadata");
        let record = DeviceTargetRecord::capture(std::path::Path::new("dev/null"), &metadata)
            .expect("capture target");
        let rootfs_record = super::DeviceRootfsRecord::capture(&rootfs).expect("rootfs record");
        let manifest = DeviceTargetManifest {
            schema_version: DEVICE_TARGETS_SCHEMA_VERSION.to_string(),
            rootfs: rootfs_record.clone(),
            targets: vec![record.clone()],
        };
        let retained_parent = rootfs.join("dev.retained");
        std::fs::rename(rootfs.join("dev"), &retained_parent).expect("move target parent");
        std::fs::write(external.join("null"), b"external").expect("external target");
        std::os::unix::fs::symlink(&external, rootfs.join("dev")).expect("escaping parent symlink");

        let error = cleanup_device_target_manifest(&manifest).expect_err("reject symlink parent");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert_eq!(
            std::fs::read(external.join("null")).expect("external target"),
            b"external"
        );
        assert_eq!(
            std::fs::read(retained_parent.join("null")).expect("retained placeholder"),
            b"placeholder"
        );

        let mut traversal = record;
        traversal.relative_path = std::path::PathBuf::from("../external/null");
        let traversal_manifest = DeviceTargetManifest {
            schema_version: DEVICE_TARGETS_SCHEMA_VERSION.to_string(),
            rootfs: rootfs_record,
            targets: vec![traversal],
        };
        let error = cleanup_device_target_manifest(&traversal_manifest)
            .expect_err("reject traversal target");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert_eq!(
            std::fs::read(external.join("null")).expect("external target after traversal"),
            b"external"
        );
    }

    #[test]
    fn device_target_rootfs_binding_is_single_assignment() {
        let temporary = tempdir().expect("temporary plan workspace");
        let runtime_directory = temporary.path().join("runtime");
        let rootfs = temporary.path().join("rootfs");
        std::fs::create_dir_all(&runtime_directory).expect("runtime directory");
        std::fs::create_dir_all(&rootfs).expect("rootfs directory");
        let prepared = PreparedDeviceSources {
            sources: Some(Vec::new()),
            verify_ownership: true,
            manifest: std::sync::Mutex::new(None),
            manifest_file: std::sync::Mutex::new(None),
            manifest_path: Some(runtime_directory.join("device-targets.json")),
        };

        prepared.bind_rootfs(&rootfs).expect("bind rootfs once");
        assert!(prepared.bind_rootfs(&rootfs).is_err());
    }

    #[test]
    fn retained_manifest_descriptor_survives_private_path_becoming_unresolvable() {
        let temporary = tempdir().expect("temporary plan workspace");
        let runtime_directory = temporary.path().join("runtime");
        let retained_directory = temporary.path().join("runtime-retained");
        let rootfs = temporary.path().join("rootfs");
        std::fs::create_dir(&runtime_directory).expect("runtime directory");
        std::fs::create_dir(&rootfs).expect("rootfs directory");
        let target = rootfs.join("null");
        std::fs::write(&target, b"placeholder").expect("placeholder file");
        let metadata = std::fs::symlink_metadata(&target).expect("placeholder metadata");
        let record = DeviceTargetRecord::capture(std::path::Path::new("null"), &metadata)
            .expect("capture target");
        let prepared = PreparedDeviceSources {
            sources: Some(Vec::new()),
            verify_ownership: false,
            manifest: std::sync::Mutex::new(None),
            manifest_file: std::sync::Mutex::new(None),
            manifest_path: Some(runtime_directory.join("device-targets.json")),
        };
        prepared.bind_rootfs(&rootfs).expect("bind rootfs");

        std::fs::rename(&runtime_directory, &retained_directory)
            .expect("hide the supervisor runtime directory path");
        std::fs::write(&runtime_directory, b"not a directory")
            .expect("block path-based manifest reopening");
        prepared
            .record_device_target(record.clone())
            .expect("update through the retained manifest descriptor");

        let loaded =
            load_device_target_manifest_from(&retained_directory.join(DEVICE_TARGETS_RECORD_NAME))
                .expect("load retained manifest")
                .expect("retained manifest");
        assert_eq!(loaded.targets, vec![record]);
        std::fs::remove_file(runtime_directory).expect("remove blocking path");
    }

    #[test]
    fn device_target_manifest_failure_rolls_back_new_placeholder() {
        let temporary = tempdir().expect("temporary plan workspace");
        let runtime_directory = temporary.path().join("runtime");
        let rootfs = temporary.path().join("rootfs");
        std::fs::create_dir(&runtime_directory).expect("runtime directory");
        std::fs::create_dir(&rootfs).expect("rootfs directory");
        std::fs::create_dir(rootfs.join("dev")).expect("device directory");
        let manifest_path = runtime_directory.join("device-targets.json");
        let prepared = PreparedDeviceSources {
            sources: Some(Vec::new()),
            verify_ownership: false,
            manifest: std::sync::Mutex::new(None),
            manifest_file: std::sync::Mutex::new(None),
            manifest_path: Some(manifest_path.clone()),
        };
        prepared.bind_rootfs(&rootfs).expect("bind rootfs");
        prepared
            .manifest_file
            .lock()
            .expect("manifest file state")
            .take();
        let node = DeviceNode {
            path: std::path::PathBuf::from("/dev/null"),
            kind: DeviceKind::Character,
            major: 1,
            minor: 3,
            mode: 0o666,
            uid: 0,
            gid: 0,
        };
        let source: OwnedFd = std::fs::File::open("/dev/null")
            .expect("device source")
            .into();
        let source = super::PreparedDeviceSource::RetainedNode(source);

        let error = node
            .bind_source(&rootfs, &source, false, &prepared)
            .expect_err("manifest persistence must fail");
        assert!(error.message.contains("manifest file was not opened"));
        assert!(!rootfs.join("dev/null").exists());
        assert!(manifest_path.is_file());
        assert!(!runtime_directory.join(".device-targets.json.next").exists());
        assert!(prepared
            .manifest
            .lock()
            .expect("manifest state")
            .as_ref()
            .expect("bound manifest")
            .targets
            .is_empty());
    }

    #[test]
    fn device_target_manifest_round_trips_exact_records() {
        let temporary = tempdir().expect("temporary device target directory");
        let runtime_directory = temporary.path().join("runtime");
        std::fs::create_dir(&runtime_directory).expect("runtime directory");
        std::fs::set_permissions(&runtime_directory, std::fs::Permissions::from_mode(0o700))
            .expect("runtime permissions");
        let rootfs = runtime_directory.join("rootfs");
        std::fs::create_dir(&rootfs).expect("rootfs directory");
        let path = rootfs.join("null");
        std::fs::write(&path, b"placeholder").expect("placeholder file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("placeholder permissions");
        let metadata = std::fs::symlink_metadata(&path).expect("placeholder metadata");
        let record = DeviceTargetRecord::capture(std::path::Path::new("null"), &metadata)
            .expect("capture target");
        let manifest = DeviceTargetManifest {
            schema_version: DEVICE_TARGETS_SCHEMA_VERSION.to_string(),
            rootfs: super::DeviceRootfsRecord::capture(&rootfs).expect("rootfs record"),
            targets: vec![record],
        };
        let manifest_path = runtime_directory.join("device-targets.json");

        write_device_target_manifest(&manifest_path, &manifest).expect("write manifest");
        let loaded = load_device_target_manifest_from(&manifest_path)
            .expect("load manifest")
            .expect("manifest");
        assert_eq!(loaded, manifest);
        assert_eq!(
            load_device_target_manifest(&runtime_directory)
                .expect("load runtime manifest")
                .expect("runtime manifest"),
            manifest
        );
    }

    #[test]
    fn legacy_absolute_device_target_manifest_fails_closed() {
        let temporary = tempdir().expect("temporary device target directory");
        let manifest_path = temporary.path().join("device-targets.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "schemaVersion": "a3s.oci.native-linux-device-targets.v1",
                "targets": [{
                    "path": "/tmp/untrusted",
                    "dev": 1,
                    "ino": 2,
                    "mode": 384,
                    "uid": 0,
                    "gid": 0
                }]
            }))
            .expect("encode legacy manifest"),
        )
        .expect("write legacy manifest");
        std::fs::set_permissions(&manifest_path, std::fs::Permissions::from_mode(0o600))
            .expect("legacy manifest permissions");

        let error = load_device_target_manifest_from(&manifest_path)
            .expect_err("legacy manifest must fail closed");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert!(error.message.contains("legacy v1 absolute paths"));
    }

    #[test]
    fn plans_the_exact_a3s_box_device_allowlist() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/a3s-box/config.json"))
                .expect("decode fixture");
        let linux: Linux =
            serde_json::from_value(config["linux"].clone()).expect("decode Linux config");
        let namespaces =
            NamespacePlan::from_linux(Some(&linux), 0, 0, &[]).expect("namespace plan");
        let mounts = mount::plan_all(
            serde_json::from_value::<Vec<a3s_oci_sdk::oci_spec::runtime::Mount>>(
                config["mounts"].clone(),
            )
            .expect("decode mounts")
            .as_slice()
            .into(),
            &namespaces,
        )
        .expect("mount plan");
        let plan = DevicePlan::from_linux(Some(&linux), &mounts).expect("device plan");
        assert_eq!(plan.len(), 6);
        plan.validate_rootless_device_set()
            .expect("A3S Box fixture is the fixed rootless device set");
    }

    #[test]
    fn rootless_policy_rejects_devices_outside_the_fixed_safe_set() {
        let mut config: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/a3s-box/config.json"))
                .expect("decode fixture");
        config["linux"]["devices"][0]["path"] = serde_json::json!("/dev/sda");
        let linux: Linux =
            serde_json::from_value(config["linux"].clone()).expect("decode Linux config");
        let plan = DevicePlan::from_linux(Some(&linux), &[]).expect("device plan");
        let error = plan
            .validate_rootless_device_set()
            .expect_err("device outside the fixed safe set must be rejected");
        assert_eq!(error.code, ErrorCode::Unsupported);
    }

    #[test]
    fn plans_read_only_device_allowlist_rules() {
        let linux: Linux = serde_json::from_value(serde_json::json!({
            "devices": [
                {
                    "path": "/dev/null",
                    "type": "c",
                    "major": 1,
                    "minor": 3,
                    "fileMode": 420,
                    "uid": 0,
                    "gid": 0
                }
            ],
            "resources": {
                "devices": [
                    {"allow": false, "access": "rwm"},
                    {"allow": true, "type": "c", "major": 1, "minor": 3, "access": "r"}
                ]
            }
        }))
        .expect("decode read-only device policy");
        let plan = DevicePlan::from_linux(Some(&linux), &[]).expect("device plan");
        assert!(plan.requires_setup());
        assert_eq!(plan.len(), 1);
    }

    #[test]
    fn deny_only_device_policy_still_requires_rootfs_enforcement() {
        let linux: Linux = serde_json::from_value(serde_json::json!({
            "resources": {
                "devices": [{"allow": false, "access": "rwm"}]
            }
        }))
        .expect("decode deny-only device policy");
        let plan = DevicePlan::from_linux(Some(&linux), &[]).expect("device plan");
        assert!(plan.requires_setup());
        assert_eq!(plan.len(), 0);
    }

    #[test]
    fn replans_device_access_masks_for_live_updates() {
        let current = DevicePlan {
            nodes: vec![DeviceNode {
                path: std::path::PathBuf::from("/dev/null"),
                kind: DeviceKind::Character,
                major: 1,
                minor: 3,
                mode: 0o660,
                uid: 0,
                gid: 0,
            }],
            allow_access_masks: vec![7],
            enforce_allowlist: true,
        };
        let resources: LinuxResources = serde_json::from_value(serde_json::json!({
            "devices": [
                {"allow": false, "access": "rwm"},
                {"allow": true, "type": "c", "major": 1, "minor": 3, "access": "r"}
            ]
        }))
        .expect("decode live device update");
        let updated = current
            .update_from_resources(&resources)
            .expect("live device update should replan")
            .expect("live device update should produce a new plan");
        assert_eq!(updated.nodes, current.nodes);
        assert_eq!(updated.allow_access_masks, vec![BPF_DEVCG_ACC_READ as u8]);
        assert!(updated.requires_setup());
    }

    #[test]
    fn replans_to_disable_device_enforcement_when_rules_are_cleared() {
        let current = DevicePlan {
            nodes: Vec::new(),
            allow_access_masks: Vec::new(),
            enforce_allowlist: true,
        };
        let resources: LinuxResources = serde_json::from_value(serde_json::json!({
            "devices": []
        }))
        .expect("decode cleared device policy");
        let updated = current
            .update_from_resources(&resources)
            .expect("cleared device policy should replan")
            .expect("cleared device policy should produce a new plan");
        assert_eq!(updated, DevicePlan::default());
        assert!(!updated.requires_setup());
    }

    #[test]
    fn fixed_device_nodes_survive_disable_for_later_reenable() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/a3s-box/config.json"))
                .expect("decode fixture");
        let linux: Linux =
            serde_json::from_value(config["linux"].clone()).expect("decode Linux config");
        let current = DevicePlan::from_linux(Some(&linux), &[]).expect("device plan");
        let disabled: LinuxResources =
            serde_json::from_value(serde_json::json!({"devices": []})).expect("disabled policy");
        let disabled = current
            .update_from_resources(&disabled)
            .expect("disable policy")
            .expect("updated policy");
        assert_eq!(disabled.nodes, current.nodes);
        assert!(!disabled.requires_setup());

        let resources = linux.resources().clone().expect("fixture resources");
        let reenabled = disabled
            .update_from_resources(&resources)
            .expect("reenable policy")
            .expect("updated policy");
        assert_eq!(reenabled.nodes, current.nodes);
        assert_eq!(reenabled.allow_access_masks, current.allow_access_masks);
        assert!(reenabled.requires_setup());
    }

    #[test]
    fn rejects_device_allowlist_rules_that_do_not_match_the_created_nodes() {
        let mut config: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/a3s-box/config.json"))
                .expect("decode fixture");
        let linux: Linux =
            serde_json::from_value(config["linux"].clone()).expect("decode Linux config");
        let namespaces =
            NamespacePlan::from_linux(Some(&linux), 0, 0, &[]).expect("namespace plan");
        let mounts = mount::plan_all(
            serde_json::from_value::<Vec<a3s_oci_sdk::oci_spec::runtime::Mount>>(
                config["mounts"].clone(),
            )
            .expect("decode mounts")
            .as_slice()
            .into(),
            &namespaces,
        )
        .expect("mount plan");

        config["linux"]["resources"]["devices"][2]["minor"] = serde_json::json!(6);
        let mutated_linux: Linux =
            serde_json::from_value(config["linux"].clone()).expect("decode mutated Linux config");
        let error = DevicePlan::from_linux(Some(&mutated_linux), &mounts)
            .expect_err("mismatched allowlist must fail");
        assert_eq!(error.code, ErrorCode::Unsupported);
        assert!(error.message.contains("matching created device"));
    }

    #[test]
    fn builds_cgroup_device_bpf_for_block_and_char_devices_only() {
        let nodes = vec![
            DeviceNode {
                path: std::path::PathBuf::from("/dev/ttyS0"),
                kind: DeviceKind::Character,
                major: 4,
                minor: 64,
                mode: 0o660,
                uid: 0,
                gid: 0,
            },
            DeviceNode {
                path: std::path::PathBuf::from("/dev/loop0"),
                kind: DeviceKind::Block,
                major: 7,
                minor: 0,
                mode: 0o660,
                uid: 0,
                gid: 0,
            },
            DeviceNode {
                path: std::path::PathBuf::from("/tmp/fifo"),
                kind: DeviceKind::Fifo,
                major: 0,
                minor: 0,
                mode: 0o600,
                uid: 0,
                gid: 0,
            },
        ];
        let program = build_cgroup_device_program(&nodes, &[7, 7, 7]).expect("device BPF program");
        assert_eq!(program.len(), 18);
        assert_eq!(
            program[0].code,
            (libc::BPF_LDX | libc::BPF_W | libc::BPF_MEM) as u8
        );
        assert_eq!(program[1].imm, 0xFFFF);
        assert_eq!(
            program[2].code,
            (libc::BPF_LDX | libc::BPF_W | libc::BPF_MEM) as u8
        );
        assert_eq!(program[3].imm, 16);
        assert_eq!(program[6].imm, 2);
        assert_eq!(program[6].off, 4);
        assert_eq!(program[11].imm, 1);
        assert_eq!(program[11].off, 4);
        assert_eq!(program[16].imm, 0);
        assert_eq!(program[17].code, (libc::BPF_JMP | super::BPF_EXIT) as u8);
    }

    #[test]
    fn fifo_only_device_plans_fall_back_to_reject_all() {
        let nodes = vec![DeviceNode {
            path: std::path::PathBuf::from("/tmp/fifo"),
            kind: DeviceKind::Fifo,
            major: 0,
            minor: 0,
            mode: 0o600,
            uid: 0,
            gid: 0,
        }];
        let program = build_cgroup_device_program(&nodes, &[7]).expect("device BPF program");
        assert_eq!(program.len(), 2);
        assert_eq!(program[0].imm, 0);
        assert_eq!(program[1].code, (libc::BPF_JMP | super::BPF_EXIT) as u8);
    }

    #[test]
    fn builds_cgroup_device_bpf_with_access_subsets() {
        let nodes = vec![DeviceNode {
            path: std::path::PathBuf::from("/dev/null"),
            kind: DeviceKind::Character,
            major: 1,
            minor: 3,
            mode: 0o660,
            uid: 0,
            gid: 0,
        }];
        let program = build_cgroup_device_program(&nodes, &[BPF_DEVCG_ACC_READ as u8])
            .expect("device BPF program");
        assert_eq!(program.len(), 16);
        assert_eq!(
            program[2].code,
            (libc::BPF_LDX | libc::BPF_W | libc::BPF_MEM) as u8
        );
        assert_eq!(program[3].imm, 16);
        assert_eq!(program[6].imm, 2);
        assert_eq!(program[7].code, (BPF_ALU64 | BPF_MOV | libc::BPF_X) as u8);
        assert_eq!(program[8].imm, BPF_DEVCG_ACC_READ as i32);
        assert_eq!(program[9].off, 4);
        assert_eq!(program[10].off, 3);
        assert_eq!(program[11].off, 2);
        assert_eq!(program[12].imm, 1);
        assert_eq!(program[13].code, (libc::BPF_JMP | super::BPF_EXIT) as u8);
        assert_eq!(program[14].imm, 0);
        assert_eq!(program[15].code, (libc::BPF_JMP | super::BPF_EXIT) as u8);
    }
}
