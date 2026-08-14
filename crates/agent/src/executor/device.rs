use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread::sleep;
use std::time::{Duration, Instant};

use a3s_oci_sdk::oci_spec::runtime::{Linux, LinuxDevice, LinuxDeviceType, LinuxResources};
use a3s_oci_sdk::{Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};

use super::mount::MountPlan;
use super::namespace::NamespacePlan;
use super::recovery::read_json_record;

mod access;

pub(super) use access::LoadedDeviceProgram;
use access::{DeviceAccessKind, DeviceAccessPolicy};

const MAX_DEVICES: usize = 256;
const MAX_SCANNED_ROOTFS_ENTRIES: usize = 1_000_000;
const DEVICE_TARGETS_RECORD_NAME: &str = "device-targets.json";
const DEVICE_TARGETS_SCHEMA_VERSION: &str = "a3s.oci.native-linux-device-targets.v2";
const DEVICE_TARGETS_SCHEMA_VERSION_V1: &str = "a3s.oci.native-linux-device-targets.v1";
const MAX_DEVICE_TARGETS_RECORD_BYTES: u64 = 64 * 1024;
const DEVICE_TARGET_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const DEVICE_TARGET_CLEANUP_POLL_INTERVAL: Duration = Duration::from_millis(10);
pub(super) const ROOTLESS_DEVICE_MOUNT_COUNT: usize = 6;
const ROOTLESS_SAFE_DEVICES: [(&str, DeviceKind, u32, u32); ROOTLESS_DEVICE_MOUNT_COUNT] = [
    ("/dev/null", DeviceKind::Character, 1, 3),
    ("/dev/zero", DeviceKind::Character, 1, 5),
    ("/dev/full", DeviceKind::Character, 1, 7),
    ("/dev/random", DeviceKind::Character, 1, 8),
    ("/dev/urandom", DeviceKind::Character, 1, 9),
    ("/dev/tty", DeviceKind::Character, 5, 0),
];
const DEFAULT_DEVICE_MODE: u32 = 0o666;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DevicePlan {
    nodes: Vec<DeviceNode>,
    access_policy: Option<DeviceAccessPolicy>,
    terminal: bool,
}

#[derive(Debug)]
pub(super) struct PreparedDeviceSources {
    sources: Option<Vec<PreparedDeviceSource>>,
    verify_ownership: bool,
    target_host_owner: Option<(u32, u32)>,
    manifest: Mutex<Option<DeviceTargetManifest>>,
    manifest_file: Mutex<Option<File>>,
    manifest_path: Option<PathBuf>,
}

#[derive(Debug)]
enum PreparedDeviceSource {
    DetachedMount(OwnedFd),
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

    fn capture_for_cleanup(
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

fn default_device_nodes() -> Vec<DeviceNode> {
    ROOTLESS_SAFE_DEVICES
        .iter()
        .map(|(path, kind, major, minor)| DeviceNode {
            path: PathBuf::from(path),
            kind: *kind,
            major: *major,
            minor: *minor,
            mode: DEFAULT_DEVICE_MODE,
            uid: 0,
            gid: 0,
        })
        .collect()
}

impl DevicePlan {
    pub(super) fn from_linux(
        linux: Option<&Linux>,
        mounts: &[MountPlan],
        terminal: bool,
        mount_namespace_isolated: bool,
    ) -> Result<Self> {
        let Some(linux) = linux else {
            return Ok(Self::default());
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
        let mut explicit_nodes = devices
            .iter()
            .enumerate()
            .map(|(index, device)| DeviceNode::from_oci(index, device))
            .collect::<Result<Vec<_>>>()?;
        let mut nodes = if mount_namespace_isolated {
            default_device_nodes()
        } else {
            Vec::new()
        };
        for explicit in explicit_nodes.drain(..) {
            if let Some(default) = nodes
                .iter_mut()
                .find(|default| default.path == explicit.path)
            {
                *default = explicit;
            } else {
                nodes.push(explicit);
            }
        }
        let mut unique_paths = BTreeSet::new();
        for node in &nodes {
            if !unique_paths.insert(node.path.clone()) {
                return Err(invalid(format!(
                    "linux.devices contains duplicate path {}",
                    node.path.display()
                )));
            }
        }
        let access_policy = DeviceAccessPolicy::from_oci(rules)?;
        if access_policy.is_some() {
            validate_bind_mounts_are_nodev(mounts)?;
        }
        Ok(Self {
            nodes,
            access_policy,
            terminal,
        })
    }

    pub(super) fn validate_rootfs(&self, rootfs: &Path) -> Result<()> {
        if self.nodes.is_empty() && self.access_policy.is_none() {
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
        device_source_directory: &Path,
        rootless: bool,
        rootless_mount_descriptors: &[OwnedFd],
    ) -> Result<PreparedDeviceSources> {
        let target_host_owner = if namespaces.new_user() {
            Some((
                namespaces.host_uid(0).ok_or_else(|| {
                    device_error(
                        ErrorCode::InvalidArgument,
                        "container root UID is not covered by linux.uidMappings",
                    )
                })?,
                namespaces.host_gid(0).ok_or_else(|| {
                    device_error(
                        ErrorCode::InvalidArgument,
                        "container root GID is not covered by linux.gidMappings",
                    )
                })?,
            ))
        } else {
            None
        };
        if !rootless && !rootless_mount_descriptors.is_empty() {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                "privileged device preparation received rootless mount descriptors",
            ));
        }
        if rootless && rootless_mount_descriptors.len() > ROOTLESS_DEVICE_MOUNT_COUNT {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                format!(
                    "rootless device preparation received {} mount descriptors; maximum is {ROOTLESS_DEVICE_MOUNT_COUNT}",
                    rootless_mount_descriptors.len()
                ),
            ));
        }
        if !namespaces.has_user() {
            if !rootless_mount_descriptors.is_empty() {
                return Err(device_error(
                    ErrorCode::PermissionDenied,
                    "device mount descriptors were supplied without a user namespace",
                ));
            }
            return Ok(PreparedDeviceSources {
                sources: None,
                verify_ownership: true,
                target_host_owner,
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
            if !rootless_mount_descriptors.is_empty() {
                return Err(device_error(
                    ErrorCode::PermissionDenied,
                    "rootless device mount descriptors were supplied without device nodes",
                ));
            }
            return Ok(PreparedDeviceSources {
                sources: Some(Vec::new()),
                verify_ownership: !rootless,
                target_host_owner,
                manifest: Mutex::new(None),
                manifest_file: Mutex::new(None),
                manifest_path: None,
            });
        }

        if rootless {
            let mounts = self.prepare_rootless_sources(rootless_mount_descriptors)?;
            return Ok(PreparedDeviceSources {
                sources: Some(mounts),
                verify_ownership: false,
                target_host_owner,
                manifest: Mutex::new(None),
                manifest_file: Mutex::new(None),
                manifest_path: Some(runtime_directory.join(DEVICE_TARGETS_RECORD_NAME)),
            });
        }

        let device_source_directory = canonical_device_source_directory(device_source_directory)?;
        let directory = device_source_directory.join("devices");
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
                target_host_owner,
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
        ensure_ptmx_link()?;
        Ok(())
    }

    pub(super) const fn uses_prepared_sources(prepared: &PreparedDeviceSources) -> bool {
        prepared.sources.is_some()
    }

    pub(super) fn requires_setup(&self) -> bool {
        self.has_node_setup() || self.has_access_policy() || self.terminal
    }

    pub(super) fn has_node_setup(&self) -> bool {
        !self.nodes.is_empty()
    }

    pub(super) fn has_access_policy(&self) -> bool {
        self.access_policy.is_some()
    }

    pub(super) fn update_from_resources(&self, resources: &LinuxResources) -> Result<Option<Self>> {
        let Some(rules) = resources.devices().as_deref() else {
            return Ok(None);
        };
        let access_policy = DeviceAccessPolicy::from_oci(rules)?;
        Ok(Some(Self {
            nodes: self.nodes.clone(),
            access_policy,
            terminal: self.terminal,
        }))
    }

    pub(super) fn load_cgroup_device_program(&self) -> Result<Option<OwnedFd>> {
        self.access_policy
            .as_ref()
            .map(DeviceAccessPolicy::load)
            .transpose()
    }

    pub(super) fn load_device_program(&self) -> Result<LoadedDeviceProgram> {
        self.validate_serialized_policy()?;
        self.access_policy
            .as_ref()
            .ok_or_else(|| {
                device_error(
                    ErrorCode::PermissionDenied,
                    "serialized rootless device policy has no active access policy",
                )
            })?
            .load_for_rootless_helper()
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
        if !self.has_rootless_safe_nodes() || !self.has_rootless_safe_access_policy() {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                "serialized rootless device policy is not a bounded active allowlist",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn validate_rootless_device_set(&self) -> Result<()> {
        self.validate_rootless_device_support()?;
        if !self.has_rootless_safe_access_policy() {
            Err(device_error(
                ErrorCode::Unsupported,
                "rootless device policy requires the exact six-node A3S Box safe-device profile",
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn validate_rootless_device_support(&self) -> Result<()> {
        if !self.has_rootless_safe_nodes()
            || self.terminal
            || (self.access_policy.is_some() && !self.has_rootless_safe_access_policy())
        {
            Err(device_error(
                ErrorCode::Unsupported,
                "rootless device support requires the exact six-node A3S Box safe-device profile",
            ))
        } else {
            Ok(())
        }
    }

    fn prepare_rootless_sources(
        &self,
        descriptors: &[OwnedFd],
    ) -> Result<Vec<PreparedDeviceSource>> {
        self.validate_rootless_device_support()?;
        if descriptors.len() != self.nodes.len() {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                format!(
                    "rootless device mount descriptor count {} does not match the fixed device set {}",
                    descriptors.len(),
                    self.nodes.len()
                ),
            ));
        }
        self.nodes
            .iter()
            .zip(descriptors)
            .enumerate()
            .map(|(index, (node, descriptor))| {
                node.prepare_inherited_rootless_source(index, descriptor.as_raw_fd())
            })
            .collect()
    }

    pub(super) fn attach_loaded_cgroup_device_program(
        &self,
        cgroup_path: &Path,
        loaded: &OwnedFd,
    ) -> Result<()> {
        access::attach_loaded_cgroup_device_program(cgroup_path, loaded)
    }

    pub(super) fn replace_loaded_cgroup_device_program(
        &self,
        cgroup_path: &Path,
        loaded: &OwnedFd,
        replaced: &OwnedFd,
    ) -> Result<()> {
        access::replace_loaded_cgroup_device_program(cgroup_path, loaded, replaced)
    }

    pub(super) fn detach_loaded_cgroup_device_program(
        &self,
        cgroup_path: &Path,
        attached: &OwnedFd,
    ) -> Result<()> {
        access::detach_loaded_cgroup_device_program(cgroup_path, attached)
    }

    pub(super) fn install_cgroup_device_filter(
        &self,
        cgroup_path: &Path,
    ) -> Result<Option<OwnedFd>> {
        if self.access_policy.is_none() {
            return Ok(None);
        }
        let Some(loaded) = self.load_cgroup_device_program()? else {
            return Ok(None);
        };
        self.attach_loaded_cgroup_device_program(cgroup_path, &loaded)?;
        Ok(Some(loaded))
    }

    fn has_rootless_safe_access_policy(&self) -> bool {
        let expected = ROOTLESS_SAFE_DEVICES.map(|(_, kind, major, minor)| {
            (kind.access_kind().expect("safe device kind"), major, minor)
        });
        self.access_policy
            .as_ref()
            .is_some_and(|policy| policy.is_exact_rootless_allowlist(&expected))
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.nodes.len()
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

    fn prepare_inherited_rootless_source(
        &self,
        index: usize,
        descriptor: RawFd,
    ) -> Result<PreparedDeviceSource> {
        if !is_rootless_safe_device(self) {
            return Err(unsupported(
                &format!("linux.devices[{index}].path"),
                "rootless device profiles support only the fixed A3S Box safe-device set",
            ));
        }
        if descriptor < 0 {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                format!("rootless device mount slot {index} has an invalid descriptor"),
            ));
        }
        // The fixed descriptor is owned by container-init. Duplicate it so
        // PreparedDeviceSources owns a close-on-exec copy with ordinary Rust
        // lifetime semantics, without consuming or mutating the inherited slot.
        let duplicated = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicated < 0 {
            return Err(last_os_error(format!(
                "duplicate inherited rootless device mount {}",
                self.path.display()
            )));
        }
        // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor.
        let duplicated = unsafe { OwnedFd::from_raw_fd(duplicated) };
        if !self.matches_source_metadata(&metadata_for_fd(&duplicated)?) {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                format!(
                    "inherited rootless device mount {} does not match the fixed device slot",
                    self.path.display()
                ),
            ));
        }
        Ok(PreparedDeviceSource::DetachedMount(duplicated))
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
        let record = DeviceTargetRecord::capture_for_cleanup(
            relative,
            &metadata,
            prepared.target_host_owner,
        )?;
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

        let PreparedDeviceSource::DetachedMount(source) = source;
        attach_device_mount(source, &target, &self.path)?;
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

fn ensure_ptmx_link() -> Result<()> {
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
        Ok(_) => {
            return Err(device_error(
                ErrorCode::FailedPrecondition,
                "/dev/ptmx already exists and is not the required symlink",
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

    const fn access_kind(self) -> Option<DeviceAccessKind> {
        match self {
            Self::Block => Some(DeviceAccessKind::Block),
            Self::Character => Some(DeviceAccessKind::Character),
            Self::Fifo => None,
        }
    }
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

fn canonical_device_source_directory(path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        device_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect OCI device-source directory {}: {error}",
                path.display()
            ),
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(device_error(
            ErrorCode::PermissionDenied,
            format!(
                "OCI device-source directory is not a real directory: {}",
                path.display()
            ),
        ));
    }
    path.canonicalize().map_err(|error| {
        device_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to resolve OCI device-source directory {}: {error}",
                path.display()
            ),
        )
    })
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
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use a3s_oci_sdk::oci_spec::runtime::{Linux, LinuxResources};
    use a3s_oci_sdk::ErrorCode;

    use super::{
        canonical_device_source_directory, cleanup_device_target_manifest,
        load_device_target_manifest, load_device_target_manifest_from,
        write_device_target_manifest, DeviceKind, DeviceNode, DevicePlan, DeviceTargetManifest,
        DeviceTargetRecord, PreparedDeviceSources, DEVICE_TARGETS_RECORD_NAME,
        DEVICE_TARGETS_SCHEMA_VERSION, ROOTLESS_DEVICE_MOUNT_COUNT,
    };
    use crate::executor::mount;
    use crate::executor::namespace::NamespacePlan;
    use tempfile::tempdir;

    #[test]
    fn device_source_directory_must_be_a_real_directory() {
        let temporary = tempdir().expect("temporary device source parent");
        let directory = temporary.path().join("sources");
        let symlink = temporary.path().join("sources-link");
        std::fs::create_dir(&directory).expect("device source directory");
        std::os::unix::fs::symlink(&directory, &symlink).expect("device source symlink");

        assert_eq!(
            canonical_device_source_directory(&directory).expect("real source directory"),
            directory
                .canonicalize()
                .expect("canonical source directory")
        );
        let error = canonical_device_source_directory(&symlink)
            .expect_err("device source symlink must fail closed");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
    }

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
    fn cleanup_record_uses_host_owner_for_user_namespace_placeholder() {
        let temporary = tempdir().expect("temporary device target directory");
        let path = temporary.path().join("null");
        std::fs::write(&path, b"placeholder").expect("placeholder file");
        let metadata = std::fs::symlink_metadata(&path).expect("placeholder metadata");
        let namespace_record = DeviceTargetRecord::capture(std::path::Path::new("null"), &metadata)
            .expect("capture namespace target");
        let host_owner = (
            namespace_record.uid.wrapping_add(1),
            namespace_record.gid.wrapping_add(1),
        );

        let host_record = DeviceTargetRecord::capture_for_cleanup(
            std::path::Path::new("null"),
            &metadata,
            Some(host_owner),
        )
        .expect("capture mapped target");
        assert_eq!((host_record.uid, host_record.gid), host_owner);
        // Model the initial-user-namespace view used by the supervisor after
        // the container mount namespace has gone away.
        let observed = super::TargetMetadata {
            file_type: libc::S_IFREG,
            dev: metadata.dev(),
            rdev: metadata.rdev(),
            ino: metadata.ino(),
            mode: metadata.mode() & 0o7777,
            uid: host_owner.0,
            gid: host_owner.1,
        };

        assert!(!namespace_record.matches(&observed));
        assert!(host_record.matches(&observed));
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
            target_host_owner: None,
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
            target_host_owner: None,
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
            target_host_owner: None,
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
        let source = super::PreparedDeviceSource::DetachedMount(
            std::fs::File::open("/dev/null")
                .expect("device source")
                .into(),
        );

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
        let plan = DevicePlan::from_linux(Some(&linux), &mounts, false, true).expect("device plan");
        assert_eq!(plan.len(), 6);
        plan.validate_rootless_device_set()
            .expect("A3S Box fixture is the fixed rootless device set");
    }

    #[test]
    fn rootless_default_devices_do_not_require_an_access_policy() {
        let linux: Linux = serde_json::from_value(serde_json::json!({}))
            .expect("decode empty Linux configuration");
        let plan = DevicePlan::from_linux(Some(&linux), &[], false, true)
            .expect("plan normative default devices");

        assert_eq!(plan.len(), ROOTLESS_DEVICE_MOUNT_COUNT);
        plan.validate_rootless_device_support()
            .expect("default devices need only the bounded mount helper");
        assert!(plan.validate_rootless_device_set().is_err());
    }

    #[test]
    fn rootless_policy_rejects_devices_outside_the_fixed_safe_set() {
        let mut config: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/a3s-box/config.json"))
                .expect("decode fixture");
        config["linux"]["devices"][0] = serde_json::json!({
            "path": "/dev/sda",
            "type": "b",
            "major": 8,
            "minor": 0,
            "fileMode": 438,
            "uid": 0,
            "gid": 0
        });
        let linux: Linux =
            serde_json::from_value(config["linux"].clone()).expect("decode Linux config");
        let plan = DevicePlan::from_linux(Some(&linux), &[], false, true).expect("device plan");
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
        let plan = DevicePlan::from_linux(Some(&linux), &[], false, true).expect("device plan");
        assert!(plan.requires_setup());
        assert_eq!(plan.len(), 6);
    }

    #[test]
    fn deny_only_device_policy_still_requires_rootfs_enforcement() {
        let linux: Linux = serde_json::from_value(serde_json::json!({
            "resources": {
                "devices": [{"allow": false, "access": "rwm"}]
            }
        }))
        .expect("decode deny-only device policy");
        let plan = DevicePlan::from_linux(Some(&linux), &[], false, true).expect("device plan");
        assert!(plan.requires_setup());
        assert_eq!(plan.len(), 6);
    }

    #[test]
    fn replans_device_access_masks_for_live_updates() {
        let linux: Linux = serde_json::from_value(serde_json::json!({
            "resources": {
                "devices": [
                    {"allow": false, "access": "rwm"},
                    {"allow": true, "type": "c", "major": 1, "minor": 3, "access": "rwm"}
                ]
            }
        }))
        .expect("decode initial device policy");
        let current = DevicePlan::from_linux(Some(&linux), &[], false, true).expect("device plan");
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
        assert_ne!(updated.access_policy, current.access_policy);
        assert!(updated.requires_setup());
    }

    #[test]
    fn replans_to_disable_device_enforcement_when_rules_are_cleared() {
        let current = DevicePlan::default();
        let resources: LinuxResources = serde_json::from_value(serde_json::json!({
            "devices": []
        }))
        .expect("decode cleared device policy");
        let updated = current
            .update_from_resources(&resources)
            .expect("cleared device policy should replan")
            .expect("cleared device policy should produce a new plan");
        assert_eq!(updated.access_policy, None);
        assert_eq!(updated.nodes, current.nodes);
    }

    #[test]
    fn fixed_device_nodes_survive_disable_for_later_reenable() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/a3s-box/config.json"))
                .expect("decode fixture");
        let linux: Linux =
            serde_json::from_value(config["linux"].clone()).expect("decode Linux config");
        let current = DevicePlan::from_linux(Some(&linux), &[], false, true).expect("device plan");
        let disabled: LinuxResources =
            serde_json::from_value(serde_json::json!({"devices": []})).expect("disabled policy");
        let disabled = current
            .update_from_resources(&disabled)
            .expect("disable policy")
            .expect("updated policy");
        assert_eq!(disabled.nodes, current.nodes);
        assert!(disabled.requires_setup());

        let resources = linux.resources().clone().expect("fixture resources");
        let reenabled = disabled
            .update_from_resources(&resources)
            .expect("reenable policy")
            .expect("updated policy");
        assert_eq!(reenabled.nodes, current.nodes);
        assert_eq!(reenabled.access_policy, current.access_policy);
        assert!(reenabled.requires_setup());
    }

    #[test]
    fn keeps_device_access_rules_independent_from_created_nodes() {
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
        let plan = DevicePlan::from_linux(Some(&mutated_linux), &mounts, false, true)
            .expect("independent access rule");
        assert_eq!(plan.len(), 6);
        assert!(plan.access_policy.is_some());
    }
}
