use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::{Linux, LinuxDevice, LinuxDeviceCgroup, LinuxDeviceType};
use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::mount::MountPlan;
use super::namespace::NamespacePlan;

const MAX_DEVICES: usize = 256;
const MAX_SCANNED_ROOTFS_ENTRIES: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DevicePlan {
    nodes: Vec<DeviceNode>,
    enforce_allowlist: bool,
}

#[derive(Debug)]
pub(super) struct PreparedDeviceSources {
    mounts: Option<Vec<OwnedFd>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DeviceNode {
    path: PathBuf,
    kind: DeviceKind,
    major: u32,
    minor: u32,
    mode: u32,
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
        validate_device_policy(&nodes, Some(rules))?;
        let enforce_allowlist = !nodes.is_empty() || !rules.is_empty();
        if enforce_allowlist {
            validate_bind_mounts_are_nodev(mounts)?;
        }
        Ok(Self {
            nodes,
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
    ) -> Result<PreparedDeviceSources> {
        if !namespaces.has_user() {
            return Ok(PreparedDeviceSources { mounts: None });
        }
        if !namespaces.new_user() && !self.nodes.is_empty() {
            return Err(unsupported(
                "linux.devices",
                "devices in a joined user namespace require externally prepared mount sources",
            ));
        }
        if self.nodes.is_empty() {
            return Ok(PreparedDeviceSources {
                mounts: Some(Vec::new()),
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
                mounts: Some(mounts),
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
        let Some(mounts) = prepared.mounts.as_ref() else {
            return Ok(());
        };
        if mounts.len() != self.nodes.len() {
            return Err(device_error(
                ErrorCode::Internal,
                "prepared device source count does not match the OCI device plan",
            ));
        }
        for (node, source) in self.nodes.iter().zip(mounts) {
            node.bind_source(rootfs, source)?;
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
        prepared.mounts.is_some()
    }

    pub(super) fn requires_setup(&self) -> bool {
        self.enforce_allowlist
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.nodes.len()
    }
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
    ) -> Result<OwnedFd> {
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
        clone_device_mount(&path)
    }

    fn bind_source(&self, rootfs: &Path, source: &OwnedFd) -> Result<()> {
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

        attach_device_mount(source, &target, &self.path)?;
        self.verify_at(&target, self.uid, self.gid)
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

fn validate_device_policy(nodes: &[DeviceNode], rules: Option<&[LinuxDeviceCgroup]>) -> Result<()> {
    let rules = rules.unwrap_or_default();
    if nodes.is_empty() && rules.is_empty() {
        return Ok(());
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
    for (index, (node, rule)) in nodes.iter().zip(&rules[1..]).enumerate() {
        let expected_type = match node.kind {
            DeviceKind::Block => LinuxDeviceType::B,
            DeviceKind::Character => LinuxDeviceType::C,
            DeviceKind::Fifo => LinuxDeviceType::P,
        };
        if !rule.allow()
            || rule.typ() != Some(expected_type)
            || rule.major() != Some(i64::from(node.major))
            || rule.minor() != Some(i64::from(node.minor))
            || rule.access().as_deref() != Some("rwm")
        {
            return Err(unsupported(
                &format!("linux.resources.devices[{}]", index + 1),
                "the rule must allow rwm for the matching created device",
            ));
        }
    }
    Ok(())
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
    use a3s_oci_sdk::oci_spec::runtime::Linux;
    use a3s_oci_sdk::ErrorCode;

    use super::DevicePlan;
    use crate::executor::mount;
    use crate::executor::namespace::NamespacePlan;

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
}
