use std::collections::BTreeSet;
use std::fs::{self, File};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use a3s_oci_sdk::oci_spec::runtime::{Linux, LinuxResources};
use a3s_oci_sdk::{Error, ErrorCode, Result};

use crate::executor::mount::MountPlan;
use crate::executor::namespace::NamespacePlan;
use crate::OCI_LINUX_DEFAULT_DEVICE_NODES;

use super::access::{self, DeviceAccessBoundary, DeviceAccessPolicy, LoadedDeviceProgram};
use super::console::{
    bind_console_source, ensure_ptmx_link, prepare_console_source, verify_console_metadata,
    verify_ptmx_from_root,
};
use super::manifest::DEVICE_TARGETS_RECORD_NAME;
use super::mount_source::{
    canonical_device_source_directory, metadata_for_fd, openat2_beneath, target_metadata_for_path,
};
use super::node::default_device_nodes;
use super::types::{
    DeviceKind, DeviceNode, DevicePlan, PreparedDeviceSource, PreparedDeviceSources,
    ROOTLESS_DEVICE_MOUNT_COUNT,
};
use super::{device_error, invalid, unsupported};

const MAX_DEVICES: usize = 256;
const MAX_SCANNED_ROOTFS_ENTRIES: usize = 1_000_000;
const CHECKPOINT_DEVICE_COOKIE_PREFIX: &str = "a3s-oci-device";
impl DevicePlan {
    pub(in crate::executor) fn from_linux(
        linux: Option<&Linux>,
        mounts: &[MountPlan],
        terminal: bool,
        mount_namespace_isolated: bool,
    ) -> Result<Self> {
        let devices = linux
            .and_then(|linux| linux.devices().as_deref())
            .unwrap_or_default();
        let rules = linux
            .and_then(|linux| linux.resources().as_ref())
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
        let mut unique_paths = BTreeSet::new();
        let mut unique_identities = BTreeSet::new();
        for node in &explicit_nodes {
            if !unique_paths.insert(node.path.clone()) {
                return Err(invalid(format!(
                    "linux.devices contains duplicate path {}",
                    node.path.display()
                )));
            }
            let Some(identity) = node.kernel_identity() else {
                continue;
            };
            if !unique_identities.insert(identity) {
                return Err(invalid(format!(
                    "linux.devices contains duplicate kernel device identity {} {}:{}",
                    node.kind.label(),
                    node.major,
                    node.minor
                )));
            }
        }
        let mut nodes = default_device_nodes();
        for explicit in explicit_nodes.drain(..) {
            if let Some(default) = nodes
                .iter_mut()
                .find(|default| default.path == explicit.path)
            {
                if default.kernel_identity() != explicit.kernel_identity() {
                    return Err(invalid(format!(
                        "linux.devices path {} conflicts with normative default device {} {}:{}",
                        explicit.path.display(),
                        default.kind.label(),
                        default.major,
                        default.minor
                    )));
                }
                *default = explicit;
            } else {
                nodes.push(explicit);
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
            create_nodes: mount_namespace_isolated,
        })
    }

    pub(in crate::executor) fn validate_rootfs(&self, rootfs: &Path) -> Result<()> {
        if self.nodes.is_empty() && self.access_policy.is_none() {
            return Ok(());
        }
        let allowed = self
            .nodes
            .iter()
            .map(|node| node.path.clone())
            .chain(self.terminal.then(|| PathBuf::from("/dev/console")))
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

    pub(in crate::executor) fn prepare_sources(
        &self,
        namespaces: &NamespacePlan,
        runtime_directory: &Path,
        device_source_directory: &Path,
        rootless: bool,
        rootless_mount_descriptors: &[OwnedFd],
    ) -> Result<PreparedDeviceSources> {
        let target_host_owner = if namespaces.has_user() {
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
        if !self.create_nodes {
            if !rootless_mount_descriptors.is_empty() {
                return Err(device_error(
                    ErrorCode::PermissionDenied,
                    "device mount descriptors were supplied for an existing mount namespace",
                ));
            }
            return Ok(PreparedDeviceSources {
                sources: None,
                console: None,
                verify_ownership: true,
                target_host_owner,
                manifest: Mutex::new(None),
                manifest_file: Mutex::new(None),
                manifest_path: None,
            });
        }
        if rootless && !namespaces.has_user() {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                "rootless device preparation requires a new or joined user namespace",
            ));
        }

        if rootless {
            let mounts = self.prepare_rootless_sources(rootless_mount_descriptors)?;
            return Ok(PreparedDeviceSources {
                sources: Some(mounts),
                console: None,
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

        let prepared = (|| {
            let mounts = self
                .nodes
                .iter()
                .enumerate()
                .map(|(index, node)| node.prepare_source(index, &directory, namespaces))
                .collect::<Result<Vec<_>>>()?;
            let console = self.terminal.then(prepare_console_source).transpose()?;
            Ok::<_, Error>((mounts, console))
        })();
        match prepared {
            Ok((mounts, console)) => Ok(PreparedDeviceSources {
                sources: Some(mounts),
                console,
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

    pub(in crate::executor) fn bind_prepared_sources(
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
        if let Some(console) = &prepared.console {
            bind_console_source(rootfs, console, prepared)?;
        }
        Ok(())
    }

    /// Recreate only the file mountpoints that CRIU needs before rebuilding
    /// the saved mount tree. The restored namespace supplies the device
    /// mounts themselves; the host rootfs receives only runtime-owned regular
    /// placeholders tracked by the ordinary device cleanup manifest.
    pub(in crate::executor) fn prepare_restore_targets(
        &self,
        rootfs: &Path,
        runtime_directory: &Path,
    ) -> Result<()> {
        if !self.create_nodes || self.nodes.is_empty() {
            return Ok(());
        }
        let prepared = PreparedDeviceSources {
            sources: None,
            console: None,
            verify_ownership: true,
            target_host_owner: None,
            manifest: Mutex::new(None),
            manifest_file: Mutex::new(None),
            manifest_path: Some(runtime_directory.join(DEVICE_TARGETS_RECORD_NAME)),
        };
        prepared.bind_rootfs(rootfs)?;
        for node in &self.nodes {
            node.prepare_restore_target(rootfs, &prepared)?;
        }
        Ok(())
    }

    pub(in crate::executor) fn checkpoint_external_mounts(&self) -> Vec<(String, PathBuf)> {
        if !self.create_nodes {
            return Vec::new();
        }
        self.nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (checkpoint_device_cookie(index), node.path.clone()))
            .collect()
    }

    pub(in crate::executor) fn prepare_restore_external_mounts(
        &self,
        namespaces: &NamespacePlan,
        runtime_directory: &Path,
    ) -> Result<Vec<(String, PathBuf, PathBuf)>> {
        if !self.create_nodes || self.nodes.is_empty() {
            return Ok(Vec::new());
        }
        let prepared =
            self.prepare_sources(namespaces, runtime_directory, runtime_directory, false, &[])?;
        drop(prepared);
        let source_directory = runtime_directory.join("devices");
        self.nodes
            .iter()
            .enumerate()
            .map(|(index, node)| {
                let source = source_directory.join(format!("device-{index:04}"));
                let metadata = fs::symlink_metadata(&source).map_err(|error| {
                    device_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "failed to inspect prepared restore device source {}: {error}",
                            source.display()
                        ),
                    )
                })?;
                if metadata.file_type().is_symlink()
                    || !(metadata.file_type().is_char_device()
                        || metadata.file_type().is_block_device()
                        || metadata.file_type().is_fifo())
                {
                    return Err(device_error(
                        ErrorCode::PermissionDenied,
                        format!(
                            "prepared restore device source has an invalid type: {}",
                            source.display()
                        ),
                    ));
                }
                Ok((checkpoint_device_cookie(index), node.path.clone(), source))
            })
            .collect()
    }

    pub(in crate::executor) fn create_all(&self) -> Result<()> {
        debug_assert!(self.create_nodes);
        for node in &self.nodes {
            node.create()?;
        }
        Ok(())
    }

    pub(in crate::executor) fn finish_rootfs_devices(&self) -> Result<()> {
        ensure_ptmx_link()?;
        if self.terminal {
            verify_console_metadata(&target_metadata_for_path(Path::new("/dev/console"))?)?;
        }
        Ok(())
    }

    pub(in crate::executor) fn verify_existing_from_root(&self, rootfs: &File) -> Result<()> {
        for node in &self.nodes {
            node.verify_from_root(rootfs)?;
        }
        verify_ptmx_from_root(rootfs)?;
        if self.terminal {
            let console = openat2_beneath(
                rootfs.as_raw_fd(),
                Path::new("dev/console"),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                false,
            )?
            .ok_or_else(|| {
                device_error(
                    ErrorCode::FailedPrecondition,
                    "terminal configuration requires /dev/console in the joined mount namespace",
                )
            })?;
            verify_console_metadata(&metadata_for_fd(&console)?)?;
        }
        Ok(())
    }

    pub(in crate::executor) const fn uses_prepared_sources(
        prepared: &PreparedDeviceSources,
    ) -> bool {
        prepared.sources.is_some()
    }

    pub(in crate::executor) fn requires_setup(&self) -> bool {
        self.has_node_setup() || self.has_device_filter() || self.terminal
    }

    pub(in crate::executor) fn has_node_setup(&self) -> bool {
        self.create_nodes && !self.nodes.is_empty()
    }

    #[cfg(test)]
    pub(in crate::executor) fn has_access_policy(&self) -> bool {
        self.access_policy.is_some()
    }

    pub(in crate::executor) fn has_device_filter(&self) -> bool {
        self.nodes
            .iter()
            .any(|node| node.kind.access_kind().is_some())
    }

    pub(in crate::executor) fn update_from_resources(
        &self,
        resources: &LinuxResources,
    ) -> Result<Option<Self>> {
        let Some(rules) = resources.devices().as_deref() else {
            return Ok(None);
        };
        let access_policy = DeviceAccessPolicy::from_oci(rules)?;
        Ok(Some(Self {
            nodes: self.nodes.clone(),
            access_policy,
            terminal: self.terminal,
            create_nodes: self.create_nodes,
        }))
    }

    pub(in crate::executor) fn load_cgroup_device_program(&self) -> Result<Option<OwnedFd>> {
        self.access_boundary()?
            .map(|boundary| boundary.load())
            .transpose()
    }

    pub(in crate::executor) fn load_device_program(&self) -> Result<LoadedDeviceProgram> {
        self.validate_serialized_policy()?;
        self.access_boundary()?
            .ok_or_else(|| {
                device_error(
                    ErrorCode::PermissionDenied,
                    "serialized rootless device policy has no OCI device boundary",
                )
            })?
            .load_for_rootless_helper()
    }

    fn has_rootless_safe_nodes(&self) -> bool {
        self.nodes.len() == OCI_LINUX_DEFAULT_DEVICE_NODES.len()
            && self
                .nodes
                .iter()
                .zip(OCI_LINUX_DEFAULT_DEVICE_NODES)
                .all(|(node, device)| {
                    node.path == Path::new(device.path)
                        && node.kind == DeviceKind::Character
                        && node.major == device.major
                        && node.minor == device.minor
                        && node.mode == device.mode
                        && node.uid == 0
                        && node.gid == 0
                })
    }

    fn validate_serialized_policy(&self) -> Result<()> {
        if !self.has_rootless_safe_nodes()
            || self.terminal
            || (self.access_policy.is_some() && !self.has_rootless_safe_access_policy())
        {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                "serialized rootless device policy is outside the bounded safe-device profile",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::executor) fn validate_rootless_device_set(&self) -> Result<()> {
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

    pub(in crate::executor) fn validate_rootless_device_support(&self) -> Result<()> {
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

    pub(in crate::executor) fn attach_loaded_cgroup_device_program(
        &self,
        cgroup_path: &Path,
        loaded: &OwnedFd,
    ) -> Result<()> {
        access::attach_loaded_cgroup_device_program(cgroup_path, loaded)
    }

    pub(in crate::executor) fn replace_loaded_cgroup_device_program(
        &self,
        cgroup_path: &Path,
        loaded: &OwnedFd,
        replaced: &OwnedFd,
    ) -> Result<()> {
        access::replace_loaded_cgroup_device_program(cgroup_path, loaded, replaced)
    }

    pub(in crate::executor) fn detach_loaded_cgroup_device_program(
        &self,
        cgroup_path: &Path,
        attached: &OwnedFd,
    ) -> Result<()> {
        access::detach_loaded_cgroup_device_program(cgroup_path, attached)
    }

    pub(in crate::executor) fn install_cgroup_device_filter(
        &self,
        cgroup_path: &Path,
    ) -> Result<Option<OwnedFd>> {
        if !self.has_device_filter() {
            return Ok(None);
        }
        let Some(loaded) = self.load_cgroup_device_program()? else {
            return Ok(None);
        };
        self.attach_loaded_cgroup_device_program(cgroup_path, &loaded)?;
        Ok(Some(loaded))
    }

    fn has_rootless_safe_access_policy(&self) -> bool {
        let expected = OCI_LINUX_DEFAULT_DEVICE_NODES.map(|device| {
            (
                DeviceKind::Character
                    .access_kind()
                    .expect("safe device kind"),
                device.major,
                device.minor,
            )
        });
        self.access_policy
            .as_ref()
            .is_some_and(|policy| policy.is_exact_rootless_allowlist(&expected))
    }

    fn access_boundary(&self) -> Result<Option<DeviceAccessBoundary>> {
        if !self.has_device_filter() {
            return Ok(None);
        }
        let nodes = self.nodes.iter().filter_map(|node| {
            node.kind
                .access_kind()
                .map(|kind| (kind, node.major, node.minor))
        });
        DeviceAccessBoundary::for_oci_nodes(nodes, self.access_policy.clone()).map(Some)
    }

    #[cfg(test)]
    pub(in crate::executor) fn len(&self) -> usize {
        self.nodes.len()
    }
}

fn checkpoint_device_cookie(index: usize) -> String {
    format!("{CHECKPOINT_DEVICE_COOKIE_PREFIX}-{index:04}")
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
