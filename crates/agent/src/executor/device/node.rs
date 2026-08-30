use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::{LinuxDevice, LinuxDeviceType};
use a3s_oci_sdk::{ErrorCode, Result};

use crate::executor::namespace::NamespacePlan;
use crate::OCI_LINUX_DEFAULT_DEVICE_NODES;

use super::access::DeviceAccessKind;
use super::mount_source::{
    attach_device_mount, clone_device_mount, metadata_for_fd, openat2_beneath, path_cstring,
};
use super::types::{
    DeviceKind, DeviceNode, PreparedDeviceSource, PreparedDeviceSources, TargetMetadata,
};
use super::{device_error, invalid, last_os_error, unsupported};

pub(super) fn default_device_nodes() -> Vec<DeviceNode> {
    OCI_LINUX_DEFAULT_DEVICE_NODES
        .iter()
        .map(|device| DeviceNode {
            path: PathBuf::from(device.path),
            kind: DeviceKind::Character,
            major: device.major,
            minor: device.minor,
            mode: device.mode,
            uid: 0,
            gid: 0,
        })
        .collect()
}
impl DeviceNode {
    pub(super) fn from_oci(index: usize, device: &LinuxDevice) -> Result<Self> {
        let path = normalize_device_path(index, device.path())?;
        let kind = DeviceKind::from_oci(index, device.typ())?;
        let (major, minor) = if kind == DeviceKind::Fifo {
            (0, 0)
        } else {
            (
                u32::try_from(device.major()).map_err(|_| {
                    invalid(format!(
                        "linux.devices[{index}].major must be a non-negative u32"
                    ))
                })?,
                u32::try_from(device.minor()).map_err(|_| {
                    invalid(format!(
                        "linux.devices[{index}].minor must be a non-negative u32"
                    ))
                })?,
            )
        };
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

    pub(super) fn prepare_source(
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

    pub(super) fn prepare_inherited_rootless_source(
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

    pub(super) fn bind_source(
        &self,
        rootfs: &Path,
        source: &PreparedDeviceSource,
        verify_ownership: bool,
        prepared: &PreparedDeviceSources,
    ) -> Result<()> {
        let (target, relative) = self.resolve_target(rootfs)?;
        if !self.create_placeholder(&target, &relative, prepared)? {
            return if verify_ownership {
                self.verify_at(&target, self.uid, self.gid)
            } else {
                self.verify_device_at(&target)
            };
        }

        let PreparedDeviceSource::DetachedMount(source) = source;
        attach_device_mount(source, &target, &self.path)?;
        if verify_ownership {
            self.verify_at(&target, self.uid, self.gid)
        } else {
            self.verify_device_at(&target)
        }
    }

    pub(super) fn prepare_detached_bind_target(
        &self,
        rootfs: &Path,
        prepared: &PreparedDeviceSources,
    ) -> Result<bool> {
        let (target, relative) = self.resolve_target(rootfs)?;
        self.create_placeholder(&target, &relative, prepared)
    }

    pub(super) fn attach_source_to_staged_root(
        &self,
        rootfs: &Path,
        source: &PreparedDeviceSource,
        attach: bool,
        verify_ownership: bool,
    ) -> Result<()> {
        let (target, _) = self.resolve_target(rootfs)?;
        if attach {
            let PreparedDeviceSource::DetachedMount(source) = source;
            attach_device_mount(source, &target, &self.path)?;
        }
        if verify_ownership {
            self.verify_at(&target, self.uid, self.gid)
        } else {
            self.verify_device_at(&target)
        }
    }

    pub(super) fn prepare_restore_target(
        &self,
        rootfs: &Path,
        prepared: &PreparedDeviceSources,
    ) -> Result<()> {
        let (target, relative) = self.resolve_target(rootfs)?;
        if self.create_placeholder(&target, &relative, prepared)? {
            return Ok(());
        }
        let metadata = fs::symlink_metadata(&target).map_err(|error| {
            device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to inspect existing restore mount target {}: {error}",
                    self.path.display()
                ),
            )
        })?;
        if metadata.file_type().is_symlink() || metadata.is_dir() {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                format!(
                    "restore mount target must be a nonsymlink file: {}",
                    self.path.display()
                ),
            ));
        }
        Ok(())
    }

    fn resolve_target(&self, rootfs: &Path) -> Result<(PathBuf, PathBuf)> {
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
        if canonical_parent != parent || !canonical_parent.starts_with(&canonical_rootfs) {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                format!(
                    "OCI device parent must be a real directory beneath the container rootfs: {}",
                    self.path.display()
                ),
            ));
        }
        Ok((target, relative.to_path_buf()))
    }

    fn create_placeholder(
        &self,
        target: &Path,
        relative: &Path,
        prepared: &PreparedDeviceSources,
    ) -> Result<bool> {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(target)
        {
            Ok(target) => drop(target),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
            Err(error) => {
                return Err(invalid(format!(
                    "failed to create OCI device bind target {}: {error}",
                    self.path.display()
                )));
            }
        }
        prepared.record_created_target(target, relative)?;
        Ok(true)
    }

    pub(super) fn create(&self) -> Result<()> {
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
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::AlreadyExists {
                return self.verify_at(&self.path, self.uid, self.gid);
            }
            return Err(device_error(
                ErrorCode::FailedPrecondition,
                format!("create OCI device {} failed: {error}", self.path.display()),
            ));
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

    pub(super) fn verify_from_root(&self, rootfs: &File) -> Result<()> {
        let relative = self.path.strip_prefix(Path::new("/")).map_err(|error| {
            device_error(
                ErrorCode::Internal,
                format!("invalid normalized OCI device path: {error}"),
            )
        })?;
        let target = openat2_beneath(
            rootfs.as_raw_fd(),
            relative,
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            false,
        )?
        .ok_or_else(|| {
            device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "required OCI device is missing from the joined mount namespace: {}",
                    self.path.display()
                ),
            )
        })?;
        let metadata = metadata_for_fd(&target)?;
        if !self.matches_source_metadata(&metadata)
            || metadata.uid != self.uid
            || metadata.gid != self.gid
        {
            return Err(device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "required OCI device differs in the joined mount namespace: {}; observed \
                     type={:#o} rdev={}:{} mode={:#o} uid={} gid={}, expected type={:#o} \
                     rdev={}:{} mode={:#o} uid={} gid={}",
                    self.path.display(),
                    metadata.file_type,
                    libc::major(metadata.rdev),
                    libc::minor(metadata.rdev),
                    metadata.mode,
                    metadata.uid,
                    metadata.gid,
                    self.file_type(),
                    self.major,
                    self.minor,
                    self.mode,
                    self.uid,
                    self.gid
                ),
            ));
        }
        Ok(())
    }
}

fn is_rootless_safe_device(node: &DeviceNode) -> bool {
    node.uid == 0
        && node.gid == 0
        && OCI_LINUX_DEFAULT_DEVICE_NODES.iter().any(|device| {
            node.path == Path::new(device.path)
                && node.kind == DeviceKind::Character
                && node.major == device.major
                && node.minor == device.minor
                && node.mode == device.mode
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

    pub(super) const fn access_kind(self) -> Option<DeviceAccessKind> {
        match self {
            Self::Block => Some(DeviceAccessKind::Block),
            Self::Character => Some(DeviceAccessKind::Character),
            Self::Fifo => None,
        }
    }

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Character => "character",
            Self::Fifo => "fifo",
        }
    }
}

impl DeviceNode {
    pub(super) const fn kernel_identity(&self) -> Option<(DeviceKind, u32, u32)> {
        match self.kind {
            DeviceKind::Block | DeviceKind::Character => Some((self.kind, self.major, self.minor)),
            DeviceKind::Fifo => None,
        }
    }
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
