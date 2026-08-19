use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use a3s_oci_sdk::{ErrorCode, OciLinuxCgroupPath, Result};

use super::super::device_policy::DevicePolicyAuthority;
use super::{
    available_supported_controllers, cgroup_error, cleanup_cgroup_tree, enable_controllers,
    ensure_real_directory, initialize_cpuset, CGROUP_PROCS, REQUIRED_CONTROLLERS,
};

const CGROUP2_SUPER_MAGIC: i128 = 0x6367_7270;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CgroupIdentity {
    device: u64,
    inode: u64,
}

impl CgroupIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Option<Self> {
        (metadata.is_dir() && !metadata.file_type().is_symlink()).then_some(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

#[derive(Debug, Clone)]
pub(in crate::executor) struct RootlessCgroupDelegation {
    root: PathBuf,
    effective_uid: u32,
    effective_gid: u32,
    device: u64,
    inode: u64,
    device_policy_authority: Option<DevicePolicyAuthority>,
}

impl RootlessCgroupDelegation {
    pub(in crate::executor) fn root(&self) -> &Path {
        &self.root
    }

    pub(in crate::executor) fn open(
        root: impl AsRef<Path>,
        effective_uid: u32,
        effective_gid: u32,
    ) -> Result<Self> {
        let root = validate_delegated_root_path(root.as_ref())?;
        let metadata = verify_delegated_root(&root, effective_uid, effective_gid)?;
        required_delegated_controllers(&root)?;
        verify_delegated_owner_membership(&root)?;
        Ok(Self {
            root,
            effective_uid,
            effective_gid,
            device: metadata.dev(),
            inode: metadata.ino(),
            device_policy_authority: None,
        })
    }

    pub(in crate::executor) fn open_root_descriptor(&self) -> Result<OwnedFd> {
        let root = CString::new(self.root.as_os_str().as_bytes()).map_err(|error| {
            cgroup_error(
                ErrorCode::InvalidArgument,
                format!("rootless cgroup delegation path contains NUL: {error}"),
            )
        })?;
        // SAFETY: the canonical delegation path is NUL-terminated and open
        // returns a fresh descriptor without following a final symlink.
        let descriptor = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(cgroup_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to retain rootless cgroup delegation descriptor {}: {}",
                    self.root.display(),
                    io::Error::last_os_error()
                ),
            ));
        }
        // SAFETY: open returned a fresh owned descriptor.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        let metadata = std::fs::metadata(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))
            .map_err(|error| {
                cgroup_error(
                    ErrorCode::FailedPrecondition,
                    format!("failed to inspect retained cgroup descriptor: {error}"),
                )
            })?;
        if !self.identity_matches(&metadata) {
            return Err(cgroup_error(
                ErrorCode::Conflict,
                "rootless cgroup delegation changed while its descriptor was retained",
            ));
        }
        Ok(descriptor)
    }

    pub(in crate::executor) fn install_device_policy_authority(
        &mut self,
        authority: DevicePolicyAuthority,
    ) -> Result<()> {
        if self.device_policy_authority.is_some() {
            return Err(cgroup_error(
                ErrorCode::Conflict,
                "rootless cgroup delegation already has a device-policy authority",
            ));
        }
        self.device_policy_authority = Some(authority);
        Ok(())
    }

    pub(in crate::executor) fn verify(&self) -> Result<BTreeSet<&'static str>> {
        let metadata = verify_delegated_root(&self.root, self.effective_uid, self.effective_gid)?;
        if !self.identity_matches(&metadata) {
            return Err(cgroup_error(
                ErrorCode::Conflict,
                format!(
                    "rootless cgroup delegation changed after executor open: {}",
                    self.root.display()
                ),
            ));
        }
        verify_delegated_owner_membership(&self.root)?;
        required_delegated_controllers(&self.root)
    }

    fn identity_matches(&self, metadata: &std::fs::Metadata) -> bool {
        metadata.dev() == self.device && metadata.ino() == self.inode
    }

    pub(in crate::executor) fn has_device_policy_authority(&self) -> bool {
        self.device_policy_authority.is_some()
    }

    pub(in crate::executor) fn shutdown_device_policy_authority(&self) -> Result<()> {
        if let Some(authority) = &self.device_policy_authority {
            authority.shutdown()
        } else {
            Ok(())
        }
    }

    pub(in crate::executor) fn prepare_device_mounts(&self) -> Result<Vec<OwnedFd>> {
        self.device_policy_authority
            .as_ref()
            .ok_or_else(|| {
                cgroup_error(
                    ErrorCode::Unsupported,
                    "rootless device mount preparation requires a device-policy authority",
                )
            })?
            .prepare_device_mounts()
    }
}

#[cfg(test)]
impl RootlessCgroupDelegation {
    fn fixture(
        root: PathBuf,
        effective_uid: u32,
        effective_gid: u32,
        device: u64,
        inode: u64,
    ) -> Self {
        Self {
            root,
            effective_uid,
            effective_gid,
            device,
            inode,
            device_policy_authority: None,
        }
    }
}

#[derive(Debug)]
pub(in crate::executor) struct CgroupManager {
    mountpoint: PathBuf,
    authority_root: PathBuf,
    root: PathBuf,
    controllers: BTreeSet<&'static str>,
    device_policy_authority: Option<DevicePolicyAuthority>,
    owned_paths: Mutex<BTreeMap<PathBuf, CgroupIdentity>>,
    removed: bool,
}

impl CgroupManager {
    pub(in crate::executor) fn create() -> Result<Self> {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").map_err(|error| {
            cgroup_error(
                ErrorCode::FailedPrecondition,
                format!("failed to read cgroup mount topology: {error}"),
            )
        })?;
        let mountpoint = cgroup2_mountpoint(&mountinfo).ok_or_else(|| {
            cgroup_error(
                ErrorCode::Unsupported,
                "a writable unified cgroup v2 mount is required",
            )
        })?;
        ensure_real_directory(&mountpoint)?;
        let mut controllers = available_supported_controllers(&mountpoint)?;
        if let Some(missing) = REQUIRED_CONTROLLERS
            .iter()
            .find(|controller| !controllers.contains(**controller))
        {
            return Err(cgroup_error(
                ErrorCode::Unsupported,
                format!(
                    "the unified cgroup v2 hierarchy does not expose required controller `{missing}`"
                ),
            ));
        }
        let required = REQUIRED_CONTROLLERS.into_iter().collect::<BTreeSet<_>>();
        enable_controllers(&mountpoint, &required)?;
        let optional = controllers
            .difference(&required)
            .copied()
            .collect::<Vec<_>>();
        for controller in optional {
            if enable_controllers(&mountpoint, &BTreeSet::from([controller])).is_err() {
                controllers.remove(controller);
            }
        }

        Self::create_below(mountpoint.clone(), mountpoint, controllers, None)
    }

    pub(in crate::executor) fn create_delegated(
        delegation: &RootlessCgroupDelegation,
    ) -> Result<Self> {
        let controllers = delegation.verify()?;
        let mountpoint = visible_cgroup2_mountpoint(&delegation.root)?;
        Self::create_below(
            mountpoint,
            delegation.root.clone(),
            controllers,
            delegation.device_policy_authority.clone(),
        )
    }

    fn create_below(
        mountpoint: PathBuf,
        authority_root: PathBuf,
        controllers: BTreeSet<&'static str>,
        device_policy_authority: Option<DevicePolicyAuthority>,
    ) -> Result<Self> {
        ensure_real_directory(&authority_root)?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                cgroup_error(
                    ErrorCode::Internal,
                    format!("system clock is before the Unix epoch: {error}"),
                )
            })?
            .as_nanos();
        let root = authority_root.join(format!("a3s-oci-{}-{timestamp:032x}", std::process::id()));
        std::fs::create_dir(&root).map_err(|error| {
            cgroup_error(
                if error.kind() == io::ErrorKind::AlreadyExists {
                    ErrorCode::Conflict
                } else {
                    ErrorCode::PermissionDenied
                },
                format!(
                    "failed to create private cgroup manager {}: {error}",
                    root.display()
                ),
            )
        })?;
        if let Err(error) = initialize_cpuset(&root).and_then(|()| {
            let delegated = available_supported_controllers(&root)?;
            if let Some(missing) = controllers
                .iter()
                .find(|controller| !delegated.contains(**controller))
            {
                return Err(cgroup_error(
                    ErrorCode::Unsupported,
                    format!(
                        "cgroup v2 controller `{missing}` was not delegated to the runtime manager"
                    ),
                ));
            }
            enable_controllers(&root, &controllers)
        }) {
            let _ = std::fs::remove_dir(&root);
            return Err(error);
        }
        Ok(Self {
            mountpoint,
            authority_root,
            root,
            controllers,
            device_policy_authority,
            owned_paths: Mutex::new(BTreeMap::new()),
            removed: false,
        })
    }

    pub(in crate::executor) fn remove(mut self) -> Result<()> {
        let owned = self.cleanup_owned_paths();
        let private_root = cleanup_cgroup_tree(&self.root);
        match (owned, private_root) {
            (Ok(()), Ok(())) => {
                self.removed = true;
                Ok(())
            }
            (Err(error), _) | (Ok(()), Err(error)) => Err(error),
        }
    }

    pub(in crate::executor) fn root(&self) -> &Path {
        &self.root
    }

    pub(in crate::executor) fn authority_root(&self) -> &Path {
        &self.authority_root
    }

    pub(super) fn controllers(&self) -> &BTreeSet<&'static str> {
        &self.controllers
    }

    pub(super) fn device_policy_authority(&self) -> Option<&DevicePolicyAuthority> {
        self.device_policy_authority.as_ref()
    }

    pub(super) fn relative_to_authority(&self, path: &Path) -> Result<PathBuf> {
        path.strip_prefix(&self.authority_root)
            .ok()
            .filter(|relative| !relative.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .ok_or_else(|| {
                cgroup_error(
                    ErrorCode::PermissionDenied,
                    format!(
                        "container cgroup {} is outside the delegated authority {}",
                        path.display(),
                        self.authority_root.display()
                    ),
                )
            })
    }

    pub(super) fn resolve_path(&self, path: &OciLinuxCgroupPath) -> Result<(PathBuf, PathBuf)> {
        let relative = PathBuf::from(path.relative());
        if !path.is_absolute() {
            return Ok((self.root.clone(), relative));
        }

        let target = self.mountpoint.join(&relative);
        let relative = target
            .strip_prefix(&self.authority_root)
            .ok()
            .filter(|relative| !relative.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .ok_or_else(|| {
                cgroup_error(
                    ErrorCode::PermissionDenied,
                    format!(
                        "absolute linux.cgroupsPath resolves outside the delegated cgroup authority: {}; authority {}",
                        target.display(),
                        self.authority_root.display()
                    ),
                )
            })?;
        Ok((self.authority_root.clone(), relative))
    }

    pub(super) fn register_owned_path(&self, path: &Path) -> Result<()> {
        let identity = current_cgroup_identity(path)?.ok_or_else(|| {
            cgroup_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "new runtime-owned cgroup has no stable directory identity: {}",
                    path.display()
                ),
            )
        })?;
        self.owned_paths
            .lock()
            .map_err(|_| {
                cgroup_error(
                    ErrorCode::Internal,
                    "runtime-owned cgroup path registry is poisoned",
                )
            })?
            .insert(path.to_path_buf(), identity);
        Ok(())
    }

    pub(super) fn owns_path(&self, path: &Path) -> Result<bool> {
        let identity = self
            .owned_paths
            .lock()
            .map_err(|_| {
                cgroup_error(
                    ErrorCode::Internal,
                    "runtime-owned cgroup path registry is poisoned",
                )
            })?
            .get(path)
            .copied();
        match identity {
            Some(identity) => Ok(current_cgroup_identity(path)? == Some(identity)),
            None => Ok(false),
        }
    }

    fn cleanup_owned_paths(&self) -> Result<()> {
        let mut paths = self
            .owned_paths
            .lock()
            .map_err(|_| {
                cgroup_error(
                    ErrorCode::Internal,
                    "runtime-owned cgroup path registry is poisoned",
                )
            })?
            .iter()
            .map(|(path, identity)| (path.clone(), *identity))
            .collect::<Vec<_>>();
        paths.sort_by(|(left, _), (right, _)| {
            right
                .components()
                .count()
                .cmp(&left.components().count())
                .then_with(|| right.cmp(left))
        });
        let mut first_error = None;
        for (path, identity) in paths {
            match current_cgroup_identity(&path) {
                Ok(Some(current)) if current == identity => {}
                Ok(_) => continue,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            }
            match std::fs::remove_dir(&path) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                    ) => {}
                Err(error) => {
                    first_error.get_or_insert_with(|| {
                        cgroup_error(
                            ErrorCode::Internal,
                            format!(
                                "failed to remove runtime-owned cgroup {}: {error}",
                                path.display()
                            ),
                        )
                    });
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn current_cgroup_identity(path: &Path) -> Result<Option<CgroupIdentity>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(CgroupIdentity::from_metadata(&metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(cgroup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect runtime-owned cgroup identity {}: {error}",
                path.display()
            ),
        )),
    }
}

impl Drop for CgroupManager {
    fn drop(&mut self) {
        if !self.removed {
            let _ = self.cleanup_owned_paths();
            let _ = cleanup_cgroup_tree(&self.root);
        }
    }
}

fn cgroup2_mountpoint(mountinfo: &str) -> Option<PathBuf> {
    cgroup2_mountpoints(mountinfo).into_iter().next()
}

fn cgroup2_mountpoint_for_path(mountinfo: &str, path: &Path) -> Option<PathBuf> {
    cgroup2_mountpoints(mountinfo)
        .into_iter()
        .filter(|mountpoint| path == mountpoint || path.starts_with(mountpoint))
        .max_by_key(|mountpoint| mountpoint.components().count())
}

fn cgroup2_mountpoints(mountinfo: &str) -> Vec<PathBuf> {
    mountinfo
        .lines()
        .filter_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            if right.split_ascii_whitespace().next()? != "cgroup2" {
                return None;
            }
            let mountpoint = left.split_ascii_whitespace().nth(4)?;
            (!mountpoint.contains('\\')).then(|| PathBuf::from(mountpoint))
        })
        .collect()
}

fn visible_cgroup2_mountpoint(path: &Path) -> Result<PathBuf> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").map_err(|error| {
        cgroup_error(
            ErrorCode::FailedPrecondition,
            format!("failed to read cgroup mount topology: {error}"),
        )
    })?;
    cgroup2_mountpoint_for_path(&mountinfo, path).ok_or_else(|| {
        cgroup_error(
            ErrorCode::Unsupported,
            format!(
                "delegated cgroup authority is not below a visible cgroup v2 mount: {}",
                path.display()
            ),
        )
    })
}

fn validate_delegated_root_path(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute()
        || path.as_os_str().as_bytes().contains(&0)
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(cgroup_error(
            ErrorCode::InvalidArgument,
            format!(
                "rootless cgroup delegation must be an absolute normalized path: {}",
                path.display()
            ),
        ));
    }
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        cgroup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to resolve rootless cgroup delegation {}: {error}",
                path.display()
            ),
        )
    })?;
    if canonical.as_os_str() != path.as_os_str() {
        return Err(cgroup_error(
            ErrorCode::PermissionDenied,
            format!(
                "rootless cgroup delegation must already be canonical: {}",
                path.display()
            ),
        ));
    }
    Ok(canonical)
}

fn verify_delegated_root(
    root: &Path,
    effective_uid: u32,
    effective_gid: u32,
) -> Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(root).map_err(|error| {
        cgroup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect rootless cgroup delegation {}: {error}",
                root.display()
            ),
        )
    })?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid
        || metadata.gid() != effective_gid
    {
        return Err(cgroup_error(
            ErrorCode::PermissionDenied,
            format!(
                "rootless cgroup delegation must be a real directory owned by {effective_uid}:{effective_gid}: {}",
                root.display()
            ),
        ));
    }
    let path = CString::new(root.as_os_str().as_bytes()).map_err(|error| {
        cgroup_error(
            ErrorCode::InvalidArgument,
            format!("rootless cgroup delegation contains NUL: {error}"),
        )
    })?;
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `filesystem` points to writable
    // storage for one `statfs` result.
    if unsafe { libc::statfs(path.as_ptr(), filesystem.as_mut_ptr()) } != 0 {
        return Err(cgroup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect rootless cgroup delegation filesystem {}: {}",
                root.display(),
                io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: `statfs` succeeded and initialized the structure.
    let filesystem = unsafe { filesystem.assume_init() };
    // glibc exposes f_type as a signed fsword while musl uses an unsigned
    // word. Compare the kernel magic as a common bit pattern on both ABIs.
    if i128::from(filesystem.f_type) != CGROUP2_SUPER_MAGIC {
        return Err(cgroup_error(
            ErrorCode::Unsupported,
            format!(
                "rootless cgroup delegation is not on a cgroup v2 filesystem: {}",
                root.display()
            ),
        ));
    }
    let procs = std::fs::read_to_string(root.join(CGROUP_PROCS)).map_err(|error| {
        cgroup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect rootless cgroup delegation membership {}: {error}",
                root.display()
            ),
        )
    })?;
    if !procs.trim().is_empty() {
        return Err(cgroup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "rootless cgroup delegation must not contain processes: {}",
                root.display()
            ),
        ));
    }
    let procs_metadata = std::fs::symlink_metadata(root.join(CGROUP_PROCS)).map_err(|error| {
        cgroup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect rootless cgroup delegation control ownership {}: {error}",
                root.display()
            ),
        )
    })?;
    if !procs_metadata.is_file()
        || procs_metadata.file_type().is_symlink()
        || procs_metadata.uid() != effective_uid
        || procs_metadata.gid() != effective_gid
        || procs_metadata.mode() & 0o200 == 0
    {
        return Err(cgroup_error(
            ErrorCode::PermissionDenied,
            format!(
                "rootless cgroup delegation cgroup.procs must be writable and owned by {effective_uid}:{effective_gid}: {}",
                root.display()
            ),
        ));
    }
    Ok(metadata)
}

fn verify_delegated_owner_membership(root: &Path) -> Result<()> {
    let membership = std::fs::read_to_string("/proc/self/cgroup").map_err(|error| {
        cgroup_error(
            ErrorCode::FailedPrecondition,
            format!("failed to inspect rootless executor cgroup membership: {error}"),
        )
    })?;
    let relative = unified_cgroup_membership(&membership)?;
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").map_err(|error| {
        cgroup_error(
            ErrorCode::FailedPrecondition,
            format!("failed to inspect rootless executor cgroup topology: {error}"),
        )
    })?;
    let mountpoint = cgroup2_mountpoint(&mountinfo).ok_or_else(|| {
        cgroup_error(
            ErrorCode::Unsupported,
            "rootless cgroup delegation requires a visible cgroup v2 mount",
        )
    })?;
    let current = mountpoint.join(relative.strip_prefix("/").unwrap_or(relative));
    let current = std::fs::canonicalize(&current).map_err(|error| {
        cgroup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to resolve rootless executor cgroup membership {}: {error}",
                current.display()
            ),
        )
    })?;
    if current == root || !current.starts_with(root) {
        return Err(cgroup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "rootless executor must run in a host-owned child below its empty cgroup delegation: executor {}; delegation {}",
                current.display(),
                root.display()
            ),
        ));
    }
    Ok(())
}

fn unified_cgroup_membership(contents: &str) -> Result<&Path> {
    let mut unified = contents.lines().filter_map(|line| {
        let (hierarchy, remainder) = line.split_once(':')?;
        let (controllers, path) = remainder.split_once(':')?;
        (hierarchy == "0" && controllers.is_empty()).then_some(Path::new(path))
    });
    let path = unified.next().ok_or_else(|| {
        cgroup_error(
            ErrorCode::Unsupported,
            "rootless executor has no unified cgroup v2 membership",
        )
    })?;
    if unified.next().is_some()
        || !path.is_absolute()
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(cgroup_error(
            ErrorCode::FailedPrecondition,
            "rootless executor has an invalid unified cgroup v2 membership",
        ));
    }
    Ok(path)
}

fn required_delegated_controllers(root: &Path) -> Result<BTreeSet<&'static str>> {
    let controllers = available_supported_controllers(root)?;
    if let Some(missing) = REQUIRED_CONTROLLERS
        .iter()
        .find(|controller| !controllers.contains(**controller))
    {
        return Err(cgroup_error(
            ErrorCode::Unsupported,
            format!("rootless cgroup delegation does not expose required controller `{missing}`"),
        ));
    }
    let enabled_path = root.join("cgroup.subtree_control");
    let enabled = std::fs::read_to_string(&enabled_path).map_err(|error| {
        cgroup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect rootless delegated controller state {}: {error}",
                enabled_path.display()
            ),
        )
    })?;
    let enabled = enabled.split_ascii_whitespace().collect::<BTreeSet<_>>();
    if let Some(missing) = REQUIRED_CONTROLLERS
        .iter()
        .find(|controller| !enabled.contains(**controller))
    {
        return Err(cgroup_error(
            ErrorCode::Unsupported,
            format!("rootless cgroup delegation has not enabled required controller `{missing}`"),
        ));
    }
    Ok(controllers
        .into_iter()
        .filter(|controller| enabled.contains(controller))
        .collect())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use a3s_oci_sdk::{ErrorCode, OciLinuxCgroupPath};

    use super::{
        cgroup2_mountpoint, cgroup2_mountpoint_for_path, required_delegated_controllers,
        validate_delegated_root_path, CgroupManager, RootlessCgroupDelegation,
    };

    fn manager_fixture(mountpoint: &str, authority_root: &str, root: &str) -> CgroupManager {
        CgroupManager {
            mountpoint: mountpoint.into(),
            authority_root: authority_root.into(),
            root: root.into(),
            controllers: BTreeSet::new(),
            device_policy_authority: None,
            owned_paths: Mutex::new(BTreeMap::new()),
            removed: true,
        }
    }

    #[test]
    fn parses_unified_mount_and_membership() {
        let mountinfo = "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n31 29 0:26 /delegated /run/user/cgroup rw - cgroup2 cgroup rw\n30 23 0:27 / /tmp rw - tmpfs tmpfs rw\n";
        assert_eq!(
            cgroup2_mountpoint(mountinfo).as_deref(),
            Some(Path::new("/sys/fs/cgroup"))
        );
        assert_eq!(
            cgroup2_mountpoint_for_path(mountinfo, Path::new("/run/user/cgroup/workload"))
                .as_deref(),
            Some(Path::new("/run/user/cgroup"))
        );
        assert!(cgroup2_mountpoint_for_path(mountinfo, Path::new("/tmp")).is_none());
    }

    #[test]
    fn resolves_absolute_and_relative_paths_from_distinct_stable_bases() {
        let manager = manager_fixture(
            "/sys/fs/cgroup",
            "/sys/fs/cgroup",
            "/sys/fs/cgroup/a3s-oci-private",
        );
        let absolute = OciLinuxCgroupPath::parse("/tenant/workload").expect("absolute path");
        let relative = OciLinuxCgroupPath::parse("tenant/workload").expect("relative path");

        assert_eq!(
            manager.resolve_path(&absolute).expect("absolute location"),
            (
                PathBuf::from("/sys/fs/cgroup"),
                PathBuf::from("tenant/workload")
            )
        );
        assert_eq!(
            manager.resolve_path(&relative).expect("relative location"),
            (
                PathBuf::from("/sys/fs/cgroup/a3s-oci-private"),
                PathBuf::from("tenant/workload")
            )
        );
        assert_eq!(
            manager
                .resolve_path(&absolute)
                .expect("repeat absolute location"),
            manager
                .resolve_path(&absolute)
                .expect("stable absolute location")
        );
        assert_eq!(
            manager
                .resolve_path(&relative)
                .expect("repeat relative location"),
            manager
                .resolve_path(&relative)
                .expect("stable relative location")
        );
    }

    #[test]
    fn rejects_absolute_paths_outside_a_rootless_delegation() {
        let manager = manager_fixture(
            "/sys/fs/cgroup",
            "/sys/fs/cgroup/user.slice/delegated",
            "/sys/fs/cgroup/user.slice/delegated/a3s-oci-private",
        );
        let inside = OciLinuxCgroupPath::parse("/user.slice/delegated/workload")
            .expect("delegated absolute path");
        let outside =
            OciLinuxCgroupPath::parse("/system.slice/workload").expect("outside absolute path");

        assert_eq!(
            manager.resolve_path(&inside).expect("inside delegation"),
            (
                PathBuf::from("/sys/fs/cgroup/user.slice/delegated"),
                PathBuf::from("workload")
            )
        );
        let error = manager
            .resolve_path(&outside)
            .expect_err("outside delegation must fail");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
    }

    #[test]
    fn stale_registry_identity_does_not_claim_or_remove_a_recreated_path() {
        let directory = tempfile::tempdir().expect("temporary cgroup identity root");
        let path = directory.path().join("tenant");
        std::fs::create_dir(&path).expect("initial runtime-owned path");
        let manager = manager_fixture(
            directory.path().to_str().expect("UTF-8 temporary path"),
            directory.path().to_str().expect("UTF-8 temporary path"),
            directory.path().to_str().expect("UTF-8 temporary path"),
        );
        manager
            .register_owned_path(&path)
            .expect("register runtime-owned path");
        assert!(manager.owns_path(&path).expect("initial identity"));

        let retained = std::fs::File::open(&path).expect("retain initial directory inode");
        std::fs::remove_dir(&path).expect("remove initial path");
        std::fs::create_dir(&path).expect("recreate same path");
        assert!(!manager.owns_path(&path).expect("replacement identity"));
        manager
            .cleanup_owned_paths()
            .expect("skip replacement during cleanup");
        assert!(path.is_dir(), "replacement path must be preserved");
        drop(retained);
    }

    #[test]
    fn rootless_delegation_path_must_be_absolute_normalized_and_canonical() {
        let directory = tempfile::tempdir().expect("temporary delegation path");
        assert_eq!(
            validate_delegated_root_path(directory.path()).expect("canonical path"),
            directory.path()
        );
        assert!(validate_delegated_root_path(Path::new("relative")).is_err());
        assert!(validate_delegated_root_path(&directory.path().join(".")).is_err());
    }

    #[test]
    fn rootless_delegation_identity_is_inode_bound() {
        let directory = tempfile::tempdir().expect("temporary delegation identity");
        let metadata = std::fs::metadata(directory.path()).expect("delegation metadata");
        let delegation = RootlessCgroupDelegation::fixture(
            directory.path().to_path_buf(),
            metadata.uid(),
            metadata.gid(),
            metadata.dev(),
            metadata.ino().saturating_add(1),
        );
        assert!(!delegation.identity_matches(&metadata));
    }

    #[test]
    fn rootless_delegation_requires_baseline_and_filters_unenabled_optional_controllers() {
        let directory = tempfile::tempdir().expect("temporary delegation controller root");
        std::fs::write(
            directory.path().join("cgroup.controllers"),
            "cpu cpuset memory pids",
        )
        .expect("available controllers");
        std::fs::write(
            directory.path().join("cgroup.subtree_control"),
            "cpu cpuset memory",
        )
        .expect("enabled controllers");
        let error = required_delegated_controllers(directory.path())
            .expect_err("missing enabled controller must fail");
        assert_eq!(error.code, ErrorCode::Unsupported);
        assert!(error.message.contains("required controller `pids`"));

        std::fs::write(
            directory.path().join("cgroup.subtree_control"),
            "cpu cpuset memory pids",
        )
        .expect("all enabled controllers");
        assert_eq!(
            required_delegated_controllers(directory.path()).expect("delegated controllers"),
            BTreeSet::from(["cpu", "cpuset", "memory", "pids"])
        );

        std::fs::write(
            directory.path().join("cgroup.controllers"),
            "cpu cpuset hugetlb io memory pids rdma",
        )
        .expect("optional controllers");
        assert_eq!(
            required_delegated_controllers(directory.path())
                .expect("delegation with an unenabled optional I/O controller"),
            BTreeSet::from(["cpu", "cpuset", "memory", "pids"]),
            "optional controllers are unusable until the delegator enables them"
        );

        std::fs::write(
            directory.path().join("cgroup.subtree_control"),
            "cpu cpuset hugetlb io memory pids rdma",
        )
        .expect("enabled optional controllers");
        assert_eq!(
            required_delegated_controllers(directory.path())
                .expect("delegation with enabled optional controllers"),
            BTreeSet::from(["cpu", "cpuset", "hugetlb", "io", "memory", "pids", "rdma"]),
            "enabled optional controllers are propagated without becoming baseline requirements"
        );
    }
}
