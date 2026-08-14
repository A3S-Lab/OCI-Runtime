use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::{Linux, LinuxIdMapping, LinuxNamespaceType};
use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::control;

mod join;
mod joined_user;
mod mount_idmap;
mod network;
mod retained;
mod time;
mod user;

#[cfg(test)]
#[path = "namespace_tests.rs"]
mod tests;

pub(super) use mount_idmap::{IdmapNamespaceHandles, IdmapPlan};
pub(super) use retained::{RetainedExecutionContext, RetainedNamespaceArgument};
pub(super) use user::{apply_supplementary_groups, install_user_mappings, UserMappingRuntime};

const MAX_ID_MAPPINGS: usize = 340;
const NANOSECONDS_PER_SECOND: u32 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct IdMapping {
    pub(super) container_id: u32,
    pub(super) host_id: u32,
    pub(super) size: u32,
}

impl From<&LinuxIdMapping> for IdMapping {
    fn from(mapping: &LinuxIdMapping) -> Self {
        Self {
            container_id: mapping.container_id(),
            host_id: mapping.host_id(),
            size: mapping.size(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TimeOffset {
    pub(super) secs: i64,
    pub(super) nanosecs: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
enum NamespaceAction {
    #[default]
    Inherit,
    Create,
    Join(PathBuf),
}

impl NamespaceAction {
    const fn is_new(&self) -> bool {
        matches!(self, Self::Create)
    }

    const fn is_configured(&self) -> bool {
        !matches!(self, Self::Inherit)
    }

    fn joined(&self) -> Option<&Path> {
        match self {
            Self::Join(path) => Some(path),
            Self::Inherit | Self::Create => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct NamespacePlan {
    uts: NamespaceAction,
    mount: NamespaceAction,
    ipc: NamespaceAction,
    network: NamespaceAction,
    cgroup: NamespaceAction,
    pid: NamespaceAction,
    user: NamespaceAction,
    time: NamespaceAction,
    uid_mappings: Vec<IdMapping>,
    gid_mappings: Vec<IdMapping>,
    joined_user_authority: Option<joined_user::JoinedUserNamespaceAuthority>,
    monotonic_offset: Option<TimeOffset>,
    boottime_offset: Option<TimeOffset>,
}

impl NamespacePlan {
    pub(super) fn from_linux(
        linux: Option<&Linux>,
        process_uid: u32,
        process_gid: u32,
        additional_gids: &[u32],
    ) -> Result<Self> {
        let Some(linux) = linux else {
            return Ok(Self::default());
        };
        let mut plan = Self::default();
        if let Some(namespaces) = linux.namespaces().as_deref() {
            for (index, namespace) in namespaces.iter().enumerate() {
                let action = match namespace.typ() {
                    LinuxNamespaceType::Uts => &mut plan.uts,
                    LinuxNamespaceType::Mount => &mut plan.mount,
                    LinuxNamespaceType::Ipc => &mut plan.ipc,
                    LinuxNamespaceType::Network => &mut plan.network,
                    LinuxNamespaceType::Cgroup => &mut plan.cgroup,
                    LinuxNamespaceType::Pid => &mut plan.pid,
                    LinuxNamespaceType::User => &mut plan.user,
                    LinuxNamespaceType::Time => &mut plan.time,
                };
                if action.is_configured() {
                    return Err(invalid(format!(
                        "linux.namespaces contains duplicate {:?} entries",
                        namespace.typ()
                    )));
                }
                *action = match namespace.path() {
                    Some(path) => NamespaceAction::Join(validate_join_path(index, path)?),
                    None => NamespaceAction::Create,
                };
            }
        }

        plan.uid_mappings = collect_mappings("linux.uidMappings", linux.uid_mappings().as_deref())?;
        plan.gid_mappings = collect_mappings("linux.gidMappings", linux.gid_mappings().as_deref())?;
        if plan.new_user() {
            if plan.uid_mappings.is_empty() || plan.gid_mappings.is_empty() {
                return Err(unsupported(
                    "linux.uidMappings/linux.gidMappings",
                    "the bootstrap executor requires both UID and GID mappings for a new user namespace",
                ));
            }
            ensure_id_mapped("container root UID", 0, &plan.uid_mappings)?;
            ensure_id_mapped("container root GID", 0, &plan.gid_mappings)?;
            ensure_id_mapped("process.user.uid", process_uid, &plan.uid_mappings)?;
            ensure_id_mapped("process.user.gid", process_gid, &plan.gid_mappings)?;
            for (index, gid) in additional_gids.iter().copied().enumerate() {
                ensure_id_mapped(
                    &format!("process.user.additionalGids[{index}]"),
                    gid,
                    &plan.gid_mappings,
                )?;
            }
        } else if !plan.uid_mappings.is_empty() || !plan.gid_mappings.is_empty() {
            return Err(invalid(
                "Linux UID/GID mappings require a newly created user namespace",
            ));
        }

        if let Some(offsets) = linux.time_offsets() {
            if !plan.new_time() {
                return Err(invalid(
                    "linux.timeOffsets requires a newly created time namespace",
                ));
            }
            if let Some(offset) = offsets.get("monotonic") {
                plan.monotonic_offset = Some(time_offset("monotonic", offset)?);
            }
            if let Some(offset) = offsets.get("boottime") {
                plan.boottime_offset = Some(time_offset("boottime", offset)?);
            }
            if let Some(clock) = offsets
                .keys()
                .find(|clock| !matches!(clock.as_str(), "monotonic" | "boottime"))
            {
                return Err(unsupported(
                    &format!("linux.timeOffsets.{clock}"),
                    "the Linux time namespace supports only monotonic and boottime offsets",
                ));
            }
        }
        Ok(plan)
    }

    pub(super) const fn new_uts(&self) -> bool {
        self.uts.is_new()
    }

    pub(super) const fn new_mount(&self) -> bool {
        self.mount.is_new()
    }

    pub(super) const fn new_ipc(&self) -> bool {
        self.ipc.is_new()
    }

    pub(super) const fn new_network(&self) -> bool {
        self.network.is_new()
    }

    pub(super) const fn new_cgroup(&self) -> bool {
        self.cgroup.is_new()
    }

    pub(super) const fn new_pid(&self) -> bool {
        self.pid.is_new()
    }

    pub(super) const fn new_user(&self) -> bool {
        self.user.is_new()
    }

    pub(super) const fn new_time(&self) -> bool {
        self.time.is_new()
    }

    pub(super) const fn has_uts(&self) -> bool {
        self.uts.is_configured()
    }

    pub(super) const fn has_user(&self) -> bool {
        self.user.is_configured()
    }

    pub(super) fn joined_uts(&self) -> Option<&Path> {
        self.uts.joined()
    }

    pub(super) fn joined_mount(&self) -> Option<&Path> {
        self.mount.joined()
    }

    pub(super) fn joined_ipc(&self) -> Option<&Path> {
        self.ipc.joined()
    }

    pub(super) fn joined_network(&self) -> Option<&Path> {
        self.network.joined()
    }

    pub(super) fn joined_cgroup(&self) -> Option<&Path> {
        self.cgroup.joined()
    }

    pub(super) fn joined_pid(&self) -> Option<&Path> {
        self.pid.joined()
    }

    pub(super) fn joined_user(&self) -> Option<&Path> {
        self.user.joined()
    }

    pub(super) fn joined_time(&self) -> Option<&Path> {
        self.time.joined()
    }

    pub(super) fn uid_mappings(&self) -> &[IdMapping] {
        &self.uid_mappings
    }

    pub(super) fn gid_mappings(&self) -> &[IdMapping] {
        &self.gid_mappings
    }

    pub(super) fn host_uid(&self, container_id: u32) -> Option<u32> {
        mapped_host_id(container_id, &self.uid_mappings)
    }

    pub(super) fn host_gid(&self, container_id: u32) -> Option<u32> {
        mapped_host_id(container_id, &self.gid_mappings)
    }

    pub(super) fn resolve_joined_user_mappings(
        &mut self,
        process_uid: u32,
        process_gid: u32,
        additional_gids: &[u32],
    ) -> Result<()> {
        let Some(path) = self.joined_user().map(Path::to_path_buf) else {
            return Ok(());
        };
        if self.joined_user_authority.is_some()
            || !self.uid_mappings.is_empty()
            || !self.gid_mappings.is_empty()
        {
            return Err(namespace_error(
                ErrorCode::Conflict,
                "joined user namespace authority was already resolved",
            ));
        }
        let observed = joined_user::observe(&path)?;
        let uid_mappings = validate_observed_mappings("UID", observed.uid_mappings)?;
        let gid_mappings = validate_observed_mappings("GID", observed.gid_mappings)?;
        ensure_id_mapped("container root UID", 0, &uid_mappings)?;
        ensure_id_mapped("container root GID", 0, &gid_mappings)?;
        ensure_id_mapped("process.user.uid", process_uid, &uid_mappings)?;
        ensure_id_mapped("process.user.gid", process_gid, &gid_mappings)?;
        for (index, gid) in additional_gids.iter().copied().enumerate() {
            ensure_id_mapped(
                &format!("process.user.additionalGids[{index}]"),
                gid,
                &gid_mappings,
            )?;
        }
        self.uid_mappings = uid_mappings;
        self.gid_mappings = gid_mappings;
        self.joined_user_authority = Some(observed.authority);
        Ok(())
    }

    fn verify_joined_user_identity(&self, path: &Path, namespace: &File) -> Result<()> {
        let authority = self.joined_user_authority.as_ref().ok_or_else(|| {
            namespace_error(
                ErrorCode::FailedPrecondition,
                "joined user namespace authority was not resolved before namespace entry",
            )
        })?;
        authority.verify(path, namespace)
    }

    pub(super) const fn monotonic_offset(&self) -> Option<TimeOffset> {
        self.monotonic_offset
    }

    pub(super) const fn boottime_offset(&self) -> Option<TimeOffset> {
        self.boottime_offset
    }
}

pub(super) fn enter_new_namespaces(plan: &NamespacePlan, control: &mut UnixStream) -> Result<()> {
    join::enter(plan)?;

    if plan.new_user() {
        unshare(libc::CLONE_NEWUSER, "create Linux OCI user namespace")?;
        control::request_user_mapping(control)?;
    }

    let mut flags = 0;
    if plan.new_uts() {
        flags |= libc::CLONE_NEWUTS;
    }
    if plan.new_mount() {
        flags |= libc::CLONE_NEWNS;
    }
    if plan.new_ipc() {
        flags |= libc::CLONE_NEWIPC;
    }
    if plan.new_network() {
        flags |= libc::CLONE_NEWNET;
    }
    if plan.new_cgroup() {
        flags |= libc::CLONE_NEWCGROUP;
    }
    if plan.new_pid() {
        flags |= libc::CLONE_NEWPID;
    }
    if plan.new_time() {
        flags |= libc::CLONE_NEWTIME;
    }
    if flags != 0 {
        unshare(flags, "create Linux OCI namespaces")?;
    }
    if plan.new_time() {
        time::apply_offsets(plan)?;
    }
    if plan.has_user() {
        // Switching mapped credentials resets Linux dumpability. Keep the
        // original credentials until after `/proc/self/timens_offsets` has
        // been opened, written, and read back, then become namespace root
        // before any rootfs or mount mutation.
        become_user_namespace_root(if plan.new_user() { "new" } else { "joined" })?;
    }
    if plan.new_network() {
        network::bring_loopback_up()?;
    }
    Ok(())
}

pub(super) fn become_user_namespace_root(kind: &str) -> Result<()> {
    apply_supplementary_groups(
        &[],
        &format!("clear supplementary groups in the {kind} user namespace"),
    )?;
    // SAFETY: the dedicated init wrapper is single-threaded. A successful new
    // or joined user-namespace transition grants the capabilities required to
    // select mapped namespace-root IDs.
    unsafe {
        if libc::setresgid(0, 0, 0) != 0 {
            return Err(namespace_credential_error(
                format!("become root GID in the {kind} user namespace"),
                io::Error::last_os_error(),
            ));
        }
        if libc::setresuid(0, 0, 0) != 0 {
            return Err(namespace_credential_error(
                format!("become root UID in the {kind} user namespace"),
                io::Error::last_os_error(),
            ));
        }
    }
    Ok(())
}

fn namespace_credential_error(operation: String, error: io::Error) -> Error {
    let code = if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) {
        ErrorCode::PermissionDenied
    } else {
        ErrorCode::FailedPrecondition
    };
    namespace_error(code, format!("failed to {operation}: {error}"))
}

fn validate_join_path(index: usize, path: &Path) -> Result<PathBuf> {
    let field = format!("linux.namespaces[{index}].path");
    if !path.is_absolute() {
        return Err(invalid(format!("{field} must be absolute")));
    }
    if path.as_os_str().as_bytes().contains(&0) {
        return Err(invalid(format!("{field} must not contain a NUL byte")));
    }
    Ok(path.to_path_buf())
}

fn unshare(flags: libc::c_int, operation: &str) -> Result<()> {
    // SAFETY: `unshare` has no pointer preconditions. The dedicated init
    // process is single-threaded before it reports the created barrier.
    if unsafe { libc::unshare(flags) } == 0 {
        Ok(())
    } else {
        Err(namespace_error(
            ErrorCode::Internal,
            format!("{operation} failed: {}", io::Error::last_os_error()),
        ))
    }
}

pub(super) fn collect_mappings(
    field: &str,
    mappings: Option<&[LinuxIdMapping]>,
) -> Result<Vec<IdMapping>> {
    let mappings = mappings.unwrap_or_default();
    if mappings.len() > MAX_ID_MAPPINGS {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            format!(
                "{field} contains {} entries; maximum is {MAX_ID_MAPPINGS}",
                mappings.len()
            ),
        )
        .for_operation("plan-guest-init"));
    }
    let mut mappings = mappings
        .iter()
        .enumerate()
        .map(|(index, mapping)| {
            if mapping.size() == 0 {
                return Err(invalid(format!("{field}[{index}].size must be positive")));
            }
            let last_offset = mapping.size() - 1;
            mapping
                .container_id()
                .checked_add(last_offset)
                .and_then(|_| mapping.host_id().checked_add(last_offset))
                .ok_or_else(|| invalid(format!("{field}[{index}] exceeds the uint32 ID space")))?;
            Ok(IdMapping::from(mapping))
        })
        .collect::<Result<Vec<_>>>()?;
    validate_non_overlapping_mappings(field, &mappings)?;
    mappings.sort_unstable();
    Ok(mappings)
}

fn validate_non_overlapping_mappings(field: &str, mappings: &[IdMapping]) -> Result<()> {
    for (index, mapping) in mappings.iter().enumerate() {
        for (prior_index, prior) in mappings[..index].iter().enumerate() {
            if mapping_ranges_overlap(
                mapping.container_id,
                mapping.size,
                prior.container_id,
                prior.size,
            ) {
                return Err(invalid(format!(
                    "{field}[{index}].containerID overlaps {field}[{prior_index}]"
                )));
            }
            if mapping_ranges_overlap(mapping.host_id, mapping.size, prior.host_id, prior.size) {
                return Err(invalid(format!(
                    "{field}[{index}].hostID overlaps {field}[{prior_index}]"
                )));
            }
        }
    }
    Ok(())
}

fn validate_observed_mappings(kind: &str, mut mappings: Vec<IdMapping>) -> Result<Vec<IdMapping>> {
    if mappings.is_empty() {
        return Err(namespace_error(
            ErrorCode::FailedPrecondition,
            format!("joined user namespace has no {kind} mappings"),
        ));
    }
    if mappings.len() > MAX_ID_MAPPINGS {
        return Err(namespace_error(
            ErrorCode::ResourceExhausted,
            format!(
                "joined user namespace has {} {kind} mappings; maximum is {MAX_ID_MAPPINGS}",
                mappings.len()
            ),
        ));
    }
    for (index, mapping) in mappings.iter().enumerate() {
        if mapping.size == 0 {
            return Err(namespace_error(
                ErrorCode::FailedPrecondition,
                format!("joined user namespace {kind} mapping {index} has zero size"),
            ));
        }
        let last_offset = mapping.size - 1;
        if mapping.container_id.checked_add(last_offset).is_none()
            || mapping.host_id.checked_add(last_offset).is_none()
        {
            return Err(namespace_error(
                ErrorCode::FailedPrecondition,
                format!("joined user namespace {kind} mapping {index} exceeds the uint32 ID space"),
            ));
        }
        for (prior_index, prior) in mappings[..index].iter().enumerate() {
            if mapping_ranges_overlap(
                mapping.container_id,
                mapping.size,
                prior.container_id,
                prior.size,
            ) || mapping_ranges_overlap(mapping.host_id, mapping.size, prior.host_id, prior.size)
            {
                return Err(namespace_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "joined user namespace {kind} mappings {prior_index} and {index} overlap"
                    ),
                ));
            }
        }
    }
    mappings.sort_unstable();
    Ok(mappings)
}

fn mapping_ranges_overlap(left: u32, left_size: u32, right: u32, right_size: u32) -> bool {
    let left = u64::from(left)..u64::from(left) + u64::from(left_size);
    let right = u64::from(right)..u64::from(right) + u64::from(right_size);
    left.start < right.end && right.start < left.end
}

fn ensure_id_mapped(field: &str, id: u32, mappings: &[IdMapping]) -> Result<()> {
    if mappings
        .iter()
        .any(|mapping| id >= mapping.container_id && id - mapping.container_id < mapping.size)
    {
        Ok(())
    } else {
        Err(invalid(format!(
            "{field} value {id} is not covered by its container ID mappings"
        )))
    }
}

fn mapped_host_id(id: u32, mappings: &[IdMapping]) -> Option<u32> {
    mappings.iter().find_map(|mapping| {
        let offset = id.checked_sub(mapping.container_id)?;
        (offset < mapping.size)
            .then(|| mapping.host_id.checked_add(offset))
            .flatten()
    })
}

fn time_offset(
    clock: &str,
    offset: &a3s_oci_sdk::oci_spec::runtime::LinuxTimeOffset,
) -> Result<TimeOffset> {
    let nanosecs = offset.nanosecs().unwrap_or_default();
    if nanosecs >= NANOSECONDS_PER_SECOND {
        return Err(invalid(format!(
            "linux.timeOffsets.{clock}.nanosecs must be less than {NANOSECONDS_PER_SECOND}"
        )));
    }
    Ok(TimeOffset {
        secs: offset.secs().unwrap_or_default(),
        nanosecs,
    })
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message).for_operation("plan-guest-init")
}

fn unsupported(field: &str, reason: &str) -> Error {
    Error::new(ErrorCode::Unsupported, format!("{field}: {reason}"))
        .for_operation("plan-guest-init")
}

fn namespace_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("run-container-init")
}
