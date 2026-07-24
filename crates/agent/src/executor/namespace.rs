use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::{Linux, LinuxIdMapping, LinuxNamespaceType};
use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::control;

mod join;
mod time;
mod user;

pub(super) use user::install_user_mappings;

const MAX_ID_MAPPINGS: usize = 340;
const NANOSECONDS_PER_SECOND: u32 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    pub(super) const fn has_pid(&self) -> bool {
        self.pid.is_configured()
    }

    pub(super) const fn has_time(&self) -> bool {
        self.time.is_configured()
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

    pub(super) const fn requires_child_process(&self) -> bool {
        self.has_pid() || self.has_time()
    }

    pub(super) fn uid_mappings(&self) -> &[IdMapping] {
        &self.uid_mappings
    }

    pub(super) fn gid_mappings(&self) -> &[IdMapping] {
        &self.gid_mappings
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
    Ok(())
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

fn collect_mappings(field: &str, mappings: Option<&[LinuxIdMapping]>) -> Result<Vec<IdMapping>> {
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
    let mappings = mappings
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
    Ok(mappings)
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
