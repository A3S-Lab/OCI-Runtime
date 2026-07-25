use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::{Linux, LinuxResources};
use a3s_oci_sdk::{Error, ErrorCode, Result};

const CGROUP_EVENTS: &str = "cgroup.events";
const CGROUP_FREEZE: &str = "cgroup.freeze";
const CGROUP_PROCS: &str = "cgroup.procs";
const FREEZE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const FREEZE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CGROUP_PATH_BYTES: usize = 4_096;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct CgroupPlan {
    relative_path: Option<PathBuf>,
    memory_limit: Option<i64>,
    memory_reservation: Option<i64>,
    memory_swap: Option<i64>,
    cpu_shares: Option<u64>,
    cpu_quota: Option<i64>,
    cpu_period: Option<u64>,
    cpuset_cpus: Option<String>,
    cpuset_mems: Option<String>,
    pids_limit: Option<i64>,
}

impl CgroupPlan {
    pub(super) fn from_linux(linux: Option<&Linux>) -> Result<Self> {
        let Some(linux) = linux else {
            return Ok(Self::default());
        };
        let relative_path = linux
            .cgroups_path()
            .as_deref()
            .map(validate_cgroup_path)
            .transpose()?;
        let Some(resources) = linux.resources().as_ref() else {
            return Ok(Self {
                relative_path,
                ..Self::default()
            });
        };
        validate_supported_resource_fields(resources)?;

        let memory = resources.memory().as_ref();
        let cpu = resources.cpu().as_ref();
        let pids = resources.pids().as_ref();
        let plan = Self {
            relative_path,
            memory_limit: memory.and_then(|memory| memory.limit()),
            memory_reservation: memory.and_then(|memory| memory.reservation()),
            memory_swap: memory.and_then(|memory| memory.swap()),
            cpu_shares: cpu.and_then(|cpu| cpu.shares()),
            cpu_quota: cpu.and_then(|cpu| cpu.quota()),
            cpu_period: cpu.and_then(|cpu| cpu.period()),
            cpuset_cpus: cpu.and_then(|cpu| cpu.cpus().clone()),
            cpuset_mems: cpu.and_then(|cpu| cpu.mems().clone()),
            pids_limit: pids.map(|pids| pids.limit()),
        };
        plan.validate()?;
        if plan.has_limits() && plan.relative_path.is_none() {
            return Err(unsupported(
                "linux.cgroupsPath",
                "resource limits require an explicit normalized cgroup v2 path",
            ));
        }
        Ok(plan)
    }

    fn validate(&self) -> Result<()> {
        if self.memory_limit.is_some_and(|value| value <= 0) {
            return Err(invalid("linux.resources.memory.limit must be positive"));
        }
        if self
            .memory_reservation
            .is_some_and(|value| value < 0 || self.memory_limit.is_some_and(|limit| value > limit))
        {
            return Err(invalid(
                "linux.resources.memory.reservation must be non-negative and not exceed limit",
            ));
        }
        if self.memory_swap.is_some_and(|value| {
            value < -1
                || self
                    .memory_limit
                    .is_some_and(|limit| value != -1 && value < limit)
        }) {
            return Err(invalid(
                "linux.resources.memory.swap must be -1 or at least the memory limit",
            ));
        }
        if self
            .cpu_shares
            .is_some_and(|value| !(2..=262_144).contains(&value))
        {
            return Err(invalid(
                "linux.resources.cpu.shares must be between 2 and 262144",
            ));
        }
        if self
            .cpu_quota
            .is_some_and(|value| value != -1 && value <= 0)
        {
            return Err(invalid("linux.resources.cpu.quota must be -1 or positive"));
        }
        if self.cpu_period.is_some_and(|value| value == 0) {
            return Err(invalid("linux.resources.cpu.period must be positive"));
        }
        if self.cpu_quota.is_some() != self.cpu_period.is_some() {
            return Err(invalid(
                "linux.resources.cpu.quota and period must be specified together",
            ));
        }
        for (field, value) in [
            ("linux.resources.cpu.cpus", self.cpuset_cpus.as_deref()),
            ("linux.resources.cpu.mems", self.cpuset_mems.as_deref()),
        ] {
            if let Some(value) = value {
                validate_cpuset(field, value)?;
            }
        }
        if self.pids_limit.is_some_and(|value| value <= 0) {
            return Err(invalid("linux.resources.pids.limit must be positive"));
        }
        Ok(())
    }

    pub(super) fn settings(&self) -> Vec<(&'static str, String)> {
        let mut settings = Vec::new();
        if let Some(value) = &self.cpuset_mems {
            settings.push(("cpuset.mems", value.clone()));
        }
        if let Some(value) = &self.cpuset_cpus {
            settings.push(("cpuset.cpus", value.clone()));
        }
        if let Some(value) = self.memory_limit {
            settings.push(("memory.max", value.to_string()));
            settings.push(("memory.oom.group", "1".to_string()));
        }
        if let Some(value) = self.memory_reservation {
            settings.push(("memory.low", value.to_string()));
        }
        if let Some(value) = self.memory_swap {
            let value = if value == -1 {
                "max".to_string()
            } else {
                (value - self.memory_limit.unwrap_or_default()).to_string()
            };
            settings.push(("memory.swap.max", value));
        }
        if let (Some(quota), Some(period)) = (self.cpu_quota, self.cpu_period) {
            let quota = if quota == -1 {
                "max".to_string()
            } else {
                quota.to_string()
            };
            settings.push(("cpu.max", format!("{quota} {period}")));
        }
        if let Some(shares) = self.cpu_shares {
            settings.push(("cpu.weight", shares_to_weight(shares).to_string()));
        }
        if let Some(value) = self.pids_limit {
            settings.push(("pids.max", value.to_string()));
        }
        settings
    }

    fn required_controllers(&self) -> BTreeSet<&'static str> {
        let mut controllers = BTreeSet::new();
        if self.memory_limit.is_some()
            || self.memory_reservation.is_some()
            || self.memory_swap.is_some()
        {
            controllers.insert("memory");
        }
        if self.cpu_shares.is_some() || self.cpu_quota.is_some() {
            controllers.insert("cpu");
        }
        if self.cpuset_cpus.is_some() || self.cpuset_mems.is_some() {
            controllers.insert("cpuset");
        }
        if self.pids_limit.is_some() {
            controllers.insert("pids");
        }
        controllers
    }

    fn has_limits(&self) -> bool {
        !self.settings().is_empty()
    }
}

#[derive(Debug)]
pub(super) struct CgroupHandle {
    created: Vec<PathBuf>,
    leaf: PathBuf,
    procs: File,
}

impl CgroupHandle {
    pub(super) fn create(plan: &CgroupPlan) -> Result<Option<Self>> {
        let Some(relative_path) = &plan.relative_path else {
            return Ok(None);
        };
        let root = delegated_cgroup_root()?;
        let controllers = plan.required_controllers();
        let mut current = root;
        let mut created = Vec::new();
        for (index, component) in relative_path.components().enumerate() {
            enable_controllers(&current, &controllers)?;
            current.push(component.as_os_str());
            let is_leaf = index + 1 == relative_path.components().count();
            match std::fs::create_dir(&current) {
                Ok(()) => created.push(current.clone()),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists && !is_leaf => {
                    ensure_real_directory(&current)?;
                }
                Err(error) => {
                    cleanup_directories(&created);
                    return Err(cgroup_error(
                        if error.kind() == io::ErrorKind::AlreadyExists {
                            ErrorCode::Conflict
                        } else {
                            ErrorCode::PermissionDenied
                        },
                        format!("failed to create cgroup {}: {error}", current.display()),
                    ));
                }
            }
        }
        if let Err(error) = apply_settings(&current, plan) {
            cleanup_directories(&created);
            return Err(error);
        }
        let procs = OpenOptions::new()
            .write(true)
            .open(current.join(CGROUP_PROCS))
            .map_err(|error| {
                cleanup_directories(&created);
                cgroup_error(
                    ErrorCode::PermissionDenied,
                    format!(
                        "failed to open container cgroup.procs at {}: {error}",
                        current.display()
                    ),
                )
            })?;
        Ok(Some(Self {
            created,
            leaf: current,
            procs,
        }))
    }

    pub(super) fn procs_descriptor(&self) -> RawFd {
        self.procs.as_raw_fd()
    }

    pub(super) async fn set_frozen(&self, frozen: bool) -> Result<()> {
        let freeze_path = self.leaf.join(CGROUP_FREEZE);
        tokio::fs::write(&freeze_path, if frozen { b"1" } else { b"0" })
            .await
            .map_err(|error| {
                cgroup_error(
                    if error.kind() == io::ErrorKind::NotFound {
                        ErrorCode::Unsupported
                    } else {
                        ErrorCode::PermissionDenied
                    },
                    format!(
                        "failed to {} container cgroup {}: {error}",
                        if frozen { "freeze" } else { "thaw" },
                        self.leaf.display()
                    ),
                )
            })?;

        let deadline = tokio::time::Instant::now() + FREEZE_TIMEOUT;
        loop {
            let events_path = self.leaf.join(CGROUP_EVENTS);
            let events = tokio::fs::read_to_string(&events_path)
                .await
                .map_err(|error| {
                    cgroup_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "failed to verify container freezer state at {}: {error}",
                            events_path.display()
                        ),
                    )
                })?;
            if cgroup_event_value(&events, "frozen") == Some(u64::from(frozen)) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(cgroup_error(
                    ErrorCode::DeadlineExceeded,
                    format!(
                        "timed out waiting for container cgroup {} to become {}",
                        self.leaf.display(),
                        if frozen { "frozen" } else { "thawed" }
                    ),
                )
                .retryable(true));
            }
            tokio::time::sleep(FREEZE_POLL_INTERVAL).await;
        }
    }
}

impl Drop for CgroupHandle {
    fn drop(&mut self) {
        cleanup_directories(&self.created);
    }
}

pub(super) fn join_from_pre_exec(descriptor: RawFd) -> io::Result<()> {
    let payload = b"0";
    // SAFETY: the descriptor is a live cgroup.procs file inherited across
    // fork, and writing `0` moves only the calling process.
    let written = unsafe { libc::write(descriptor, payload.as_ptr().cast(), payload.len()) };
    if written == payload.len() as isize {
        Ok(())
    } else if written < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "partial write to cgroup.procs",
        ))
    }
}

fn apply_settings(path: &Path, plan: &CgroupPlan) -> Result<()> {
    for (file, value) in plan.settings() {
        let destination = path.join(file);
        std::fs::write(&destination, value.as_bytes()).map_err(|error| {
            cgroup_error(
                ErrorCode::PermissionDenied,
                format!(
                    "failed to apply cgroup setting {}={value}: {error}",
                    destination.display()
                ),
            )
        })?;
        let actual = std::fs::read_to_string(&destination).map_err(|error| {
            cgroup_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to verify cgroup setting {}: {error}",
                    destination.display()
                ),
            )
        })?;
        if normalize_cgroup_value(&actual) != normalize_cgroup_value(&value) {
            return Err(cgroup_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "cgroup setting {} read back differently",
                    destination.display()
                ),
            ));
        }
    }
    Ok(())
}

fn enable_controllers(path: &Path, required: &BTreeSet<&str>) -> Result<()> {
    if required.is_empty() {
        return Ok(());
    }
    let available_path = path.join("cgroup.controllers");
    let available = std::fs::read_to_string(&available_path).map_err(|error| {
        cgroup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect delegated controllers {}: {error}",
                available_path.display()
            ),
        )
    })?;
    let available = available.split_ascii_whitespace().collect::<BTreeSet<_>>();
    if let Some(missing) = required
        .iter()
        .find(|controller| !available.contains(**controller))
    {
        return Err(cgroup_error(
            ErrorCode::Unsupported,
            format!("delegated cgroup v2 controller `{missing}` is unavailable"),
        ));
    }
    let value = required
        .iter()
        .map(|controller| format!("+{controller}"))
        .collect::<Vec<_>>()
        .join(" ");
    std::fs::write(path.join("cgroup.subtree_control"), value).map_err(|error| {
        cgroup_error(
            ErrorCode::PermissionDenied,
            format!(
                "failed to enable delegated cgroup v2 controllers at {}: {error}",
                path.display()
            ),
        )
    })
}

fn delegated_cgroup_root() -> Result<PathBuf> {
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
    let membership = std::fs::read_to_string("/proc/self/cgroup").map_err(|error| {
        cgroup_error(
            ErrorCode::FailedPrecondition,
            format!("failed to read current cgroup membership: {error}"),
        )
    })?;
    let relative = unified_membership(&membership).ok_or_else(|| {
        cgroup_error(
            ErrorCode::Unsupported,
            "current process has no unified cgroup v2 membership",
        )
    })?;
    let root = mountpoint.join(relative.trim_start_matches('/'));
    ensure_real_directory(&root)?;
    Ok(root)
}

fn cgroup2_mountpoint(mountinfo: &str) -> Option<PathBuf> {
    mountinfo.lines().find_map(|line| {
        let (left, right) = line.split_once(" - ")?;
        if right.split_ascii_whitespace().next()? != "cgroup2" {
            return None;
        }
        let mountpoint = left.split_ascii_whitespace().nth(4)?;
        (!mountpoint.contains('\\')).then(|| PathBuf::from(mountpoint))
    })
}

fn unified_membership(cgroup: &str) -> Option<&str> {
    cgroup.lines().find_map(|line| line.strip_prefix("0::"))
}

fn validate_cgroup_path(path: &Path) -> Result<PathBuf> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid("linux.cgroupsPath is not valid UTF-8"))?;
    if value.is_empty() || value.len() > MAX_CGROUP_PATH_BYTES || value.as_bytes().contains(&0) {
        return Err(invalid(format!(
            "linux.cgroupsPath must contain 1..={MAX_CGROUP_PATH_BYTES} bytes and no NUL"
        )));
    }
    let relative = value.trim_start_matches('/');
    let path = Path::new(relative);
    if relative.is_empty()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_))
                || component.as_os_str().to_string_lossy().contains(':')
        })
    {
        return Err(invalid(
            "linux.cgroupsPath must be a normalized cgroupfs path without systemd syntax",
        ));
    }
    Ok(path.to_path_buf())
}

fn validate_supported_resource_fields(resources: &LinuxResources) -> Result<()> {
    let value = serde_json::to_value(resources).map_err(|error| {
        cgroup_error(
            ErrorCode::Internal,
            format!("failed to inspect OCI resources: {error}"),
        )
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("linux.resources must be an object"))?;
    if let Some(field) = object
        .keys()
        .find(|field| !matches!(field.as_str(), "devices" | "memory" | "cpu" | "pids"))
    {
        return Err(unsupported(
            &format!("linux.resources.{field}"),
            "this cgroup v2 resource is not implemented",
        ));
    }
    for (name, allowed) in [
        ("memory", &["limit", "reservation", "swap"][..]),
        ("cpu", &["shares", "quota", "period", "cpus", "mems"][..]),
        ("pids", &["limit"][..]),
    ] {
        if let Some(object) = object.get(name).and_then(serde_json::Value::as_object) {
            if let Some(field) = object
                .keys()
                .find(|field| !allowed.contains(&field.as_str()))
            {
                return Err(unsupported(
                    &format!("linux.resources.{name}.{field}"),
                    "this cgroup v2 resource is not implemented",
                ));
            }
        }
    }
    Ok(())
}

fn validate_cpuset(field: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 4_096
        || value.split(',').any(|range| match range.split_once('-') {
            Some((start, end)) => {
                start.parse::<u32>().is_err()
                    || end.parse::<u32>().is_err()
                    || start.parse::<u32>().ok() > end.parse::<u32>().ok()
            }
            None => range.parse::<u32>().is_err(),
        })
    {
        Err(invalid(format!(
            "{field} must be a comma-separated list of CPU or memory-node indices and ranges"
        )))
    } else {
        Ok(())
    }
}

const fn shares_to_weight(shares: u64) -> u64 {
    1 + ((shares - 2) * 9_999) / 262_142
}

fn normalize_cgroup_value(value: &str) -> String {
    value.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

fn cgroup_event_value(events: &str, key: &str) -> Option<u64> {
    events.lines().find_map(|line| {
        let mut fields = line.split_ascii_whitespace();
        (fields.next()? == key)
            .then(|| fields.next()?.parse().ok())
            .flatten()
    })
}

fn ensure_real_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        cgroup_error(
            ErrorCode::FailedPrecondition,
            format!("failed to inspect cgroup {}: {error}", path.display()),
        )
    })?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(cgroup_error(
            ErrorCode::PermissionDenied,
            format!("cgroup path is not a real directory: {}", path.display()),
        ))
    }
}

fn cleanup_directories(paths: &[PathBuf]) {
    for path in paths.iter().rev() {
        let _ = std::fs::remove_dir(path);
    }
}

fn invalid(message: impl Into<String>) -> Error {
    cgroup_error(ErrorCode::InvalidArgument, message)
}

fn unsupported(field: &str, reason: &str) -> Error {
    cgroup_error(ErrorCode::Unsupported, format!("{field}: {reason}"))
}

fn cgroup_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("configure-container-cgroup")
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::oci_spec::runtime::Linux;

    use super::{
        cgroup2_mountpoint, cgroup_event_value, shares_to_weight, unified_membership, CgroupPlan,
    };

    fn fixture_linux() -> Linux {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/a3s-box/config.json"))
                .expect("decode fixture");
        serde_json::from_value(config["linux"].clone()).expect("decode Linux config")
    }

    #[test]
    fn plans_exact_a3s_box_cgroup_v2_settings() {
        let plan = CgroupPlan::from_linux(Some(&fixture_linux())).expect("cgroup plan");
        assert_eq!(
            plan.settings(),
            [
                ("cpuset.cpus", "0-1".to_string()),
                ("memory.max", "536870912".to_string()),
                ("memory.oom.group", "1".to_string()),
                ("memory.low", "268435456".to_string()),
                ("memory.swap.max", "536870912".to_string()),
                ("cpu.max", "200000 100000".to_string()),
                ("cpu.weight", "39".to_string()),
                ("pids.max", "512".to_string()),
            ]
        );
    }

    #[test]
    fn parses_unified_mount_and_membership() {
        let mountinfo =
            "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n30 23 0:27 / /tmp rw - tmpfs tmpfs rw\n";
        assert_eq!(
            cgroup2_mountpoint(mountinfo).as_deref(),
            Some(std::path::Path::new("/sys/fs/cgroup"))
        );
        assert_eq!(
            unified_membership("0::/user.slice/a3s.service\n"),
            Some("/user.slice/a3s.service")
        );
    }

    #[test]
    fn uses_the_runc_cpu_shares_conversion() {
        assert_eq!(shares_to_weight(2), 1);
        assert_eq!(shares_to_weight(1_024), 39);
        assert_eq!(shares_to_weight(262_144), 10_000);
    }

    #[test]
    fn parses_exact_cgroup_event_values() {
        let events = "populated 1\nfrozen 0\n";
        assert_eq!(cgroup_event_value(events, "populated"), Some(1));
        assert_eq!(cgroup_event_value(events, "frozen"), Some(0));
        assert_eq!(cgroup_event_value(events, "missing"), None);
        assert_eq!(cgroup_event_value("frozen invalid\n", "frozen"), None);
        assert_eq!(cgroup_event_value("frozen\n", "frozen"), None);
    }
}
