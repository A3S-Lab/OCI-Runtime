use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use a3s_oci_sdk::{
    Error, ErrorCode, Result, CONTROL_CGROUP_NAME, CONTROL_CGROUP_PROCS_FD, WORKLOAD_CGROUP_NAME,
    WORKLOAD_CGROUP_PROCS_FD,
};

mod plan;
mod stats;
mod update;

pub(super) use plan::CgroupPlan;
use plan::{
    shares_to_weight, validate_cpuset, validate_supported_resource_fields, ControlHeadroom,
};

const CGROUP_EVENTS: &str = "cgroup.events";
const CGROUP_FREEZE: &str = "cgroup.freeze";
const CGROUP_PROCS: &str = "cgroup.procs";
const SUPPORTED_CONTROLLERS: [&str; 4] = ["cpu", "cpuset", "memory", "pids"];
const FREEZE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const FREEZE_TIMEOUT: Duration = Duration::from_secs(5);
const PROTECTED_CGROUP_DESCRIPTOR_MINIMUM: RawFd = 10;

#[derive(Debug)]
pub(super) struct CgroupManager {
    root: PathBuf,
    controllers: BTreeSet<&'static str>,
}

impl CgroupManager {
    pub(super) fn create() -> Result<Self> {
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
        let controllers = available_supported_controllers(&mountpoint)?;
        if let Some(missing) = SUPPORTED_CONTROLLERS
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
        enable_controllers(&mountpoint, &controllers)?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                cgroup_error(
                    ErrorCode::Internal,
                    format!("system clock is before the Unix epoch: {error}"),
                )
            })?
            .as_nanos();
        let root = mountpoint.join(format!("a3s-oci-{}-{timestamp:032x}", std::process::id()));
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
        Ok(Self { root, controllers })
    }

    pub(super) fn remove(self) -> Result<()> {
        cleanup_cgroup_tree(&self.root)
    }

    pub(super) fn root(&self) -> &Path {
        &self.root
    }
}

#[derive(Debug)]
pub(super) struct CgroupHandle {
    created: Vec<PathBuf>,
    leaf: PathBuf,
    init_procs: File,
    control_workload: Option<ControlWorkloadCgroup>,
}

#[derive(Debug)]
struct ControlWorkloadCgroup {
    management: PathBuf,
    headroom: ControlHeadroom,
    control_procs: File,
    workload_procs: File,
}

#[derive(Debug)]
struct ControlWorkloadMembership {
    init_procs: File,
    control_procs: File,
    workload_procs: File,
}

impl CgroupHandle {
    pub(super) fn create(
        plan: &CgroupPlan,
        manager: Option<&CgroupManager>,
    ) -> Result<Option<Self>> {
        let Some(relative_path) = &plan.relative_path else {
            return Ok(None);
        };
        let manager = manager.ok_or_else(|| {
            cgroup_error(
                ErrorCode::FailedPrecondition,
                "an explicit cgroup path requires a private cgroup manager",
            )
        })?;
        let required = plan.required_controllers();
        if let Some(missing) = required
            .iter()
            .find(|controller| !manager.controllers.contains(**controller))
        {
            return Err(cgroup_error(
                ErrorCode::Unsupported,
                format!("cgroup v2 controller `{missing}` is unavailable"),
            ));
        }
        let controllers = &manager.controllers;
        let mut current = manager.root.clone();
        let mut created = Vec::new();
        for (index, component) in relative_path.components().enumerate() {
            initialize_cpuset(&current)?;
            enable_controllers(&current, controllers)?;
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
        let configured = (|| {
            initialize_cpuset(&current)?;
            let Some(headroom) = plan.control_headroom() else {
                apply_settings(&current, &plan.settings())?;
                let init_procs = open_cgroup_procs(&current)?;
                return Ok((current.clone(), init_procs, None));
            };

            // Keep the OCI leaf free of delegated controllers until init has
            // created its cgroup namespace while rooted here, then moved into
            // control. The create-hook barrier finalizes delegation only after
            // the management envelope is empty again.
            let management = plan.management_plan(headroom)?;
            apply_settings(&current, &management.settings())?;

            let control = current.join(CONTROL_CGROUP_NAME);
            create_cgroup_directory(&control, &mut created)?;

            let workload = current.join(WORKLOAD_CGROUP_NAME);
            create_cgroup_directory(&workload, &mut created)?;

            // Init enters management only long enough to create a cgroup
            // namespace rooted at the complete container topology. It then
            // moves through the protected control descriptor before the parent
            // enables domain controllers on this envelope.
            let membership = open_control_workload_membership(&current, &control, &workload)?;
            let control_workload = ControlWorkloadCgroup {
                management: current.clone(),
                headroom: headroom.clone(),
                control_procs: membership.control_procs,
                workload_procs: membership.workload_procs,
            };
            Ok((workload, membership.init_procs, Some(control_workload)))
        })();
        match configured {
            Ok((leaf, init_procs, control_workload)) => Ok(Some(Self {
                created,
                leaf,
                init_procs,
                control_workload,
            })),
            Err(error) => {
                cleanup_directories(&created);
                Err(error)
            }
        }
    }

    pub(super) fn finalize_control_workload(
        &mut self,
        plan: &CgroupPlan,
        manager: &CgroupManager,
    ) -> Result<()> {
        let Some(layout) = &self.control_workload else {
            return Ok(());
        };
        if plan.control_headroom().is_none() {
            return Err(cgroup_error(
                ErrorCode::Internal,
                "control/workload cgroup handle lost its versioned plan",
            ));
        }

        let management_procs = layout.management.join(CGROUP_PROCS);
        let remaining = std::fs::read_to_string(&management_procs).map_err(|error| {
            cgroup_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to verify empty cgroup management envelope {}: {error}",
                    management_procs.display()
                ),
            )
        })?;
        if !remaining.trim().is_empty() {
            return Err(cgroup_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "trusted init has not left cgroup management envelope {}",
                    layout.management.display()
                ),
            ));
        }

        enable_controllers(&layout.management, &manager.controllers)?;
        let control = layout.management.join(CONTROL_CGROUP_NAME);
        let workload = layout.management.join(WORKLOAD_CGROUP_NAME);
        initialize_cpuset(&control)?;
        initialize_cpuset(&workload)?;
        apply_settings(&workload, &plan.settings_with_oom_group(false))
    }

    pub(super) fn init_procs_descriptor(&self) -> RawFd {
        self.init_procs.as_raw_fd()
    }

    pub(super) fn workload_procs_descriptor(&self) -> RawFd {
        self.control_workload.as_ref().map_or_else(
            || self.init_procs.as_raw_fd(),
            |layout| layout.workload_procs.as_raw_fd(),
        )
    }

    pub(super) fn control_workload_descriptors(&self) -> Option<(RawFd, RawFd)> {
        self.control_workload.as_ref().map(|layout| {
            (
                layout.control_procs.as_raw_fd(),
                layout.workload_procs.as_raw_fd(),
            )
        })
    }

    pub(super) fn recovery_paths(&self) -> (&Path, &[PathBuf]) {
        (&self.leaf, &self.created)
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

pub(super) fn join_current_process(descriptor: RawFd) -> io::Result<()> {
    let payload = b"0";
    // SAFETY: the descriptor is a live cgroup.procs file inherited across
    // fork, and writing `0` moves only the calling process. This stays valid
    // both in pre-exec hooks and immediately after cgroup namespace creation.
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

pub(super) fn install_control_workload_descriptors_from_pre_exec(
    control_source: RawFd,
    workload_source: RawFd,
) -> io::Result<()> {
    install_inherited_descriptor(control_source, CONTROL_CGROUP_PROCS_FD)?;
    install_inherited_descriptor(workload_source, WORKLOAD_CGROUP_PROCS_FD)
}

fn install_inherited_descriptor(source: RawFd, target: RawFd) -> io::Result<()> {
    if source != target && unsafe { libc::dup2(source, target) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // dup2 clears FD_CLOEXEC for a distinct target. Clear it explicitly as
    // well so the helper remains correct if a future source already occupies
    // its fixed target.
    let flags = unsafe { libc::fcntl(target, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::FD_CLOEXEC != 0
        && unsafe { libc::fcntl(target, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn create_cgroup_directory(path: &Path, created: &mut Vec<PathBuf>) -> Result<()> {
    std::fs::create_dir(path).map_err(|error| {
        cgroup_error(
            if error.kind() == io::ErrorKind::AlreadyExists {
                ErrorCode::Conflict
            } else {
                ErrorCode::PermissionDenied
            },
            format!("failed to create cgroup {}: {error}", path.display()),
        )
    })?;
    created.push(path.to_path_buf());
    Ok(())
}

fn open_control_workload_membership(
    management: &Path,
    control: &Path,
    workload: &Path,
) -> Result<ControlWorkloadMembership> {
    Ok(ControlWorkloadMembership {
        init_procs: open_cgroup_procs(management)?,
        control_procs: open_cgroup_procs(control)?,
        workload_procs: open_cgroup_procs(workload)?,
    })
}

fn open_cgroup_procs(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .open(path.join(CGROUP_PROCS))
        .map_err(|error| {
            cgroup_error(
                ErrorCode::PermissionDenied,
                format!(
                    "failed to open container cgroup.procs at {}: {error}",
                    path.display()
                ),
            )
        })?;
    // Keep every source above the fixed inherited targets so installing one
    // descriptor can never overwrite the source of the other.
    let descriptor = unsafe {
        libc::fcntl(
            file.as_raw_fd(),
            libc::F_DUPFD_CLOEXEC,
            PROTECTED_CGROUP_DESCRIPTOR_MINIMUM,
        )
    };
    if descriptor < 0 {
        return Err(cgroup_error(
            ErrorCode::Internal,
            format!(
                "failed to protect cgroup.procs descriptor at {}: {}",
                path.display(),
                io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: F_DUPFD_CLOEXEC returned a distinct owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn apply_settings(path: &Path, settings: &[(&'static str, String)]) -> Result<()> {
    for (file, value) in settings {
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
        if normalize_cgroup_value(&actual) != normalize_cgroup_value(value) {
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
    let subtree_path = path.join("cgroup.subtree_control");
    let current = std::fs::read_to_string(&subtree_path).map_err(|error| {
        cgroup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect delegated controller state {}: {error}",
                subtree_path.display()
            ),
        )
    })?;
    let current = current.split_ascii_whitespace().collect::<BTreeSet<_>>();
    let missing = required
        .iter()
        .filter(|controller| !current.contains(**controller))
        .copied()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(());
    }
    let value = missing
        .iter()
        .map(|controller| format!("+{controller}"))
        .collect::<Vec<_>>()
        .join(" ");
    std::fs::write(&subtree_path, value).map_err(|error| {
        cgroup_error(
            ErrorCode::PermissionDenied,
            format!(
                "failed to enable delegated cgroup v2 controllers at {}: {error}",
                path.display()
            ),
        )
    })
}

fn available_supported_controllers(path: &Path) -> Result<BTreeSet<&'static str>> {
    let available_path = path.join("cgroup.controllers");
    let available = std::fs::read_to_string(&available_path).map_err(|error| {
        cgroup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect supported controllers {}: {error}",
                available_path.display()
            ),
        )
    })?;
    Ok(SUPPORTED_CONTROLLERS
        .into_iter()
        .filter(|controller| {
            available
                .split_ascii_whitespace()
                .any(|candidate| candidate == *controller)
        })
        .collect())
}

fn initialize_cpuset(path: &Path) -> Result<()> {
    for name in ["cpuset.cpus", "cpuset.mems"] {
        let destination = path.join(name);
        let Ok(current) = std::fs::read_to_string(&destination) else {
            continue;
        };
        if !current.trim().is_empty() {
            continue;
        }
        let effective_path = path.join(format!("{name}.effective"));
        let effective = std::fs::read_to_string(&effective_path).map_err(|error| {
            cgroup_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to inspect effective cpuset {}: {error}",
                    effective_path.display()
                ),
            )
        })?;
        if effective.trim().is_empty() {
            return Err(cgroup_error(
                ErrorCode::FailedPrecondition,
                format!("effective cpuset is empty at {}", effective_path.display()),
            ));
        }
        std::fs::write(&destination, effective.trim()).map_err(|error| {
            cgroup_error(
                ErrorCode::PermissionDenied,
                format!(
                    "failed to initialize cpuset {}: {error}",
                    destination.display()
                ),
            )
        })?;
    }
    Ok(())
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

fn normalize_cgroup_value(value: &str) -> String {
    value.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

async fn read_required(path: &Path, file: &str, operation: &str) -> Result<String> {
    let source = path.join(file);
    tokio::fs::read_to_string(&source).await.map_err(|error| {
        let code = if error.kind() == io::ErrorKind::NotFound {
            ErrorCode::Unsupported
        } else {
            ErrorCode::FailedPrecondition
        };
        let message = format!("failed to read cgroup file {}: {error}", source.display());
        Error::new(code, message).for_operation(operation)
    })
}

fn parse_u64_value(field: &str, value: &str) -> Result<u64> {
    value.trim().parse::<u64>().map_err(|error| {
        stats_error(format!(
            "cgroup counter {field} is not a non-negative integer: {error}"
        ))
    })
}

fn parse_max_value(field: &str, value: &str) -> Result<Option<u64>> {
    let value = value.trim();
    if value == "max" {
        Ok(None)
    } else {
        value.parse::<u64>().map(Some).map_err(|error| {
            stats_error(format!(
                "cgroup limit {field} is neither `max` nor a non-negative integer: {error}"
            ))
        })
    }
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

fn cleanup_cgroup_tree(root: &Path) -> Result<()> {
    fn remove_children(path: &Path) -> io::Result<()> {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() && !file_type.is_symlink() {
                remove_children(&entry.path())?;
                std::fs::remove_dir(entry.path())?;
            }
        }
        Ok(())
    }

    remove_children(root)
        .and_then(|()| std::fs::remove_dir(root))
        .map_err(|error| {
            cgroup_error(
                ErrorCode::Internal,
                format!(
                    "failed to remove private cgroup manager {}: {error}",
                    root.display()
                ),
            )
        })
}

fn cgroup_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("configure-container-cgroup")
}

fn stats_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message).for_operation("read-container-cgroup-stats")
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    use super::{
        cgroup2_mountpoint, cgroup_event_value, install_control_workload_descriptors_from_pre_exec,
        open_cgroup_procs, open_control_workload_membership,
    };

    #[test]
    fn roots_init_in_management_until_the_cgroup_namespace_exists() {
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir().expect("temporary cgroup topology");
        let management_file = directory.path().join("cgroup.procs");
        let control_path = directory.path().join("control");
        let workload_path = directory.path().join("workload");
        std::fs::create_dir(&control_path).expect("control directory");
        std::fs::create_dir(&workload_path).expect("workload directory");
        let control_file = control_path.join("cgroup.procs");
        let workload_file = workload_path.join("cgroup.procs");
        std::fs::write(&management_file, "").expect("management descriptor file");
        std::fs::write(&control_file, "").expect("control descriptor file");
        std::fs::write(&workload_file, "").expect("workload descriptor file");

        let membership =
            open_control_workload_membership(directory.path(), &control_path, &workload_path)
                .expect("control/workload membership");
        let inode = |file: &std::fs::File| file.metadata().expect("membership metadata").ino();
        assert_ne!(
            inode(&membership.init_procs),
            inode(&membership.control_procs)
        );
        assert_ne!(
            inode(&membership.init_procs),
            inode(&membership.workload_procs)
        );
    }

    #[test]
    fn installs_fixed_control_workload_descriptors_across_exec() {
        let directory = tempfile::tempdir().expect("temporary descriptor directory");
        let control_path = directory.path().join("control");
        let workload_path = directory.path().join("workload");
        std::fs::create_dir(&control_path).expect("control directory");
        std::fs::create_dir(&workload_path).expect("workload directory");
        std::fs::write(control_path.join("cgroup.procs"), "").expect("control descriptor file");
        std::fs::write(workload_path.join("cgroup.procs"), "").expect("workload descriptor file");
        let control = open_cgroup_procs(&control_path).expect("protected control descriptor");
        let workload = open_cgroup_procs(&workload_path).expect("protected workload descriptor");
        let control_descriptor = control.as_raw_fd();
        let workload_descriptor = workload.as_raw_fd();
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("printf control-v1 >&6 && printf workload-v1 >&7")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the child callback performs only bounded dup2/fcntl
        // operations over protected descriptors captured before fork.
        unsafe {
            command.pre_exec(move || {
                install_control_workload_descriptors_from_pre_exec(
                    control_descriptor,
                    workload_descriptor,
                )
            });
        }
        let status = command.status().expect("run descriptor child");
        assert!(status.success(), "descriptor child failed with {status}");
        assert_eq!(
            std::fs::read(control_path.join("cgroup.procs")).expect("read control descriptor"),
            b"control-v1"
        );
        assert_eq!(
            std::fs::read(workload_path.join("cgroup.procs")).expect("read workload descriptor"),
            b"workload-v1"
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
