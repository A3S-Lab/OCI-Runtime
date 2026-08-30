use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::LinuxIntelRdt;
use a3s_oci_sdk::{
    Error, ErrorCode, Result, OCI_LINUX_INTEL_RDT_MAX_CLOS_ID_BYTES,
    OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_BYTES, OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_LINES,
    OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_LINE_BYTES,
};

const RESCTRL_TASKS: &str = "tasks";
const RESCTRL_SCHEMATA: &str = "schemata";
const RESCTRL_MON_GROUPS: &str = "mon_groups";

/// Validated Intel RDT configuration retained by the runtime-namespace owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IntelRdtPlan {
    clos_id: Option<String>,
    schemata_writes: Vec<Vec<String>>,
    expected_schemata: BTreeMap<String, String>,
    monitoring: bool,
}

/// Owned resctrl paths that must survive native owner-death recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IntelRdtRecovery {
    pub(super) mountpoint: PathBuf,
    pub(super) control_group: PathBuf,
    pub(super) remove_control_group: bool,
    pub(super) monitoring_group: Option<PathBuf>,
}

/// Live Intel RDT ownership retained with the configured init process.
#[derive(Debug)]
pub(super) struct IntelRdtHandle(ResctrlHandle<KernelResctrlFilesystem>);

impl IntelRdtPlan {
    pub(super) fn from_oci(value: Option<&LinuxIntelRdt>) -> Result<Option<Self>> {
        let Some(value) = value else {
            return Ok(None);
        };
        let clos_id = value.clos_id().clone();
        if let Some(clos_id) = &clos_id {
            validate_clos_id(clos_id)?;
        }

        let mut schemata_writes = Vec::new();
        if let Some(schema) = value.l3_cache_schema().as_deref() {
            validate_schema_line("linux.intelRdt.l3CacheSchema", schema, Some("L3"))?;
            schemata_writes.push(vec![schema.to_string()]);
        }
        if let Some(schema) = value.mem_bw_schema().as_deref() {
            validate_schema_line("linux.intelRdt.memBwSchema", schema, Some("MB"))?;
            schemata_writes.push(vec![schema.to_string()]);
        }
        if let Some(lines) = value
            .schemata()
            .as_deref()
            .filter(|lines| !lines.is_empty())
        {
            if lines.len() > OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_LINES {
                return Err(plan_error(format!(
                    "linux.intelRdt.schemata contains {} lines; maximum is {}",
                    lines.len(),
                    OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_LINES
                )));
            }
            for (index, line) in lines.iter().enumerate() {
                validate_schema_line(&format!("linux.intelRdt.schemata[{index}]"), line, None)?;
            }
            schemata_writes.push(lines.to_vec());
        }

        let total_lines = schemata_writes.iter().map(Vec::len).sum::<usize>();
        if total_lines > OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_LINES {
            return Err(plan_error(format!(
                "linux.intelRdt contains {total_lines} schemata lines across all ordered writes; maximum is {OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_LINES}"
            )));
        }
        let total_bytes = schemata_writes
            .iter()
            .flatten()
            .try_fold(0_usize, |total, line| {
                total.checked_add(line.len().saturating_add(1))
            })
            .ok_or_else(|| plan_error("linux.intelRdt schemata size overflow"))?;
        if total_bytes > OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_BYTES {
            return Err(plan_error(format!(
                "linux.intelRdt schemata exceeds the {OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_BYTES}-byte limit"
            )));
        }

        let expected_schemata = effective_schemata(&schemata_writes);
        Ok(Some(Self {
            clos_id,
            schemata_writes,
            expected_schemata,
            monitoring: value.enable_monitoring().unwrap_or(false),
        }))
    }

    fn has_schemata(&self) -> bool {
        !self.schemata_writes.is_empty()
    }
}

impl IntelRdtHandle {
    pub(super) fn create(plan: Option<&IntelRdtPlan>, container_id: &str) -> Result<Option<Self>> {
        let Some(plan) = plan else {
            return Ok(None);
        };
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").map_err(|source| {
            rdt_error(
                error_code_for_io(&source),
                format!("failed to read resctrl mount topology: {source}"),
                "prepare-linux-intel-rdt",
            )
        })?;
        let mountpoint = resctrl_mountpoint(&mountinfo).ok_or_else(|| {
            rdt_error(
                ErrorCode::Unsupported,
                "linux.intelRdt requires a mounted resctrl pseudo-filesystem in the runtime mount namespace",
                "prepare-linux-intel-rdt",
            )
        })?;
        ResctrlHandle::create_at(plan, container_id, mountpoint, KernelResctrlFilesystem)
            .map(Self)
            .map(Some)
    }

    pub(super) fn assign(&mut self, pid: i32) -> Result<()> {
        self.0.assign(pid)
    }

    pub(super) fn cleanup(&mut self) -> Result<()> {
        self.0.cleanup()
    }

    pub(super) fn recovery(&self) -> Option<IntelRdtRecovery> {
        self.0.recovery()
    }
}

#[derive(Debug)]
struct ResctrlHandle<F: ResctrlFilesystem> {
    filesystem: F,
    mountpoint: PathBuf,
    control_group: PathBuf,
    remove_control_group: bool,
    monitoring_group: Option<PathBuf>,
    assigned_pid: Option<i32>,
    cleaned: bool,
}

impl<F: ResctrlFilesystem> ResctrlHandle<F> {
    fn create_at(
        plan: &IntelRdtPlan,
        container_id: &str,
        mountpoint: PathBuf,
        filesystem: F,
    ) -> Result<Self> {
        validate_container_id(container_id)?;
        ensure_absolute_normalized(&mountpoint, "resctrl mountpoint")?;
        ensure_real_directory(&mountpoint, "resctrl mountpoint")?;

        let (control_group, remove_control_group, created_control) = match plan.clos_id.as_deref() {
            None => {
                let control_group = mountpoint.join(container_id);
                filesystem
                    .create_control_group(&control_group)
                    .map_err(|source| {
                        rdt_io_error(
                            &source,
                            format!(
                                "failed to create runtime-owned resctrl CLOS {}: {source}",
                                control_group.display()
                            ),
                            "prepare-linux-intel-rdt",
                        )
                    })?;
                (control_group, true, true)
            }
            Some("/") => (mountpoint.clone(), false, false),
            Some(clos_id) => {
                let control_group = mountpoint.join(clos_id);
                match real_directory_exists(&control_group)? {
                    true => (control_group, false, false),
                    false if plan.has_schemata() => {
                        filesystem
                            .create_control_group(&control_group)
                            .map_err(|source| {
                                rdt_io_error(
                                    &source,
                                    format!(
                                        "failed to create configured resctrl CLOS {}: {source}",
                                        control_group.display()
                                    ),
                                    "prepare-linux-intel-rdt",
                                )
                            })?;
                        (control_group, false, true)
                    }
                    false => {
                        return Err(rdt_error(
                            ErrorCode::FailedPrecondition,
                            format!(
                                "preconfigured resctrl CLOS {} does not exist",
                                control_group.display()
                            ),
                            "prepare-linux-intel-rdt",
                        ));
                    }
                }
            }
        };

        let mut handle = Self {
            filesystem,
            mountpoint,
            control_group,
            remove_control_group,
            monitoring_group: None,
            assigned_pid: None,
            cleaned: false,
        };
        ensure_real_directory(&handle.control_group, "resctrl control group")?;
        handle
            .filesystem
            .read_tasks(&handle.control_group)
            .map_err(|source| {
                rdt_io_error(
                    &source,
                    format!(
                        "failed to inspect resctrl tasks in {}: {source}",
                        handle.control_group.display()
                    ),
                    "prepare-linux-intel-rdt",
                )
            })?;

        if plan.has_schemata() {
            if created_control {
                for lines in &plan.schemata_writes {
                    handle
                        .filesystem
                        .write_schemata(&handle.control_group, lines)
                        .map_err(|source| {
                            rdt_io_error(
                                &source,
                                format!(
                                    "failed to write resctrl schemata in {}: {source}",
                                    handle.control_group.display()
                                ),
                                "prepare-linux-intel-rdt",
                            )
                        })?;
                }
            }
            handle.verify_schemata(&plan.expected_schemata)?;
        }

        if plan.monitoring {
            let monitoring_parent = handle.control_group.join(RESCTRL_MON_GROUPS);
            ensure_real_directory(&monitoring_parent, "resctrl monitoring root")?;
            let monitoring_group = monitoring_parent.join(container_id);
            handle
                .filesystem
                .create_monitoring_group(&monitoring_group)
                .map_err(|source| {
                    rdt_io_error(
                        &source,
                        format!(
                            "failed to create dedicated resctrl monitoring group {}: {source}",
                            monitoring_group.display()
                        ),
                        "prepare-linux-intel-rdt",
                    )
                })?;
            handle.monitoring_group = Some(monitoring_group.clone());
            ensure_real_directory(&monitoring_group, "resctrl monitoring group")?;
            handle
                .filesystem
                .read_tasks(&monitoring_group)
                .map_err(|source| {
                    rdt_io_error(
                        &source,
                        format!(
                            "failed to inspect resctrl monitoring tasks in {}: {source}",
                            monitoring_group.display()
                        ),
                        "prepare-linux-intel-rdt",
                    )
                })?;
        }
        Ok(handle)
    }

    fn verify_schemata(&self, expected: &BTreeMap<String, String>) -> Result<()> {
        let actual = self
            .filesystem
            .read_schemata(&self.control_group)
            .map_err(|source| {
                rdt_io_error(
                    &source,
                    format!(
                        "failed to read back resctrl schemata in {}: {source}",
                        self.control_group.display()
                    ),
                    "prepare-linux-intel-rdt",
                )
            })?;
        let actual = schema_map(actual.lines());
        for (resource, expected_line) in expected {
            if actual.get(resource) != Some(expected_line) {
                return Err(rdt_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "resctrl schemata mismatch for resource {resource:?} in {}: requested {expected_line:?}, observed {:?}",
                        self.control_group.display(),
                        actual.get(resource)
                    ),
                    "prepare-linux-intel-rdt",
                ));
            }
        }
        Ok(())
    }

    fn assign(&mut self, pid: i32) -> Result<()> {
        if pid <= 0 {
            return Err(rdt_error(
                ErrorCode::InvalidArgument,
                format!("resctrl assignment requires a positive process ID, received {pid}"),
                "assign-linux-intel-rdt",
            ));
        }
        if self.assigned_pid.is_some_and(|assigned| assigned != pid) {
            return Err(rdt_error(
                ErrorCode::Conflict,
                format!(
                    "resctrl handle is already assigned to process {:?}, not {pid}",
                    self.assigned_pid
                ),
                "assign-linux-intel-rdt",
            ));
        }
        self.assign_to(&self.control_group, pid, "control")?;
        if let Some(monitoring_group) = &self.monitoring_group {
            self.assign_to(monitoring_group, pid, "monitoring")?;
        }
        self.assigned_pid = Some(pid);
        Ok(())
    }

    fn assign_to(&self, group: &Path, pid: i32, role: &str) -> Result<()> {
        self.filesystem.write_task(group, pid).map_err(|source| {
            rdt_io_error(
                &source,
                format!(
                    "failed to assign process {pid} to resctrl {role} group {}: {source}",
                    group.display()
                ),
                "assign-linux-intel-rdt",
            )
        })?;
        let tasks = self.filesystem.read_tasks(group).map_err(|source| {
            rdt_io_error(
                &source,
                format!(
                    "failed to read back resctrl {role} tasks in {}: {source}",
                    group.display()
                ),
                "assign-linux-intel-rdt",
            )
        })?;
        if !task_list_contains(&tasks, pid) {
            return Err(rdt_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "resctrl {role} group {} did not retain process {pid}",
                    group.display()
                ),
                "assign-linux-intel-rdt",
            ));
        }
        Ok(())
    }

    fn recovery(&self) -> Option<IntelRdtRecovery> {
        (self.remove_control_group || self.monitoring_group.is_some()).then(|| IntelRdtRecovery {
            mountpoint: self.mountpoint.clone(),
            control_group: self.control_group.clone(),
            remove_control_group: self.remove_control_group,
            monitoring_group: self.monitoring_group.clone(),
        })
    }

    fn cleanup(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }
        if let Some(monitoring_group) = &self.monitoring_group {
            match self.filesystem.remove_monitoring_group(monitoring_group) {
                Ok(()) => self.monitoring_group = None,
                Err(source) if source.kind() == io::ErrorKind::NotFound => {
                    self.monitoring_group = None;
                }
                Err(source) => {
                    return Err(rdt_io_error(
                        &source,
                        format!(
                            "failed to remove resctrl monitoring group {}: {source}",
                            monitoring_group.display()
                        ),
                        "cleanup-linux-intel-rdt",
                    ));
                }
            }
        }
        if self.remove_control_group {
            match self.filesystem.remove_control_group(&self.control_group) {
                Ok(()) => self.remove_control_group = false,
                Err(source) if source.kind() == io::ErrorKind::NotFound => {
                    self.remove_control_group = false;
                }
                Err(source) => {
                    return Err(rdt_io_error(
                        &source,
                        format!(
                            "failed to remove runtime-owned resctrl CLOS {}: {source}",
                            self.control_group.display()
                        ),
                        "cleanup-linux-intel-rdt",
                    ));
                }
            }
        }
        self.cleaned = true;
        Ok(())
    }
}

impl<F: ResctrlFilesystem> Drop for ResctrlHandle<F> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

trait ResctrlFilesystem: std::fmt::Debug {
    fn create_control_group(&self, path: &Path) -> io::Result<()>;
    fn create_monitoring_group(&self, path: &Path) -> io::Result<()>;
    fn write_schemata(&self, group: &Path, lines: &[String]) -> io::Result<()>;
    fn read_schemata(&self, group: &Path) -> io::Result<String>;
    fn write_task(&self, group: &Path, pid: i32) -> io::Result<()>;
    fn read_tasks(&self, group: &Path) -> io::Result<String>;
    fn remove_monitoring_group(&self, path: &Path) -> io::Result<()>;
    fn remove_control_group(&self, path: &Path) -> io::Result<()>;
}

#[derive(Debug)]
struct KernelResctrlFilesystem;

impl ResctrlFilesystem for KernelResctrlFilesystem {
    fn create_control_group(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir(path)
    }

    fn create_monitoring_group(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir(path)
    }

    fn write_schemata(&self, group: &Path, lines: &[String]) -> io::Result<()> {
        write_nofollow(&group.join(RESCTRL_SCHEMATA), &encoded_lines(lines))
    }

    fn read_schemata(&self, group: &Path) -> io::Result<String> {
        read_nofollow(&group.join(RESCTRL_SCHEMATA))
    }

    fn write_task(&self, group: &Path, pid: i32) -> io::Result<()> {
        write_nofollow(&group.join(RESCTRL_TASKS), format!("{pid}\n").as_bytes())
    }

    fn read_tasks(&self, group: &Path) -> io::Result<String> {
        read_nofollow(&group.join(RESCTRL_TASKS))
    }

    fn remove_monitoring_group(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_dir(path)
    }

    fn remove_control_group(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_dir(path)
    }
}

fn write_nofollow(path: &Path, value: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    file.write_all(value)
}

fn read_nofollow(path: &Path) -> io::Result<String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    let mut value = String::new();
    file.read_to_string(&mut value)?;
    Ok(value)
}

fn encoded_lines(lines: &[String]) -> Vec<u8> {
    let mut value = lines.join("\n").into_bytes();
    value.push(b'\n');
    value
}

fn effective_schemata(writes: &[Vec<String>]) -> BTreeMap<String, String> {
    schema_map(writes.iter().flatten().map(String::as_str))
}

fn schema_map<'a>(lines: impl IntoIterator<Item = &'a str>) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in lines
        .into_iter()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        values.insert(schema_key(line).to_string(), line.to_string());
    }
    values
}

fn schema_key(line: &str) -> &str {
    line.split_once(':')
        .map(|(resource, _)| resource)
        .filter(|resource| !resource.is_empty())
        .unwrap_or(line)
}

fn task_list_contains(tasks: &str, pid: i32) -> bool {
    tasks
        .split_ascii_whitespace()
        .any(|candidate| candidate.parse::<i32>() == Ok(pid))
}

fn validate_clos_id(clos_id: &str) -> Result<()> {
    if clos_id == "/" {
        return Ok(());
    }
    if clos_id.is_empty()
        || clos_id.len() > OCI_LINUX_INTEL_RDT_MAX_CLOS_ID_BYTES
        || matches!(clos_id, "." | "..")
        || clos_id.contains('/')
        || clos_id.as_bytes().contains(&0)
    {
        return Err(plan_error(format!(
            "linux.intelRdt.closID must be / or a nonempty safe resctrl directory name of at most {OCI_LINUX_INTEL_RDT_MAX_CLOS_ID_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_container_id(container_id: &str) -> Result<()> {
    if container_id.is_empty()
        || container_id.len() > OCI_LINUX_INTEL_RDT_MAX_CLOS_ID_BYTES
        || matches!(container_id, "." | "..")
        || container_id.contains('/')
        || container_id.as_bytes().contains(&0)
    {
        return Err(rdt_error(
            ErrorCode::InvalidArgument,
            "container ID cannot be used as a safe resctrl group name",
            "prepare-linux-intel-rdt",
        ));
    }
    Ok(())
}

fn validate_schema_line(field: &str, line: &str, prefix: Option<&str>) -> Result<()> {
    if line.is_empty()
        || line.len() > OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_LINE_BYTES
        || line.as_bytes().contains(&0)
        || line.contains('\r')
        || line.contains('\n')
    {
        return Err(plan_error(format!(
            "{field} must be one nonempty resctrl schemata line of at most {OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_LINE_BYTES} bytes"
        )));
    }
    if prefix.is_some_and(|prefix| !line.starts_with(&format!("{prefix}:"))) {
        return Err(plan_error(format!("{field} must start with {prefix:?}:")));
    }
    Ok(())
}

fn resctrl_mountpoint(mountinfo: &str) -> Option<PathBuf> {
    mountinfo.lines().find_map(resctrl_mountpoint_from_line)
}

pub(super) fn is_resctrl_mountpoint(mountinfo: &str, expected: &Path) -> bool {
    mountinfo
        .lines()
        .filter_map(resctrl_mountpoint_from_line)
        .any(|mountpoint| mountpoint == expected)
}

fn resctrl_mountpoint_from_line(line: &str) -> Option<PathBuf> {
    let (left, right) = line.split_once(" - ")?;
    if right.split_ascii_whitespace().next()? != "resctrl" {
        return None;
    }
    let mountpoint = left.split_ascii_whitespace().nth(4)?;
    (mountpoint.starts_with('/') && !mountpoint.contains('\\')).then(|| PathBuf::from(mountpoint))
}

fn ensure_absolute_normalized(path: &Path, role: &str) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(rdt_error(
            ErrorCode::PermissionDenied,
            format!(
                "{role} is not an absolute normalized path: {}",
                path.display()
            ),
            "prepare-linux-intel-rdt",
        ));
    }
    Ok(())
}

fn real_directory_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(rdt_error(
            ErrorCode::PermissionDenied,
            format!("resctrl path is not a real directory: {}", path.display()),
            "prepare-linux-intel-rdt",
        )),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(rdt_io_error(
            &source,
            format!(
                "failed to inspect resctrl path {}: {source}",
                path.display()
            ),
            "prepare-linux-intel-rdt",
        )),
    }
}

fn ensure_real_directory(path: &Path, role: &str) -> Result<()> {
    if real_directory_exists(path)? {
        Ok(())
    } else {
        Err(rdt_error(
            ErrorCode::FailedPrecondition,
            format!("{role} does not exist: {}", path.display()),
            "prepare-linux-intel-rdt",
        ))
    }
}

fn error_code_for_io(source: &io::Error) -> ErrorCode {
    match source.kind() {
        io::ErrorKind::AlreadyExists => ErrorCode::Conflict,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => ErrorCode::InvalidArgument,
        io::ErrorKind::NotFound => ErrorCode::FailedPrecondition,
        io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        io::ErrorKind::OutOfMemory | io::ErrorKind::StorageFull => ErrorCode::ResourceExhausted,
        _ => ErrorCode::FailedPrecondition,
    }
}

fn rdt_io_error(source: &io::Error, message: impl Into<String>, operation: &str) -> Error {
    rdt_error(error_code_for_io(source), message, operation)
}

fn plan_error(message: impl Into<String>) -> Error {
    rdt_error(ErrorCode::InvalidArgument, message, "plan-linux-intel-rdt")
}

fn rdt_error(code: ErrorCode, message: impl Into<String>, operation: &str) -> Error {
    Error::new(code, message).for_operation(operation)
}

#[cfg(test)]
#[path = "intel_rdt_test_support.rs"]
mod test_support;

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::oci_spec::runtime::LinuxIntelRdt;

    use super::test_support::Fixture;
    use super::{
        effective_schemata, resctrl_mountpoint, IntelRdtHandle, IntelRdtPlan, ResctrlHandle,
        RESCTRL_MON_GROUPS, RESCTRL_SCHEMATA, RESCTRL_TASKS,
    };

    fn plan(value: serde_json::Value) -> IntelRdtPlan {
        let value: LinuxIntelRdt = serde_json::from_value(value).expect("decode Intel RDT");
        IntelRdtPlan::from_oci(Some(&value))
            .expect("plan Intel RDT")
            .expect("present plan")
    }

    #[test]
    fn plans_ordered_schemata_monitoring_and_omission() {
        let plan = plan(serde_json::json!({
            "l3CacheSchema": "L3:0=ff",
            "memBwSchema": "MB:0=20",
            "schemata": ["L2:0=f", "MB:0=70"],
            "enableMonitoring": true
        }));
        assert_eq!(
            plan.schemata_writes,
            [
                vec!["L3:0=ff".to_string()],
                vec!["MB:0=20".to_string()],
                vec!["L2:0=f".to_string(), "MB:0=70".to_string()]
            ]
        );
        assert_eq!(
            plan.expected_schemata,
            effective_schemata(&plan.schemata_writes)
        );
        assert!(plan.monitoring);
        assert!(IntelRdtPlan::from_oci(None)
            .expect("omitted Intel RDT")
            .is_none());
    }

    #[test]
    fn omitted_plan_does_not_inspect_resctrl_or_validate_a_group_name() {
        assert!(IntelRdtHandle::create(None, "../unused")
            .expect("omitted Intel RDT is a no-op")
            .is_none());
    }

    #[test]
    fn rejects_unsafe_names_unbounded_or_multiline_schemata() {
        for value in [
            serde_json::json!({"closID": ""}),
            serde_json::json!({"closID": "../escape"}),
            serde_json::json!({"l3CacheSchema": "MB:0=20"}),
            serde_json::json!({"memBwSchema": "L3:0=ff"}),
            serde_json::json!({"schemata": ["L3:0=ff\nMB:0=20"]}),
        ] {
            let value: LinuxIntelRdt =
                serde_json::from_value(value).expect("decode invalid Intel RDT shape");
            assert!(IntelRdtPlan::from_oci(Some(&value)).is_err());
        }
        let value: LinuxIntelRdt = serde_json::from_value(serde_json::json!({
            "l3CacheSchema": "L3:0=ff",
            "memBwSchema": "MB:0=20",
            "schemata": vec!["L2:0=f"; 255]
        }))
        .expect("decode over-limit Intel RDT shape");
        assert!(IntelRdtPlan::from_oci(Some(&value)).is_err());
    }

    #[test]
    fn creates_assigns_and_cleans_runtime_owned_groups_in_normative_order() {
        let fixture = Fixture::new();
        let plan = plan(serde_json::json!({
            "l3CacheSchema": "L3:0=ff",
            "memBwSchema": "MB:0=20",
            "schemata": ["MB:0=70"],
            "enableMonitoring": true
        }));
        let mut handle = ResctrlHandle::create_at(
            &plan,
            "container-a",
            fixture.root.clone(),
            fixture.filesystem.clone(),
        )
        .expect("create resctrl groups");
        let control = fixture.root.join("container-a");
        let monitoring = control.join(RESCTRL_MON_GROUPS).join("container-a");
        assert_eq!(
            std::fs::read_to_string(control.join(RESCTRL_SCHEMATA)).expect("read schemata"),
            "L3:0=ff\nMB:0=70\n"
        );

        handle.assign(42_001).expect("assign init process");
        assert_eq!(
            std::fs::read_to_string(control.join(RESCTRL_TASKS)).expect("control tasks"),
            "42001\n"
        );
        assert_eq!(
            std::fs::read_to_string(monitoring.join(RESCTRL_TASKS)).expect("monitor tasks"),
            "42001\n"
        );
        let recovery = handle.recovery().expect("owned recovery paths");
        assert!(recovery.remove_control_group);
        assert_eq!(
            recovery.monitoring_group.as_deref(),
            Some(monitoring.as_path())
        );

        handle.cleanup().expect("clean resctrl groups");
        handle.cleanup().expect("repeat cleanup");
        assert!(!control.exists());
        let operations = fixture.filesystem.operations();
        assert!(operations.windows(3).any(|window| window
            == [
                "write-schemata:L3:0=ff",
                "write-schemata:MB:0=20",
                "write-schemata:MB:0=70"
            ]));
        assert!(
            operations
                .iter()
                .position(|operation| operation.starts_with("remove-monitor:"))
                .expect("monitor removal")
                < operations
                    .iter()
                    .position(|operation| operation.starts_with("remove-control:"))
                    .expect("control removal")
        );
    }

    #[test]
    fn preconfigured_clos_is_compared_and_never_removed() {
        let fixture = Fixture::new();
        let control = fixture.preconfigured("shared", "L3:0=ff\nMB:0=20\n");
        let matching_plan = plan(serde_json::json!({
            "closID": "shared",
            "l3CacheSchema": "L3:0=ff",
            "memBwSchema": "MB:0=20"
        }));
        let mut handle = ResctrlHandle::create_at(
            &matching_plan,
            "container-b",
            fixture.root.clone(),
            fixture.filesystem.clone(),
        )
        .expect("open matching preconfigured CLOS");
        assert!(handle.recovery().is_none());
        handle.assign(42_002).expect("assign shared CLOS");
        handle.cleanup().expect("cleanup external CLOS handle");
        assert!(control.exists());
        assert!(!fixture
            .filesystem
            .operations()
            .iter()
            .any(|operation| operation.starts_with("write-schemata:")));

        let mismatch = plan(serde_json::json!({
            "closID": "shared",
            "l3CacheSchema": "L3:0=0f"
        }));
        assert!(ResctrlHandle::create_at(
            &mismatch,
            "container-c",
            fixture.root.clone(),
            fixture.filesystem.clone(),
        )
        .is_err());
        assert_eq!(
            std::fs::read_to_string(control.join(RESCTRL_SCHEMATA)).expect("unchanged schemata"),
            "L3:0=ff\nMB:0=20\n"
        );
    }

    #[test]
    fn configured_clos_without_schemata_must_already_exist() {
        let fixture = Fixture::new();
        let plan = plan(serde_json::json!({"closID": "missing"}));
        let error = ResctrlHandle::create_at(
            &plan,
            "container-d",
            fixture.root.clone(),
            fixture.filesystem.clone(),
        )
        .expect_err("missing preconfigured CLOS must fail");
        assert_eq!(error.code, a3s_oci_sdk::ErrorCode::FailedPrecondition);
        assert!(!fixture.root.join("missing").exists());
    }

    #[test]
    fn default_and_explicit_clos_preserve_external_ownership() {
        let fixture = Fixture::new();
        let root_plan = plan(serde_json::json!({"closID": "/"}));
        let mut root = ResctrlHandle::create_at(
            &root_plan,
            "container-root",
            fixture.root.clone(),
            fixture.filesystem.clone(),
        )
        .expect("open default CLOS");
        root.assign(42_003).expect("assign default CLOS");
        root.cleanup().expect("release default CLOS");
        assert!(fixture.root.exists());
        assert!(root.recovery().is_none());

        let explicit_plan = plan(serde_json::json!({
            "closID": "retained",
            "schemata": ["L2:0=f"]
        }));
        let mut explicit = ResctrlHandle::create_at(
            &explicit_plan,
            "container-explicit",
            fixture.root.clone(),
            fixture.filesystem.clone(),
        )
        .expect("create explicit CLOS");
        let explicit_path = fixture.root.join("retained");
        assert!(explicit_path.exists());
        assert!(explicit.recovery().is_none());
        explicit.cleanup().expect("release explicit CLOS");
        assert!(explicit_path.exists());

        let operations = fixture.filesystem.operations();
        assert_eq!(
            operations
                .iter()
                .filter(|operation| operation.starts_with("write-schemata:"))
                .count(),
            1,
            "the default CLOS must not receive a schemata write"
        );
        assert!(!operations
            .iter()
            .any(|operation| operation.starts_with("remove-control:")));
    }

    #[test]
    fn monitoring_creation_failure_is_reported_and_rolls_back_owned_clos() {
        let fixture = Fixture::new();
        fixture.filesystem.reject_next_monitoring_group();
        let plan = plan(serde_json::json!({"enableMonitoring": true}));
        let error = ResctrlHandle::create_at(
            &plan,
            "container-monitor-failure",
            fixture.root.clone(),
            fixture.filesystem.clone(),
        )
        .expect_err("monitoring group failure must propagate");
        assert_eq!(error.code, a3s_oci_sdk::ErrorCode::FailedPrecondition);
        assert!(!fixture.root.join("container-monitor-failure").exists());
    }

    #[test]
    fn parses_only_unescaped_resctrl_mounts() {
        let mountinfo = "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n\
                         30 23 0:27 / /sys/fs/resctrl rw - resctrl resctrl rw\n";
        assert_eq!(
            resctrl_mountpoint(mountinfo).as_deref(),
            Some(std::path::Path::new("/sys/fs/resctrl"))
        );
        assert!(super::is_resctrl_mountpoint(
            mountinfo,
            std::path::Path::new("/sys/fs/resctrl")
        ));
        assert!(!super::is_resctrl_mountpoint(
            mountinfo,
            std::path::Path::new("/tmp/not-resctrl")
        ));
        assert!(resctrl_mountpoint(
            "30 23 0:27 / /sys/fs/resctrl\\040bad rw - resctrl resctrl rw\n"
        )
        .is_none());
        assert!(
            resctrl_mountpoint("29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n").is_none()
        );
    }
}
