use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{
    Error, ErrorCode, IoMode, OciBundle, ProcessIo, Result, CONTROL_CGROUP_PROCS_FD,
    CONTROL_CGROUP_PROCS_FD_ENV, WORKLOAD_CGROUP_PROCS_FD, WORKLOAD_CGROUP_PROCS_FD_ENV,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::capability::CapabilityPlan;
use super::cgroup::{CgroupOwnershipPlan, CgroupPlan};
use super::cpu_affinity::CpuAffinityPlan;
use super::device::DevicePlan;
use super::hook::HookSet;
use super::intel_rdt::IntelRdtPlan;
use super::io_priority::IoPriorityPlan;
use super::linux_support;
use super::memory_policy::MemoryPolicyPlan;
use super::mount::{self, DefaultFilesystemPlan, MountPlan};
use super::namespace::NamespacePlan;
use super::network_device::NetworkDevicePlan;
use super::personality::PersonalityPlan;
use super::rlimit::RlimitPlan;
use super::rootfs::RootfsPropagation;
use super::scheduler::SchedulerPlan;
use super::seccomp::SeccompPlan;
use super::sysctl::SysctlPlan;

const MAX_ARGUMENTS: usize = 4_096;
const MAX_ENVIRONMENT_ENTRIES: usize = 4_096;
const MAX_EXEC_BYTES: usize = 1024 * 1024;
const MAX_RESTRICTED_PATHS: usize = 4_096;
const MAX_ANNOTATIONS: usize = 1_024;
const LINUX_UTS_NAME_MAX: usize = 64;

/// Validated process fields shared by configured init and exec launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProcessPlan {
    pub(super) args: Vec<String>,
    pub(super) environment: Vec<String>,
    pub(super) cwd: String,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) additional_gids: Vec<u32>,
    pub(super) umask: Option<u32>,
    #[serde(default)]
    pub(super) oom_score_adj: Option<i32>,
    #[serde(default)]
    pub(super) io_priority: Option<IoPriorityPlan>,
    #[serde(default)]
    pub(super) scheduler: Option<SchedulerPlan>,
    #[serde(default)]
    pub(super) exec_cpu_affinity: Option<CpuAffinityPlan>,
    pub(super) no_new_privileges: bool,
    pub(super) terminal: bool,
    pub(super) rlimits: RlimitPlan,
    pub(super) capabilities: CapabilityPlan,
    pub(super) seccomp: SeccompPlan,
}

impl ProcessPlan {
    pub(super) fn from_init_process(process: &Process, io: &ProcessIo) -> Result<Self> {
        Self::build(process, io, false)
    }

    pub(super) fn from_exec_process(process: &Process, io: &ProcessIo) -> Result<Self> {
        Self::build(process, io, true)
    }

    fn without_init_process(io: &ProcessIo) -> Result<Self> {
        validate_process_io(io, false)?;
        Ok(Self {
            args: Vec::new(),
            environment: Vec::new(),
            cwd: "/".to_string(),
            uid: 0,
            gid: 0,
            additional_gids: Vec::new(),
            umask: None,
            oom_score_adj: None,
            io_priority: None,
            scheduler: None,
            exec_cpu_affinity: None,
            no_new_privileges: false,
            terminal: false,
            rlimits: RlimitPlan::default(),
            capabilities: CapabilityPlan::default(),
            seccomp: SeccompPlan::default(),
        })
    }

    fn build(process: &Process, io: &ProcessIo, include_exec_affinity: bool) -> Result<Self> {
        linux_support::shared()?.validate_process(process, "plan-guest-init")?;
        let terminal = process.terminal().unwrap_or(false);
        let resolved_io = io.resolve_for_process(process)?;
        validate_process_io(&resolved_io, terminal)?;
        validate_process_profile(process)?;

        let args = process
            .args()
            .as_ref()
            .filter(|args| !args.is_empty())
            .ok_or_else(|| invalid("process.args must contain an executable"))?
            .clone();
        validate_string_vector("process.args", &args, MAX_ARGUMENTS)?;
        if args[0].is_empty() {
            return Err(invalid("process.args[0] must not be empty"));
        }

        let environment = process.env().as_ref().cloned().unwrap_or_default();
        validate_environment(&environment)?;
        let cwd = linux_path(process.cwd(), "process.cwd", true)?;

        let user = process.user();
        if user.username().is_some() {
            return Err(unsupported(
                "process.user.username",
                "username lookup is not implemented",
            ));
        }
        let additional_gids = user.additional_gids().as_ref().cloned().unwrap_or_default();
        if user.umask().is_some_and(|umask| umask > 0o777) {
            return Err(invalid(
                "process.user.umask must fit the POSIX permission mask",
            ));
        }
        let capabilities = CapabilityPlan::from_oci(process.capabilities().as_ref())?;
        let rlimits = RlimitPlan::from_oci(process.rlimits().as_deref())?;
        let io_priority = IoPriorityPlan::from_oci(process.io_priority().as_ref())?;
        let scheduler = SchedulerPlan::from_oci(process.scheduler().as_ref())?;
        let exec_cpu_affinity = if include_exec_affinity {
            CpuAffinityPlan::from_oci(process.exec_cpu_affinity().as_ref())?
        } else {
            None
        };

        Ok(Self {
            args,
            environment,
            cwd,
            uid: user.uid(),
            gid: user.gid(),
            additional_gids,
            umask: user.umask(),
            oom_score_adj: process.oom_score_adj(),
            io_priority,
            scheduler,
            exec_cpu_affinity,
            no_new_privileges: process.no_new_privileges().unwrap_or(false),
            terminal,
            rlimits,
            capabilities,
            seccomp: SeccompPlan::default(),
        })
    }

    pub(super) fn attach_seccomp(&mut self, seccomp: &SeccompPlan) {
        self.seccomp = seccomp.clone();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InitPlan {
    pub(super) oci_version: String,
    pub(super) bundle_directory: PathBuf,
    pub(super) rootfs: PathBuf,
    pub(super) has_process: bool,
    pub(super) args: Vec<String>,
    pub(super) environment: Vec<String>,
    pub(super) cwd: String,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) additional_gids: Vec<u32>,
    pub(super) umask: Option<u32>,
    pub(super) oom_score_adj: Option<i32>,
    pub(super) io_priority: Option<IoPriorityPlan>,
    pub(super) scheduler: Option<SchedulerPlan>,
    pub(super) personality: Option<PersonalityPlan>,
    pub(super) memory_policy: Option<MemoryPolicyPlan>,
    pub(super) no_new_privileges: bool,
    pub(super) terminal: bool,
    pub(super) rlimits: RlimitPlan,
    pub(super) capabilities: CapabilityPlan,
    pub(super) seccomp: SeccompPlan,
    pub(super) cgroup: CgroupPlan,
    pub(super) cgroup_ownership: CgroupOwnershipPlan,
    pub(super) intel_rdt: Option<IntelRdtPlan>,
    pub(super) devices: DevicePlan,
    pub(super) network_devices: NetworkDevicePlan,
    pub(super) namespaces: NamespacePlan,
    pub(super) sysctls: SysctlPlan,
    pub(super) mounts: Vec<MountPlan>,
    pub(super) default_filesystems: DefaultFilesystemPlan,
    pub(super) root_readonly: bool,
    pub(super) rootfs_propagation: Option<RootfsPropagation>,
    pub(super) masked_paths: Vec<PathBuf>,
    pub(super) readonly_paths: Vec<PathBuf>,
    pub(super) hostname: Option<String>,
    pub(super) domainname: Option<String>,
    pub(super) annotations: BTreeMap<String, String>,
    pub(super) hooks: HookSet,
}

impl InitPlan {
    pub(super) fn from_bundle(bundle: &OciBundle, io: &ProcessIo) -> Result<Self> {
        let spec = bundle.spec();
        linux_support::shared()?.validate_spec(spec, "plan-guest-init")?;
        let projection = serde_json::to_value(spec).map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("validated OCI configuration could not be projected: {error}"),
            )
            .for_operation("plan-guest-init")
        })?;
        validate_profile(&projection)?;

        let root = spec.root().as_ref().ok_or_else(|| {
            invalid("OCI bootstrap executor requires a root filesystem configuration")
        })?;
        let root_path = resolve_rootfs_path(bundle.directory(), root.path())?;
        let root_readonly = root.readonly().unwrap_or(false);

        let (has_process, mut process_plan) = match spec.process().as_ref() {
            Some(process) => (true, ProcessPlan::from_init_process(process, io)?),
            None => (false, ProcessPlan::without_init_process(io)?),
        };
        let annotations = plan_annotations(spec.annotations().as_ref())?;
        let namespaces = NamespacePlan::from_linux(
            spec.linux().as_ref(),
            process_plan.uid,
            process_plan.gid,
            &process_plan.additional_gids,
        )?;
        let hostname = spec
            .hostname()
            .as_deref()
            .map(|value| validate_uts_name("hostname", value))
            .transpose()?;
        let domainname = spec
            .domainname()
            .as_deref()
            .map(|value| validate_uts_name("domainname", value))
            .transpose()?;
        if (hostname.is_some() || domainname.is_some()) && !namespaces.has_uts() {
            return Err(unsupported(
                "hostname/domainname",
                "the bootstrap executor changes UTS names only in a configured UTS namespace",
            ));
        }
        let sysctls =
            SysctlPlan::from_linux(spec.linux().as_ref(), &namespaces, domainname.as_deref())?;
        let network_devices = NetworkDevicePlan::from_linux(spec.linux().as_ref(), &namespaces)?;
        super::portable_rootfs_metadata::validate_plan(
            &annotations,
            root.path().is_absolute(),
            namespaces.new_mount(),
            namespaces.new_user(),
        )?;
        let cgroup = CgroupPlan::from_linux(spec.linux().as_ref(), &annotations)?;
        let intel_rdt = IntelRdtPlan::from_oci(
            spec.linux()
                .as_ref()
                .and_then(|linux| linux.intel_rdt().as_ref()),
        )?;
        if cgroup.uses_control_workload_layout() {
            if !namespaces.new_cgroup() {
                return Err(invalid(
                    "control/workload cgroup layout requires a newly created Linux cgroup namespace",
                ));
            }
            inject_control_workload_environment(&mut process_plan.environment)?;
        }
        let seccomp = SeccompPlan::from_linux(spec.linux().as_ref())?;
        let personality = PersonalityPlan::from_oci(
            spec.linux()
                .as_ref()
                .and_then(|linux| linux.personality().as_ref()),
        )?;
        let memory_policy = MemoryPolicyPlan::from_oci(
            spec.linux()
                .as_ref()
                .and_then(|linux| linux.memory_policy().as_ref()),
        )?;
        let rootfs_propagation = spec
            .linux()
            .as_ref()
            .and_then(|linux| linux.rootfs_propagation().as_deref())
            .map(RootfsPropagation::parse)
            .transpose()?;
        let masked_paths = plan_restricted_paths(
            spec.linux()
                .as_ref()
                .and_then(|linux| linux.masked_paths().as_deref()),
            "linux.maskedPaths",
        )?;
        if masked_paths.iter().any(|path| path == Path::new("/")) {
            return Err(invalid(
                "linux.maskedPaths must not replace the container root",
            ));
        }
        let readonly_paths = plan_restricted_paths(
            spec.linux()
                .as_ref()
                .and_then(|linux| linux.readonly_paths().as_deref()),
            "linux.readonlyPaths",
        )?;
        let mut mounts = mount::plan_all(spec.mounts().as_deref(), &namespaces)?;
        mount::mark_ordered_bind_sources(&mut mounts, bundle.directory(), &root_path);
        let sysfs_mount_allowed = !namespaces.has_user() || namespaces.new_network();
        let default_filesystems = DefaultFilesystemPlan::from_configured(
            &mounts,
            namespaces.new_mount(),
            sysfs_mount_allowed,
            default_devpts_gid(&namespaces, process_plan.gid),
        );
        let cgroup_ownership = CgroupOwnershipPlan::from_mounts(&mounts, &namespaces);
        if cgroup.uses_control_workload_layout() {
            mount::validate_control_workload_cgroup_mount(&mounts)?;
        }
        let prepare_device_mounts = namespaces.new_mount()
            || (namespaces.joined_mount().is_some() && !process_plan.terminal);
        let devices = DevicePlan::from_linux(
            spec.linux().as_ref(),
            &mounts,
            process_plan.terminal,
            prepare_device_mounts,
        )?;
        if !mounts.is_empty() && !namespaces.new_mount() {
            return Err(unsupported(
                "mounts",
                "the bootstrap executor applies mounts only in a newly created mount namespace",
            ));
        }
        if devices.has_node_setup()
            && !namespaces.new_mount()
            && namespaces.joined_mount().is_none()
        {
            return Err(unsupported(
                "linux.devices",
                "device creation requires a newly created mount namespace",
            ));
        }
        if (root_readonly
            || rootfs_propagation.is_some()
            || !masked_paths.is_empty()
            || !readonly_paths.is_empty())
            && !namespaces.new_mount()
        {
            return Err(unsupported(
                "rootfs mount controls",
                "rootfs propagation, path restrictions, and read-only enforcement require a newly created mount namespace",
            ));
        }
        let hooks = HookSet::from_oci(spec.hooks().as_ref())?;

        Ok(Self {
            oci_version: spec.version().clone(),
            bundle_directory: bundle.directory().to_path_buf(),
            rootfs: root_path,
            has_process,
            args: process_plan.args,
            environment: process_plan.environment,
            cwd: process_plan.cwd,
            uid: process_plan.uid,
            gid: process_plan.gid,
            additional_gids: process_plan.additional_gids,
            umask: process_plan.umask,
            oom_score_adj: process_plan.oom_score_adj,
            io_priority: process_plan.io_priority,
            scheduler: process_plan.scheduler,
            personality,
            memory_policy,
            no_new_privileges: process_plan.no_new_privileges,
            terminal: process_plan.terminal,
            rlimits: process_plan.rlimits,
            capabilities: process_plan.capabilities,
            seccomp,
            cgroup,
            cgroup_ownership,
            intel_rdt,
            devices,
            network_devices,
            namespaces,
            sysctls,
            mounts,
            default_filesystems,
            root_readonly,
            rootfs_propagation,
            masked_paths,
            readonly_paths,
            hostname,
            domainname,
            annotations,
            hooks,
        })
    }

    pub(super) fn resolve_cgroup_ownership(
        &mut self,
        rootless_effective_uid: Option<u32>,
    ) -> Result<()> {
        self.resolve_joined_user_namespace()?;
        if !self.cgroup_ownership.requested() {
            return Ok(());
        }
        self.cgroup_ownership
            .resolve(self.uid, &self.namespaces, rootless_effective_uid)
    }

    pub(super) fn resolve_joined_user_namespace(&mut self) -> Result<()> {
        self.namespaces
            .resolve_joined_user_mappings(self.uid, self.gid, &self.additional_gids)?;
        let sysfs_mount_allowed = !self.namespaces.has_user() || self.namespaces.new_network();
        self.default_filesystems = DefaultFilesystemPlan::from_configured(
            &self.mounts,
            self.namespaces.new_mount(),
            sysfs_mount_allowed,
            default_devpts_gid(&self.namespaces, self.gid),
        );
        Ok(())
    }
}

fn default_devpts_gid(namespaces: &NamespacePlan, process_gid: u32) -> u32 {
    if namespaces.has_user() && namespaces.host_gid(5).is_none() {
        process_gid
    } else {
        5
    }
}

fn inject_control_workload_environment(environment: &mut Vec<String>) -> Result<()> {
    for name in [CONTROL_CGROUP_PROCS_FD_ENV, WORKLOAD_CGROUP_PROCS_FD_ENV] {
        if environment
            .iter()
            .filter_map(|entry| entry.split_once('='))
            .any(|(candidate, _)| candidate == name)
        {
            return Err(invalid(format!(
                "process.env variable `{name}` is reserved by the control/workload cgroup layout"
            )));
        }
    }
    environment.extend([
        format!("{CONTROL_CGROUP_PROCS_FD_ENV}={CONTROL_CGROUP_PROCS_FD}"),
        format!("{WORKLOAD_CGROUP_PROCS_FD_ENV}={WORKLOAD_CGROUP_PROCS_FD}"),
    ]);
    validate_environment(environment)
}

fn validate_process_profile(process: &Process) -> Result<()> {
    let raw = serde_json::to_value(process).map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("validated OCI process could not be encoded: {error}"),
        )
        .for_operation("plan-guest-init")
    })?;
    let process = object(&raw, "process")?;
    validate_supported_process_fields(process)?;
    let user = object(
        process
            .get("user")
            .ok_or_else(|| invalid("process.user is required"))?,
        "process.user",
    )?;
    reject_unimplemented_keys(
        user,
        "process.user",
        &["uid", "gid", "umask", "additionalGids", "username"],
    )
}

fn validate_profile(raw: &Value) -> Result<()> {
    let root = object(raw, "config")?;
    reject_unimplemented_keys(
        root,
        "config",
        &[
            "ociVersion",
            "root",
            "process",
            "mounts",
            "hostname",
            "domainname",
            "annotations",
            "hooks",
            "linux",
        ],
    )?;

    let root_config = object(
        root.get("root")
            .ok_or_else(|| invalid("config.root is required"))?,
        "root",
    )?;
    reject_unimplemented_keys(root_config, "root", &["path", "readonly"])?;

    if let Some(process) = root.get("process") {
        let process = object(process, "process")?;
        validate_supported_process_fields(process)?;

        let user = object(
            process
                .get("user")
                .ok_or_else(|| invalid("process.user is required"))?,
            "process.user",
        )?;
        reject_unimplemented_keys(
            user,
            "process.user",
            &["uid", "gid", "umask", "additionalGids", "username"],
        )?;
    }

    let Some(linux) = root.get("linux") else {
        return Ok(());
    };
    let linux = object(linux, "linux")?;
    if let Some(namespaces) = linux.get("namespaces") {
        let namespaces = namespaces
            .as_array()
            .ok_or_else(|| invalid("linux.namespaces must be an array"))?;
        for (index, namespace) in namespaces.iter().enumerate() {
            let field = format!("linux.namespaces[{index}]");
            let namespace = object(namespace, &field)?;
            reject_unimplemented_keys(namespace, &field, &["type", "path"])?;
            let namespace_type = namespace
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid(format!("{field}.type must be a string")))?;
            if !matches!(
                namespace_type,
                "uts" | "mount" | "ipc" | "network" | "cgroup" | "pid" | "user" | "time"
            ) {
                return Err(unsupported(
                    &format!("{field}.type"),
                    "only Linux OCI namespace types are accepted",
                ));
            }
            if namespace.get("path").is_some_and(|path| !path.is_string()) {
                return Err(invalid(format!("{field}.path must be a string")));
            }
        }
    }
    if let Some(resources) = linux.get("resources") {
        let resources = object(resources, "linux.resources")?;
        reject_unimplemented_keys(
            resources,
            "linux.resources",
            &[
                "devices",
                "memory",
                "cpu",
                "pids",
                "blockIO",
                "hugepageLimits",
                "rdma",
                "unified",
            ],
        )?;
    }
    if let Some(intel_rdt) = linux.get("intelRdt") {
        let intel_rdt = object(intel_rdt, "linux.intelRdt")?;
        reject_unimplemented_keys(
            intel_rdt,
            "linux.intelRdt",
            &[
                "closID",
                "schemata",
                "l3CacheSchema",
                "memBwSchema",
                "enableMonitoring",
            ],
        )?;
    }
    reject_unimplemented_keys(
        linux,
        "linux",
        &[
            "namespaces",
            "uidMappings",
            "gidMappings",
            "timeOffsets",
            "sysctl",
            "cgroupsPath",
            "resources",
            "devices",
            "seccomp",
            "rootfsPropagation",
            "maskedPaths",
            "readonlyPaths",
            "personality",
            "memoryPolicy",
            "intelRdt",
            "netDevices",
        ],
    )
}

fn validate_supported_process_fields(process: &Map<String, Value>) -> Result<()> {
    reject_unimplemented_keys(
        process,
        "process",
        &[
            "terminal",
            "consoleSize",
            "user",
            "args",
            "env",
            "cwd",
            "capabilities",
            "rlimits",
            "oomScoreAdj",
            "ioPriority",
            "scheduler",
            "execCPUAffinity",
            "noNewPrivileges",
        ],
    )?;
    Ok(())
}

fn resolve_rootfs_path(bundle_directory: &Path, path: &Path) -> Result<PathBuf> {
    if path == Path::new(".") {
        return Ok(bundle_directory.to_path_buf());
    }
    let path = linux_path(path, "root.path", path.is_absolute())?;
    if path.starts_with('/') {
        Ok(PathBuf::from(path))
    } else {
        Ok(bundle_directory.join(path))
    }
}

fn plan_annotations(
    annotations: Option<&std::collections::HashMap<String, String>>,
) -> Result<BTreeMap<String, String>> {
    let annotations = annotations.cloned().unwrap_or_default();
    if annotations.len() > MAX_ANNOTATIONS {
        return Err(invalid(format!(
            "annotations contains {} entries; maximum is {MAX_ANNOTATIONS}",
            annotations.len()
        )));
    }
    let mut total_bytes = 0_usize;
    let mut planned = BTreeMap::new();
    for (key, value) in annotations {
        if key.is_empty() {
            return Err(invalid("annotation keys must not be empty"));
        }
        total_bytes = total_bytes
            .checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or_else(|| invalid("annotations size overflow"))?;
        if total_bytes > MAX_EXEC_BYTES {
            return Err(invalid(format!(
                "annotations exceeds the {MAX_EXEC_BYTES}-byte bootstrap limit"
            )));
        }
        planned.insert(key, value);
    }
    Ok(planned)
}

fn plan_restricted_paths(paths: Option<&[String]>, field: &str) -> Result<Vec<PathBuf>> {
    let paths = paths.unwrap_or_default();
    if paths.len() > MAX_RESTRICTED_PATHS {
        return Err(invalid(format!(
            "{field} contains {} entries; maximum is {MAX_RESTRICTED_PATHS}",
            paths.len()
        )));
    }
    let mut total_bytes = 0_usize;
    let mut unique = BTreeSet::new();
    let mut planned = Vec::new();
    for path in paths {
        total_bytes = total_bytes
            .checked_add(path.len().saturating_add(1))
            .ok_or_else(|| invalid(format!("{field} size overflow")))?;
        if total_bytes > MAX_EXEC_BYTES {
            return Err(invalid(format!(
                "{field} exceeds the {MAX_EXEC_BYTES}-byte bootstrap limit"
            )));
        }
        let normalized = normalize_container_path(path, field)?;
        if unique.insert(normalized.clone()) {
            planned.push(normalized);
        }
    }
    Ok(planned)
}

fn normalize_container_path(path: &str, field: &str) -> Result<PathBuf> {
    if path.is_empty()
        || !path.starts_with('/')
        || path.as_bytes().contains(&0)
        || path.contains('\\')
    {
        return Err(invalid(format!(
            "{field} entries must be absolute Linux paths without NUL bytes"
        )));
    }
    let mut normalized = PathBuf::from("/");
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                normalized.pop();
            }
            component => normalized.push(component),
        }
    }
    Ok(normalized)
}

fn validate_uts_name(field: &str, value: &str) -> Result<String> {
    if value.len() > LINUX_UTS_NAME_MAX || value.as_bytes().contains(&0) {
        return Err(invalid(format!(
            "{field} must contain at most {LINUX_UTS_NAME_MAX} bytes and no NUL"
        )));
    }
    Ok(value.to_string())
}

fn object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid(format!("{field} must be an object")))
}

fn reject_unimplemented_keys(
    object: &Map<String, Value>,
    field: &str,
    allowed: &[&str],
) -> Result<()> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        Err(unsupported(
            &format!("{field}.{key}"),
            "this OCI property is not enforced by the bootstrap executor",
        ))
    } else {
        Ok(())
    }
}

fn validate_process_io(io: &ProcessIo, process_uses_terminal: bool) -> Result<()> {
    let terminal_modes = [
        io.stdin == IoMode::Terminal,
        io.stdout == IoMode::Terminal,
        io.stderr == IoMode::Terminal,
    ];
    if process_uses_terminal {
        if terminal_modes != [true, true, true] {
            return Err(invalid(
                "process.terminal requires terminal stdin, stdout, and stderr",
            ));
        }
        let size = io.terminal_size.ok_or_else(|| {
            invalid("process.terminal requires an initial process I/O terminal size")
        })?;
        if size.width == 0 || size.height == 0 {
            return Err(invalid(
                "process I/O terminal width and height must both be positive",
            ));
        }
        return Ok(());
    }
    if terminal_modes.iter().any(|terminal| *terminal) {
        return Err(invalid(
            "terminal process I/O requires process.terminal=true",
        ));
    }
    if !matches!(io.stdin, IoMode::Null | IoMode::Pipe | IoMode::Inherit) {
        return Err(unsupported(
            "process I/O stdin",
            "the bootstrap executor accepts null, pipe, or inherited stdin",
        ));
    }
    if !matches!(io.stdout, IoMode::Null | IoMode::Capture | IoMode::Inherit) {
        return Err(unsupported(
            "process I/O stdout",
            "the bootstrap executor accepts null, captured, or inherited stdout",
        ));
    }
    if !matches!(io.stderr, IoMode::Null | IoMode::Capture | IoMode::Inherit) {
        return Err(unsupported(
            "process I/O stderr",
            "the bootstrap executor accepts null, captured, or inherited stderr",
        ));
    }
    if io.terminal_size.is_some() {
        return Err(invalid(
            "process I/O terminal size requires process.terminal=true",
        ));
    }
    Ok(())
}

fn validate_environment(environment: &[String]) -> Result<()> {
    validate_string_vector("process.env", environment, MAX_ENVIRONMENT_ENTRIES)?;
    let mut names = BTreeSet::new();
    for entry in environment {
        let Some((name, _value)) = entry.split_once('=') else {
            return Err(invalid(
                "each process.env entry must contain a name and `=` separator",
            ));
        };
        if name.is_empty() || name.contains('=') {
            return Err(invalid("process.env contains an invalid variable name"));
        }
        if !names.insert(name) {
            return Err(invalid(format!(
                "process.env contains duplicate variable `{name}`"
            )));
        }
    }
    Ok(())
}

fn validate_string_vector(field: &str, values: &[String], maximum: usize) -> Result<()> {
    if values.len() > maximum {
        return Err(invalid(format!(
            "{field} contains {} entries; maximum is {maximum}",
            values.len()
        )));
    }
    let mut bytes = 0_usize;
    for value in values {
        if value.as_bytes().contains(&0) {
            return Err(invalid(format!("{field} contains a NUL byte")));
        }
        bytes = bytes
            .checked_add(value.len().saturating_add(1))
            .ok_or_else(|| invalid(format!("{field} size overflow")))?;
        if bytes > MAX_EXEC_BYTES {
            return Err(invalid(format!(
                "{field} exceeds the {MAX_EXEC_BYTES}-byte bootstrap limit"
            )));
        }
    }
    Ok(())
}

fn linux_path(path: &Path, field: &str, require_absolute: bool) -> Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid(format!("{field} is not valid UTF-8")))?;
    if value.is_empty()
        || value.as_bytes().contains(&0)
        || value.contains('\\')
        || (require_absolute && !value.starts_with('/'))
        || (!require_absolute && value.starts_with('/'))
    {
        return Err(invalid(format!(
            "{field} must be a normalized {} Linux path",
            if require_absolute {
                "absolute"
            } else {
                "relative"
            }
        )));
    }
    let components = if require_absolute {
        value.strip_prefix('/').unwrap_or(value)
    } else {
        value
    };
    if value != "/"
        && (value.ends_with('/')
            || components
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | "..")))
    {
        return Err(invalid(format!(
            "{field} must not contain empty or dot components"
        )));
    }
    Ok(value.to_string())
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message).for_operation("plan-guest-init")
}

fn unsupported(field: &str, reason: &str) -> Error {
    Error::new(ErrorCode::Unsupported, format!("{field}: {reason}"))
        .for_operation("plan-guest-init")
}
