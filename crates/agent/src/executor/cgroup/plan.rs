use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use a3s_oci_sdk::oci_spec::runtime::{Linux, LinuxResources};
use a3s_oci_sdk::{
    Error, ErrorCode, OciLinuxCgroupPath, Result, CONTROL_CGROUP_CPU_HEADROOM_ANNOTATION,
    CONTROL_CGROUP_MEMORY_HEADROOM_ANNOTATION, CONTROL_CGROUP_PIDS_HEADROOM_ANNOTATION,
    CONTROL_WORKLOAD_CGROUP_LAYOUT_ANNOTATION, CONTROL_WORKLOAD_CGROUP_LAYOUT_V1,
};

use super::{cgroup_error, io::BlockIoPlan};

pub(super) const DEFAULT_CPU_PERIOD_MICROS: u64 = 100_000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
enum CgroupLayout {
    #[default]
    Flat,
    ControlWorkload(ControlHeadroom),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ControlHeadroom {
    pub(super) memory_bytes: i64,
    pub(super) cpu_quota_micros: i64,
    pub(super) pids: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::executor) struct CgroupPlan {
    layout: CgroupLayout,
    pub(super) path: Option<OciLinuxCgroupPath>,
    memory_limit: Option<i64>,
    memory_reservation: Option<i64>,
    memory_swap: Option<i64>,
    cpu_shares: Option<u64>,
    cpu_quota: Option<i64>,
    cpu_burst: Option<u64>,
    cpu_period: Option<u64>,
    cpu_idle: Option<i64>,
    cpuset_cpus: Option<String>,
    cpuset_mems: Option<String>,
    pids_limit: Option<i64>,
    block_io: BlockIoPlan,
}

impl CgroupPlan {
    pub(in crate::executor) fn from_linux(
        linux: Option<&Linux>,
        annotations: &BTreeMap<String, String>,
    ) -> Result<Self> {
        let layout = cgroup_layout(annotations)?;
        let Some(linux) = linux else {
            if !matches!(layout, CgroupLayout::Flat) {
                return Err(invalid(
                    "control/workload cgroup layout requires a linux configuration",
                ));
            }
            return Ok(Self::default());
        };
        let path = linux
            .cgroups_path()
            .as_deref()
            .map(parse_cgroup_path)
            .transpose()?;
        let Some(resources) = linux.resources().as_ref() else {
            if !matches!(layout, CgroupLayout::Flat) {
                return Err(invalid(
                    "control/workload cgroup layout requires linux.resources",
                ));
            }
            return Ok(Self {
                layout,
                path,
                ..Self::default()
            });
        };
        validate_supported_resource_fields(resources)?;

        let memory = resources.memory().as_ref();
        let cpu = resources.cpu().as_ref();
        let pids = resources.pids().as_ref();
        let block_io = BlockIoPlan::from_oci(resources.block_io().as_ref())?;
        let plan = Self {
            layout,
            path,
            memory_limit: memory.and_then(|memory| memory.limit()),
            memory_reservation: memory.and_then(|memory| memory.reservation()),
            memory_swap: memory.and_then(|memory| memory.swap()),
            cpu_shares: cpu.and_then(|cpu| cpu.shares()),
            cpu_quota: cpu.and_then(|cpu| cpu.quota()),
            cpu_burst: cpu.and_then(|cpu| cpu.burst()),
            cpu_period: cpu.and_then(|cpu| cpu.period()),
            cpu_idle: cpu.and_then(|cpu| cpu.idle()),
            cpuset_cpus: cpu.and_then(|cpu| cpu.cpus().clone()),
            cpuset_mems: cpu.and_then(|cpu| cpu.mems().clone()),
            pids_limit: pids.map(|pids| pids.limit()),
            block_io,
        };
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("linux.resources.memory.limit", self.memory_limit),
            (
                "linux.resources.memory.reservation",
                self.memory_reservation,
            ),
            ("linux.resources.memory.swap", self.memory_swap),
        ] {
            if let Some(value) = value {
                validate_memory_value(field, value)?;
            }
        }
        if let Some(swap) = self.memory_swap.filter(|value| *value != -1) {
            let Some(limit) = self.memory_limit.filter(|value| *value != -1) else {
                return Err(invalid(
                    "finite linux.resources.memory.swap requires a finite memory.limit",
                ));
            };
            if swap < limit {
                return Err(invalid(
                    "linux.resources.memory.swap must be at least the finite memory.limit",
                ));
            }
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
        if self.cpu_burst.is_some_and(|burst| {
            self.cpu_quota
                .is_some_and(|quota| quota > 0 && burst > quota as u64)
        }) {
            return Err(invalid(
                "linux.resources.cpu.burst must not exceed a positive CPU quota",
            ));
        }
        if self.cpu_idle.is_some_and(|value| !matches!(value, 0 | 1)) {
            return Err(invalid("linux.resources.cpu.idle must be 0 or 1"));
        }
        for (field, value) in [
            ("linux.resources.cpu.cpus", self.cpuset_cpus.as_deref()),
            ("linux.resources.cpu.mems", self.cpuset_mems.as_deref()),
        ] {
            if let Some(value) = value {
                validate_cpuset(field, value)?;
            }
        }
        if let Some(value) = self.pids_limit {
            validate_pids_limit(value)?;
        }
        if matches!(self.layout, CgroupLayout::ControlWorkload(_))
            && (self.memory_limit.is_none_or(|value| value == -1)
                || self.cpu_quota.is_none_or(|value| value <= 0)
                || self.cpu_period.is_none()
                || self.pids_limit.is_none_or(|value| value == -1))
        {
            return Err(invalid(
                "control/workload cgroup layout requires finite memory, CPU, and PID limits",
            ));
        }
        Ok(())
    }

    pub(super) fn settings(&self) -> Vec<(&'static str, String)> {
        self.settings_with_oom_group(true)
    }

    pub(super) fn settings_with_oom_group(&self, oom_group: bool) -> Vec<(&'static str, String)> {
        let mut settings = Vec::new();
        if let Some(value) = &self.cpuset_mems {
            settings.push(("cpuset.mems", value.clone()));
        }
        if let Some(value) = &self.cpuset_cpus {
            settings.push(("cpuset.cpus", value.clone()));
        }
        if let Some(value) = self.memory_limit {
            settings.push(("memory.max", cgroup_v2_limit_value(value)));
            settings.push((
                "memory.oom.group",
                if oom_group { "1" } else { "0" }.to_string(),
            ));
        }
        if let Some(value) = self.memory_reservation {
            settings.push(("memory.low", cgroup_v2_limit_value(value)));
        }
        if let Some(value) = self.memory_swap {
            let value = if value == -1 {
                "max".to_string()
            } else {
                (value - self.memory_limit.unwrap_or_default()).to_string()
            };
            settings.push(("memory.swap.max", value));
        }
        if self.cpu_quota.is_some() || self.cpu_period.is_some() {
            let quota = self.cpu_quota.unwrap_or(-1);
            let period = self.cpu_period.unwrap_or(DEFAULT_CPU_PERIOD_MICROS);
            let quota = if quota == -1 {
                "max".to_string()
            } else {
                quota.to_string()
            };
            settings.push(("cpu.max", format!("{quota} {period}")));
        }
        if let Some(burst) = self.cpu_burst {
            settings.push(("cpu.max.burst", burst.to_string()));
        }
        if let Some(shares) = self.cpu_shares {
            settings.push(("cpu.weight", shares_to_weight(shares).to_string()));
        }
        if let Some(idle) = self.cpu_idle {
            settings.push(("cpu.idle", idle.to_string()));
        }
        if let Some(value) = self.pids_limit {
            settings.push(("pids.max", cgroup_v2_limit_value(value)));
        }
        settings
    }

    pub(super) fn management_plan(&self, headroom: &ControlHeadroom) -> Result<Self> {
        let mut management = self.clone();
        management.layout = CgroupLayout::Flat;
        management.memory_limit = self
            .memory_limit
            .map(|value| {
                if value == -1 {
                    return Err(invalid(
                        "control/workload cgroup layout requires a finite memory limit",
                    ));
                }
                value
                    .checked_add(headroom.memory_bytes)
                    .ok_or_else(|| invalid("control-plane memory envelope overflows i64"))
            })
            .transpose()?;
        management.memory_reservation = None;
        management.block_io = BlockIoPlan::default();
        management.memory_swap = self
            .memory_swap
            .map(|value| {
                if value == -1 {
                    Ok(-1)
                } else {
                    value
                        .checked_add(headroom.memory_bytes)
                        .ok_or_else(|| invalid("control-plane swap envelope overflows i64"))
                }
            })
            .transpose()?;
        management.cpu_quota = self
            .cpu_quota
            .and_then(|value| value.checked_add(headroom.cpu_quota_micros))
            .ok_or_else(|| invalid("control-plane CPU envelope overflows i64"))
            .map(Some)?;
        management.cpu_burst = None;
        management.cpu_idle = None;
        let pids_limit = self
            .pids_limit
            .ok_or_else(|| invalid("control/workload cgroup layout requires a finite PID limit"))?;
        if pids_limit == -1 {
            return Err(invalid(
                "control/workload cgroup layout requires a finite PID limit",
            ));
        }
        management.pids_limit = Some(
            pids_limit
                .checked_add(headroom.pids)
                .ok_or_else(|| invalid("control-plane PID envelope overflows i64"))?,
        );
        Ok(management)
    }

    pub(super) fn control_headroom(&self) -> Option<&ControlHeadroom> {
        match &self.layout {
            CgroupLayout::Flat => None,
            CgroupLayout::ControlWorkload(headroom) => Some(headroom),
        }
    }

    pub(super) fn block_io(&self) -> &BlockIoPlan {
        &self.block_io
    }

    pub(super) fn required_controllers(&self) -> BTreeSet<&'static str> {
        let mut controllers = BTreeSet::new();
        if self.memory_limit.is_some()
            || self.memory_reservation.is_some()
            || self.memory_swap.is_some()
        {
            controllers.insert("memory");
        }
        if self.cpu_shares.is_some()
            || self.cpu_quota.is_some()
            || self.cpu_burst.is_some()
            || self.cpu_period.is_some()
            || self.cpu_idle.is_some()
        {
            controllers.insert("cpu");
        }
        if self.cpuset_cpus.is_some() || self.cpuset_mems.is_some() {
            controllers.insert("cpuset");
        }
        if self.pids_limit.is_some() {
            controllers.insert("pids");
        }
        if !self.block_io.is_empty() {
            controllers.insert("io");
        }
        controllers
    }

    pub(in crate::executor) fn has_cgroup(&self) -> bool {
        self.path.is_some()
    }

    pub(in crate::executor) fn ensure_runtime_path(
        &mut self,
        container_id: &str,
        generation: u64,
    ) -> Result<()> {
        if self.path.is_some() {
            return Ok(());
        }
        let generated = format!("containers/{container_id}-g{generation:016x}");
        self.path = Some(OciLinuxCgroupPath::parse(&generated).map_err(|error| {
            cgroup_error(
                ErrorCode::Internal,
                format!("failed to construct the private runtime cgroup path: {error}"),
            )
        })?);
        Ok(())
    }

    pub(in crate::executor) fn uses_control_workload_layout(&self) -> bool {
        matches!(self.layout, CgroupLayout::ControlWorkload(_))
    }
}

fn cgroup_layout(annotations: &BTreeMap<String, String>) -> Result<CgroupLayout> {
    let layout = annotations
        .get(CONTROL_WORKLOAD_CGROUP_LAYOUT_ANNOTATION)
        .map(String::as_str);
    let headroom_keys = [
        CONTROL_CGROUP_MEMORY_HEADROOM_ANNOTATION,
        CONTROL_CGROUP_CPU_HEADROOM_ANNOTATION,
        CONTROL_CGROUP_PIDS_HEADROOM_ANNOTATION,
    ];
    match layout {
        None => {
            if let Some(key) = headroom_keys
                .iter()
                .find(|key| annotations.contains_key(**key))
            {
                return Err(invalid(format!(
                    "annotation {key:?} requires {CONTROL_WORKLOAD_CGROUP_LAYOUT_ANNOTATION:?}"
                )));
            }
            Ok(CgroupLayout::Flat)
        }
        Some(CONTROL_WORKLOAD_CGROUP_LAYOUT_V1) => {
            Ok(CgroupLayout::ControlWorkload(ControlHeadroom {
                memory_bytes: positive_annotation(
                    annotations,
                    CONTROL_CGROUP_MEMORY_HEADROOM_ANNOTATION,
                )?,
                cpu_quota_micros: positive_annotation(
                    annotations,
                    CONTROL_CGROUP_CPU_HEADROOM_ANNOTATION,
                )?,
                pids: positive_annotation(annotations, CONTROL_CGROUP_PIDS_HEADROOM_ANNOTATION)?,
            }))
        }
        Some(value) => Err(unsupported(
            CONTROL_WORKLOAD_CGROUP_LAYOUT_ANNOTATION,
            &format!("unknown cgroup layout version {value:?}"),
        )),
    }
}

fn positive_annotation(annotations: &BTreeMap<String, String>, key: &str) -> Result<i64> {
    let value = annotations
        .get(key)
        .ok_or_else(|| invalid(format!("control/workload cgroup layout requires {key:?}")))?;
    value
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid(format!("annotation {key:?} must be a positive i64")))
}

fn parse_cgroup_path(path: &Path) -> Result<OciLinuxCgroupPath> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid("linux.cgroupsPath is not valid UTF-8"))?;
    OciLinuxCgroupPath::parse(value).map_err(|error| invalid(error.to_string()))
}

pub(super) fn validate_supported_resource_fields(resources: &LinuxResources) -> Result<()> {
    let value = serde_json::to_value(resources).map_err(|error| {
        cgroup_error(
            ErrorCode::Internal,
            format!("failed to inspect OCI resources: {error}"),
        )
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("linux.resources must be an object"))?;
    if let Some(field) = object.keys().find(|field| {
        !matches!(
            field.as_str(),
            "devices" | "memory" | "cpu" | "pids" | "blockIO"
        )
    }) {
        return Err(unsupported(
            &format!("linux.resources.{field}"),
            "this cgroup v2 resource is not implemented",
        ));
    }
    for (name, allowed) in [
        ("memory", &["limit", "reservation", "swap"][..]),
        (
            "cpu",
            &["shares", "quota", "burst", "period", "cpus", "mems", "idle"][..],
        ),
        ("pids", &["limit"][..]),
        (
            "blockIO",
            &[
                "weight",
                "leafWeight",
                "weightDevice",
                "throttleReadBpsDevice",
                "throttleWriteBpsDevice",
                "throttleReadIOPSDevice",
                "throttleWriteIOPSDevice",
            ][..],
        ),
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

pub(super) fn validate_cpuset(field: &str, value: &str) -> Result<()> {
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

pub(super) fn validate_pids_limit(value: i64) -> Result<()> {
    if value < -1 {
        Err(invalid(
            "linux.resources.pids.limit must be -1 or non-negative",
        ))
    } else {
        Ok(())
    }
}

pub(super) fn validate_memory_value(field: &str, value: i64) -> Result<()> {
    if value < -1 {
        Err(invalid(format!("{field} must be -1 or non-negative")))
    } else {
        Ok(())
    }
}

pub(super) fn cgroup_v2_limit_value(value: i64) -> String {
    debug_assert!(
        value >= -1,
        "cgroup v2 limit must be validated before encoding"
    );
    if value == -1 {
        "max".to_string()
    } else {
        value.to_string()
    }
}

pub(super) const fn shares_to_weight(shares: u64) -> u64 {
    1 + ((shares - 2) * 9_999) / 262_142
}

fn invalid(message: impl Into<String>) -> Error {
    cgroup_error(ErrorCode::InvalidArgument, message)
}

fn unsupported(field: &str, reason: &str) -> Error {
    cgroup_error(ErrorCode::Unsupported, format!("{field}: {reason}"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use a3s_oci_sdk::oci_spec::runtime::Linux;
    use a3s_oci_sdk::{
        CONTROL_CGROUP_CPU_HEADROOM_ANNOTATION, CONTROL_CGROUP_MEMORY_HEADROOM_ANNOTATION,
        CONTROL_CGROUP_PIDS_HEADROOM_ANNOTATION, CONTROL_WORKLOAD_CGROUP_LAYOUT_ANNOTATION,
        CONTROL_WORKLOAD_CGROUP_LAYOUT_V1,
    };

    use super::{shares_to_weight, CgroupPlan};

    fn fixture_linux() -> Linux {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../../../../../fixtures/a3s-box/config.json"))
                .expect("decode fixture");
        serde_json::from_value(config["linux"].clone()).expect("decode Linux config")
    }

    fn linux_with_cgroup_path(path: &str) -> Linux {
        serde_json::from_value(serde_json::json!({"cgroupsPath": path}))
            .expect("decode Linux cgroup path")
    }

    fn linux_with_cpu(cpu: serde_json::Value) -> Linux {
        serde_json::from_value(serde_json::json!({
            "cgroupsPath": "cpu/controls",
            "resources": {"cpu": cpu}
        }))
        .expect("decode Linux CPU controls")
    }

    fn linux_with_pids(limit: i64) -> Linux {
        serde_json::from_value(serde_json::json!({
            "cgroupsPath": "pids/controls",
            "resources": {"pids": {"limit": limit}}
        }))
        .expect("decode Linux PIDs controls")
    }

    fn linux_with_memory(memory: serde_json::Value) -> Linux {
        serde_json::from_value(serde_json::json!({
            "cgroupsPath": "memory/controls",
            "resources": {"memory": memory}
        }))
        .expect("decode Linux memory controls")
    }

    fn linux_with_block_io(block_io: serde_json::Value) -> Linux {
        serde_json::from_value(serde_json::json!({
            "cgroupsPath": "io/controls",
            "resources": {"blockIO": block_io}
        }))
        .expect("decode Linux block I/O controls")
    }

    fn control_workload_annotations() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                CONTROL_WORKLOAD_CGROUP_LAYOUT_ANNOTATION.to_string(),
                CONTROL_WORKLOAD_CGROUP_LAYOUT_V1.to_string(),
            ),
            (
                CONTROL_CGROUP_MEMORY_HEADROOM_ANNOTATION.to_string(),
                "67108864".to_string(),
            ),
            (
                CONTROL_CGROUP_CPU_HEADROOM_ANNOTATION.to_string(),
                "25000".to_string(),
            ),
            (
                CONTROL_CGROUP_PIDS_HEADROOM_ANNOTATION.to_string(),
                "16".to_string(),
            ),
        ])
    }

    #[test]
    fn preserves_absolute_and_relative_cgroup_path_identity() {
        let absolute = CgroupPlan::from_linux(
            Some(&linux_with_cgroup_path("/tenant/workload")),
            &BTreeMap::new(),
        )
        .expect("absolute cgroup plan");
        let relative = CgroupPlan::from_linux(
            Some(&linux_with_cgroup_path("tenant/workload")),
            &BTreeMap::new(),
        )
        .expect("relative cgroup plan");

        assert!(absolute.path.as_ref().expect("absolute path").is_absolute());
        assert!(!relative.path.as_ref().expect("relative path").is_absolute());
        assert_eq!(
            absolute.path.as_ref().expect("absolute path").relative(),
            relative.path.as_ref().expect("relative path").relative()
        );
    }

    #[test]
    fn assigns_a_private_runtime_path_without_overwriting_an_oci_path() {
        let generated_linux: Linux = serde_json::from_value(serde_json::json!({
            "resources": {"pids": {"limit": 64}}
        }))
        .expect("decode generated-path resources");
        let mut generated = CgroupPlan::from_linux(Some(&generated_linux), &BTreeMap::new())
            .expect("resource plan without an explicit cgroup path");
        assert!(!generated.has_cgroup());
        assert_eq!(generated.settings(), vec![("pids.max", "64".to_string())]);
        generated
            .ensure_runtime_path("container_01", 7)
            .expect("private runtime path");
        let generated = generated.path.as_ref().expect("generated path");
        assert!(!generated.is_absolute());
        assert_eq!(
            generated.relative(),
            "containers/container_01-g0000000000000007"
        );

        let mut explicit = CgroupPlan::from_linux(
            Some(&linux_with_cgroup_path("tenant/explicit")),
            &BTreeMap::new(),
        )
        .expect("explicit cgroup plan");
        explicit
            .ensure_runtime_path("ignored", 9)
            .expect("retain explicit path");
        assert_eq!(
            explicit.path.as_ref().expect("explicit path").relative(),
            "tenant/explicit"
        );
    }

    #[test]
    fn rejects_unsafe_cgroup_paths_during_planning() {
        for path in [
            "",
            "/",
            "tenant/",
            "tenant//workload",
            "tenant/./workload",
            "tenant/../workload",
            "system.slice:a3s:workload",
            "tenant\nworkload",
            "tenant\0workload",
        ] {
            let error =
                CgroupPlan::from_linux(Some(&linux_with_cgroup_path(path)), &BTreeMap::new())
                    .expect_err("unsafe cgroup path must fail planning");
            assert_eq!(error.code, a3s_oci_sdk::ErrorCode::InvalidArgument);
        }
    }

    #[test]
    fn plans_exact_a3s_box_cgroup_v2_settings() {
        let plan =
            CgroupPlan::from_linux(Some(&fixture_linux()), &BTreeMap::new()).expect("cgroup plan");
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
    fn plans_complete_cgroup_v2_cpu_controls() {
        let plan = CgroupPlan::from_linux(
            Some(&linux_with_cpu(serde_json::json!({
                "shares": 1024,
                "quota": 50000,
                "burst": 10000,
                "period": 100000,
                "cpus": "0-1",
                "mems": "0",
                "idle": 1
            }))),
            &BTreeMap::new(),
        )
        .expect("complete cgroup v2 CPU plan");

        assert_eq!(
            plan.settings(),
            [
                ("cpuset.mems", "0".to_string()),
                ("cpuset.cpus", "0-1".to_string()),
                ("cpu.max", "50000 100000".to_string()),
                ("cpu.max.burst", "10000".to_string()),
                ("cpu.weight", "39".to_string()),
                ("cpu.idle", "1".to_string()),
            ]
        );
        assert_eq!(plan.required_controllers(), ["cpu", "cpuset"].into());
    }

    #[test]
    fn plans_block_io_as_an_independent_keyed_controller() {
        let linux = linux_with_block_io(serde_json::json!({
            "weight": 500,
            "weightDevice": [{"major": 8, "minor": 0, "weight": 250}],
            "throttleReadBpsDevice": [{"major": 8, "minor": 0, "rate": 1048576}],
            "throttleWriteIOPSDevice": [{"major": 8, "minor": 16, "rate": 200}]
        }));
        let plan =
            CgroupPlan::from_linux(Some(&linux), &BTreeMap::new()).expect("block I/O cgroup plan");

        assert!(plan.settings().is_empty());
        assert!(!plan.block_io().is_empty());
        assert_eq!(plan.required_controllers(), ["io"].into());
    }

    #[test]
    fn preserves_independent_cpu_quota_and_period_requests() {
        let quota = CgroupPlan::from_linux(
            Some(&linux_with_cpu(serde_json::json!({"quota": 50000}))),
            &BTreeMap::new(),
        )
        .expect("quota-only CPU plan");
        assert_eq!(quota.settings(), [("cpu.max", "50000 100000".to_string())]);

        let period = CgroupPlan::from_linux(
            Some(&linux_with_cpu(serde_json::json!({"period": 200000}))),
            &BTreeMap::new(),
        )
        .expect("period-only CPU plan");
        assert_eq!(period.settings(), [("cpu.max", "max 200000".to_string())]);
    }

    #[test]
    fn plans_zero_and_unlimited_pids_limits() {
        for (limit, expected) in [(0, "0"), (-1, "max")] {
            let plan = CgroupPlan::from_linux(Some(&linux_with_pids(limit)), &BTreeMap::new())
                .expect("valid PIDs plan");

            assert_eq!(plan.settings(), [("pids.max", expected.to_string())]);
            assert_eq!(plan.required_controllers(), ["pids"].into());
        }
    }

    #[test]
    fn plans_zero_and_unlimited_memory_controls() {
        for (value, expected) in [(0, "0"), (-1, "max")] {
            let plan = CgroupPlan::from_linux(
                Some(&linux_with_memory(serde_json::json!({
                    "limit": value,
                    "reservation": value,
                    "swap": value
                }))),
                &BTreeMap::new(),
            )
            .expect("valid memory plan");

            assert_eq!(
                plan.settings(),
                [
                    ("memory.max", expected.to_string()),
                    ("memory.oom.group", "1".to_string()),
                    ("memory.low", expected.to_string()),
                    ("memory.swap.max", expected.to_string()),
                ]
            );
            assert_eq!(plan.required_controllers(), ["memory"].into());
        }
    }

    #[test]
    fn accepts_memory_reservation_above_the_hard_limit() {
        let plan = CgroupPlan::from_linux(
            Some(&linux_with_memory(serde_json::json!({
                "limit": 64,
                "reservation": 128
            }))),
            &BTreeMap::new(),
        )
        .expect("cgroup v2 clamps memory.low to the effective hard limit");

        assert_eq!(
            plan.settings(),
            [
                ("memory.max", "64".to_string()),
                ("memory.oom.group", "1".to_string()),
                ("memory.low", "128".to_string()),
            ]
        );
    }

    #[test]
    fn rejects_memory_values_below_the_unlimited_sentinel() {
        for field in ["limit", "reservation", "swap"] {
            let error = CgroupPlan::from_linux(
                Some(&linux_with_memory(serde_json::json!({field: -2}))),
                &BTreeMap::new(),
            )
            .expect_err("a memory value below -1 must fail planning");

            assert_eq!(error.code, a3s_oci_sdk::ErrorCode::InvalidArgument);
            assert!(error.message.contains("-1 or non-negative"));
        }
    }

    #[test]
    fn rejects_unsupported_memory_controls() {
        for (field, value) in [
            ("kernel", serde_json::json!(1)),
            ("kernelTCP", serde_json::json!(1)),
            ("swappiness", serde_json::json!(50)),
            ("disableOOMKiller", serde_json::json!(true)),
            ("useHierarchy", serde_json::json!(true)),
            ("checkBeforeUpdate", serde_json::json!(true)),
        ] {
            let error = CgroupPlan::from_linux(
                Some(&linux_with_memory(serde_json::json!({field: value}))),
                &BTreeMap::new(),
            )
            .expect_err("unsupported cgroup v1 memory control must fail planning");

            assert_eq!(error.code, a3s_oci_sdk::ErrorCode::Unsupported);
            assert!(error
                .message
                .contains(&format!("linux.resources.memory.{field}")));
        }
    }

    #[test]
    fn finite_memory_swap_requires_a_finite_compatible_limit() {
        for memory in [
            serde_json::json!({"swap": 128}),
            serde_json::json!({"limit": -1, "swap": 128}),
            serde_json::json!({"limit": 128, "swap": 64}),
        ] {
            let error = CgroupPlan::from_linux(Some(&linux_with_memory(memory)), &BTreeMap::new())
                .expect_err("finite swap needs a compatible finite memory limit");

            assert_eq!(error.code, a3s_oci_sdk::ErrorCode::InvalidArgument);
            assert!(error.message.contains("memory.swap"));
        }
    }

    #[test]
    fn rejects_pids_limits_below_the_unlimited_sentinel() {
        let error = CgroupPlan::from_linux(Some(&linux_with_pids(-2)), &BTreeMap::new())
            .expect_err("a PIDs limit below -1 must fail planning");

        assert_eq!(error.code, a3s_oci_sdk::ErrorCode::InvalidArgument);
        assert!(error.message.contains("-1 or non-negative"));
    }

    #[test]
    fn control_workload_accepts_zero_but_rejects_unlimited_pids() {
        let annotations = control_workload_annotations();
        let mut zero = serde_json::to_value(fixture_linux()).expect("encode Linux fixture");
        zero["resources"]["pids"]["limit"] = serde_json::json!(0);
        let zero = serde_json::from_value(zero).expect("decode zero-PIDs Linux fixture");
        let plan =
            CgroupPlan::from_linux(Some(&zero), &annotations).expect("zero is a finite PIDs limit");
        assert!(plan.settings().contains(&("pids.max", "0".to_string())));
        assert!(plan
            .management_plan(plan.control_headroom().expect("control headroom"))
            .expect("zero-PIDs management envelope")
            .settings()
            .contains(&("pids.max", "16".to_string())));

        let mut unlimited = serde_json::to_value(fixture_linux()).expect("encode Linux fixture");
        unlimited["resources"]["pids"]["limit"] = serde_json::json!(-1);
        let unlimited =
            serde_json::from_value(unlimited).expect("decode unlimited-PIDs Linux fixture");
        let error = CgroupPlan::from_linux(Some(&unlimited), &annotations)
            .expect_err("control/workload layout must retain a finite PIDs limit");
        assert_eq!(error.code, a3s_oci_sdk::ErrorCode::InvalidArgument);
        assert!(error.message.contains("finite memory, CPU, and PID limits"));
    }

    #[test]
    fn control_workload_accepts_zero_but_rejects_unlimited_memory() {
        let annotations = control_workload_annotations();
        let mut zero = serde_json::to_value(fixture_linux()).expect("encode Linux fixture");
        zero["resources"]["memory"]["limit"] = serde_json::json!(0);
        let zero = serde_json::from_value(zero).expect("decode zero-memory Linux fixture");
        let plan = CgroupPlan::from_linux(Some(&zero), &annotations)
            .expect("zero is a finite memory limit");
        assert!(plan.settings().contains(&("memory.max", "0".to_string())));
        assert!(plan
            .management_plan(plan.control_headroom().expect("control headroom"))
            .expect("zero-memory management envelope")
            .settings()
            .contains(&("memory.max", "67108864".to_string())));

        let mut unlimited = serde_json::to_value(fixture_linux()).expect("encode Linux fixture");
        unlimited["resources"]["memory"]["limit"] = serde_json::json!(-1);
        unlimited["resources"]["memory"]["reservation"] = serde_json::json!(-1);
        unlimited["resources"]["memory"]["swap"] = serde_json::json!(-1);
        let unlimited =
            serde_json::from_value(unlimited).expect("decode unlimited-memory Linux fixture");
        let error = CgroupPlan::from_linux(Some(&unlimited), &annotations)
            .expect_err("control/workload layout must retain a finite memory limit");
        assert_eq!(error.code, a3s_oci_sdk::ErrorCode::InvalidArgument);
        assert!(error.message.contains("finite memory, CPU, and PID limits"));
    }

    #[test]
    fn rejects_invalid_cpu_burst_idle_and_realtime_controls() {
        for cpu in [
            serde_json::json!({"quota": 10000, "burst": 10001}),
            serde_json::json!({"idle": -1}),
            serde_json::json!({"idle": 2}),
        ] {
            let error = CgroupPlan::from_linux(Some(&linux_with_cpu(cpu)), &BTreeMap::new())
                .expect_err("invalid CPU control must fail planning");
            assert_eq!(error.code, a3s_oci_sdk::ErrorCode::InvalidArgument);
        }

        for cpu in [
            serde_json::json!({"realtimeRuntime": 1000}),
            serde_json::json!({"realtimePeriod": 10000}),
        ] {
            let error = CgroupPlan::from_linux(Some(&linux_with_cpu(cpu)), &BTreeMap::new())
                .expect_err("cgroup v1 realtime CPU control must fail planning");
            assert_eq!(error.code, a3s_oci_sdk::ErrorCode::Unsupported);
        }
    }

    #[test]
    fn derives_management_headroom_while_preserving_exact_workload_limits() {
        let annotations = control_workload_annotations();
        let mut linux = serde_json::to_value(fixture_linux()).expect("encode Linux fixture");
        linux["resources"]["cpu"]["burst"] = serde_json::json!(10_000);
        linux["resources"]["cpu"]["idle"] = serde_json::json!(1);
        let linux = serde_json::from_value(linux).expect("decode extended Linux fixture");
        let plan = CgroupPlan::from_linux(Some(&linux), &annotations)
            .expect("control/workload cgroup plan");
        assert!(plan.uses_control_workload_layout());
        assert_eq!(
            plan.settings_with_oom_group(false),
            [
                ("cpuset.cpus", "0-1".to_string()),
                ("memory.max", "536870912".to_string()),
                ("memory.oom.group", "0".to_string()),
                ("memory.low", "268435456".to_string()),
                ("memory.swap.max", "536870912".to_string()),
                ("cpu.max", "200000 100000".to_string()),
                ("cpu.max.burst", "10000".to_string()),
                ("cpu.weight", "39".to_string()),
                ("cpu.idle", "1".to_string()),
                ("pids.max", "512".to_string()),
            ]
        );

        let management = plan
            .management_plan(plan.control_headroom().expect("control headroom"))
            .expect("management envelope");
        assert_eq!(
            management.settings(),
            [
                ("cpuset.cpus", "0-1".to_string()),
                ("memory.max", "603979776".to_string()),
                ("memory.oom.group", "1".to_string()),
                ("memory.swap.max", "536870912".to_string()),
                ("cpu.max", "225000 100000".to_string()),
                ("cpu.weight", "39".to_string()),
                ("pids.max", "528".to_string()),
            ]
        );
    }

    #[test]
    fn rejects_partial_or_unversioned_control_headroom_annotations() {
        let partial = BTreeMap::from([(
            CONTROL_WORKLOAD_CGROUP_LAYOUT_ANNOTATION.to_string(),
            CONTROL_WORKLOAD_CGROUP_LAYOUT_V1.to_string(),
        )]);
        assert!(CgroupPlan::from_linux(Some(&fixture_linux()), &partial)
            .expect_err("missing control headroom must fail")
            .message
            .contains(CONTROL_CGROUP_MEMORY_HEADROOM_ANNOTATION));

        let unversioned = BTreeMap::from([(
            CONTROL_CGROUP_MEMORY_HEADROOM_ANNOTATION.to_string(),
            "67108864".to_string(),
        )]);
        assert!(CgroupPlan::from_linux(Some(&fixture_linux()), &unversioned)
            .expect_err("unversioned control headroom must fail")
            .message
            .contains(CONTROL_WORKLOAD_CGROUP_LAYOUT_ANNOTATION));
    }

    #[test]
    fn uses_the_runc_cpu_shares_conversion() {
        assert_eq!(shares_to_weight(2), 1);
        assert_eq!(shares_to_weight(1_024), 39);
        assert_eq!(shares_to_weight(262_144), 10_000);
    }
}
