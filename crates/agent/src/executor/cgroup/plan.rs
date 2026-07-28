use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::{Linux, LinuxResources};
use a3s_oci_sdk::{
    Error, ErrorCode, Result, CONTROL_CGROUP_CPU_HEADROOM_ANNOTATION,
    CONTROL_CGROUP_MEMORY_HEADROOM_ANNOTATION, CONTROL_CGROUP_PIDS_HEADROOM_ANNOTATION,
    CONTROL_WORKLOAD_CGROUP_LAYOUT_ANNOTATION, CONTROL_WORKLOAD_CGROUP_LAYOUT_V1,
};

use super::cgroup_error;

const MAX_CGROUP_PATH_BYTES: usize = 4_096;

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
    pub(super) relative_path: Option<PathBuf>,
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
        let relative_path = linux
            .cgroups_path()
            .as_deref()
            .map(validate_cgroup_path)
            .transpose()?;
        let Some(resources) = linux.resources().as_ref() else {
            if !matches!(layout, CgroupLayout::Flat) {
                return Err(invalid(
                    "control/workload cgroup layout requires linux.resources",
                ));
            }
            return Ok(Self {
                layout,
                relative_path,
                ..Self::default()
            });
        };
        validate_supported_resource_fields(resources)?;

        let memory = resources.memory().as_ref();
        let cpu = resources.cpu().as_ref();
        let pids = resources.pids().as_ref();
        let plan = Self {
            layout,
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
            .memory_swap
            .is_some_and(|value| value != -1 && self.memory_limit.is_none())
        {
            return Err(invalid(
                "linux.resources.memory.swap requires memory.limit when it is finite",
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
        if matches!(self.layout, CgroupLayout::ControlWorkload(_))
            && (self.memory_limit.is_none()
                || self.cpu_quota.is_none_or(|value| value <= 0)
                || self.cpu_period.is_none()
                || self.pids_limit.is_none())
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
            settings.push(("memory.max", value.to_string()));
            settings.push((
                "memory.oom.group",
                if oom_group { "1" } else { "0" }.to_string(),
            ));
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

    pub(super) fn management_plan(&self, headroom: &ControlHeadroom) -> Result<Self> {
        let mut management = self.clone();
        management.layout = CgroupLayout::Flat;
        management.memory_limit = self
            .memory_limit
            .and_then(|value| value.checked_add(headroom.memory_bytes))
            .ok_or_else(|| invalid("control-plane memory envelope overflows i64"))
            .map(Some)?;
        management.memory_reservation = None;
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
        management.pids_limit = self
            .pids_limit
            .and_then(|value| value.checked_add(headroom.pids))
            .ok_or_else(|| invalid("control-plane PID envelope overflows i64"))
            .map(Some)?;
        Ok(management)
    }

    pub(super) fn control_headroom(&self) -> Option<&ControlHeadroom> {
        match &self.layout {
            CgroupLayout::Flat => None,
            CgroupLayout::ControlWorkload(headroom) => Some(headroom),
        }
    }

    pub(super) fn required_controllers(&self) -> BTreeSet<&'static str> {
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

    pub(in crate::executor) fn has_cgroup(&self) -> bool {
        self.relative_path.is_some()
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
    fn derives_management_headroom_while_preserving_exact_workload_limits() {
        let annotations = BTreeMap::from([
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
        ]);
        let plan = CgroupPlan::from_linux(Some(&fixture_linux()), &annotations)
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
                ("cpu.weight", "39".to_string()),
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
