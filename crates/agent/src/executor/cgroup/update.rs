use std::path::{Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::LinuxResources;
use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::{
    normalize_cgroup_value, parse_max_value, parse_u64_value, read_required, shares_to_weight,
    validate_cpuset, validate_supported_resource_fields, CgroupHandle, ControlHeadroom,
};

const UPDATE_OPERATION: &str = "update-container-cgroup";

impl CgroupHandle {
    pub(in crate::executor) async fn update(&self, resources: &LinuxResources) -> Result<()> {
        let plan = CgroupUpdatePlan::from_resources(resources)?;
        let mut prepared = Vec::new();
        if let Some(layout) = &self.control_workload {
            let management = plan.management_plan(&layout.headroom)?;
            let settings = management.settings(&layout.management, true).await?;
            prepared.extend(prepare_update_settings(&layout.management, settings).await?);
        }
        let settings = plan
            .settings(&self.leaf, self.control_workload.is_none())
            .await?;
        prepared.extend(prepare_update_settings(&self.leaf, settings).await?);
        apply_prepared_update_settings(prepared).await
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CgroupUpdatePlan {
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

impl CgroupUpdatePlan {
    fn from_resources(resources: &LinuxResources) -> Result<Self> {
        validate_supported_resource_fields(resources)?;
        reject_live_device_updates(resources)?;
        let memory = resources.memory().as_ref();
        let cpu = resources.cpu().as_ref();
        let pids = resources.pids().as_ref();
        let plan = Self {
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
        Ok(plan)
    }

    fn validate(&self) -> Result<()> {
        if self.memory_limit.is_some_and(|value| value <= 0) {
            return Err(update_invalid(
                "linux.resources.memory.limit must be positive",
            ));
        }
        if self.memory_reservation.is_some_and(|value| value < 0) {
            return Err(update_invalid(
                "linux.resources.memory.reservation must be non-negative",
            ));
        }
        if self.memory_swap.is_some_and(|value| value < -1) {
            return Err(update_invalid(
                "linux.resources.memory.swap must be -1 or non-negative",
            ));
        }
        if self
            .cpu_shares
            .is_some_and(|value| !(2..=262_144).contains(&value))
        {
            return Err(update_invalid(
                "linux.resources.cpu.shares must be between 2 and 262144",
            ));
        }
        if self
            .cpu_quota
            .is_some_and(|value| value != -1 && value <= 0)
        {
            return Err(update_invalid(
                "linux.resources.cpu.quota must be -1 or positive",
            ));
        }
        if self.cpu_period.is_some_and(|value| value == 0) {
            return Err(update_invalid(
                "linux.resources.cpu.period must be positive",
            ));
        }
        for (field, value) in [
            ("linux.resources.cpu.cpus", self.cpuset_cpus.as_deref()),
            ("linux.resources.cpu.mems", self.cpuset_mems.as_deref()),
        ] {
            if let Some(value) = value {
                validate_cpuset(field, value).map_err(as_update_error)?;
            }
        }
        if self.pids_limit.is_some_and(|value| value <= 0) {
            return Err(update_invalid(
                "linux.resources.pids.limit must be positive",
            ));
        }
        Ok(())
    }

    fn management_plan(&self, headroom: &ControlHeadroom) -> Result<Self> {
        let mut management = self.clone();
        management.memory_limit = self
            .memory_limit
            .map(|value| {
                value
                    .checked_add(headroom.memory_bytes)
                    .ok_or_else(|| update_invalid("control-plane memory envelope overflows i64"))
            })
            .transpose()?;
        management.memory_reservation = None;
        management.memory_swap = self
            .memory_swap
            .map(|value| {
                if value == -1 {
                    Ok(-1)
                } else {
                    value
                        .checked_add(headroom.memory_bytes)
                        .ok_or_else(|| update_invalid("control-plane swap envelope overflows i64"))
                }
            })
            .transpose()?;
        management.cpu_quota = self
            .cpu_quota
            .map(|value| {
                if value == -1 {
                    return Err(update_invalid(
                        "control/workload cgroup layout requires a finite CPU quota",
                    ));
                }
                value
                    .checked_add(headroom.cpu_quota_micros)
                    .ok_or_else(|| update_invalid("control-plane CPU envelope overflows i64"))
            })
            .transpose()?;
        management.pids_limit = self
            .pids_limit
            .map(|value| {
                value
                    .checked_add(headroom.pids)
                    .ok_or_else(|| update_invalid("control-plane PID envelope overflows i64"))
            })
            .transpose()?;
        Ok(management)
    }

    async fn settings(&self, path: &Path, oom_group: bool) -> Result<Vec<(&'static str, String)>> {
        let mut settings = Vec::new();
        if let Some(value) = &self.cpuset_mems {
            settings.push(("cpuset.mems", value.clone()));
        }
        if let Some(value) = &self.cpuset_cpus {
            settings.push(("cpuset.cpus", value.clone()));
        }

        let changes_memory = self.memory_limit.is_some()
            || self.memory_reservation.is_some()
            || self.memory_swap.is_some();
        if changes_memory {
            let current_max_text = read_required(path, "memory.max", UPDATE_OPERATION).await?;
            let current_max =
                parse_max_value("memory.max", &current_max_text).map_err(as_update_error)?;
            let effective_max = match self.memory_limit {
                Some(limit) => Some(u64::try_from(limit).map_err(|error| {
                    update_invalid(format!("memory limit does not fit cgroup v2: {error}"))
                })?),
                None => current_max,
            };
            let current_low_text = read_required(path, "memory.low", UPDATE_OPERATION).await?;
            let current_low =
                parse_u64_value("memory.low", &current_low_text).map_err(as_update_error)?;
            let effective_low = match self.memory_reservation {
                Some(reservation) => u64::try_from(reservation).map_err(|error| {
                    update_invalid(format!(
                        "memory reservation does not fit cgroup v2: {error}"
                    ))
                })?,
                None => current_low,
            };
            if effective_max.is_some_and(|limit| effective_low > limit) {
                return Err(update_invalid(
                    "linux.resources.memory.reservation must not exceed the effective memory limit",
                ));
            }

            let new_max = self.memory_limit.map(|value| value.to_string());
            let new_low = self.memory_reservation.map(|value| value.to_string());
            match (new_max, new_low) {
                (Some(max), Some(low)) => {
                    let new_limit = effective_max.ok_or_else(|| {
                        update_error(
                            ErrorCode::Internal,
                            "finite memory update lost its effective limit",
                        )
                    })?;
                    if current_max.is_some_and(|current| new_limit < current) {
                        settings.push(("memory.low", low));
                        settings.push(("memory.max", max));
                    } else {
                        settings.push(("memory.max", max));
                        settings.push(("memory.low", low));
                    }
                }
                (Some(max), None) => settings.push(("memory.max", max)),
                (None, Some(low)) => settings.push(("memory.low", low)),
                (None, None) => {}
            }
            if self.memory_limit.is_some() {
                settings.push((
                    "memory.oom.group",
                    if oom_group { "1" } else { "0" }.to_string(),
                ));
            }
            if let Some(swap) = self.memory_swap {
                let swap_only = if swap == -1 {
                    "max".to_string()
                } else {
                    let memory = effective_max.ok_or_else(|| {
                        update_invalid(
                            "finite linux.resources.memory.swap requires a finite effective memory limit",
                        )
                    })?;
                    let total = u64::try_from(swap).map_err(|error| {
                        update_invalid(format!("memory swap does not fit cgroup v2: {error}"))
                    })?;
                    total
                        .checked_sub(memory)
                        .ok_or_else(|| {
                            update_invalid(
                                "linux.resources.memory.swap must be at least the effective memory limit",
                            )
                        })?
                        .to_string()
                };
                settings.push(("memory.swap.max", swap_only));
            }
        }

        if self.cpu_quota.is_some() || self.cpu_period.is_some() {
            let current = read_required(path, "cpu.max", UPDATE_OPERATION).await?;
            let (current_quota, current_period) = parse_cpu_max(&current)?;
            let quota = match self.cpu_quota {
                Some(-1) => "max".to_string(),
                Some(value) => value.to_string(),
                None => current_quota,
            };
            let period = self.cpu_period.unwrap_or(current_period);
            settings.push(("cpu.max", format!("{quota} {period}")));
        }
        if let Some(shares) = self.cpu_shares {
            settings.push(("cpu.weight", shares_to_weight(shares).to_string()));
        }
        if let Some(value) = self.pids_limit {
            settings.push(("pids.max", value.to_string()));
        }
        Ok(settings)
    }
}

#[cfg(test)]
async fn apply_update_settings(path: &Path, settings: Vec<(&'static str, String)>) -> Result<()> {
    let prepared = prepare_update_settings(path, settings).await?;
    apply_prepared_update_settings(prepared).await
}

#[derive(Debug)]
struct PreparedUpdateSetting {
    path: PathBuf,
    file: &'static str,
    old: String,
    value: String,
}

async fn prepare_update_settings(
    path: &Path,
    settings: Vec<(&'static str, String)>,
) -> Result<Vec<PreparedUpdateSetting>> {
    let mut prepared = Vec::with_capacity(settings.len());
    for (file, value) in settings {
        let old = read_required(path, file, UPDATE_OPERATION).await?;
        prepared.push(PreparedUpdateSetting {
            path: path.to_path_buf(),
            file,
            old: normalize_cgroup_value(&old),
            value,
        });
    }
    Ok(prepared)
}

async fn apply_prepared_update_settings(prepared: Vec<PreparedUpdateSetting>) -> Result<()> {
    let mut applied = Vec::new();
    for setting in prepared {
        if normalize_cgroup_value(&setting.value) == setting.old {
            continue;
        }
        let destination = setting.path.join(setting.file);
        if let Err(error) = tokio::fs::write(&destination, setting.value.as_bytes()).await {
            return rollback_update(
                &applied,
                update_error(
                    ErrorCode::PermissionDenied,
                    format!(
                        "failed to apply cgroup setting {}={}: {error}",
                        destination.display(),
                        setting.value,
                    ),
                ),
            )
            .await;
        }
        applied.push((setting.path, setting.file, setting.old));
        let actual = match tokio::fs::read_to_string(&destination).await {
            Ok(actual) => actual,
            Err(error) => {
                return rollback_update(
                    &applied,
                    update_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "failed to verify cgroup setting {}: {error}",
                            destination.display()
                        ),
                    ),
                )
                .await;
            }
        };
        if normalize_cgroup_value(&actual) != normalize_cgroup_value(&setting.value) {
            return rollback_update(
                &applied,
                update_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "cgroup setting {} read back differently",
                        destination.display()
                    ),
                ),
            )
            .await;
        }
    }
    Ok(())
}

async fn rollback_update(
    applied: &[(PathBuf, &'static str, String)],
    original: Error,
) -> Result<()> {
    let mut failures = Vec::new();
    for (path, file, value) in applied.iter().rev() {
        let destination = path.join(file);
        if let Err(error) = tokio::fs::write(&destination, value.as_bytes()).await {
            failures.push(format!("{}: {error}", destination.display()));
            continue;
        }
        match tokio::fs::read_to_string(&destination).await {
            Ok(actual) if normalize_cgroup_value(&actual) == *value => {}
            Ok(_) => failures.push(format!(
                "{}: rollback read-back mismatch",
                destination.display()
            )),
            Err(error) => failures.push(format!("{}: {error}", destination.display())),
        }
    }
    if failures.is_empty() {
        Err(original)
    } else {
        Err(Error::new(
            ErrorCode::Internal,
            format!(
                "{}; cgroup rollback also failed: {}",
                original.message,
                failures.join("; ")
            ),
        )
        .for_operation(UPDATE_OPERATION))
    }
}

fn reject_live_device_updates(resources: &LinuxResources) -> Result<()> {
    let value = serde_json::to_value(resources).map_err(|error| {
        update_error(
            ErrorCode::Internal,
            format!("failed to inspect OCI resource update: {error}"),
        )
    })?;
    if value
        .get("devices")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|devices| !devices.is_empty())
    {
        return Err(update_error(
            ErrorCode::Unsupported,
            "live linux.resources.devices updates are not implemented",
        ));
    }
    Ok(())
}

fn parse_cpu_max(value: &str) -> Result<(String, u64)> {
    let mut fields = value.split_ascii_whitespace();
    let quota = fields
        .next()
        .ok_or_else(|| update_invalid("cpu.max is missing its quota"))?;
    let period = fields
        .next()
        .ok_or_else(|| update_invalid("cpu.max is missing its period"))?;
    if fields.next().is_some() || (quota != "max" && quota.parse::<u64>().is_err()) || quota == "0"
    {
        return Err(update_invalid("cpu.max contains an invalid quota"));
    }
    let period = period
        .parse::<u64>()
        .map_err(|error| update_invalid(format!("cpu.max contains an invalid period: {error}")))?;
    if period == 0 {
        return Err(update_invalid("cpu.max period must be positive"));
    }
    Ok((quota.to_string(), period))
}

fn update_invalid(message: impl Into<String>) -> Error {
    update_error(ErrorCode::InvalidArgument, message)
}

fn as_update_error(error: Error) -> Error {
    update_error(error.code, error.message)
}

fn update_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation(UPDATE_OPERATION)
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::oci_spec::runtime::LinuxResources;
    use a3s_oci_sdk::ErrorCode;

    use super::{apply_update_settings, CgroupUpdatePlan};
    use crate::executor::cgroup::{CgroupHandle, ControlHeadroom, ControlWorkloadCgroup};

    #[tokio::test]
    async fn resolves_partial_updates_against_current_cgroup_values() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        std::fs::write(directory.path().join("memory.max"), "536870912\n").expect("memory max");
        std::fs::write(directory.path().join("memory.low"), "67108864\n").expect("memory low");
        std::fs::write(directory.path().join("cpu.max"), "50000 100000\n").expect("cpu max");
        let resources: LinuxResources = serde_json::from_value(serde_json::json!({
            "memory": {"swap": 1073741824},
            "cpu": {"period": 200000}
        }))
        .expect("resource update");
        let plan = CgroupUpdatePlan::from_resources(&resources).expect("update plan");

        assert_eq!(
            plan.settings(directory.path(), true)
                .await
                .expect("settings"),
            [
                ("memory.swap.max", "536870912".to_string()),
                ("cpu.max", "50000 200000".to_string()),
            ]
        );

        std::fs::write(directory.path().join("memory.max"), "max\n").expect("unlimited memory");
        assert!(plan.settings(directory.path(), true).await.is_err());
    }

    #[tokio::test]
    async fn updates_exact_workload_and_derived_management_envelope_atomically() {
        let directory = tempfile::tempdir().expect("temporary cgroup topology");
        let management = directory.path().join("management");
        let workload = directory.path().join("workload");
        std::fs::create_dir(&management).expect("management cgroup");
        std::fs::create_dir(&workload).expect("workload cgroup");
        for (path, values) in [
            (
                &management,
                [
                    ("memory.max", "603979776"),
                    ("memory.low", "0"),
                    ("memory.oom.group", "1"),
                    ("memory.swap.max", "536870912"),
                    ("cpu.max", "225000 100000"),
                    ("pids.max", "528"),
                    ("cgroup.procs", ""),
                ],
            ),
            (
                &workload,
                [
                    ("memory.max", "536870912"),
                    ("memory.low", "268435456"),
                    ("memory.oom.group", "0"),
                    ("memory.swap.max", "536870912"),
                    ("cpu.max", "200000 100000"),
                    ("pids.max", "512"),
                    ("cgroup.procs", ""),
                ],
            ),
        ] {
            for (name, value) in values {
                std::fs::write(path.join(name), value).expect("write cgroup fixture");
            }
        }
        let init_procs = std::fs::OpenOptions::new()
            .write(true)
            .open(management.join("cgroup.procs"))
            .expect("outer cgroup.procs");
        let control_procs = init_procs.try_clone().expect("control cgroup.procs");
        let workload_procs = std::fs::OpenOptions::new()
            .write(true)
            .open(workload.join("cgroup.procs"))
            .expect("workload cgroup.procs");
        let handle = CgroupHandle {
            created: Vec::new(),
            leaf: workload.clone(),
            init_procs,
            control_workload: Some(ControlWorkloadCgroup {
                management: management.clone(),
                headroom: ControlHeadroom {
                    memory_bytes: 67_108_864,
                    cpu_quota_micros: 25_000,
                    pids: 16,
                },
                control_procs,
                workload_procs,
            }),
        };
        let resources: LinuxResources = serde_json::from_value(serde_json::json!({
            "memory": {"limit": 268435456, "swap": 536870912},
            "cpu": {"quota": 100000, "period": 100000},
            "pids": {"limit": 256}
        }))
        .expect("resource update");

        handle
            .update(&resources)
            .await
            .expect("control/workload resource update");
        for (path, expected) in [
            (
                &management,
                [
                    ("memory.max", "335544320"),
                    ("memory.oom.group", "1"),
                    ("memory.swap.max", "268435456"),
                    ("cpu.max", "125000 100000"),
                    ("pids.max", "272"),
                ],
            ),
            (
                &workload,
                [
                    ("memory.max", "268435456"),
                    ("memory.oom.group", "0"),
                    ("memory.swap.max", "268435456"),
                    ("cpu.max", "100000 100000"),
                    ("pids.max", "256"),
                ],
            ),
        ] {
            for (name, value) in expected {
                assert_eq!(
                    std::fs::read_to_string(path.join(name)).expect("read updated cgroup value"),
                    value
                );
            }
        }
    }

    #[tokio::test]
    async fn applies_updates_with_exact_read_back() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        std::fs::write(directory.path().join("cpu.weight"), "100\n").expect("cpu weight");
        std::fs::write(directory.path().join("pids.max"), "64\n").expect("pids max");
        apply_update_settings(
            directory.path(),
            vec![
                ("cpu.weight", "39".to_string()),
                ("pids.max", "32".to_string()),
            ],
        )
        .await
        .expect("apply update");
        assert_eq!(
            std::fs::read_to_string(directory.path().join("cpu.weight")).expect("read cpu weight"),
            "39"
        );
        assert_eq!(
            std::fs::read_to_string(directory.path().join("pids.max")).expect("read pids max"),
            "32"
        );
    }

    #[test]
    fn rejects_live_device_updates_before_mutating_any_setting() {
        let resources: LinuxResources = serde_json::from_value(serde_json::json!({
            "devices": [
                {"allow": false, "access": "rwm"}
            ]
        }))
        .expect("live device update resource");

        let error = CgroupUpdatePlan::from_resources(&resources)
            .expect_err("live linux.resources.devices updates must fail");
        assert_eq!(error.code, ErrorCode::Unsupported);
        assert!(error
            .message
            .contains("live linux.resources.devices updates"));
    }
}
