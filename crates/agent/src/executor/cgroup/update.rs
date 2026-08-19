use std::path::{Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::LinuxResources;
use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::hugetlb::HugeTlbPlan;
use super::io::{AppliedBlockIoUpdate, BlockIoPlan};
use super::{
    cgroup_v2_limit_value, normalize_cgroup_value, parse_max_value, parse_u64_value, read_required,
    shares_to_weight, validate_cpuset, validate_memory_value, validate_pids_limit,
    validate_supported_resource_fields, CgroupHandle, CgroupSetting, ControlHeadroom,
};

const UPDATE_OPERATION: &str = "update-container-cgroup";

impl CgroupHandle {
    pub(in crate::executor) async fn update(&mut self, resources: &LinuxResources) -> Result<()> {
        let plan = CgroupUpdatePlan::from_resources(resources)?;
        let next_devices = self.devices.update_from_resources(resources)?;
        let next_device_filter = if self.delegated_device_filter.is_none() {
            match &next_devices {
                Some(plan) => plan.load_cgroup_device_program()?,
                None => None,
            }
        } else {
            None
        };
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
        let prepared_block_io = plan.block_io.prepare_update(&self.leaf).await?;
        let applied = apply_prepared_update_settings(prepared).await?;
        let applied_block_io = match prepared_block_io.apply().await {
            Ok(applied_block_io) => applied_block_io,
            Err(error) => return rollback_update(&applied, None, error).await,
        };

        let Some(next_devices) = next_devices else {
            return Ok(());
        };
        if let Some(device_filter) = &mut self.delegated_device_filter {
            let next_active = next_devices.has_device_filter();
            let result = match (device_filter.active, next_active) {
                (false, false) => Ok(()),
                (false, true) => device_filter.authority.install(
                    &device_filter.key,
                    &device_filter.relative_cgroup,
                    &next_devices,
                ),
                (true, true) => device_filter
                    .authority
                    .replace(&device_filter.key, &next_devices),
                (true, false) => device_filter.authority.remove(&device_filter.key),
            };
            if let Err(error) = result {
                return rollback_update(&applied, Some(&applied_block_io), error).await;
            }
            self.devices = next_devices;
            device_filter.active = next_active;
            return Ok(());
        }
        let device_update = match (&self.device_filter, &next_device_filter) {
            (Some(current), Some(next)) => next_devices.replace_loaded_cgroup_device_program(
                &self.device_filter_path,
                next,
                current,
            ),
            (None, Some(next)) => {
                next_devices.attach_loaded_cgroup_device_program(&self.device_filter_path, next)
            }
            (Some(current), None) => self
                .devices
                .detach_loaded_cgroup_device_program(&self.device_filter_path, current),
            (None, None) => Ok(()),
        };
        if let Err(error) = device_update {
            return rollback_update(&applied, Some(&applied_block_io), error).await;
        }
        self.devices = next_devices;
        self.device_filter = next_device_filter;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CgroupUpdatePlan {
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
    huge_tlb: HugeTlbPlan,
}

impl CgroupUpdatePlan {
    fn from_resources(resources: &LinuxResources) -> Result<Self> {
        validate_supported_resource_fields(resources)?;
        let memory = resources.memory().as_ref();
        let cpu = resources.cpu().as_ref();
        let pids = resources.pids().as_ref();
        let block_io =
            BlockIoPlan::from_oci(resources.block_io().as_ref()).map_err(as_update_error)?;
        let huge_tlb = HugeTlbPlan::from_oci(resources.hugepage_limits().as_deref())
            .map_err(as_update_error)?;
        let plan = Self {
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
            huge_tlb,
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
                validate_memory_value(field, value).map_err(as_update_error)?;
            }
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
        if self.cpu_burst.is_some_and(|burst| {
            self.cpu_quota
                .is_some_and(|quota| quota > 0 && burst > quota as u64)
        }) {
            return Err(update_invalid(
                "linux.resources.cpu.burst must not exceed a positive CPU quota",
            ));
        }
        if self.cpu_idle.is_some_and(|value| !matches!(value, 0 | 1)) {
            return Err(update_invalid("linux.resources.cpu.idle must be 0 or 1"));
        }
        for (field, value) in [
            ("linux.resources.cpu.cpus", self.cpuset_cpus.as_deref()),
            ("linux.resources.cpu.mems", self.cpuset_mems.as_deref()),
        ] {
            if let Some(value) = value {
                validate_cpuset(field, value).map_err(as_update_error)?;
            }
        }
        if let Some(value) = self.pids_limit {
            validate_pids_limit(value).map_err(as_update_error)?;
        }
        Ok(())
    }

    fn management_plan(&self, headroom: &ControlHeadroom) -> Result<Self> {
        let mut management = self.clone();
        management.memory_limit = self
            .memory_limit
            .map(|value| {
                if value == -1 {
                    return Err(update_invalid(
                        "control/workload cgroup layout requires a finite memory limit",
                    ));
                }
                value
                    .checked_add(headroom.memory_bytes)
                    .ok_or_else(|| update_invalid("control-plane memory envelope overflows i64"))
            })
            .transpose()?;
        management.memory_reservation = None;
        management.block_io = BlockIoPlan::default();
        management.huge_tlb = HugeTlbPlan::default();
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
        management.cpu_burst = None;
        management.cpu_idle = None;
        management.pids_limit = self
            .pids_limit
            .map(|value| {
                if value == -1 {
                    return Err(update_invalid(
                        "control/workload cgroup layout requires a finite PID limit",
                    ));
                }
                value
                    .checked_add(headroom.pids)
                    .ok_or_else(|| update_invalid("control-plane PID envelope overflows i64"))
            })
            .transpose()?;
        Ok(management)
    }

    async fn settings(&self, path: &Path, oom_group: bool) -> Result<Vec<CgroupSetting>> {
        let mut settings = Vec::new();
        if let Some(value) = &self.cpuset_mems {
            settings.push(CgroupSetting::new("cpuset.mems", value.clone()));
        }
        if let Some(value) = &self.cpuset_cpus {
            settings.push(CgroupSetting::new("cpuset.cpus", value.clone()));
        }

        let changes_memory = self.memory_limit.is_some()
            || self.memory_reservation.is_some()
            || self.memory_swap.is_some();
        if changes_memory {
            let current_max_text = read_required(path, "memory.max", UPDATE_OPERATION).await?;
            let current_max =
                parse_max_value("memory.max", &current_max_text).map_err(as_update_error)?;
            let effective_max = match self.memory_limit {
                Some(-1) => None,
                Some(limit) => Some(u64::try_from(limit).map_err(|error| {
                    update_invalid(format!("memory limit does not fit cgroup v2: {error}"))
                })?),
                None => current_max,
            };
            let new_max = self.memory_limit.map(cgroup_v2_limit_value);
            let new_low = self.memory_reservation.map(cgroup_v2_limit_value);
            match (new_max, new_low) {
                (Some(max), Some(low)) => {
                    let lowers_finite_limit = match (current_max, effective_max) {
                        (_, None) => false,
                        (None, Some(_)) => true,
                        (Some(current), Some(next)) => next < current,
                    };
                    if lowers_finite_limit {
                        settings.push(CgroupSetting::new("memory.low", low));
                        settings.push(CgroupSetting::new("memory.max", max));
                    } else {
                        settings.push(CgroupSetting::new("memory.max", max));
                        settings.push(CgroupSetting::new("memory.low", low));
                    }
                }
                (Some(max), None) => settings.push(CgroupSetting::new("memory.max", max)),
                (None, Some(low)) => settings.push(CgroupSetting::new("memory.low", low)),
                (None, None) => {}
            }
            if self.memory_limit.is_some() {
                settings.push(CgroupSetting::new(
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
                settings.push(CgroupSetting::new("memory.swap.max", swap_only));
            }
        }

        if self.cpu_quota.is_some() || self.cpu_period.is_some() || self.cpu_burst.is_some() {
            let current = read_required(path, "cpu.max", UPDATE_OPERATION).await?;
            let (current_quota, current_period) = parse_cpu_max(&current)?;
            let current_quota_value = parse_cpu_quota(&current_quota)?;
            let effective_quota = match self.cpu_quota {
                Some(-1) => None,
                Some(value) => Some(u64::try_from(value).map_err(|error| {
                    update_invalid(format!("CPU quota does not fit cgroup v2: {error}"))
                })?),
                None => current_quota_value,
            };
            let current_burst = match tokio::fs::read_to_string(path.join("cpu.max.burst")).await {
                Ok(value) => parse_u64_value("cpu.max.burst", &value).map_err(as_update_error)?,
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound && self.cpu_burst.is_none() =>
                {
                    0
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(update_error(
                        ErrorCode::Unsupported,
                        "cgroup v2 CPU burst control is unavailable",
                    ));
                }
                Err(error) => {
                    return Err(update_error(
                        ErrorCode::FailedPrecondition,
                        format!("failed to read cgroup CPU burst control: {error}"),
                    ));
                }
            };
            let effective_burst = self.cpu_burst.unwrap_or(current_burst);
            if effective_quota.is_some_and(|quota| effective_burst > quota) {
                return Err(update_invalid(format!(
                    "linux.resources.cpu.burst {effective_burst} exceeds the effective positive CPU quota {}",
                    effective_quota.unwrap_or_default()
                )));
            }
            let quota = match self.cpu_quota {
                Some(-1) => "max".to_string(),
                Some(value) => value.to_string(),
                None => current_quota,
            };
            let period = self.cpu_period.unwrap_or(current_period);
            let max = CgroupSetting::new("cpu.max", format!("{quota} {period}"));
            let burst = self
                .cpu_burst
                .map(|value| CgroupSetting::new("cpu.max.burst", value.to_string()));
            if effective_quota.is_some_and(|quota| current_burst > quota) {
                if let Some(burst) = burst {
                    settings.push(burst);
                }
                if self.cpu_quota.is_some() || self.cpu_period.is_some() {
                    settings.push(max);
                }
            } else {
                if self.cpu_quota.is_some() || self.cpu_period.is_some() {
                    settings.push(max);
                }
                if let Some(burst) = burst {
                    settings.push(burst);
                }
            }
        }
        if let Some(shares) = self.cpu_shares {
            settings.push(CgroupSetting::new(
                "cpu.weight",
                shares_to_weight(shares).to_string(),
            ));
        }
        if let Some(idle) = self.cpu_idle {
            settings.push(CgroupSetting::new("cpu.idle", idle.to_string()));
        }
        if let Some(value) = self.pids_limit {
            settings.push(CgroupSetting::new("pids.max", cgroup_v2_limit_value(value)));
        }
        settings.extend(
            self.huge_tlb
                .settings_async(path)
                .await
                .map_err(as_update_error)?,
        );
        Ok(settings)
    }
}

#[cfg(test)]
async fn apply_update_settings(path: &Path, settings: Vec<CgroupSetting>) -> Result<()> {
    let prepared = prepare_update_settings(path, settings).await?;
    apply_prepared_update_settings(prepared).await.map(|_| ())
}

#[derive(Debug)]
struct PreparedUpdateSetting {
    path: PathBuf,
    setting: CgroupSetting,
    old: String,
}

async fn prepare_update_settings(
    path: &Path,
    settings: Vec<CgroupSetting>,
) -> Result<Vec<PreparedUpdateSetting>> {
    let mut prepared = Vec::with_capacity(settings.len());
    for setting in settings {
        let old = read_required(path, setting.file(), UPDATE_OPERATION).await?;
        prepared.push(PreparedUpdateSetting {
            path: path.to_path_buf(),
            setting,
            old: normalize_cgroup_value(&old),
        });
    }
    Ok(prepared)
}

#[derive(Debug)]
struct AppliedUpdateSetting {
    path: PathBuf,
    file: String,
    old: String,
}

async fn apply_prepared_update_settings(
    prepared: Vec<PreparedUpdateSetting>,
) -> Result<Vec<AppliedUpdateSetting>> {
    let mut applied = Vec::new();
    for setting in prepared {
        if normalize_cgroup_value(setting.setting.value()) == setting.old {
            continue;
        }
        let destination = setting.path.join(setting.setting.file());
        let expected = setting.setting.value().to_string();
        if let Err(error) = tokio::fs::write(&destination, expected.as_bytes()).await {
            return rollback_update(
                &applied,
                None,
                update_error(
                    ErrorCode::PermissionDenied,
                    format!(
                        "failed to apply cgroup setting {}={}: {error}",
                        destination.display(),
                        setting.setting.value(),
                    ),
                ),
            )
            .await
            .map(|()| applied);
        }
        let (file, _) = setting.setting.into_parts();
        applied.push(AppliedUpdateSetting {
            path: setting.path,
            file,
            old: setting.old,
        });
        let actual = match tokio::fs::read_to_string(&destination).await {
            Ok(actual) => actual,
            Err(error) => {
                return rollback_update(
                    &applied,
                    None,
                    update_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "failed to verify cgroup setting {}: {error}",
                            destination.display()
                        ),
                    ),
                )
                .await
                .map(|()| applied);
            }
        };
        if normalize_cgroup_value(&actual) != normalize_cgroup_value(&expected) {
            return rollback_update(
                &applied,
                None,
                update_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "cgroup setting {} read back differently",
                        destination.display()
                    ),
                ),
            )
            .await
            .map(|()| applied);
        }
    }
    Ok(applied)
}

async fn rollback_update(
    applied: &[AppliedUpdateSetting],
    block_io: Option<&AppliedBlockIoUpdate>,
    original: Error,
) -> Result<()> {
    let mut failures = match block_io {
        Some(block_io) => block_io.rollback().await,
        None => Vec::new(),
    };
    for setting in applied.iter().rev() {
        let destination = setting.path.join(&setting.file);
        if let Err(error) = tokio::fs::write(&destination, setting.old.as_bytes()).await {
            failures.push(format!("{}: {error}", destination.display()));
            continue;
        }
        match tokio::fs::read_to_string(&destination).await {
            Ok(actual) if normalize_cgroup_value(&actual) == setting.old => {}
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

fn parse_cpu_quota(value: &str) -> Result<Option<u64>> {
    if value == "max" {
        Ok(None)
    } else {
        value
            .parse::<u64>()
            .map(Some)
            .map_err(|error| update_invalid(format!("cpu.max quota is invalid: {error}")))
    }
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

    use super::{
        apply_update_settings, rollback_update, update_error, AppliedUpdateSetting,
        CgroupUpdatePlan,
    };
    use crate::executor::cgroup::{
        CgroupHandle, CgroupSetting, ControlHeadroom, ControlWorkloadCgroup,
    };

    #[tokio::test]
    async fn resolves_partial_updates_against_current_cgroup_values() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        std::fs::write(directory.path().join("memory.max"), "536870912\n").expect("memory max");
        std::fs::write(directory.path().join("memory.low"), "67108864\n").expect("memory low");
        std::fs::write(directory.path().join("cpu.max"), "50000 100000\n").expect("cpu max");
        std::fs::write(directory.path().join("cpu.max.burst"), "5000\n").expect("CPU burst");
        std::fs::write(directory.path().join("cpu.idle"), "0\n").expect("CPU idle");
        let resources: LinuxResources = serde_json::from_value(serde_json::json!({
            "memory": {"swap": 1073741824},
            "cpu": {"period": 200000, "burst": 10000, "idle": 1}
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
                ("cpu.max.burst", "10000".to_string()),
                ("cpu.idle", "1".to_string()),
            ]
        );

        std::fs::write(directory.path().join("memory.max"), "max\n").expect("unlimited memory");
        assert!(plan.settings(directory.path(), true).await.is_err());
    }

    #[tokio::test]
    async fn plans_zero_and_unlimited_memory_updates() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        std::fs::write(directory.path().join("memory.max"), "536870912\n").expect("memory max");
        std::fs::write(directory.path().join("memory.low"), "67108864\n").expect("memory low");

        for (value, expected) in [(0, "0"), (-1, "max")] {
            let resources: LinuxResources = serde_json::from_value(serde_json::json!({
                "memory": {
                    "limit": value,
                    "reservation": value,
                    "swap": value
                }
            }))
            .expect("memory resource update");
            let plan =
                CgroupUpdatePlan::from_resources(&resources).expect("valid memory update plan");

            let settings = plan
                .settings(directory.path(), true)
                .await
                .expect("memory update settings");
            assert!(settings.contains(&CgroupSetting::new("memory.max", expected)));
            assert!(settings.contains(&CgroupSetting::new("memory.low", expected)));
            assert!(settings.contains(&CgroupSetting::new("memory.swap.max", expected)));
            assert!(settings.contains(&CgroupSetting::new("memory.oom.group", "1")));
        }
    }

    #[tokio::test]
    async fn partial_memory_update_accepts_an_unlimited_current_reservation() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        std::fs::write(directory.path().join("memory.max"), "536870912\n").expect("memory max");
        std::fs::write(directory.path().join("memory.low"), "max\n").expect("memory low");
        let resources: LinuxResources = serde_json::from_value(serde_json::json!({
            "memory": {"swap": 1073741824}
        }))
        .expect("memory swap update");

        assert_eq!(
            CgroupUpdatePlan::from_resources(&resources)
                .expect("valid memory update plan")
                .settings(directory.path(), true)
                .await
                .expect("partial memory update"),
            [("memory.swap.max", "536870912".to_string())]
        );
    }

    #[test]
    fn rejects_memory_update_values_below_the_unlimited_sentinel() {
        for field in ["limit", "reservation", "swap"] {
            let resources: LinuxResources = serde_json::from_value(serde_json::json!({
                "memory": {field: -2}
            }))
            .expect("invalid memory resource update");
            let error = CgroupUpdatePlan::from_resources(&resources)
                .expect_err("a memory update below -1 must fail planning");

            assert_eq!(error.code, a3s_oci_sdk::ErrorCode::InvalidArgument);
            assert!(error.message.contains("-1 or non-negative"));
        }
    }

    #[test]
    fn rejects_unsupported_memory_update_controls() {
        for (field, value) in [
            ("kernel", serde_json::json!(1)),
            ("kernelTCP", serde_json::json!(1)),
            ("swappiness", serde_json::json!(50)),
            ("disableOOMKiller", serde_json::json!(true)),
            ("useHierarchy", serde_json::json!(true)),
            ("checkBeforeUpdate", serde_json::json!(true)),
        ] {
            let resources: LinuxResources = serde_json::from_value(serde_json::json!({
                "memory": {field: value}
            }))
            .expect("unsupported memory resource update");
            let error = CgroupUpdatePlan::from_resources(&resources)
                .expect_err("unsupported cgroup v1 memory update must fail planning");

            assert_eq!(error.code, a3s_oci_sdk::ErrorCode::Unsupported);
            assert!(error
                .message
                .contains(&format!("linux.resources.memory.{field}")));
        }
    }

    #[test]
    fn control_workload_updates_accept_zero_but_reject_unlimited_memory() {
        let headroom = ControlHeadroom {
            memory_bytes: 67_108_864,
            cpu_quota_micros: 25_000,
            pids: 16,
        };
        let zero: LinuxResources = serde_json::from_value(serde_json::json!({
            "memory": {"limit": 0}
        }))
        .expect("zero-memory resource update");
        let management = CgroupUpdatePlan::from_resources(&zero)
            .expect("zero-memory update plan")
            .management_plan(&headroom)
            .expect("zero-memory management envelope");
        assert_eq!(management.memory_limit, Some(67_108_864));

        let unlimited: LinuxResources = serde_json::from_value(serde_json::json!({
            "memory": {"limit": -1}
        }))
        .expect("unlimited-memory resource update");
        let error = CgroupUpdatePlan::from_resources(&unlimited)
            .expect("unlimited memory is valid for a flat cgroup")
            .management_plan(&headroom)
            .expect_err("control/workload update must retain a finite memory limit");
        assert_eq!(error.code, a3s_oci_sdk::ErrorCode::InvalidArgument);
        assert!(error.message.contains("finite memory limit"));
    }

    #[tokio::test]
    async fn orders_cpu_quota_and_burst_updates_without_transient_invalid_state() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        std::fs::write(directory.path().join("cpu.max"), "100000 100000\n").expect("CPU max");
        std::fs::write(directory.path().join("cpu.max.burst"), "80000\n").expect("CPU burst");

        let lower: LinuxResources = serde_json::from_value(serde_json::json!({
            "cpu": {"quota": 50000, "burst": 40000}
        }))
        .expect("lower CPU update");
        assert_eq!(
            CgroupUpdatePlan::from_resources(&lower)
                .expect("lower plan")
                .settings(directory.path(), true)
                .await
                .expect("lower settings"),
            [
                ("cpu.max.burst", "40000".to_string()),
                ("cpu.max", "50000 100000".to_string()),
            ]
        );

        std::fs::write(directory.path().join("cpu.max"), "50000 100000\n")
            .expect("lowered CPU max");
        std::fs::write(directory.path().join("cpu.max.burst"), "40000\n")
            .expect("lowered CPU burst");
        let raise: LinuxResources = serde_json::from_value(serde_json::json!({
            "cpu": {"quota": 100000, "burst": 80000}
        }))
        .expect("raise CPU update");
        assert_eq!(
            CgroupUpdatePlan::from_resources(&raise)
                .expect("raise plan")
                .settings(directory.path(), true)
                .await
                .expect("raise settings"),
            [
                ("cpu.max", "100000 100000".to_string()),
                ("cpu.max.burst", "80000".to_string()),
            ]
        );

        let invalid: LinuxResources = serde_json::from_value(serde_json::json!({
            "cpu": {"quota": 30000}
        }))
        .expect("invalid CPU update");
        assert!(CgroupUpdatePlan::from_resources(&invalid)
            .expect("syntactically valid update")
            .settings(directory.path(), true)
            .await
            .expect_err("effective burst above the new quota must fail")
            .message
            .contains("burst"));
    }

    #[tokio::test]
    async fn rejects_an_unavailable_cpu_burst_control() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        std::fs::write(directory.path().join("cpu.max"), "50000 100000\n").expect("CPU max");
        let resources: LinuxResources = serde_json::from_value(serde_json::json!({
            "cpu": {"burst": 10000}
        }))
        .expect("CPU burst update");

        let error = CgroupUpdatePlan::from_resources(&resources)
            .expect("CPU burst update plan")
            .settings(directory.path(), true)
            .await
            .expect_err("a missing CPU burst control must fail");
        assert_eq!(error.code, a3s_oci_sdk::ErrorCode::Unsupported);
        assert!(error.message.contains("burst"));
    }

    #[tokio::test]
    async fn plans_zero_and_unlimited_pids_updates() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        for (limit, expected) in [(0, "0"), (-1, "max")] {
            let resources: LinuxResources = serde_json::from_value(serde_json::json!({
                "pids": {"limit": limit}
            }))
            .expect("PIDs resource update");
            let plan = CgroupUpdatePlan::from_resources(&resources).expect("valid PIDs update");

            assert_eq!(
                plan.settings(directory.path(), true)
                    .await
                    .expect("PIDs update settings"),
                [("pids.max", expected.to_string())]
            );
        }
    }

    #[test]
    fn plans_block_io_updates_only_for_the_workload_leaf() {
        let resources: LinuxResources = serde_json::from_value(serde_json::json!({
            "blockIO": {
                "weight": 500,
                "weightDevice": [{"major": 8, "minor": 0, "weight": 250}],
                "throttleReadBpsDevice": [{"major": 8, "minor": 0, "rate": 1048576}],
                "throttleWriteIOPSDevice": [{"major": 8, "minor": 16, "rate": 200}]
            }
        }))
        .expect("block I/O update");
        let plan = CgroupUpdatePlan::from_resources(&resources).expect("block I/O update plan");
        let management = plan
            .management_plan(&ControlHeadroom {
                memory_bytes: 64 * 1024 * 1024,
                cpu_quota_micros: 25_000,
                pids: 16,
            })
            .expect("management plan");

        assert!(!plan.block_io.is_empty());
        assert!(management.block_io.is_empty());
    }

    #[tokio::test]
    async fn updates_only_requested_hugetlb_page_sizes_and_reservation_controls() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        for (file, value) in [
            ("hugetlb.2MB.max", "104857600\n"),
            ("hugetlb.2MB.rsvd.max", "104857600\n"),
            ("hugetlb.1GB.max", "2147483648\n"),
            ("hugetlb.1GB.rsvd.max", "2147483648\n"),
        ] {
            std::fs::write(directory.path().join(file), value).expect("HugeTLB control");
        }
        let resources: LinuxResources = serde_json::from_value(serde_json::json!({
            "hugepageLimits": [
                {"pageSize": "2MB", "limit": 209715200}
            ]
        }))
        .expect("HugeTLB update");
        let plan = CgroupUpdatePlan::from_resources(&resources).expect("HugeTLB update plan");
        let settings = plan
            .settings(directory.path(), true)
            .await
            .expect("HugeTLB update settings");
        assert_eq!(
            settings,
            [
                CgroupSetting::new("hugetlb.2MB.max", "209715200"),
                CgroupSetting::new("hugetlb.2MB.rsvd.max", "209715200"),
            ]
        );

        apply_update_settings(directory.path(), settings)
            .await
            .expect("apply HugeTLB update");
        assert_eq!(
            std::fs::read_to_string(directory.path().join("hugetlb.2MB.max"))
                .expect("updated usage limit"),
            "209715200"
        );
        assert_eq!(
            std::fs::read_to_string(directory.path().join("hugetlb.2MB.rsvd.max"))
                .expect("updated reservation limit"),
            "209715200"
        );
        assert_eq!(
            std::fs::read_to_string(directory.path().join("hugetlb.1GB.max"))
                .expect("preserved omitted usage limit"),
            "2147483648\n"
        );
        assert_eq!(
            std::fs::read_to_string(directory.path().join("hugetlb.1GB.rsvd.max"))
                .expect("preserved omitted reservation limit"),
            "2147483648\n"
        );
    }

    #[test]
    fn plans_hugetlb_updates_only_for_the_workload_leaf() {
        let resources: LinuxResources = serde_json::from_value(serde_json::json!({
            "hugepageLimits": [
                {"pageSize": "2MB", "limit": 209715200}
            ]
        }))
        .expect("HugeTLB update");
        let plan = CgroupUpdatePlan::from_resources(&resources).expect("HugeTLB update plan");
        let management = plan
            .management_plan(&ControlHeadroom {
                memory_bytes: 64 * 1024 * 1024,
                cpu_quota_micros: 25_000,
                pids: 16,
            })
            .expect("management plan");

        assert!(!plan.huge_tlb.is_empty());
        assert!(management.huge_tlb.is_empty());
    }

    #[test]
    fn rejects_pids_updates_below_the_unlimited_sentinel() {
        let resources: LinuxResources = serde_json::from_value(serde_json::json!({
            "pids": {"limit": -2}
        }))
        .expect("invalid PIDs resource update");
        let error = CgroupUpdatePlan::from_resources(&resources)
            .expect_err("a PIDs update below -1 must fail planning");

        assert_eq!(error.code, a3s_oci_sdk::ErrorCode::InvalidArgument);
        assert!(error.message.contains("-1 or non-negative"));
    }

    #[test]
    fn control_workload_updates_accept_zero_but_reject_unlimited_pids() {
        let headroom = ControlHeadroom {
            memory_bytes: 67_108_864,
            cpu_quota_micros: 25_000,
            pids: 16,
        };
        let zero: LinuxResources = serde_json::from_value(serde_json::json!({
            "pids": {"limit": 0}
        }))
        .expect("zero-PIDs resource update");
        let management = CgroupUpdatePlan::from_resources(&zero)
            .expect("zero-PIDs update plan")
            .management_plan(&headroom)
            .expect("zero-PIDs management envelope");
        assert_eq!(management.pids_limit, Some(16));

        let unlimited: LinuxResources = serde_json::from_value(serde_json::json!({
            "pids": {"limit": -1}
        }))
        .expect("unlimited-PIDs resource update");
        let error = CgroupUpdatePlan::from_resources(&unlimited)
            .expect("unlimited PIDs is valid for a flat cgroup")
            .management_plan(&headroom)
            .expect_err("control/workload update must retain a finite PIDs limit");
        assert_eq!(error.code, a3s_oci_sdk::ErrorCode::InvalidArgument);
        assert!(error.message.contains("finite PID limit"));
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
                    ("cpu.max.burst", "5000"),
                    ("cpu.idle", "0"),
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
                    ("cpu.max.burst", "10000"),
                    ("cpu.idle", "0"),
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
        let mut handle = CgroupHandle {
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
            devices: super::super::DevicePlan::default(),
            device_filter_path: management.clone(),
            device_filter: None,
            delegated_device_filter: None,
        };
        let resources: LinuxResources = serde_json::from_value(serde_json::json!({
            "memory": {"limit": 268435456, "swap": 536870912},
            "cpu": {"quota": 100000, "burst": 20000, "period": 100000, "idle": 1},
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
                    ("cpu.max.burst", "5000"),
                    ("cpu.idle", "0"),
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
                    ("cpu.max.burst", "20000"),
                    ("cpu.idle", "1"),
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
                CgroupSetting::new("cpu.weight", "39"),
                CgroupSetting::new("pids.max", "32"),
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

    #[tokio::test]
    async fn rolls_back_owned_dynamic_cgroup_settings_in_reverse_order() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        let file = "hugetlb.2MB.rsvd.max";
        std::fs::write(directory.path().join(file), "30").expect("current HugeTLB limit");
        let applied = vec![
            AppliedUpdateSetting {
                path: directory.path().to_path_buf(),
                file: file.to_string(),
                old: "10".to_string(),
            },
            AppliedUpdateSetting {
                path: directory.path().to_path_buf(),
                file: file.to_string(),
                old: "20".to_string(),
            },
        ];
        let error = rollback_update(
            &applied,
            None,
            update_error(ErrorCode::PermissionDenied, "synthetic update failure"),
        )
        .await
        .expect_err("rollback returns the original update failure");

        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert_eq!(
            std::fs::read_to_string(directory.path().join(file)).expect("rolled-back limit"),
            "10",
            "reverse rollback must restore the oldest retained value last"
        );
    }

    #[test]
    fn accepts_live_device_updates_for_the_fenced_filter_transition() {
        let resources: LinuxResources = serde_json::from_value(serde_json::json!({
            "devices": [
                {"allow": false, "access": "rwm"}
            ]
        }))
        .expect("live device update resource");

        let plan = CgroupUpdatePlan::from_resources(&resources)
            .expect("the retained device filter handles device-policy updates");
        assert_eq!(plan, CgroupUpdatePlan::default());
    }
}
