use std::collections::BTreeSet;
use std::io;
use std::mem::{size_of, zeroed};

use a3s_oci_sdk::oci_spec::runtime::ExecCPUAffinity;
use a3s_oci_sdk::{Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};

const MAX_AFFINITY_STRING_BYTES: usize = 16 * 1024;

/// Validated CPU sets applied around an exec process cgroup transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CpuAffinityPlan {
    initial: Option<CpuSetPlan>,
    #[serde(rename = "final")]
    final_set: Option<CpuSetPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CpuSetPlan {
    cpus: Vec<usize>,
}

impl CpuAffinityPlan {
    pub(super) fn from_oci(value: Option<&ExecCPUAffinity>) -> Result<Option<Self>> {
        let Some(value) = value else {
            return Ok(None);
        };
        let initial = CpuSetPlan::optional(
            value.initial().as_deref(),
            "process.execCPUAffinity.initial",
        )?;
        let final_set = CpuSetPlan::optional(
            value.cpu_affinity_final().as_deref(),
            "process.execCPUAffinity.final",
        )?;
        if initial.is_none() && final_set.is_none() {
            Ok(None)
        } else {
            Ok(Some(Self { initial, final_set }))
        }
    }

    fn apply_initial(&self) -> Result<()> {
        self.initial
            .as_ref()
            .map_or(Ok(()), |cpus| cpus.apply("initial"))
    }

    fn apply_final(&self) -> Result<()> {
        self.final_set
            .as_ref()
            .map_or(Ok(()), |cpus| cpus.apply("final"))
    }
}

impl CpuSetPlan {
    fn optional(value: Option<&str>, field: &str) -> Result<Option<Self>> {
        match value {
            None | Some("") => Ok(None),
            Some(value) => Self::parse(value, field).map(Some),
        }
    }

    fn parse(value: &str, field: &str) -> Result<Self> {
        if value.len() > MAX_AFFINITY_STRING_BYTES {
            return Err(affinity_error(
                ErrorCode::ResourceExhausted,
                format!(
                    "{field} is {} bytes; maximum is {MAX_AFFINITY_STRING_BYTES}",
                    value.len()
                ),
                "plan-exec-cpu-affinity",
            ));
        }
        let mut cpus = BTreeSet::new();
        for component in value.split(',') {
            let mut bounds = component.split('-');
            let start = parse_cpu(bounds.next().unwrap_or_default(), field)?;
            let end = bounds
                .next()
                .map(|value| parse_cpu(value, field))
                .transpose()?
                .unwrap_or(start);
            if bounds.next().is_some() || start > end {
                return Err(affinity_error(
                    ErrorCode::InvalidArgument,
                    format!("{field} contains invalid descending range `{component}`"),
                    "plan-exec-cpu-affinity",
                ));
            }
            for cpu in start..=end {
                cpus.insert(cpu);
            }
        }
        if cpus.is_empty() {
            return Err(affinity_error(
                ErrorCode::InvalidArgument,
                format!("{field} must select at least one CPU"),
                "plan-exec-cpu-affinity",
            ));
        }
        Ok(Self {
            cpus: cpus.into_iter().collect(),
        })
    }

    fn apply(&self, phase: &str) -> Result<()> {
        let requested = self.raw_set()?;
        // SAFETY: the mask has the exact Linux `cpu_set_t` size and the zero
        // PID selects only this trusted single-threaded exec helper.
        if unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &requested) } != 0 {
            let source = io::Error::last_os_error();
            return Err(affinity_error(
                error_code_for_io(&source),
                format!(
                    "failed to apply process.execCPUAffinity.{phase} {}: {source}",
                    self.display()
                ),
                "apply-exec-cpu-affinity",
            ));
        }
        let actual = current_cpu_ids().map_err(|source| {
            affinity_error(
                error_code_for_io(&source),
                format!(
                    "failed to read back process.execCPUAffinity.{phase} {}: {source}",
                    self.display()
                ),
                "apply-exec-cpu-affinity",
            )
        })?;
        if actual != self.cpus {
            return Err(affinity_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "process.execCPUAffinity.{phase} read-back mismatch: requested {}, observed {}",
                    self.display(),
                    display_cpu_ids(&actual)
                ),
                "apply-exec-cpu-affinity",
            ));
        }
        Ok(())
    }

    fn raw_set(&self) -> Result<libc::cpu_set_t> {
        // SAFETY: all-zero is the required initial representation of cpu_set_t.
        let mut set = unsafe { zeroed::<libc::cpu_set_t>() };
        // SAFETY: `set` is a live cpu_set_t and every CPU is bounds-checked.
        unsafe { libc::CPU_ZERO(&mut set) };
        for cpu in &self.cpus {
            validate_cpu(*cpu, "serialized process.execCPUAffinity")?;
            // SAFETY: the CPU index is strictly below CPU_SETSIZE.
            unsafe { libc::CPU_SET(*cpu, &mut set) };
        }
        Ok(set)
    }

    fn display(&self) -> String {
        display_cpu_ids(&self.cpus)
    }
}

pub(super) fn apply_initial(plan: Option<&CpuAffinityPlan>) -> Result<()> {
    plan.map_or(Ok(()), CpuAffinityPlan::apply_initial)
}

pub(super) fn apply_final(plan: Option<&CpuAffinityPlan>) -> Result<()> {
    plan.map_or(Ok(()), CpuAffinityPlan::apply_final)
}

fn parse_cpu(value: &str, field: &str) -> Result<usize> {
    let cpu = value.parse::<usize>().map_err(|_| {
        affinity_error(
            ErrorCode::InvalidArgument,
            format!("{field} contains invalid CPU `{value}`"),
            "plan-exec-cpu-affinity",
        )
    })?;
    validate_cpu(cpu, field)?;
    Ok(cpu)
}

fn validate_cpu(cpu: usize, field: &str) -> Result<()> {
    let limit = libc::CPU_SETSIZE as usize;
    if cpu >= limit {
        return Err(affinity_error(
            ErrorCode::Unsupported,
            format!(
                "{field} CPU {cpu} exceeds this runtime mask limit {}",
                limit - 1
            ),
            "plan-exec-cpu-affinity",
        ));
    }
    Ok(())
}

fn current_cpu_ids() -> io::Result<Vec<usize>> {
    // SAFETY: all-zero is the required initial representation of cpu_set_t.
    let mut set = unsafe { zeroed::<libc::cpu_set_t>() };
    // SAFETY: the kernel writes at most the supplied cpu_set_t size and the
    // zero PID selects only the calling thread.
    if unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut set) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut cpus = Vec::new();
    for cpu in 0..libc::CPU_SETSIZE as usize {
        // SAFETY: the CPU index is strictly below CPU_SETSIZE.
        if unsafe { libc::CPU_ISSET(cpu, &set) } {
            cpus.push(cpu);
        }
    }
    if cpus.is_empty() {
        Err(io::Error::from_raw_os_error(libc::EPROTO))
    } else {
        Ok(cpus)
    }
}

fn display_cpu_ids(cpus: &[usize]) -> String {
    cpus.iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn error_code_for_io(source: &io::Error) -> ErrorCode {
    match source.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => ErrorCode::PermissionDenied,
        Some(libc::EINVAL) => ErrorCode::InvalidArgument,
        Some(libc::ESRCH) => ErrorCode::FailedPrecondition,
        Some(libc::ENOSYS | libc::EOPNOTSUPP) => ErrorCode::Unsupported,
        _ => ErrorCode::Internal,
    }
}

fn affinity_error(code: ErrorCode, message: impl Into<String>, operation: &'static str) -> Error {
    Error::new(code, message).for_operation(operation)
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use a3s_oci_sdk::oci_spec::runtime::ExecCPUAffinity;
    use a3s_oci_sdk::ErrorCode;

    use super::{apply_final, apply_initial, current_cpu_ids, CpuAffinityPlan, CpuSetPlan};

    const CHILD_PROBE: &str = "A3S_OCI_CPU_AFFINITY_CHILD_PROBE";
    const APPLY_TEST: &str =
        "executor::cpu_affinity::tests::applies_exact_affinity_in_an_isolated_process";

    fn affinity(value: serde_json::Value) -> ExecCPUAffinity {
        let process = a3s_oci_sdk::process_serde::decode(serde_json::json!({
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/true"],
            "cwd": "/",
            "execCPUAffinity": value,
            "noNewPrivileges": true
        }))
        .expect("decode exec CPU affinity");
        process
            .exec_cpu_affinity()
            .clone()
            .expect("decoded exec CPU affinity")
    }

    #[test]
    fn plans_canonical_initial_and_final_cpu_sets() {
        let plan = CpuAffinityPlan::from_oci(Some(&affinity(serde_json::json!({
            "initial": "3,1-2,2",
            "final": "0"
        }))))
        .expect("plan CPU affinity")
        .expect("present CPU affinity");
        assert_eq!(plan.initial.expect("initial set").cpus, [1, 2, 3]);
        assert_eq!(plan.final_set.expect("final set").cpus, [0]);

        let empty = CpuAffinityPlan::from_oci(Some(&affinity(serde_json::json!({}))))
            .expect("plan empty CPU affinity");
        assert!(empty.is_none());
    }

    #[test]
    fn rejects_descending_and_unrepresentable_cpu_sets_before_mutation() {
        let descending = CpuAffinityPlan::from_oci(Some(&affinity(serde_json::json!({
            "initial": "3-1"
        }))))
        .expect_err("descending range must fail");
        assert_eq!(descending.code, ErrorCode::InvalidArgument);

        let unrepresentable = CpuAffinityPlan::from_oci(Some(&affinity(serde_json::json!({
            "final": (libc::CPU_SETSIZE as usize).to_string()
        }))))
        .expect_err("unrepresentable CPU must fail");
        assert_eq!(unrepresentable.code, ErrorCode::Unsupported);
    }

    #[test]
    fn applies_exact_affinity_in_an_isolated_process() {
        if std::env::var_os(CHILD_PROBE).is_some() {
            let before = current_cpu_ids().expect("read inherited CPU affinity");
            apply_initial(None).expect("omit initial affinity");
            assert_eq!(current_cpu_ids().expect("read omitted affinity"), before);

            let selected = before[0];
            let plan = CpuAffinityPlan {
                initial: Some(CpuSetPlan {
                    cpus: vec![selected],
                }),
                final_set: None,
            };
            apply_initial(Some(&plan)).expect("apply initial CPU affinity");
            assert_eq!(
                current_cpu_ids().expect("read initial CPU affinity"),
                [selected]
            );
            apply_final(Some(&plan)).expect("omit final CPU affinity without mutation");
            assert_eq!(
                current_cpu_ids().expect("read omitted final CPU affinity"),
                [selected]
            );

            let final_plan = CpuAffinityPlan {
                initial: None,
                final_set: Some(CpuSetPlan {
                    cpus: vec![selected],
                }),
            };
            apply_final(Some(&final_plan)).expect("apply final CPU affinity");
            assert_eq!(
                current_cpu_ids().expect("read final CPU affinity"),
                [selected]
            );
            return;
        }

        let output = Command::new(std::env::current_exe().expect("resolve test executable"))
            .args(["--exact", APPLY_TEST, "--nocapture"])
            .env(CHILD_PROBE, "1")
            .output()
            .expect("run isolated CPU affinity probe");
        assert!(
            output.status.success(),
            "isolated CPU affinity probe failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
