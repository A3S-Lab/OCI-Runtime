use std::collections::BTreeSet;
use std::io;
use std::mem::size_of;

use a3s_oci_sdk::oci_spec::runtime::{LinuxSchedulerFlag, LinuxSchedulerPolicy, Scheduler};
use a3s_oci_sdk::{Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};

const SCHED_ISO: u32 = 4;
const LINUX_REALTIME_PRIORITY_MIN: i32 = 1;
const LINUX_REALTIME_PRIORITY_MAX: i32 = 99;
const LINUX_NICE_MIN: i32 = -20;
const LINUX_NICE_MAX: i32 = 19;
const LINUX_DEADLINE_MIN_NS: u64 = 1_024;
const LINUX_DEADLINE_MAX_NS: u64 = i64::MAX as u64;

const FLAG_RESET_ON_FORK: u64 = libc::SCHED_FLAG_RESET_ON_FORK as u64;
const FLAG_RECLAIM: u64 = libc::SCHED_FLAG_RECLAIM as u64;
const FLAG_DL_OVERRUN: u64 = libc::SCHED_FLAG_DL_OVERRUN as u64;
const FLAG_KEEP_POLICY: u64 = libc::SCHED_FLAG_KEEP_POLICY as u64;
const FLAG_KEEP_PARAMS: u64 = libc::SCHED_FLAG_KEEP_PARAMS as u64;
const FLAG_UTIL_CLAMP_MIN: u64 = libc::SCHED_FLAG_UTIL_CLAMP_MIN as u64;
const FLAG_UTIL_CLAMP_MAX: u64 = libc::SCHED_FLAG_UTIL_CLAMP_MAX as u64;
const TRANSIENT_FLAGS: u64 = FLAG_KEEP_POLICY | FLAG_KEEP_PARAMS;
const PERSISTENT_FLAGS: u64 =
    FLAG_RESET_ON_FORK | FLAG_RECLAIM | FLAG_DL_OVERRUN | FLAG_UTIL_CLAMP_MIN | FLAG_UTIL_CLAMP_MAX;

/// Validated Linux scheduler attributes retained for init and exec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SchedulerPlan {
    policy: SchedulerPolicyPlan,
    nice: i32,
    priority: u32,
    flags: u64,
    runtime: u64,
    deadline: u64,
    period: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SchedulerPolicyPlan {
    Other,
    Fifo,
    RoundRobin,
    Batch,
    Iso,
    Idle,
    Deadline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SchedulerFlagPlan {
    ResetOnFork,
    Reclaim,
    DeadlineOverrun,
    KeepPolicy,
    KeepParameters,
    UtilClampMinimum,
    UtilClampMaximum,
}

/// Linux's extensible `sched_attr` ABI, including the utilization-clamp tail.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RawSchedulerAttributes {
    size: u32,
    policy: u32,
    flags: u64,
    nice: i32,
    priority: u32,
    runtime: u64,
    deadline: u64,
    period: u64,
    util_min: u32,
    util_max: u32,
}

impl SchedulerPlan {
    pub(super) fn from_oci(value: Option<&Scheduler>) -> Result<Option<Self>> {
        let Some(value) = value else {
            return Ok(None);
        };
        let policy = SchedulerPolicyPlan::from_oci(value.policy());
        let nice = (*value.nice()).unwrap_or(0);
        if !(LINUX_NICE_MIN..=LINUX_NICE_MAX).contains(&nice) {
            return Err(scheduler_error(
                ErrorCode::InvalidArgument,
                format!(
                    "process.scheduler.nice {nice} is outside the Linux range \
                     {LINUX_NICE_MIN}..={LINUX_NICE_MAX}"
                ),
                "plan-process-scheduler",
            ));
        }

        let priority = (*value.priority()).unwrap_or(0);
        match policy {
            SchedulerPolicyPlan::Fifo | SchedulerPolicyPlan::RoundRobin
                if !(LINUX_REALTIME_PRIORITY_MIN..=LINUX_REALTIME_PRIORITY_MAX)
                    .contains(&priority) =>
            {
                return Err(scheduler_error(
                    ErrorCode::InvalidArgument,
                    format!(
                        "process.scheduler.priority {priority} is outside the Linux realtime \
                         range {LINUX_REALTIME_PRIORITY_MIN}..={LINUX_REALTIME_PRIORITY_MAX}"
                    ),
                    "plan-process-scheduler",
                ));
            }
            SchedulerPolicyPlan::Fifo | SchedulerPolicyPlan::RoundRobin => {}
            _ if priority != 0 => {
                return Err(scheduler_error(
                    ErrorCode::InvalidArgument,
                    format!(
                        "process.scheduler.priority must be 0 for {}",
                        policy.oci_name()
                    ),
                    "plan-process-scheduler",
                ));
            }
            _ => {}
        }
        let priority = u32::try_from(priority).map_err(|_| {
            scheduler_error(
                ErrorCode::InvalidArgument,
                "process.scheduler.priority must not be negative",
                "plan-process-scheduler",
            )
        })?;

        let runtime = (*value.runtime()).unwrap_or(0);
        let deadline = (*value.deadline()).unwrap_or(0);
        let period = (*value.period()).unwrap_or(0);
        validate_deadline(policy, runtime, deadline, period)?;

        let mut flags = 0_u64;
        let mut seen = BTreeSet::new();
        for flag in value.flags().as_deref().unwrap_or_default() {
            let flag = SchedulerFlagPlan::from_oci(*flag);
            if !seen.insert(flag) {
                return Err(scheduler_error(
                    ErrorCode::InvalidArgument,
                    format!(
                        "process.scheduler.flags contains duplicate {}",
                        flag.oci_name()
                    ),
                    "plan-process-scheduler",
                ));
            }
            flags |= flag.kernel_value();
        }
        if flags & (FLAG_RECLAIM | FLAG_DL_OVERRUN) != 0 && policy != SchedulerPolicyPlan::Deadline
        {
            return Err(scheduler_error(
                ErrorCode::InvalidArgument,
                "process.scheduler SCHED_FLAG_RECLAIM and SCHED_FLAG_DL_OVERRUN require \
                 SCHED_DEADLINE",
                "plan-process-scheduler",
            ));
        }

        Ok(Some(Self {
            policy,
            nice,
            priority,
            flags,
            runtime,
            deadline,
            period,
        }))
    }

    fn apply(&self) -> Result<()> {
        let before = current_attributes().map_err(|source| {
            scheduler_error(
                error_code_for_io(&source),
                format!(
                    "failed to inspect inherited scheduler state before applying {}: {source}",
                    self.policy.oci_name()
                ),
                "apply-process-scheduler",
            )
        })?;
        let requested = self.raw_attributes();
        // SAFETY: the syscall receives the documented Linux `sched_attr` ABI,
        // targets the calling process, and uses the required zero syscall flags.
        if unsafe { libc::syscall(libc::SYS_sched_setattr, 0, &requested, 0_u32) } != 0 {
            let source = io::Error::last_os_error();
            let code = if self.policy == SchedulerPolicyPlan::Iso
                && source.raw_os_error() == Some(libc::EINVAL)
            {
                ErrorCode::Unsupported
            } else {
                error_code_for_io(&source)
            };
            return Err(scheduler_error(
                code,
                format!(
                    "failed to apply process.scheduler {} nice {} priority {} flags {:#x} \
                     runtime {} deadline {} period {}: {source}",
                    self.policy.oci_name(),
                    self.nice,
                    self.priority,
                    self.flags,
                    self.runtime,
                    self.deadline,
                    self.period
                ),
                "apply-process-scheduler",
            ));
        }

        let actual = current_attributes().map_err(|source| {
            scheduler_error(
                error_code_for_io(&source),
                format!(
                    "failed to read back process.scheduler {}: {source}",
                    self.policy.oci_name()
                ),
                "apply-process-scheduler",
            )
        })?;
        self.verify_readback(&before, &actual)
    }

    fn raw_attributes(&self) -> RawSchedulerAttributes {
        RawSchedulerAttributes {
            size: size_of::<RawSchedulerAttributes>() as u32,
            policy: self.policy.kernel_value(),
            flags: self.flags,
            nice: self.nice,
            priority: self.priority,
            runtime: self.runtime,
            deadline: self.deadline,
            period: self.period,
            util_min: 0,
            util_max: 0,
        }
    }

    fn verify_readback(
        &self,
        before: &RawSchedulerAttributes,
        actual: &RawSchedulerAttributes,
    ) -> Result<()> {
        let expected_policy = if self.flags & FLAG_KEEP_POLICY != 0 {
            before.policy
        } else {
            self.policy.kernel_value()
        };
        if actual.policy != expected_policy {
            return Err(self.readback_mismatch("policy", expected_policy, actual.policy));
        }

        let keep_parameters = self.flags & FLAG_KEEP_PARAMS != 0;
        let expected_nice = if keep_parameters || !policy_uses_nice(expected_policy) {
            before.nice
        } else {
            self.nice
        };
        if actual.nice != expected_nice {
            return Err(self.readback_mismatch("nice", expected_nice, actual.nice));
        }

        let expected_priority = if keep_parameters {
            before.priority
        } else if policy_uses_realtime_priority(expected_policy) {
            self.priority
        } else {
            0
        };
        if actual.priority != expected_priority {
            return Err(self.readback_mismatch("priority", expected_priority, actual.priority));
        }

        if expected_policy == libc::SCHED_DEADLINE as u32 {
            let (expected_runtime, expected_deadline, expected_period) = if keep_parameters {
                (before.runtime, before.deadline, before.period)
            } else {
                (
                    self.runtime,
                    self.deadline,
                    if self.period == 0 {
                        self.deadline
                    } else {
                        self.period
                    },
                )
            };
            for (field, expected, observed) in [
                ("runtime", expected_runtime, actual.runtime),
                ("deadline", expected_deadline, actual.deadline),
                ("period", expected_period, actual.period),
            ] {
                if observed != expected {
                    return Err(self.readback_mismatch(field, expected, observed));
                }
            }
        }

        let expected_flags = self.flags & PERSISTENT_FLAGS;
        let actual_flags = actual.flags & (PERSISTENT_FLAGS | TRANSIENT_FLAGS);
        if actual_flags != expected_flags {
            return Err(self.readback_mismatch("flags", expected_flags, actual_flags));
        }
        if self.flags & FLAG_UTIL_CLAMP_MIN != 0 && actual.util_min != 0 {
            return Err(self.readback_mismatch("util_min", 0, actual.util_min));
        }
        if self.flags & FLAG_UTIL_CLAMP_MAX != 0 && actual.util_max != 0 {
            return Err(self.readback_mismatch("util_max", 0, actual.util_max));
        }
        Ok(())
    }

    fn readback_mismatch(
        &self,
        field: &str,
        expected: impl std::fmt::Display,
        observed: impl std::fmt::Display,
    ) -> Error {
        scheduler_error(
            ErrorCode::FailedPrecondition,
            format!(
                "process.scheduler {} read-back mismatch for {field}: requested {expected}, \
                 observed {observed}",
                self.policy.oci_name()
            ),
            "apply-process-scheduler",
        )
    }
}

impl SchedulerPolicyPlan {
    const fn from_oci(policy: &LinuxSchedulerPolicy) -> Self {
        match policy {
            LinuxSchedulerPolicy::SchedOther => Self::Other,
            LinuxSchedulerPolicy::SchedFifo => Self::Fifo,
            LinuxSchedulerPolicy::SchedRr => Self::RoundRobin,
            LinuxSchedulerPolicy::SchedBatch => Self::Batch,
            LinuxSchedulerPolicy::SchedIso => Self::Iso,
            LinuxSchedulerPolicy::SchedIdle => Self::Idle,
            LinuxSchedulerPolicy::SchedDeadline => Self::Deadline,
        }
    }

    const fn kernel_value(self) -> u32 {
        match self {
            Self::Other => libc::SCHED_OTHER as u32,
            Self::Fifo => libc::SCHED_FIFO as u32,
            Self::RoundRobin => libc::SCHED_RR as u32,
            Self::Batch => libc::SCHED_BATCH as u32,
            Self::Iso => SCHED_ISO,
            Self::Idle => libc::SCHED_IDLE as u32,
            Self::Deadline => libc::SCHED_DEADLINE as u32,
        }
    }

    const fn oci_name(self) -> &'static str {
        match self {
            Self::Other => "SCHED_OTHER",
            Self::Fifo => "SCHED_FIFO",
            Self::RoundRobin => "SCHED_RR",
            Self::Batch => "SCHED_BATCH",
            Self::Iso => "SCHED_ISO",
            Self::Idle => "SCHED_IDLE",
            Self::Deadline => "SCHED_DEADLINE",
        }
    }
}

impl SchedulerFlagPlan {
    const fn from_oci(flag: LinuxSchedulerFlag) -> Self {
        match flag {
            LinuxSchedulerFlag::SchedResetOnFork => Self::ResetOnFork,
            LinuxSchedulerFlag::SchedFlagReclaim => Self::Reclaim,
            LinuxSchedulerFlag::SchedFlagDLOverrun => Self::DeadlineOverrun,
            LinuxSchedulerFlag::SchedFlagKeepPolicy => Self::KeepPolicy,
            LinuxSchedulerFlag::SchedFlagKeepParams => Self::KeepParameters,
            LinuxSchedulerFlag::SchedFlagUtilClampMin => Self::UtilClampMinimum,
            LinuxSchedulerFlag::SchedFlagUtilClampMax => Self::UtilClampMaximum,
        }
    }

    const fn kernel_value(self) -> u64 {
        match self {
            Self::ResetOnFork => FLAG_RESET_ON_FORK,
            Self::Reclaim => FLAG_RECLAIM,
            Self::DeadlineOverrun => FLAG_DL_OVERRUN,
            Self::KeepPolicy => FLAG_KEEP_POLICY,
            Self::KeepParameters => FLAG_KEEP_PARAMS,
            Self::UtilClampMinimum => FLAG_UTIL_CLAMP_MIN,
            Self::UtilClampMaximum => FLAG_UTIL_CLAMP_MAX,
        }
    }

    const fn oci_name(self) -> &'static str {
        match self {
            Self::ResetOnFork => "SCHED_FLAG_RESET_ON_FORK",
            Self::Reclaim => "SCHED_FLAG_RECLAIM",
            Self::DeadlineOverrun => "SCHED_FLAG_DL_OVERRUN",
            Self::KeepPolicy => "SCHED_FLAG_KEEP_POLICY",
            Self::KeepParameters => "SCHED_FLAG_KEEP_PARAMS",
            Self::UtilClampMinimum => "SCHED_FLAG_UTIL_CLAMP_MIN",
            Self::UtilClampMaximum => "SCHED_FLAG_UTIL_CLAMP_MAX",
        }
    }
}

pub(super) fn apply(plan: Option<&SchedulerPlan>) -> Result<()> {
    plan.map_or(Ok(()), SchedulerPlan::apply)
}

fn validate_deadline(
    policy: SchedulerPolicyPlan,
    runtime: u64,
    deadline: u64,
    period: u64,
) -> Result<()> {
    if policy != SchedulerPolicyPlan::Deadline {
        if runtime != 0 || deadline != 0 || period != 0 {
            return Err(scheduler_error(
                ErrorCode::InvalidArgument,
                "process.scheduler runtime, deadline, and period must be 0 outside \
                 SCHED_DEADLINE",
                "plan-process-scheduler",
            ));
        }
        return Ok(());
    }
    if runtime == 0 || deadline == 0 || runtime > deadline || (period != 0 && deadline > period) {
        return Err(scheduler_error(
            ErrorCode::InvalidArgument,
            "process.scheduler SCHED_DEADLINE requires 0 < runtime <= deadline and either \
             period=0 or deadline <= period",
            "plan-process-scheduler",
        ));
    }
    for (field, value) in [("runtime", runtime), ("deadline", deadline)]
        .into_iter()
        .chain((period != 0).then_some(("period", period)))
    {
        if !(LINUX_DEADLINE_MIN_NS..=LINUX_DEADLINE_MAX_NS).contains(&value) {
            return Err(scheduler_error(
                ErrorCode::InvalidArgument,
                format!(
                    "process.scheduler.{field} {value} is outside the Linux SCHED_DEADLINE \
                     range {LINUX_DEADLINE_MIN_NS}..={LINUX_DEADLINE_MAX_NS}"
                ),
                "plan-process-scheduler",
            ));
        }
    }
    Ok(())
}

fn current_attributes() -> io::Result<RawSchedulerAttributes> {
    let mut attributes = RawSchedulerAttributes {
        size: size_of::<RawSchedulerAttributes>() as u32,
        ..RawSchedulerAttributes::default()
    };
    // SAFETY: the output points to a writable `sched_attr` buffer of the
    // advertised size, targets the calling process, and uses zero flags.
    if unsafe {
        libc::syscall(
            libc::SYS_sched_getattr,
            0,
            &mut attributes,
            size_of::<RawSchedulerAttributes>(),
            0_u32,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if attributes.size < 48 {
        return Err(io::Error::from_raw_os_error(libc::EPROTO));
    }
    Ok(attributes)
}

const fn policy_uses_nice(policy: u32) -> bool {
    matches!(
        policy,
        value if value == libc::SCHED_OTHER as u32
            || value == libc::SCHED_BATCH as u32
            || value == SCHED_ISO
            || value == libc::SCHED_IDLE as u32
    )
}

const fn policy_uses_realtime_priority(policy: u32) -> bool {
    policy == libc::SCHED_FIFO as u32 || policy == libc::SCHED_RR as u32
}

fn error_code_for_io(source: &io::Error) -> ErrorCode {
    match source.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => ErrorCode::PermissionDenied,
        Some(libc::EINVAL) => ErrorCode::InvalidArgument,
        Some(libc::EBUSY | libc::ESRCH) => ErrorCode::FailedPrecondition,
        Some(libc::E2BIG | libc::ENOSYS | libc::EOPNOTSUPP) => ErrorCode::Unsupported,
        _ => ErrorCode::Internal,
    }
}

fn scheduler_error(code: ErrorCode, message: impl Into<String>, operation: &'static str) -> Error {
    Error::new(code, message).for_operation(operation)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::process::Command;

    use a3s_oci_sdk::oci_spec::runtime::Scheduler;
    use a3s_oci_sdk::ErrorCode;

    use super::{apply, current_attributes, error_code_for_io, SchedulerPlan};

    const CHILD_PROBE: &str = "A3S_OCI_SCHEDULER_CHILD_PROBE";
    const APPLY_TEST: &str =
        "executor::scheduler::tests::applies_batch_policy_in_an_isolated_process";

    fn scheduler(value: serde_json::Value) -> Scheduler {
        let process = a3s_oci_sdk::process_serde::decode(serde_json::json!({
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/true"],
            "cwd": "/",
            "scheduler": value,
            "noNewPrivileges": true
        }))
        .expect("decode process scheduler");
        process.scheduler().clone().expect("decoded scheduler")
    }

    #[test]
    fn plans_every_policy_and_flag_without_silent_normalization() {
        let cases = [
            (serde_json::json!({"policy": "SCHED_OTHER"}), 0),
            (
                serde_json::json!({"policy": "SCHED_FIFO", "priority": 1}),
                1,
            ),
            (serde_json::json!({"policy": "SCHED_RR", "priority": 99}), 2),
            (serde_json::json!({"policy": "SCHED_BATCH"}), 3),
            (serde_json::json!({"policy": "SCHED_ISO"}), 4),
            (serde_json::json!({"policy": "SCHED_IDLE"}), 5),
            (
                serde_json::json!({
                    "policy": "SCHED_DEADLINE",
                    "runtime": 1024,
                    "deadline": 2048,
                    "period": 0,
                    "flags": [
                        "SCHED_FLAG_RESET_ON_FORK",
                        "SCHED_FLAG_RECLAIM",
                        "SCHED_FLAG_DL_OVERRUN",
                        "SCHED_FLAG_KEEP_POLICY",
                        "SCHED_FLAG_KEEP_PARAMS",
                        "SCHED_FLAG_UTIL_CLAMP_MIN",
                        "SCHED_FLAG_UTIL_CLAMP_MAX"
                    ]
                }),
                6,
            ),
        ];
        for (value, expected_policy) in cases {
            let plan = SchedulerPlan::from_oci(Some(&scheduler(value)))
                .expect("plan scheduler")
                .expect("present scheduler");
            assert_eq!(plan.raw_attributes().policy, expected_policy);
        }
        let deadline = SchedulerPlan::from_oci(Some(&scheduler(serde_json::json!({
            "policy": "SCHED_DEADLINE",
            "runtime": 1024,
            "deadline": 2048,
            "flags": [
                "SCHED_FLAG_RESET_ON_FORK",
                "SCHED_FLAG_RECLAIM",
                "SCHED_FLAG_DL_OVERRUN",
                "SCHED_FLAG_KEEP_POLICY",
                "SCHED_FLAG_KEEP_PARAMS",
                "SCHED_FLAG_UTIL_CLAMP_MIN",
                "SCHED_FLAG_UTIL_CLAMP_MAX"
            ]
        }))))
        .expect("plan scheduler flags")
        .expect("present scheduler flags");
        assert_eq!(deadline.raw_attributes().flags, 0x7f);
        assert!(SchedulerPlan::from_oci(None)
            .expect("omit scheduler")
            .is_none());
    }

    #[test]
    fn rejects_invalid_scheduler_relationships_before_mutation() {
        for value in [
            serde_json::json!({"policy": "SCHED_OTHER", "nice": -21}),
            serde_json::json!({"policy": "SCHED_BATCH", "nice": 20}),
            serde_json::json!({"policy": "SCHED_FIFO", "priority": 0}),
            serde_json::json!({"policy": "SCHED_RR", "priority": 100}),
            serde_json::json!({"policy": "SCHED_OTHER", "priority": 1}),
            serde_json::json!({"policy": "SCHED_OTHER", "runtime": 1024}),
            serde_json::json!({
                "policy": "SCHED_DEADLINE",
                "runtime": 0,
                "deadline": 2048
            }),
            serde_json::json!({
                "policy": "SCHED_DEADLINE",
                "runtime": 2048,
                "deadline": 1024
            }),
            serde_json::json!({
                "policy": "SCHED_OTHER",
                "flags": ["SCHED_FLAG_RECLAIM"]
            }),
            serde_json::json!({
                "policy": "SCHED_OTHER",
                "flags": ["SCHED_FLAG_RESET_ON_FORK", "SCHED_FLAG_RESET_ON_FORK"]
            }),
        ] {
            let error = SchedulerPlan::from_oci(Some(&scheduler(value)))
                .expect_err("invalid scheduler relationship must fail");
            assert_eq!(error.code, ErrorCode::InvalidArgument);
        }
    }

    #[test]
    fn syscall_errors_have_stable_types() {
        assert_eq!(
            error_code_for_io(&io::Error::from_raw_os_error(libc::EPERM)),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            error_code_for_io(&io::Error::from_raw_os_error(libc::EINVAL)),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            error_code_for_io(&io::Error::from_raw_os_error(libc::EBUSY)),
            ErrorCode::FailedPrecondition
        );
        assert_eq!(
            error_code_for_io(&io::Error::from_raw_os_error(libc::ENOSYS)),
            ErrorCode::Unsupported
        );
    }

    #[test]
    fn applies_batch_policy_in_an_isolated_process() {
        if std::env::var_os(CHILD_PROBE).is_some() {
            let before = current_attributes().expect("read initial scheduler");
            apply(None).expect("omit scheduler without mutation");
            assert_eq!(
                current_attributes().expect("read omitted scheduler"),
                before
            );

            let plan = SchedulerPlan::from_oci(Some(&scheduler(serde_json::json!({
                "policy": "SCHED_BATCH",
                "nice": 7
            }))))
            .expect("plan child scheduler")
            .expect("present child scheduler");
            apply(Some(&plan)).expect("apply child scheduler");
            let actual = current_attributes().expect("read applied scheduler");
            assert_eq!(actual.policy, libc::SCHED_BATCH as u32);
            assert_eq!(actual.nice, 7);
            assert_eq!(actual.priority, 0);
            return;
        }

        let output = Command::new(std::env::current_exe().expect("resolve test executable"))
            .args(["--exact", APPLY_TEST, "--nocapture"])
            .env(CHILD_PROBE, "1")
            .output()
            .expect("run isolated scheduler probe");
        assert!(
            output.status.success(),
            "isolated scheduler probe failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
