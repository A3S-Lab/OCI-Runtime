use std::io;

use a3s_oci_sdk::oci_spec::runtime::{IOPriorityClass, LinuxIOPriority};
use a3s_oci_sdk::{Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};

const IOPRIO_WHO_PROCESS: libc::c_int = 1;
const IOPRIO_CLASS_SHIFT: u32 = 13;
const IOPRIO_PRIORITY_MAX: i64 = 7;

/// Validated Linux I/O scheduling attributes retained for init and exec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IoPriorityPlan {
    class: IoPriorityClassPlan,
    priority: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IoPriorityClassPlan {
    Realtime,
    BestEffort,
    Idle,
}

impl IoPriorityPlan {
    pub(super) fn from_oci(value: Option<&LinuxIOPriority>) -> Result<Option<Self>> {
        let Some(value) = value else {
            return Ok(None);
        };
        let priority = value.priority();
        if !(0..=IOPRIO_PRIORITY_MAX).contains(&priority) {
            return Err(io_priority_error(
                ErrorCode::InvalidArgument,
                format!(
                    "process.ioPriority.priority {priority} is outside the Linux kernel range \
                     0..={IOPRIO_PRIORITY_MAX}"
                ),
                "plan-process-io-priority",
            ));
        }
        let class = IoPriorityClassPlan::from_oci(value.class());
        if class == IoPriorityClassPlan::Idle && priority != 0 {
            return Err(io_priority_error(
                ErrorCode::InvalidArgument,
                "process.ioPriority.priority must be 0 for IOPRIO_CLASS_IDLE because Linux \
                 idle I/O scheduling has no class data",
                "plan-process-io-priority",
            ));
        }
        Ok(Some(Self {
            class,
            priority: priority as u8,
        }))
    }

    fn apply(&self) -> Result<()> {
        let expected = self.encoded();
        // SAFETY: the syscall receives the documented Linux ioprio_set scalar
        // arguments and targets the calling process (`who` zero).
        if unsafe { libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0, expected) } != 0 {
            let source = io::Error::last_os_error();
            return Err(io_priority_error(
                error_code_for_io(&source),
                format!(
                    "failed to apply process.ioPriority {} priority {}: {source}",
                    self.class.oci_name(),
                    self.priority
                ),
                "apply-process-io-priority",
            ));
        }

        let actual = current_encoded().map_err(|source| {
            io_priority_error(
                error_code_for_io(&source),
                format!(
                    "failed to read back process.ioPriority {} priority {}: {source}",
                    self.class.oci_name(),
                    self.priority
                ),
                "apply-process-io-priority",
            )
        })?;
        if actual != expected {
            return Err(io_priority_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "process.ioPriority read-back mismatch: requested {expected:#x}, \
                     observed {actual:#x}"
                ),
                "apply-process-io-priority",
            ));
        }
        Ok(())
    }

    pub(super) const fn encoded(self) -> libc::c_int {
        (self.class.kernel_value() << IOPRIO_CLASS_SHIFT) | self.priority as libc::c_int
    }
}

impl IoPriorityClassPlan {
    const fn from_oci(class: IOPriorityClass) -> Self {
        match class {
            IOPriorityClass::IoprioClassRt => Self::Realtime,
            IOPriorityClass::IoprioClassBe => Self::BestEffort,
            IOPriorityClass::IoprioClassIdle => Self::Idle,
        }
    }

    const fn kernel_value(self) -> libc::c_int {
        match self {
            Self::Realtime => 1,
            Self::BestEffort => 2,
            Self::Idle => 3,
        }
    }

    const fn oci_name(self) -> &'static str {
        match self {
            Self::Realtime => "IOPRIO_CLASS_RT",
            Self::BestEffort => "IOPRIO_CLASS_BE",
            Self::Idle => "IOPRIO_CLASS_IDLE",
        }
    }
}

pub(super) fn apply(plan: Option<&IoPriorityPlan>) -> Result<()> {
    plan.map_or(Ok(()), IoPriorityPlan::apply)
}

fn current_encoded() -> io::Result<libc::c_int> {
    // SAFETY: the syscall receives the documented Linux ioprio_get scalar
    // arguments and targets the calling process (`who` zero).
    let result = unsafe { libc::syscall(libc::SYS_ioprio_get, IOPRIO_WHO_PROCESS, 0) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        libc::c_int::try_from(result).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))
    }
}

fn error_code_for_io(source: &io::Error) -> ErrorCode {
    match source.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => ErrorCode::PermissionDenied,
        Some(libc::EINVAL) => ErrorCode::InvalidArgument,
        Some(libc::ESRCH) => ErrorCode::FailedPrecondition,
        Some(libc::ENOSYS) => ErrorCode::Unsupported,
        _ => ErrorCode::Internal,
    }
}

fn io_priority_error(
    code: ErrorCode,
    message: impl Into<String>,
    operation: &'static str,
) -> Error {
    Error::new(code, message).for_operation(operation)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::process::Command;

    use a3s_oci_sdk::oci_spec::runtime::LinuxIOPriority;
    use a3s_oci_sdk::ErrorCode;

    use super::{apply, current_encoded, error_code_for_io, IoPriorityPlan};

    const CHILD_PROBE: &str = "A3S_OCI_IO_PRIORITY_CHILD_PROBE";
    const APPLY_TEST: &str =
        "executor::io_priority::tests::applies_best_effort_in_an_isolated_process";

    fn priority(class: &str, priority: i64) -> LinuxIOPriority {
        serde_json::from_value(serde_json::json!({
            "class": class,
            "priority": priority
        }))
        .expect("decode I/O priority")
    }

    #[test]
    fn plans_every_kernel_class_without_silent_normalization() {
        let cases = [
            ("IOPRIO_CLASS_RT", 0, 1 << 13),
            ("IOPRIO_CLASS_BE", 7, (2 << 13) | 7),
            ("IOPRIO_CLASS_IDLE", 0, 3 << 13),
        ];
        for (class, priority, encoded) in cases {
            let plan = IoPriorityPlan::from_oci(Some(&self::priority(class, priority)))
                .expect("plan I/O priority")
                .expect("present I/O priority");
            assert_eq!(plan.encoded(), encoded);
        }
        assert!(IoPriorityPlan::from_oci(None)
            .expect("omit I/O priority")
            .is_none());
    }

    #[test]
    fn rejects_out_of_range_and_idle_class_data() {
        for priority in [-1, 8] {
            let error =
                IoPriorityPlan::from_oci(Some(&self::priority("IOPRIO_CLASS_BE", priority)))
                    .expect_err("out-of-range I/O priority must fail");
            assert_eq!(error.code, ErrorCode::InvalidArgument);
            assert!(error.message.contains("outside the Linux kernel range"));
        }

        let error = IoPriorityPlan::from_oci(Some(&priority("IOPRIO_CLASS_IDLE", 1)))
            .expect_err("idle class data must fail");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("has no class data"));
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
            error_code_for_io(&io::Error::from_raw_os_error(libc::ESRCH)),
            ErrorCode::FailedPrecondition
        );
        assert_eq!(
            error_code_for_io(&io::Error::from_raw_os_error(libc::ENOSYS)),
            ErrorCode::Unsupported
        );
    }

    #[test]
    fn applies_best_effort_in_an_isolated_process() {
        if std::env::var_os(CHILD_PROBE).is_some() {
            let before = current_encoded().expect("read initial I/O priority");
            apply(None).expect("omit I/O priority without mutation");
            assert_eq!(
                current_encoded().expect("read omitted I/O priority"),
                before
            );

            let plan = IoPriorityPlan::from_oci(Some(&priority("IOPRIO_CLASS_BE", 5)))
                .expect("plan child I/O priority")
                .expect("present child I/O priority");
            apply(Some(&plan)).expect("apply child I/O priority");
            assert_eq!(
                current_encoded().expect("read applied I/O priority"),
                plan.encoded()
            );
            return;
        }

        let output = Command::new(std::env::current_exe().expect("resolve test executable"))
            .args(["--exact", APPLY_TEST, "--nocapture"])
            .env(CHILD_PROBE, "1")
            .output()
            .expect("run isolated I/O priority probe");
        assert!(
            output.status.success(),
            "isolated I/O priority probe failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
