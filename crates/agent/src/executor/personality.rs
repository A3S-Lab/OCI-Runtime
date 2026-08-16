use std::io;

use a3s_oci_sdk::oci_spec::runtime::{LinuxPersonality, LinuxPersonalityDomain};
use a3s_oci_sdk::{Error, ErrorCode, Result};

const PER_LINUX: libc::c_ulong = 0x0000;
const PER_LINUX32: libc::c_ulong = 0x0008;
const PER_QUERY: libc::c_ulong = 0xffff_ffff;

/// Validated Linux execution domain retained for the configured init process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PersonalityPlan {
    domain: PersonalityDomain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersonalityDomain {
    Linux,
    Linux32,
}

impl PersonalityPlan {
    pub(super) fn from_oci(value: Option<&LinuxPersonality>) -> Result<Option<Self>> {
        let Some(value) = value else {
            return Ok(None);
        };
        if value
            .flags()
            .as_ref()
            .is_some_and(|flags| !flags.is_empty())
        {
            return Err(personality_error(
                ErrorCode::Unsupported,
                "linux.personality.flags must be empty because OCI 1.3 defines no supported flag values",
                "plan-linux-personality",
            ));
        }
        Ok(Some(Self {
            domain: PersonalityDomain::from_oci(value.domain()),
        }))
    }

    fn apply(self) -> Result<()> {
        let expected = self.domain.kernel_value();
        // SAFETY: `expected` is one of the two execution domains admitted by
        // OCI 1.3. The call changes only the dedicated init process.
        if unsafe { libc::personality(expected) } < 0 {
            let source = io::Error::last_os_error();
            return Err(personality_error(
                error_code_for_io(&source),
                format!(
                    "failed to apply linux.personality domain {}: {source}",
                    self.domain.oci_name()
                ),
                "apply-linux-personality",
            ));
        }
        let actual = current().map_err(|source| {
            personality_error(
                error_code_for_io(&source),
                format!(
                    "failed to read back linux.personality domain {}: {source}",
                    self.domain.oci_name()
                ),
                "apply-linux-personality",
            )
        })?;
        if actual != expected {
            return Err(personality_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "linux.personality read-back mismatch: requested {} ({expected:#x}), observed {actual:#x}",
                    self.domain.oci_name()
                ),
                "apply-linux-personality",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    const fn kernel_value(self) -> libc::c_ulong {
        self.domain.kernel_value()
    }
}

impl PersonalityDomain {
    const fn from_oci(value: LinuxPersonalityDomain) -> Self {
        match value {
            LinuxPersonalityDomain::PerLinux => Self::Linux,
            LinuxPersonalityDomain::PerLinux32 => Self::Linux32,
        }
    }

    const fn kernel_value(self) -> libc::c_ulong {
        match self {
            Self::Linux => PER_LINUX,
            Self::Linux32 => PER_LINUX32,
        }
    }

    const fn oci_name(self) -> &'static str {
        match self {
            Self::Linux => "LINUX",
            Self::Linux32 => "LINUX32",
        }
    }
}

pub(super) fn apply(plan: Option<&PersonalityPlan>) -> Result<()> {
    plan.copied().map_or(Ok(()), PersonalityPlan::apply)
}

fn current() -> io::Result<libc::c_ulong> {
    // SAFETY: `PER_QUERY` is the documented query-only personality argument.
    let result = unsafe { libc::personality(PER_QUERY) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as libc::c_ulong)
    }
}

fn error_code_for_io(source: &io::Error) -> ErrorCode {
    match source.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => ErrorCode::PermissionDenied,
        Some(libc::EINVAL) => ErrorCode::InvalidArgument,
        Some(libc::ENOSYS) => ErrorCode::Unsupported,
        _ => ErrorCode::Internal,
    }
}

fn personality_error(
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

    use a3s_oci_sdk::oci_spec::runtime::LinuxPersonality;
    use a3s_oci_sdk::ErrorCode;

    use super::{apply, current, error_code_for_io, PersonalityPlan, PER_LINUX, PER_LINUX32};

    const CHILD_PROBE: &str = "A3S_OCI_PERSONALITY_CHILD_PROBE";
    const APPLY_TEST: &str =
        "executor::personality::tests::applies_and_reads_back_linux32_in_an_isolated_process";

    fn personality(domain: &str, flags: &[&str]) -> LinuxPersonality {
        serde_json::from_value(serde_json::json!({
            "domain": domain,
            "flags": flags
        }))
        .expect("decode Linux personality")
    }

    #[test]
    fn plans_both_oci_domains_and_omission() {
        for (domain, expected) in [("LINUX", PER_LINUX), ("LINUX32", PER_LINUX32)] {
            let plan = PersonalityPlan::from_oci(Some(&personality(domain, &[])))
                .expect("plan Linux personality")
                .expect("present Linux personality");
            assert_eq!(plan.kernel_value(), expected);
        }
        assert!(PersonalityPlan::from_oci(None)
            .expect("omit Linux personality")
            .is_none());
    }

    #[test]
    fn rejects_every_nonempty_flag_set() {
        let error = PersonalityPlan::from_oci(Some(&personality("LINUX", &["ADDR_NO_RANDOMIZE"])))
            .expect_err("OCI 1.3 defines no personality flags");
        assert_eq!(error.code, ErrorCode::Unsupported);
        assert!(error.message.contains("linux.personality.flags"));
    }

    #[test]
    fn omission_preserves_the_inherited_domain() {
        let before = current().expect("inspect inherited personality");
        apply(None).expect("omit personality application");
        assert_eq!(current().expect("inspect preserved personality"), before);
    }

    #[test]
    fn applies_and_reads_back_linux32_in_an_isolated_process() {
        if std::env::var_os(CHILD_PROBE).is_some() {
            let plan = PersonalityPlan::from_oci(Some(&personality("LINUX32", &[])))
                .expect("plan LINUX32 personality")
                .expect("present LINUX32 personality");
            apply(Some(&plan)).expect("apply LINUX32 personality");
            assert_eq!(
                current().expect("read back LINUX32 personality"),
                PER_LINUX32
            );
            return;
        }

        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg(APPLY_TEST)
            .arg("--nocapture")
            .env(CHILD_PROBE, "1")
            .status()
            .expect("run isolated personality probe");
        assert!(
            status.success(),
            "isolated personality probe failed: {status}"
        );
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
            error_code_for_io(&io::Error::from_raw_os_error(libc::ENOSYS)),
            ErrorCode::Unsupported
        );
        assert_eq!(
            error_code_for_io(&io::Error::from_raw_os_error(libc::EIO)),
            ErrorCode::Internal
        );
    }
}
