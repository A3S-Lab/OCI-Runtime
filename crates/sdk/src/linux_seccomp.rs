//! OCI Linux seccomp values implemented by the shared executor.

use oci_spec::runtime::{Arch, LinuxSeccompAction, LinuxSeccompFilterFlag, LinuxSeccompOperator};

/// Seccomp actions accepted and enforced by the shared Linux executor.
pub const OCI_LINUX_SECCOMP_ACTIONS: &[LinuxSeccompAction] = &[
    LinuxSeccompAction::ScmpActAllow,
    LinuxSeccompAction::ScmpActErrno,
    LinuxSeccompAction::ScmpActKill,
    LinuxSeccompAction::ScmpActKillProcess,
    LinuxSeccompAction::ScmpActKillThread,
    LinuxSeccompAction::ScmpActLog,
    LinuxSeccompAction::ScmpActTrace,
    LinuxSeccompAction::ScmpActTrap,
];

/// Explicit seccomp architectures accepted by the shared Linux executor.
///
/// An omitted architecture still selects the native architecture. The OCI
/// configuration schema does not allow `SCMP_ARCH_NATIVE` as an explicit
/// value, so it is not part of this advertised registry.
pub const OCI_LINUX_SECCOMP_ARCHITECTURES: &[Arch] = &[
    Arch::ScmpArchAarch64,
    Arch::ScmpArchX86,
    Arch::ScmpArchX86_64,
    Arch::ScmpArchX32,
];

/// Seccomp comparison operators accepted and enforced by the shared executor.
pub const OCI_LINUX_SECCOMP_OPERATORS: &[LinuxSeccompOperator] = &[
    LinuxSeccompOperator::ScmpCmpEq,
    LinuxSeccompOperator::ScmpCmpGe,
    LinuxSeccompOperator::ScmpCmpGt,
    LinuxSeccompOperator::ScmpCmpLe,
    LinuxSeccompOperator::ScmpCmpLt,
    LinuxSeccompOperator::ScmpCmpMaskedEq,
    LinuxSeccompOperator::ScmpCmpNe,
];

/// Seccomp filter flags recognized by the pinned OCI 1.3 data model.
///
/// The current executor rejects every non-empty flag list before mutation, so
/// none of these values appear in the feature report's `supportedFlags` list.
pub const OCI_LINUX_SECCOMP_KNOWN_FLAGS: &[LinuxSeccompFilterFlag] = &[
    LinuxSeccompFilterFlag::SeccompFilterFlagLog,
    LinuxSeccompFilterFlag::SeccompFilterFlagSpecAllow,
    LinuxSeccompFilterFlag::SeccompFilterFlagTsync,
    LinuxSeccompFilterFlag::SeccompFilterFlagWaitKillableRecv,
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde::Serialize;

    use super::{
        OCI_LINUX_SECCOMP_ACTIONS, OCI_LINUX_SECCOMP_ARCHITECTURES, OCI_LINUX_SECCOMP_KNOWN_FLAGS,
        OCI_LINUX_SECCOMP_OPERATORS,
    };

    #[test]
    fn registries_are_exact_and_unique() {
        assert_registry(
            OCI_LINUX_SECCOMP_ACTIONS,
            &[
                "SCMP_ACT_ALLOW",
                "SCMP_ACT_ERRNO",
                "SCMP_ACT_KILL",
                "SCMP_ACT_KILL_PROCESS",
                "SCMP_ACT_KILL_THREAD",
                "SCMP_ACT_LOG",
                "SCMP_ACT_TRACE",
                "SCMP_ACT_TRAP",
            ],
        );
        assert_registry(
            OCI_LINUX_SECCOMP_ARCHITECTURES,
            &[
                "SCMP_ARCH_AARCH64",
                "SCMP_ARCH_X86",
                "SCMP_ARCH_X86_64",
                "SCMP_ARCH_X32",
            ],
        );
        assert_registry(
            OCI_LINUX_SECCOMP_OPERATORS,
            &[
                "SCMP_CMP_EQ",
                "SCMP_CMP_GE",
                "SCMP_CMP_GT",
                "SCMP_CMP_LE",
                "SCMP_CMP_LT",
                "SCMP_CMP_MASKED_EQ",
                "SCMP_CMP_NE",
            ],
        );
        assert_registry(
            OCI_LINUX_SECCOMP_KNOWN_FLAGS,
            &[
                "SECCOMP_FILTER_FLAG_LOG",
                "SECCOMP_FILTER_FLAG_SPEC_ALLOW",
                "SECCOMP_FILTER_FLAG_TSYNC",
                "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV",
            ],
        );
    }

    fn assert_registry<T: Serialize>(actual: &[T], expected: &[&str]) {
        let actual = actual
            .iter()
            .map(|value| {
                serde_json::to_value(value)
                    .expect("serialize OCI seccomp value")
                    .as_str()
                    .expect("OCI seccomp values serialize as strings")
                    .to_string()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual.iter().collect::<BTreeSet<_>>().len(),
            actual.len(),
            "seccomp registry contains duplicates"
        );
        assert_eq!(actual, expected);
    }
}
