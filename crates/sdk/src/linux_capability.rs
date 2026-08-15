use oci_spec::runtime::Capability;

/// Linux capability names recognized by the OCI runtime, in kernel-number order.
pub const OCI_LINUX_CAPABILITY_NAMES: &[&str] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

/// Return the stable Linux kernel number for an OCI capability.
#[must_use]
pub const fn oci_linux_capability_number(capability: Capability) -> u32 {
    match capability {
        Capability::Chown => 0,
        Capability::DacOverride => 1,
        Capability::DacReadSearch => 2,
        Capability::Fowner => 3,
        Capability::Fsetid => 4,
        Capability::Kill => 5,
        Capability::Setgid => 6,
        Capability::Setuid => 7,
        Capability::Setpcap => 8,
        Capability::LinuxImmutable => 9,
        Capability::NetBindService => 10,
        Capability::NetBroadcast => 11,
        Capability::NetAdmin => 12,
        Capability::NetRaw => 13,
        Capability::IpcLock => 14,
        Capability::IpcOwner => 15,
        Capability::SysModule => 16,
        Capability::SysRawio => 17,
        Capability::SysChroot => 18,
        Capability::SysPtrace => 19,
        Capability::SysPacct => 20,
        Capability::SysAdmin => 21,
        Capability::SysBoot => 22,
        Capability::SysNice => 23,
        Capability::SysResource => 24,
        Capability::SysTime => 25,
        Capability::SysTtyConfig => 26,
        Capability::Mknod => 27,
        Capability::Lease => 28,
        Capability::AuditWrite => 29,
        Capability::AuditControl => 30,
        Capability::Setfcap => 31,
        Capability::MacOverride => 32,
        Capability::MacAdmin => 33,
        Capability::Syslog => 34,
        Capability::WakeAlarm => 35,
        Capability::BlockSuspend => 36,
        Capability::AuditRead => 37,
        Capability::Perfmon => 38,
        Capability::Bpf => 39,
        Capability::CheckpointRestore => 40,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use oci_spec::runtime::Capability;

    use super::{oci_linux_capability_number, OCI_LINUX_CAPABILITY_NAMES};

    #[test]
    fn registry_covers_every_recognized_kernel_capability_once() {
        let capabilities = OCI_LINUX_CAPABILITY_NAMES
            .iter()
            .map(|name| {
                serde_json::from_value::<Capability>(serde_json::Value::String((*name).into()))
                    .expect("registered capability name must decode")
            })
            .collect::<Vec<_>>();
        let names = OCI_LINUX_CAPABILITY_NAMES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let numbers = capabilities
            .iter()
            .copied()
            .map(oci_linux_capability_number)
            .collect::<BTreeSet<_>>();

        assert_eq!(names.len(), OCI_LINUX_CAPABILITY_NAMES.len());
        assert_eq!(numbers, (0_u32..=40).collect());
        for (expected_number, capability) in capabilities.into_iter().enumerate() {
            assert_eq!(
                oci_linux_capability_number(capability),
                expected_number as u32
            );
        }
    }
}
