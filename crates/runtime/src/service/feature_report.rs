use std::collections::HashMap;
use std::fmt;

use a3s_oci_sdk::oci_spec::runtime::{
    ApparmorBuilder, Arch, CgroupBuilder, Features, FeaturesBuilder, IDMapBuilder, IntelRdtBuilder,
    LinuxFeature, LinuxFeatureBuilder, LinuxNamespaceType, LinuxSeccompAction,
    MountExtensionsBuilder, NetDevicesBuilder, SeccompBuilder, SelinuxBuilder,
};
use a3s_oci_sdk::{
    Error, ErrorCode, Result, OCI_RUNTIME_SPEC_VERSION_MAX, OCI_RUNTIME_SPEC_VERSION_MIN,
};

pub(super) const RECOGNIZED_LINUX_MOUNT_OPTIONS: &[&str] = &[
    "async",
    "atime",
    "bind",
    "defaults",
    "dev",
    "diratime",
    "dirsync",
    "exec",
    "idmap",
    "iversion",
    "lazytime",
    "loud",
    "mand",
    "noatime",
    "nodev",
    "nodiratime",
    "noexec",
    "noiversion",
    "nolazytime",
    "nomand",
    "norelatime",
    "nostrictatime",
    "nosuid",
    "nosymfollow",
    "private",
    "ratime",
    "rbind",
    "rdev",
    "rdiratime",
    "relatime",
    "remount",
    "rexec",
    "ridmap",
    "rnoatime",
    "rnodev",
    "rnodiratime",
    "rnoexec",
    "rnorelatime",
    "rnostrictatime",
    "rnosuid",
    "rnosymfollow",
    "ro",
    "rprivate",
    "rrelatime",
    "rro",
    "rrw",
    "rshared",
    "rslave",
    "rstrictatime",
    "rsuid",
    "rsymfollow",
    "runbindable",
    "rw",
    "shared",
    "silent",
    "slave",
    "strictatime",
    "suid",
    "symfollow",
    "sync",
    "unbindable",
];

pub(super) const SUPPORTED_LINUX_CAPABILITIES: &[&str] = &[
    "CAP_AUDIT_CONTROL",
    "CAP_AUDIT_READ",
    "CAP_AUDIT_WRITE",
    "CAP_BLOCK_SUSPEND",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_KILL",
    "CAP_LEASE",
    "CAP_LINUX_IMMUTABLE",
    "CAP_MAC_ADMIN",
    "CAP_MAC_OVERRIDE",
    "CAP_MKNOD",
    "CAP_NET_ADMIN",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_RAW",
    "CAP_PERFMON",
    "CAP_SETFCAP",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_CHROOT",
    "CAP_SYS_MODULE",
    "CAP_SYS_NICE",
    "CAP_SYS_PACCT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
];

pub(super) fn build(has_lifecycle: bool) -> Result<Features> {
    let annotations = HashMap::from([
        (
            "dev.a3s.oci.runtime.version".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        ),
        (
            "dev.a3s.oci.runtime.lifecycle".to_string(),
            if has_lifecycle {
                "durable-core"
            } else {
                "probe-only"
            }
            .to_string(),
        ),
    ]);
    FeaturesBuilder::default()
        .oci_version_min(OCI_RUNTIME_SPEC_VERSION_MIN)
        .oci_version_max(OCI_RUNTIME_SPEC_VERSION_MAX)
        .hooks(Vec::<String>::new())
        .mount_options(
            RECOGNIZED_LINUX_MOUNT_OPTIONS
                .iter()
                .map(|option| (*option).to_string())
                .collect::<Vec<_>>(),
        )
        .linux(compiled_linux_features()?)
        .annotations(annotations)
        .potentially_unsafe_config_annotations(Vec::<String>::new())
        .build()
        .map_err(feature_build_error)
}

fn compiled_linux_features() -> Result<LinuxFeature> {
    let cgroup = CgroupBuilder::default()
        .v1(false)
        .v2(true)
        .systemd(false)
        .systemd_user(false)
        .rdma(false)
        .build()
        .map_err(feature_build_error)?;
    let seccomp = SeccompBuilder::default()
        .enabled(true)
        .actions(vec![
            LinuxSeccompAction::ScmpActAllow,
            LinuxSeccompAction::ScmpActErrno,
            LinuxSeccompAction::ScmpActKill,
            LinuxSeccompAction::ScmpActKillProcess,
            LinuxSeccompAction::ScmpActKillThread,
            LinuxSeccompAction::ScmpActLog,
            LinuxSeccompAction::ScmpActTrace,
            LinuxSeccompAction::ScmpActTrap,
        ])
        .operators(
            [
                "SCMP_CMP_EQ",
                "SCMP_CMP_GE",
                "SCMP_CMP_GT",
                "SCMP_CMP_LE",
                "SCMP_CMP_LT",
                "SCMP_CMP_MASKED_EQ",
                "SCMP_CMP_NE",
            ]
            .map(str::to_string)
            .to_vec(),
        )
        .archs(vec![Arch::ScmpArchAarch64, Arch::ScmpArchX86_64])
        .known_flags(
            [
                "SECCOMP_FILTER_FLAG_LOG",
                "SECCOMP_FILTER_FLAG_SPEC_ALLOW",
                "SECCOMP_FILTER_FLAG_TSYNC",
                "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV",
            ]
            .map(str::to_string)
            .to_vec(),
        )
        .supported_flags(Vec::<String>::new())
        .build()
        .map_err(feature_build_error)?;
    let apparmor = ApparmorBuilder::default()
        .enabled(false)
        .build()
        .map_err(feature_build_error)?;
    let selinux = SelinuxBuilder::default()
        .enabled(false)
        .build()
        .map_err(feature_build_error)?;
    let intel_rdt = IntelRdtBuilder::default()
        .enabled(false)
        .schemata(false)
        .monitoring(false)
        .build()
        .map_err(feature_build_error)?;
    let net_devices = NetDevicesBuilder::default()
        .enabled(false)
        .build()
        .map_err(feature_build_error)?;
    let idmap = IDMapBuilder::default()
        .enabled(true)
        .build()
        .map_err(feature_build_error)?;
    let mount_extensions = MountExtensionsBuilder::default()
        .idmap(idmap)
        .build()
        .map_err(feature_build_error)?;
    LinuxFeatureBuilder::default()
        .namespaces(vec![
            LinuxNamespaceType::Cgroup,
            LinuxNamespaceType::Ipc,
            LinuxNamespaceType::Mount,
            LinuxNamespaceType::Network,
            LinuxNamespaceType::Pid,
            LinuxNamespaceType::Time,
            LinuxNamespaceType::User,
            LinuxNamespaceType::Uts,
        ])
        .capabilities(
            SUPPORTED_LINUX_CAPABILITIES
                .iter()
                .map(|capability| (*capability).to_string())
                .collect::<Vec<_>>(),
        )
        .cgroup(cgroup)
        .seccomp(seccomp)
        .apparmor(apparmor)
        .selinux(selinux)
        .intel_rdt(intel_rdt)
        .mount_extensions(mount_extensions)
        .net_devices(net_devices)
        .build()
        .map_err(feature_build_error)
}

fn feature_build_error(error: impl fmt::Display) -> Error {
    Error::new(
        ErrorCode::Internal,
        format!("failed to construct OCI feature report: {error}"),
    )
    .for_operation("features")
}
