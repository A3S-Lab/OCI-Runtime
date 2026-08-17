use std::collections::HashMap;
use std::fmt;

use a3s_oci_sdk::oci_spec::runtime::{
    ApparmorBuilder, CgroupBuilder, Features, FeaturesBuilder, IDMapBuilder, IntelRdtBuilder,
    LinuxFeature, LinuxFeatureBuilder, LinuxNamespaceType, MemoryPolicyBuilder,
    MountExtensionsBuilder, NetDevicesBuilder, SeccompBuilder, SelinuxBuilder,
};
use a3s_oci_sdk::{
    AttachmentCapabilities, Error, ErrorCode, OciSchemaValidator, Result,
    BUILTIN_POTENTIALLY_UNSAFE_CONFIG_ANNOTATIONS, OCI_LINUX_CAPABILITY_NAMES,
    OCI_LINUX_MEMORY_POLICY_FLAGS, OCI_LINUX_MEMORY_POLICY_MODES, OCI_LINUX_MOUNT_OPTIONS,
    OCI_LINUX_SECCOMP_ACTIONS, OCI_LINUX_SECCOMP_ARCHITECTURES, OCI_LINUX_SECCOMP_KNOWN_FLAGS,
    OCI_LINUX_SECCOMP_OPERATORS, OCI_RUNTIME_SPEC_VERSION_MAX, OCI_RUNTIME_SPEC_VERSION_MIN,
};

use crate::driver::OciHookPhase;

const A3S_CUSTOM_LINUX_MOUNT_OPTIONS: &[&str] = &["rnodev"];
const A3S_UNIMPLEMENTED_OPTIONAL_LINUX_MOUNT_OPTIONS: &[&str] = &["tmpcopyup"];

pub(super) fn recognized_linux_mount_options() -> Vec<String> {
    let mut options = OCI_LINUX_MOUNT_OPTIONS
        .iter()
        .map(|option| option.name())
        .filter(|name| !A3S_UNIMPLEMENTED_OPTIONAL_LINUX_MOUNT_OPTIONS.contains(name))
        .chain(A3S_CUSTOM_LINUX_MOUNT_OPTIONS.iter().copied())
        .map(str::to_string)
        .collect::<Vec<_>>();
    options.sort_unstable();
    options
}

pub(super) fn build(
    has_lifecycle: bool,
    hooks: &[OciHookPhase],
    attachments: &AttachmentCapabilities,
) -> Result<Features> {
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
    let features = FeaturesBuilder::default()
        .oci_version_min(OCI_RUNTIME_SPEC_VERSION_MIN)
        .oci_version_max(OCI_RUNTIME_SPEC_VERSION_MAX)
        .hooks(
            hooks
                .iter()
                .map(|phase| phase.as_str().to_string())
                .collect::<Vec<_>>(),
        )
        .mount_options(recognized_linux_mount_options())
        .linux(compiled_linux_features()?)
        .annotations(annotations)
        .potentially_unsafe_config_annotations(potentially_unsafe_config_annotations(
            has_lifecycle,
            attachments,
        ))
        .build()
        .map_err(feature_build_error)?;
    OciSchemaValidator::new()?.validate_features(&features)?;
    Ok(features)
}

fn potentially_unsafe_config_annotations(
    has_lifecycle: bool,
    attachments: &AttachmentCapabilities,
) -> Vec<String> {
    if !has_lifecycle {
        return Vec::new();
    }

    let mut annotations = BUILTIN_POTENTIALLY_UNSAFE_CONFIG_ANNOTATIONS
        .iter()
        .copied()
        .chain(attachments.extension_names())
        .map(str::to_string)
        .collect::<Vec<_>>();
    annotations.sort_unstable();
    annotations.dedup();
    annotations
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
        .actions(OCI_LINUX_SECCOMP_ACTIONS.to_vec())
        .operators(
            OCI_LINUX_SECCOMP_OPERATORS
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        )
        .archs(OCI_LINUX_SECCOMP_ARCHITECTURES.to_vec())
        .known_flags(
            OCI_LINUX_SECCOMP_KNOWN_FLAGS
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
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
        .enabled(true)
        .schemata(true)
        .monitoring(true)
        .build()
        .map_err(feature_build_error)?;
    let net_devices = NetDevicesBuilder::default()
        .enabled(true)
        .build()
        .map_err(feature_build_error)?;
    let memory_policy = MemoryPolicyBuilder::default()
        .modes(
            OCI_LINUX_MEMORY_POLICY_MODES
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        )
        .flags(
            OCI_LINUX_MEMORY_POLICY_FLAGS
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        )
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
            OCI_LINUX_CAPABILITY_NAMES
                .iter()
                .map(|capability| (*capability).to_string())
                .collect::<Vec<_>>(),
        )
        .cgroup(cgroup)
        .seccomp(seccomp)
        .apparmor(apparmor)
        .selinux(selinux)
        .intel_rdt(intel_rdt)
        .memory_policy(memory_policy)
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
