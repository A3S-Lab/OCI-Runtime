use oci_spec::runtime::{
    ApparmorBuilder, CgroupBuilder, IDMapBuilder, IntelRdtBuilder, LinuxFeature,
    LinuxFeatureBuilder, LinuxNamespaceType, MemoryPolicyBuilder, MountExtensionsBuilder,
    NetDevicesBuilder, SeccompBuilder, SelinuxBuilder,
};

use crate::{
    Error, ErrorCode, Result, OCI_LINUX_CAPABILITY_NAMES, OCI_LINUX_MEMORY_POLICY_FLAGS,
    OCI_LINUX_MEMORY_POLICY_MODES, OCI_LINUX_MOUNT_OPTIONS, OCI_LINUX_SECCOMP_ACTIONS,
    OCI_LINUX_SECCOMP_ARCHITECTURES, OCI_LINUX_SECCOMP_KNOWN_FLAGS, OCI_LINUX_SECCOMP_OPERATORS,
};

mod resources;
mod shape;
mod validation;

use shape::validate_feature_shape;

pub(super) const A3S_CUSTOM_LINUX_MOUNT_OPTIONS: &[&str] = &["rnodev"];
const A3S_UNIMPLEMENTED_OPTIONAL_LINUX_MOUNT_OPTIONS: &[&str] = &["tmpcopyup"];
pub(super) const CONSTRUCT_OPERATION: &str = "construct-oci-linux-support";

/// Immutable Linux configuration support published by one exact runtime driver.
///
/// A configured host service freezes this profile when it registers its
/// drivers. The same value gates Create, Exec, and Update requests and becomes
/// the OCI Linux Features document, so reporting cannot drift from admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciLinuxSupport {
    mount_options: Vec<String>,
    linux: LinuxFeature,
}

impl OciLinuxSupport {
    /// Construct and validate one deterministic driver support profile.
    pub fn new(mut mount_options: Vec<String>, linux: LinuxFeature) -> Result<Self> {
        if let Some(option) = mount_options
            .iter()
            .find(|option| option.is_empty() || option.as_bytes().contains(&0))
        {
            return Err(profile_error(
                ErrorCode::InvalidArgument,
                format!("Linux mount-option support contains an invalid name {option:?}"),
                CONSTRUCT_OPERATION,
            ));
        }
        mount_options.sort_unstable();
        if mount_options.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(profile_error(
                ErrorCode::InvalidArgument,
                "Linux mount-option support contains a duplicate name",
                CONSTRUCT_OPERATION,
            ));
        }
        validate_feature_shape(&linux)?;
        Ok(Self {
            mount_options,
            linux,
        })
    }

    /// Exact compile-time profile implemented by the shared Linux executor.
    pub fn shared_executor() -> Result<Self> {
        let mut mount_options = OCI_LINUX_MOUNT_OPTIONS
            .iter()
            .map(|option| option.name())
            .filter(|name| !A3S_UNIMPLEMENTED_OPTIONAL_LINUX_MOUNT_OPTIONS.contains(name))
            .chain(A3S_CUSTOM_LINUX_MOUNT_OPTIONS.iter().copied())
            .map(str::to_string)
            .collect::<Vec<_>>();
        mount_options.sort_unstable();

        let cgroup = CgroupBuilder::default()
            .v1(false)
            .v2(true)
            .systemd(false)
            .systemd_user(false)
            .rdma(true)
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
        let net_devices = NetDevicesBuilder::default()
            .enabled(true)
            .build()
            .map_err(feature_build_error)?;
        let linux = LinuxFeatureBuilder::default()
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
            .map_err(feature_build_error)?;
        Self::new(mount_options, linux)
    }

    /// Mount options advertised for this exact driver profile.
    #[must_use]
    pub fn mount_options(&self) -> &[String] {
        &self.mount_options
    }

    /// Linux Features object advertised for this exact driver profile.
    #[must_use]
    pub const fn linux(&self) -> &LinuxFeature {
        &self.linux
    }
}

fn feature_build_error(error: impl std::fmt::Display) -> Error {
    profile_error(
        ErrorCode::Internal,
        format!("failed to construct shared Linux executor support: {error}"),
        CONSTRUCT_OPERATION,
    )
}

pub(super) fn profile_error(
    code: ErrorCode,
    message: impl Into<String>,
    operation: &'static str,
) -> Error {
    Error::new(code, message).for_operation(operation)
}

#[cfg(test)]
#[path = "linux_support_tests.rs"]
mod tests;
