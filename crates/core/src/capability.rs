use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Schema emitted by the runtime `features` command.
pub const FEATURES_SCHEMA_VERSION: &str = "a3s.oci.features.v1";

/// Host operating-system family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostPlatform {
    /// Linux host.
    Linux,
    /// macOS host.
    Macos,
    /// Windows host.
    Windows,
    /// A host that the runtime does not support.
    Unsupported,
}

impl HostPlatform {
    /// Return the platform of the current build.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::Macos
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Unsupported
        }
    }
}

/// Concrete runtime driver identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DriverKind {
    /// Native Linux namespaces and cgroups without a VM.
    NativeLinux,
    /// libkrun using Linux KVM.
    LibkrunKvm,
    /// libkrun using macOS Hypervisor.framework.
    LibkrunHvf,
    /// libkrun using Windows Hypervisor Platform.
    LibkrunWhpx,
}

/// Effective kernel-sharing and host boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationClass {
    /// One workload owns a hardware VM and guest kernel.
    DedicatedVm,
    /// Containers in one trust domain share a guest kernel.
    SharedGuestKernel,
    /// Containers share the Linux host kernel.
    SharedHostKernel,
}

/// Host availability of a driver prerequisite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityStatus {
    /// The host prerequisite was verified.
    Available,
    /// The platform is supported, but the prerequisite is not currently usable.
    Unavailable,
    /// The driver does not apply to this host platform.
    Unsupported,
}

/// Implementation maturity of a runtime driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DriverReadiness {
    /// Only platform probing is implemented; workload launch is forbidden.
    ProbeOnly,
    /// Workload launch is available behind an explicit experimental opt-in.
    Experimental,
    /// The driver has passed its production release gates.
    Supported,
}

/// Capability and implementation evidence for one runtime driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverCapability {
    /// Driver represented by this entry.
    pub driver: DriverKind,
    /// Whether the host prerequisite is usable.
    pub status: CapabilityStatus,
    /// Whether the driver may launch workloads.
    pub readiness: DriverReadiness,
    /// Isolation classes this driver is designed to provide.
    pub isolation_classes: Vec<IsolationClass>,
    /// Human-readable reason when the status is not available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Stable evidence fields collected by the probe.
    pub evidence: BTreeMap<String, String>,
}

impl DriverCapability {
    /// Return whether workload launch may be selected.
    #[must_use]
    pub const fn can_launch(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && matches!(
                self.readiness,
                DriverReadiness::Experimental | DriverReadiness::Supported
            )
    }
}

/// Machine-readable runtime feature inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFeatures {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host platform detected at compile time.
    pub platform: HostPlatform,
    /// Rust target architecture.
    pub architecture: String,
    /// Runtime driver capability entries.
    pub drivers: Vec<DriverCapability>,
}

impl RuntimeFeatures {
    /// Construct a feature inventory for the current host.
    #[must_use]
    pub fn current(drivers: Vec<DriverCapability>) -> Self {
        Self {
            schema_version: FEATURES_SCHEMA_VERSION.to_string(),
            platform: HostPlatform::current(),
            architecture: std::env::consts::ARCH.to_string(),
            drivers,
        }
    }

    /// Find capability evidence for a specific driver.
    #[must_use]
    pub fn driver(&self, driver: DriverKind) -> Option<&DriverCapability> {
        self.drivers.iter().find(|item| item.driver == driver)
    }
}

#[cfg(test)]
mod tests {
    use super::{CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, IsolationClass};

    #[test]
    fn probe_only_driver_never_claims_launch_support() {
        let capability = DriverCapability {
            driver: DriverKind::LibkrunWhpx,
            status: CapabilityStatus::Available,
            readiness: DriverReadiness::ProbeOnly,
            isolation_classes: vec![
                IsolationClass::DedicatedVm,
                IsolationClass::SharedGuestKernel,
            ],
            reason: None,
            evidence: Default::default(),
        };

        assert!(!capability.can_launch());
    }

    #[test]
    fn supported_driver_requires_available_host_capability() {
        let capability = DriverCapability {
            driver: DriverKind::LibkrunWhpx,
            status: CapabilityStatus::Unavailable,
            readiness: DriverReadiness::Supported,
            isolation_classes: vec![IsolationClass::DedicatedVm],
            reason: Some("hypervisor is not running".to_string()),
            evidence: Default::default(),
        };

        assert!(!capability.can_launch());
    }
}
