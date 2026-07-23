use a3s_oci_core::{CapabilityStatus, HostPlatform};
use serde::{Deserialize, Serialize};

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use crate::VmConfig;

/// Schema emitted by the libkrun context smoke.
pub const KRUN_CONTEXT_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.krun-context-smoke.v1";

/// Evidence from creating, configuring, and releasing one libkrun context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KrunContextSmokeReport {
    pub schema_version: String,
    pub platform: HostPlatform,
    pub status: CapabilityStatus,
    pub runtime_bundle_loaded: bool,
    pub context_created: bool,
    pub vm_configured: bool,
    pub context_released: bool,
    pub vcpus: u8,
    pub memory_mib: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl KrunContextSmokeReport {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    pub(crate) fn windows(config: VmConfig) -> Self {
        Self {
            schema_version: KRUN_CONTEXT_SMOKE_SCHEMA_VERSION.to_string(),
            platform: HostPlatform::Windows,
            status: CapabilityStatus::Unavailable,
            runtime_bundle_loaded: option_env!("A3S_OCI_KRUN_RUNTIME_DIR").is_some(),
            context_created: false,
            vm_configured: false,
            context_released: false,
            vcpus: config.vcpus(),
            memory_mib: config.memory_mib(),
            reason: None,
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    pub(crate) fn failed(reason: String) -> Self {
        Self {
            schema_version: KRUN_CONTEXT_SMOKE_SCHEMA_VERSION.to_string(),
            platform: HostPlatform::Windows,
            status: CapabilityStatus::Unavailable,
            runtime_bundle_loaded: option_env!("A3S_OCI_KRUN_RUNTIME_DIR").is_some(),
            context_created: false,
            vm_configured: false,
            context_released: false,
            vcpus: 1,
            memory_mib: 128,
            reason: Some(reason),
        }
    }

    /// Return whether every context-lifecycle step succeeded.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.runtime_bundle_loaded
            && self.context_created
            && self.vm_configured
            && self.context_released
    }
}
