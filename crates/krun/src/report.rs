use a3s_oci_core::{CapabilityStatus, HostPlatform};
use serde::{Deserialize, Serialize};

use crate::VmConfig;

/// Schema emitted by the libkrun context smoke.
pub const KRUN_CONTEXT_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.krun-context-smoke.v2";
/// Schema emitted while binding the immutable Linux KVM boot compatibility set.
pub const KRUN_SYSTEM_IMAGE_CONTEXT_SMOKE_SCHEMA_VERSION: &str =
    "a3s.oci.krun-system-image-context-smoke.v1";
/// Schema emitted by the real utility-VM entry smoke.
pub const KRUN_VM_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.krun-vm-smoke.v2";
/// Schema emitted while booting the negotiation-only guest agent.
pub const KRUN_AGENT_VM_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.krun-agent-vm-smoke.v6";

/// Exact immutable macOS boot assets observed by the isolated VM worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosBootAssetsEvidence {
    pub manifest_sha256: String,
    pub system_image_sha256: String,
    pub system_image_size: u64,
    pub runtime_archive_sha256: String,
    pub libkrun_sha256: String,
    pub firmware_sha256: String,
    pub kernel_bundle_sha256: String,
    pub kernel_bundle_size: u64,
    pub kernel_guest_load_address: String,
    pub kernel_entry_address: String,
    pub root_disk_read_only: bool,
    pub runtime_share_separate: bool,
}

impl MacosBootAssetsEvidence {
    /// Return whether all retained macOS asset and isolation evidence is present.
    #[must_use]
    pub fn is_success(&self) -> bool {
        [
            &self.manifest_sha256,
            &self.system_image_sha256,
            &self.runtime_archive_sha256,
            &self.libkrun_sha256,
            &self.firmware_sha256,
            &self.kernel_bundle_sha256,
        ]
        .into_iter()
        .all(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) && self.system_image_size > 0
            && self.kernel_bundle_size > 0
            && self.kernel_guest_load_address.starts_with("0x")
            && self.kernel_entry_address.starts_with("0x")
            && self.root_disk_read_only
            && self.runtime_share_separate
    }
}

/// Exact immutable Linux KVM boot assets bound to one libkrun context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxBootAssetsEvidence {
    pub target_arch: String,
    pub manifest_sha256: String,
    pub system_image_sha256: String,
    pub system_image_size: u64,
    pub guest_agent_sha256: String,
    pub guest_agent_size: u64,
    pub runtime_archive_sha256: String,
    pub libkrun_sha256: String,
    pub firmware_sha256: String,
    pub kernel_bundle_sha256: String,
    pub kernel_bundle_size: u64,
    pub kernel_guest_load_address: String,
    pub kernel_entry_address: String,
    pub root_disk_read_only: bool,
}

impl LinuxBootAssetsEvidence {
    /// Return whether every immutable Linux boot-asset identity is present.
    #[must_use]
    pub fn is_success(&self) -> bool {
        [
            &self.manifest_sha256,
            &self.system_image_sha256,
            &self.guest_agent_sha256,
            &self.runtime_archive_sha256,
            &self.libkrun_sha256,
            &self.firmware_sha256,
            &self.kernel_bundle_sha256,
        ]
        .into_iter()
        .all(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) && matches!(self.target_arch.as_str(), "x86_64" | "aarch64")
            && self.system_image_size > 0
            && self.guest_agent_size > 0
            && self.kernel_bundle_size > 0
            && self.kernel_guest_load_address.starts_with("0x")
            && self.kernel_entry_address.starts_with("0x")
            && self.root_disk_read_only
    }
}

/// Exact immutable Windows boot assets observed by the isolated shim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsBootAssetsEvidence {
    pub manifest_sha256: String,
    pub system_image_sha256: String,
    pub system_image_size: u64,
    pub runtime_archive_sha256: String,
    pub krun_dll_sha256: String,
    pub firmware_sha256: String,
    pub box_revision: String,
    pub libkrun_revision: String,
    pub firmware_wrapper_revision: String,
    pub libkrunfw_revision: String,
    pub kernel_version: String,
    pub kernel_source_sha256: String,
    pub kernel_bundle_sha256: String,
    pub kernel_bundle_size: u64,
    pub kernel_guest_load_address: String,
    pub kernel_entry_address: String,
    pub root_disk_read_only: bool,
    pub runtime_share_separate: bool,
}

impl WindowsBootAssetsEvidence {
    /// Return whether all retained Windows asset and isolation evidence is present.
    #[must_use]
    pub fn is_success(&self) -> bool {
        [
            &self.manifest_sha256,
            &self.system_image_sha256,
            &self.runtime_archive_sha256,
            &self.krun_dll_sha256,
            &self.firmware_sha256,
            &self.kernel_source_sha256,
            &self.kernel_bundle_sha256,
        ]
        .into_iter()
        .all(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) && [
            &self.box_revision,
            &self.libkrun_revision,
            &self.firmware_wrapper_revision,
            &self.libkrunfw_revision,
        ]
        .into_iter()
        .all(|revision| {
            revision.len() == 40
                && revision
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) && !self.kernel_version.is_empty()
            && self.system_image_size > 0
            && self.kernel_bundle_size > 0
            && self.kernel_guest_load_address.starts_with("0x")
            && self.kernel_entry_address.starts_with("0x")
            && self.root_disk_read_only
            && self.runtime_share_separate
    }
}

/// Evidence from creating, configuring, and releasing one libkrun context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KrunContextSmokeReport {
    pub schema_version: String,
    pub platform: HostPlatform,
    pub status: CapabilityStatus,
    pub runtime_bundle_loaded: bool,
    pub context_created: bool,
    pub vm_configured: bool,
    pub agent_vsock_configured: bool,
    pub context_released: bool,
    pub vcpus: u8,
    pub memory_mib: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl KrunContextSmokeReport {
    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    fn initial(platform: HostPlatform, config: VmConfig, runtime_bundle_loaded: bool) -> Self {
        Self {
            schema_version: KRUN_CONTEXT_SMOKE_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            runtime_bundle_loaded,
            context_created: false,
            vm_configured: false,
            agent_vsock_configured: false,
            context_released: false,
            vcpus: config.vcpus(),
            memory_mib: config.memory_mib(),
            reason: None,
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    pub(crate) fn windows(config: VmConfig) -> Self {
        Self::initial(
            HostPlatform::Windows,
            config,
            option_env!("A3S_OCI_KRUN_RUNTIME_DIR").is_some(),
        )
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn macos(config: VmConfig) -> Self {
        Self::initial(HostPlatform::Macos, config, false)
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub(crate) fn linux(config: VmConfig) -> Self {
        Self::initial(HostPlatform::Linux, config, false)
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    pub(crate) fn failed(reason: String) -> Self {
        let mut report = Self::windows(VmConfig {
            vcpus: 1,
            memory_mib: 128,
        });
        report.reason = Some(reason);
        report
    }

    /// Return whether every context-lifecycle step succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.runtime_bundle_loaded
            && self.context_created
            && self.vm_configured
            && self.agent_vsock_configured
            && self.context_released
    }
}

/// Evidence from binding a manifest-verified Linux system image to libkrun.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KrunSystemImageContextSmokeReport {
    pub schema_version: String,
    pub platform: HostPlatform,
    pub status: CapabilityStatus,
    pub runtime_bundle_loaded: bool,
    pub system_image_verified: bool,
    pub context_created: bool,
    pub vm_configured: bool,
    pub root_disk_configured: bool,
    pub agent_vsock_configured: bool,
    pub context_released: bool,
    pub vcpus: u8,
    pub memory_mib: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_assets: Option<LinuxBootAssetsEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl KrunSystemImageContextSmokeReport {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub(crate) fn linux(config: VmConfig) -> Self {
        Self {
            schema_version: KRUN_SYSTEM_IMAGE_CONTEXT_SMOKE_SCHEMA_VERSION.to_string(),
            platform: HostPlatform::Linux,
            status: CapabilityStatus::Unavailable,
            runtime_bundle_loaded: false,
            system_image_verified: false,
            context_created: false,
            vm_configured: false,
            root_disk_configured: false,
            agent_vsock_configured: false,
            context_released: false,
            vcpus: config.vcpus(),
            memory_mib: config.memory_mib(),
            boot_assets: None,
            reason: None,
        }
    }

    /// Return whether the full pre-entry compatibility-set gate succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.runtime_bundle_loaded
            && self.system_image_verified
            && self.context_created
            && self.vm_configured
            && self.root_disk_configured
            && self.agent_vsock_configured
            && self.context_released
            && self
                .boot_assets
                .as_ref()
                .is_some_and(LinuxBootAssetsEvidence::is_success)
    }
}

/// Evidence from entering a real libkrun utility VM and running a guest command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KrunVmSmokeReport {
    pub schema_version: String,
    pub platform: HostPlatform,
    pub status: CapabilityStatus,
    pub runtime_bundle_loaded: bool,
    pub context_created: bool,
    pub vm_configured: bool,
    pub rootfs_configured: bool,
    pub runtime_share_configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub macos_boot_assets: Option<MacosBootAssetsEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_boot_assets: Option<WindowsBootAssetsEvidence>,
    pub workload_configured: bool,
    pub console_configured: bool,
    pub vm_entered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_exit_code: Option<i32>,
    pub marker_verified: bool,
    pub marker_removed: bool,
    pub console_created: bool,
    pub vcpus: u8,
    pub memory_mib: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl KrunVmSmokeReport {
    pub(crate) fn initial(platform: HostPlatform, config: VmConfig) -> Self {
        Self {
            schema_version: KRUN_VM_SMOKE_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            runtime_bundle_loaded: option_env!("A3S_OCI_KRUN_RUNTIME_DIR").is_some(),
            context_created: false,
            vm_configured: false,
            rootfs_configured: false,
            runtime_share_configured: false,
            macos_boot_assets: None,
            windows_boot_assets: None,
            workload_configured: false,
            console_configured: false,
            vm_entered: false,
            guest_exit_code: None,
            marker_verified: false,
            marker_removed: false,
            console_created: false,
            vcpus: config.vcpus(),
            memory_mib: config.memory_mib(),
            reason: None,
        }
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    pub(crate) fn unsupported(platform: HostPlatform, config: VmConfig) -> Self {
        let mut report = Self::initial(platform, config);
        report.status = CapabilityStatus::Unsupported;
        report.reason = Some(
            "the utility-VM entry smoke is implemented only for Windows x86_64/WHPX and \
             macOS aarch64/HVF"
                .into(),
        );
        report
    }

    /// Return whether boot, workload execution, and host verification succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.runtime_bundle_loaded
            && self.context_created
            && self.vm_configured
            && self.rootfs_configured
            && (!matches!(self.platform, HostPlatform::Macos)
                || (self.runtime_share_configured
                    && self
                        .macos_boot_assets
                        .as_ref()
                        .is_some_and(MacosBootAssetsEvidence::is_success)))
            && self.workload_configured
            && self.console_configured
            && self.vm_entered
            && matches!(self.guest_exit_code, Some(0))
            && self.marker_verified
            && self.marker_removed
            && self.console_created
    }
}

/// Shim-local evidence from booting the Linux guest agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KrunAgentVmSmokeReport {
    pub schema_version: String,
    pub platform: HostPlatform,
    pub status: CapabilityStatus,
    pub runtime_bundle_loaded: bool,
    pub context_created: bool,
    pub vm_configured: bool,
    pub rootfs_configured: bool,
    pub runtime_share_configured: bool,
    pub kvm_device_opened: bool,
    pub kvm_api_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux_boot_assets: Option<LinuxBootAssetsEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub macos_boot_assets: Option<MacosBootAssetsEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_boot_assets: Option<WindowsBootAssetsEvidence>,
    pub agent_binary_present: bool,
    pub agent_vsock_configured: bool,
    pub workload_configured: bool,
    pub console_configured: bool,
    pub vm_entered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_exit_code: Option<i32>,
    pub console_created: bool,
    /// In-process Windows handle count after immutable assets were pinned and
    /// immediately before the libkrun context was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_handles_before_vm: Option<u32>,
    /// In-process Windows handle count after `krun_start_enter` returned,
    /// before the shim process was allowed to exit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_handles_after_vm: Option<u32>,
    /// Whether the post-entry Windows handle inventory exactly matched the
    /// pre-context inventory without relying on process teardown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_handle_inventory_restored: Option<bool>,
    pub vcpus: u8,
    pub memory_mib: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl KrunAgentVmSmokeReport {
    pub(crate) fn initial(platform: HostPlatform, config: VmConfig) -> Self {
        Self {
            schema_version: KRUN_AGENT_VM_SMOKE_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            runtime_bundle_loaded: option_env!("A3S_OCI_KRUN_RUNTIME_DIR").is_some(),
            context_created: false,
            vm_configured: false,
            rootfs_configured: false,
            runtime_share_configured: false,
            kvm_device_opened: false,
            kvm_api_verified: false,
            linux_boot_assets: None,
            macos_boot_assets: None,
            windows_boot_assets: None,
            agent_binary_present: false,
            agent_vsock_configured: false,
            workload_configured: false,
            console_configured: false,
            vm_entered: false,
            guest_exit_code: None,
            console_created: false,
            windows_handles_before_vm: None,
            windows_handles_after_vm: None,
            windows_handle_inventory_restored: None,
            vcpus: config.vcpus(),
            memory_mib: config.memory_mib(),
            reason: None,
        }
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    pub(crate) fn unsupported(platform: HostPlatform, config: VmConfig) -> Self {
        let mut report = Self::initial(platform, config);
        report.status = CapabilityStatus::Unsupported;
        report.reason = Some(
            "the guest-agent VM smoke is implemented only for Linux x86_64/aarch64 KVM, \
             Windows x86_64/WHPX, and macOS aarch64/HVF"
                .into(),
        );
        report
    }

    /// Return whether the shim setup and guest process exit succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.runtime_bundle_loaded
            && self.context_created
            && self.vm_configured
            && self.rootfs_configured
            && match self.platform {
                HostPlatform::Linux => {
                    self.runtime_share_configured
                        && self.kvm_device_opened
                        && self.kvm_api_verified
                        && self
                            .linux_boot_assets
                            .as_ref()
                            .is_some_and(LinuxBootAssetsEvidence::is_success)
                }
                HostPlatform::Windows => {
                    self.runtime_share_configured
                        && self
                            .windows_boot_assets
                            .as_ref()
                            .is_some_and(WindowsBootAssetsEvidence::is_success)
                        && self
                            .windows_handles_before_vm
                            .is_some_and(|count| count > 0)
                        && self.windows_handles_after_vm == self.windows_handles_before_vm
                        && self.windows_handle_inventory_restored == Some(true)
                }
                HostPlatform::Macos => {
                    self.runtime_share_configured
                        && self
                            .macos_boot_assets
                            .as_ref()
                            .is_some_and(MacosBootAssetsEvidence::is_success)
                }
                _ => true,
            }
            && self.agent_binary_present
            && self.agent_vsock_configured
            && self.workload_configured
            && self.console_configured
            && self.vm_entered
            && matches!(self.guest_exit_code, Some(0))
            && self.console_created
    }
}
