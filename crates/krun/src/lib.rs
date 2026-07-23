//! Isolated libkrun boundary used by the utility-VM owner process.
//!
//! The main runtime, CLI, and SDK do not link libkrun. Only the dedicated shim
//! process depends on the native library, so feature inspection and native
//! Linux execution remain independent of KVM, HVF, or WHPX.

use std::path::Path;

mod agent_smoke;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod context;
mod report;

pub use a3s_oci_agent_protocol::{AgentVsockEndpoint, AGENT_VSOCK_PORT};
use a3s_oci_core::CapabilityStatus;
use a3s_oci_core::HostPlatform;
use a3s_oci_sdk::{Error, ErrorCode, Result};
pub use agent_smoke::agent_vm_smoke;
pub use report::{
    KrunAgentVmSmokeReport, KrunContextSmokeReport, KrunVmSmokeReport,
    KRUN_AGENT_VM_SMOKE_SCHEMA_VERSION, KRUN_CONTEXT_SMOKE_SCHEMA_VERSION,
    KRUN_VM_SMOKE_SCHEMA_VERSION,
};

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const VM_SMOKE_TOKEN: &str = "a3s-oci-whpx-vm-smoke-v1";

/// Validated utility-VM resource configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmConfig {
    vcpus: u8,
    memory_mib: u32,
}

impl VmConfig {
    /// Validate a libkrun VM resource request.
    pub fn new(vcpus: u8, memory_mib: u32) -> Result<Self> {
        if vcpus == 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "virtual CPU count must be at least 1",
            ));
        }
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        if vcpus != 1 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "the certified Windows WHPX path currently supports exactly 1 vCPU; \
                     requested {vcpus}"
                ),
            ));
        }
        if memory_mib == 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "VM memory must be at least 1 MiB",
            ));
        }

        Ok(Self { vcpus, memory_mib })
    }

    /// Virtual CPU count accepted by libkrun.
    #[must_use]
    pub const fn vcpus(self) -> u8 {
        self.vcpus
    }

    /// Guest memory in MiB.
    #[must_use]
    pub const fn memory_mib(self) -> u32 {
        self.memory_mib
    }
}

/// Create, configure, and release one real libkrun context.
#[must_use]
pub fn context_smoke() -> KrunContextSmokeReport {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        context_smoke_windows()
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        KrunContextSmokeReport {
            schema_version: KRUN_CONTEXT_SMOKE_SCHEMA_VERSION.to_string(),
            platform: HostPlatform::current(),
            status: CapabilityStatus::Unsupported,
            runtime_bundle_loaded: false,
            context_created: false,
            vm_configured: false,
            agent_vsock_configured: false,
            context_released: false,
            vcpus: 1,
            memory_mib: 128,
            reason: Some(
                "the current context smoke is implemented only for Windows x86_64/WHPX".into(),
            ),
        }
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn context_smoke_windows() -> KrunContextSmokeReport {
    use context::KrunContext;

    let config = match VmConfig::new(1, 128) {
        Ok(config) => config,
        Err(error) => return KrunContextSmokeReport::failed(error.to_string()),
    };
    let mut report = KrunContextSmokeReport::windows(config);

    let mut context = match KrunContext::create() {
        Ok(context) => {
            report.context_created = true;
            context
        }
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    };

    if let Err(error) = context.set_vm_config(config) {
        report.context_released = context.close().is_ok();
        report.reason = Some(error.to_string());
        return report;
    }
    report.vm_configured = true;

    let endpoint =
        match AgentVsockEndpoint::new(format!("a3s-oci-context-smoke-{}", std::process::id())) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                report.context_released = context.close().is_ok();
                report.reason = Some(error.to_string());
                return report;
            }
        };
    if let Err(error) = context.set_agent_vsock(&endpoint) {
        report.context_released = context.close().is_ok();
        report.reason = Some(error.to_string());
        return report;
    }
    report.agent_vsock_configured = true;

    match context.close() {
        Ok(()) => {
            report.context_released = true;
            report.status = CapabilityStatus::Available;
        }
        Err(error) => report.reason = Some(error.to_string()),
    }
    report
}

/// Enter a real utility VM, execute `/bin/sh`, and verify a guest-written marker.
///
/// This is intentionally a shim-only validation API. `krun_start_enter`
/// consumes the process-local libkrun context and must never run inside an SDK
/// client process.
#[must_use]
pub fn vm_smoke(rootfs: &Path, console: &Path) -> KrunVmSmokeReport {
    let config = match VmConfig::new(1, 512) {
        Ok(config) => config,
        Err(error) => {
            let mut report = KrunVmSmokeReport::initial(HostPlatform::current(), fallback_config());
            report.reason = Some(error.to_string());
            return report;
        }
    };

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        vm_smoke_windows(rootfs, console, config)
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        let _ = (rootfs, console);
        KrunVmSmokeReport::unsupported(HostPlatform::current(), config)
    }
}

pub(crate) fn fallback_config() -> VmConfig {
    VmConfig {
        vcpus: 1,
        memory_mib: 512,
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn vm_smoke_windows(rootfs: &Path, console: &Path, config: VmConfig) -> KrunVmSmokeReport {
    use std::fs;

    use context::KrunContext;

    let mut report = KrunVmSmokeReport::initial(HostPlatform::Windows, config);
    let rootfs = match rootfs.canonicalize() {
        Ok(path) if path.is_dir() => path,
        Ok(path) => {
            report.reason = Some(format!("rootfs is not a directory: {}", path.display()));
            return report;
        }
        Err(error) => {
            report.reason = Some(format!(
                "failed to resolve rootfs {}: {error}",
                rootfs.display()
            ));
            return report;
        }
    };

    let console_parent = match console.parent() {
        Some(parent) => parent,
        None => {
            report.reason = Some(format!(
                "console path has no parent directory: {}",
                console.display()
            ));
            return report;
        }
    };
    if let Err(error) = fs::create_dir_all(console_parent) {
        report.reason = Some(format!(
            "failed to create console directory {}: {error}",
            console_parent.display()
        ));
        return report;
    }

    let marker_name = format!(".a3s-oci-vm-smoke-{}", std::process::id());
    let marker_host_path = rootfs.join(&marker_name);
    if marker_host_path.exists() {
        report.reason = Some(format!(
            "refusing to overwrite an existing smoke marker: {}",
            marker_host_path.display()
        ));
        return report;
    }

    let mut context = match KrunContext::create() {
        Ok(context) => {
            report.context_created = true;
            context
        }
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    };

    if let Err(error) = context.set_vm_config(config) {
        report.reason = Some(error.to_string());
        return report;
    }
    report.vm_configured = true;

    if let Err(error) = context.set_root(&rootfs) {
        report.reason = Some(error.to_string());
        return report;
    }
    report.rootfs_configured = true;

    if let Err(error) = context.set_workdir("/") {
        report.reason = Some(error.to_string());
        return report;
    }

    let marker_guest_path = format!("/{marker_name}");
    let command = format!(
        "printf '%s\\n' '{VM_SMOKE_TOKEN}' > '{marker_guest_path}' && \
         printf '%s\\n' '{VM_SMOKE_TOKEN}'"
    );
    let arguments = vec!["-c".to_string(), command];
    if let Err(error) = context.set_exec("/bin/sh", &arguments, &[]) {
        report.reason = Some(error.to_string());
        return report;
    }
    report.workload_configured = true;

    if let Err(error) = context.set_console_output(console) {
        report.reason = Some(error.to_string());
        return report;
    }
    report.console_configured = true;

    // A3S's Windows libkrun build exposes an opt-in return path so this
    // one-shot diagnostic can verify guest effects before the shim exits.
    std::env::set_var("LIBKRUN_WINDOWS_RETURN_ON_EXIT", "1");
    match context.start_enter() {
        Ok(exit_code) => {
            report.vm_entered = true;
            report.guest_exit_code = Some(exit_code);
            if exit_code != 0 {
                report.reason = Some(format!(
                    "guest workload returned non-zero exit code {exit_code}"
                ));
            }
        }
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    }

    report.console_created = console.is_file();
    match fs::read_to_string(&marker_host_path) {
        Ok(contents) if contents == format!("{VM_SMOKE_TOKEN}\n") => {
            report.marker_verified = true;
        }
        Ok(contents) => {
            report.reason = Some(format!(
                "guest marker had unexpected contents ({} bytes)",
                contents.len()
            ));
        }
        Err(error) => {
            report.reason = Some(format!(
                "failed to read guest marker {}: {error}",
                marker_host_path.display()
            ));
        }
    }

    if marker_host_path.exists() {
        match fs::remove_file(&marker_host_path) {
            Ok(()) => report.marker_removed = true,
            Err(error) => {
                report.reason.get_or_insert_with(|| {
                    format!(
                        "failed to remove guest marker {}: {error}",
                        marker_host_path.display()
                    )
                });
            }
        }
    }

    if report.guest_exit_code == Some(0)
        && report.marker_verified
        && report.marker_removed
        && report.console_created
    {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    } else if report.reason.is_none() {
        report.reason = Some("guest workload did not satisfy the smoke-test contract".into());
    }

    report
}

#[cfg(test)]
mod tests {
    use super::{fallback_config, VmConfig};

    #[test]
    fn rejects_zero_resources() {
        assert!(VmConfig::new(0, 128).is_err());
        assert!(VmConfig::new(1, 0).is_err());
    }

    #[test]
    fn accepts_certified_smoke_configuration() {
        let config = VmConfig::new(1, 128).expect("smoke config must be valid");
        assert_eq!(config.vcpus(), 1);
        assert_eq!(config.memory_mib(), 128);
    }

    #[test]
    fn fallback_config_matches_vm_smoke_resources() {
        let config = fallback_config();
        assert_eq!(config.vcpus(), 1);
        assert_eq!(config.memory_mib(), 512);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn rejects_uncertified_windows_smp_configuration() {
        let error = VmConfig::new(2, 128).expect_err("Windows SMP must remain gated");
        assert!(error.to_string().contains("exactly 1 vCPU"));
    }
}
