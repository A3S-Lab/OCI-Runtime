//! Isolated libkrun boundary used by the utility-VM owner process.
//!
//! The main runtime, CLI, and SDK do not link libkrun. Only the dedicated shim
//! process depends on the native library, so feature inspection and native
//! Linux execution remain independent of KVM, HVF, or WHPX.

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod context;
mod report;

use a3s_oci_core::CapabilityStatus;
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
use a3s_oci_core::HostPlatform;
use a3s_oci_sdk::{Error, ErrorCode, Result};
pub use report::{KrunContextSmokeReport, KRUN_CONTEXT_SMOKE_SCHEMA_VERSION};

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

    match context.close() {
        Ok(()) => {
            report.context_released = true;
            report.status = CapabilityStatus::Available;
        }
        Err(error) => report.reason = Some(error.to_string()),
    }
    report
}

#[cfg(test)]
mod tests {
    use super::VmConfig;

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

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn rejects_uncertified_windows_smp_configuration() {
        let error = VmConfig::new(2, 128).expect_err("Windows SMP must remain gated");
        assert!(error.to_string().contains("exactly 1 vCPU"));
    }
}
