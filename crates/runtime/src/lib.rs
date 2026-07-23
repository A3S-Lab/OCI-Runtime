//! Cross-platform host orchestration and platform capability probing.

mod platform;
mod report;
mod service;

pub use report::WhpxSmokeReport;
pub use service::HostRuntimeService;

use a3s_oci_core::RuntimeFeatures;

/// Inspect runtime drivers without claiming unsupported workload capability.
#[must_use]
pub fn features() -> RuntimeFeatures {
    platform::features()
}

/// Exercise the Windows Hypervisor Platform partition-object lifecycle.
#[must_use]
pub fn whpx_smoke() -> WhpxSmokeReport {
    platform::whpx_smoke()
}
