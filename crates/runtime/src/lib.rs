//! Cross-platform host orchestration and platform capability probing.

#[cfg(windows)]
mod agent_pipe;
mod driver;
mod platform;
mod report;
mod service;
mod state;
#[cfg(windows)]
mod windows_security;

#[cfg(windows)]
pub use agent_pipe::WindowsAgentPipeListener;
pub use driver::{
    DriverCreateRequest, DriverDeleteRequest, DriverKillRequest, DriverStartRequest, DriverState,
    RuntimeDriver,
};
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
