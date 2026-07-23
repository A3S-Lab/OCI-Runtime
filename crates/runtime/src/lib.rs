//! Cross-platform host orchestration and platform capability probing.

#[cfg(windows)]
mod agent_pipe;
mod agent_smoke;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod agent_smoke_process;
mod driver;
mod platform;
mod report;
mod service;
mod state;
#[cfg(windows)]
mod windows_security;

#[cfg(windows)]
pub use agent_pipe::WindowsAgentPipeListener;
pub use agent_smoke::agent_vm_smoke;
pub use driver::{
    DriverCreateRequest, DriverDeleteRequest, DriverKillRequest, DriverStartRequest, DriverState,
    RuntimeDriver,
};
pub use report::{AgentVmSmokeReport, WhpxSmokeReport};
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
