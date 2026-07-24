//! Cross-platform host orchestration and platform capability probing.

#[cfg(windows)]
mod agent_pipe;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod agent_session;
mod agent_smoke;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod agent_smoke_process;
mod driver;
#[cfg(target_os = "linux")]
mod native_linux_driver;
mod native_smoke;
mod oci_smoke;
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
#[cfg(target_os = "linux")]
pub use native_linux_driver::NativeLinuxDriver;
pub use native_smoke::native_linux_smoke;
pub use oci_smoke::oci_vm_smoke;
pub use report::{
    AgentVmSmokeReport, HvfSmokeReport, NativeLinuxSmokeReport, OciVmSmokeReport, WhpxSmokeReport,
};
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

/// Exercise the macOS Hypervisor.framework VM-object lifecycle.
#[must_use]
pub fn hvf_smoke() -> HvfSmokeReport {
    platform::hvf_smoke()
}
