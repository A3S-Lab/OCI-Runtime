//! Cross-platform host orchestration and platform capability probing.

#[cfg(windows)]
mod agent_pipe;
#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
mod agent_session;
mod agent_smoke;
#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
mod agent_smoke_process;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod agent_socket;
mod cleanup_report;
mod driver;
mod fault;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod host_cleanup;
mod multi_container_report;
mod namespace_join;
#[cfg(target_os = "linux")]
mod native_control;
#[cfg(target_os = "linux")]
mod native_linux_driver;
mod native_smoke;
mod oci_smoke;
mod platform;
mod report;
mod rootfs_enforcement;
mod service;
mod state;
#[cfg(windows)]
mod windows_security;

#[cfg(windows)]
pub use agent_pipe::WindowsAgentPipeListener;
pub use agent_smoke::agent_vm_smoke;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use agent_socket::MacosAgentSocketListener;
pub use cleanup_report::{
    FaultInjectionEvidence, LifecycleFaultPoint, NativeLinuxFaultCleanupReport,
    OciVmFaultCleanupReport,
};
pub use driver::{
    DriverCloseStdinRequest, DriverContainerOperationRequest, DriverCreateAttachments,
    DriverCreateRequest, DriverDeleteRequest, DriverExecRequest, DriverKillRequest, DriverProcess,
    DriverReadOutputRequest, DriverResizeRequest, DriverSignalProcessRequest, DriverStartRequest,
    DriverState, DriverUpdateRequest, DriverWaitProcessRequest, DriverWaitRequest,
    DriverWriteStdinRequest, OciHookPhase, RuntimeDriver,
};
pub use multi_container_report::{
    MultiContainerLifecycleEvidence, NamespaceJoinEvidence, NativeLinuxMultiContainerSmokeReport,
    OciVmMultiContainerSmokeReport, PidSupervisionEvidence, RootfsMountEvidence,
};
#[cfg(target_os = "linux")]
pub use native_control::{
    NativeControlDescriptors, EXEC_LISTENER_FD, INIT_LOG_FD, PTY_LISTENER_FD,
};
#[cfg(target_os = "linux")]
pub use native_linux_driver::NativeLinuxDriver;
pub use native_smoke::{
    native_linux_fault_cleanup, native_linux_multi_container_smoke, native_linux_smoke,
};
pub use oci_smoke::{oci_vm_fault_cleanup, oci_vm_multi_container_smoke, oci_vm_smoke};
pub use report::{
    AgentVmSmokeReport, HvfSmokeReport, MacosHostCleanupEvidence, NativeLinuxSmokeReport,
    OciVmSmokeReport, WhpxSmokeReport,
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
