//! Cross-platform host orchestration and platform capability probing.

#[cfg(any(
    target_os = "linux",
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
mod agent_driver;
#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod agent_launch_cleanup;
#[cfg(windows)]
mod agent_pipe;
#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod agent_session;
mod agent_smoke;
#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod agent_smoke_process;
#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod agent_socket;
mod box_whpx_service;
mod cleanup_report;
mod driver;
mod fault;
#[cfg(any(
    target_os = "linux",
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
mod filesystem_smoke;
mod guest_isolation_report;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod host_cleanup;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod hvf_driver;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod kvm_driver;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux_kvm_recovery_smoke;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux_kvm_service;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos_hvf_host_smoke;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos_hvf_service;
mod marker;
mod multi_container_report;
mod namespace_join;
#[cfg(target_os = "linux")]
mod native_checkpoint;
mod native_checkpoint_report;
#[cfg(target_os = "linux")]
mod native_control;
#[cfg(target_os = "linux")]
mod native_hook_recovery_smoke;
#[cfg(target_os = "linux")]
mod native_linux_driver;
mod native_network_enforcement_report;
#[cfg(target_os = "linux")]
mod native_recovery_smoke;
#[cfg(target_os = "linux")]
mod native_service;
mod native_smoke;
mod oci_smoke;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod operation_journal_evidence;
mod operation_reopen_replacement_report;
mod platform;
mod reopen_replacement_report;
mod report;
mod rootfs_enforcement;
#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
mod runtime_client_process_smoke;
mod service;
mod soak_report;
mod state;
mod transport_cleanup_report;
#[cfg(unix)]
mod unix_service;
#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod utility_vm_driver;
#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod utility_vm_host_service;
mod utility_vm_soak_report;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod whpx_bootstrap;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod whpx_driver;
mod whpx_driver_smoke;
mod whpx_recovery_smoke;
#[cfg(windows)]
#[doc(hidden)]
pub mod windows_security;
#[cfg(windows)]
mod windows_service;

#[cfg(target_os = "linux")]
pub use a3s_oci_agent::RootlessDevicePolicyBootstrap;
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct RootlessDevicePolicyBootstrap {
    _private: (),
}
pub use a3s_oci_agent_protocol::{
    AgentTransportFaultStage, AgentTransportOperationStage, AgentTransportShutdownStage,
};
#[cfg(windows)]
pub use agent_pipe::WindowsAgentPipeListener;
pub use agent_smoke::agent_vm_smoke;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[doc(hidden)]
pub use agent_smoke::qualify_kvm_compatibility_drift;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[doc(hidden)]
pub use agent_smoke::qualify_kvm_post_probe_failure;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub use agent_socket::LinuxAgentSocketListener;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use agent_socket::MacosAgentSocketListener;
pub use box_whpx_service::{
    serve_box_whpx_qualification, BoxWhpxServiceConfig, BOX_WHPX_SERVICE_READY_SCHEMA_VERSION,
};
pub use cleanup_report::{
    FaultInjectionEvidence, LifecycleFaultPoint, NativeLinuxFaultCleanupReport,
    OciVmFaultCleanupReport,
};
pub use driver::{
    DriverAttestationRequest, DriverAttestationResult, DriverCheckpointRequest,
    DriverCheckpointResult, DriverCloseStdinRequest, DriverContainerOperationRequest,
    DriverCreateAttachments, DriverCreateRequest, DriverDeleteRequest, DriverExecRequest,
    DriverKillRequest, DriverProcess, DriverReadOutputRequest, DriverRecovery, DriverResizeRequest,
    DriverRestoreRequest, DriverRestoreValidationRequest, DriverSignalProcessRequest,
    DriverStartRequest, DriverState, DriverUpdateRequest, DriverWaitProcessRequest,
    DriverWaitRequest, DriverWriteStdinRequest, OciHookPhase, RuntimeDriver,
};
pub use guest_isolation_report::{
    OciVmGuestIsolationCaseEvidence, OciVmGuestIsolationSmokeReport,
    OCI_VM_GUEST_ISOLATION_CASE_COUNT, OCI_VM_GUEST_ISOLATION_SMOKE_SCHEMA_VERSION,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use hvf_driver::{HvfRuntimeDriver, HvfRuntimeDriverConfig};
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub use kvm_driver::{KvmRuntimeDriver, KvmRuntimeDriverConfig};
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[doc(hidden)]
pub use linux_kvm_recovery_smoke::{
    linux_kvm_recovery_smoke, linux_kvm_soak, LinuxKvmRecoveryEvidence,
    LinuxKvmRecoverySmokeConfig, LinuxKvmRecoverySmokeReport, LinuxKvmSoakReport,
    LinuxKvmSoakSmokeConfig, LinuxKvmSoakWaveEvidence, LinuxProcessIdentity,
    DEFAULT_LINUX_KVM_SOAK_ITERATIONS, LINUX_KVM_RECOVERY_SMOKE_SCHEMA_VERSION,
    LINUX_KVM_SOAK_SCHEMA_VERSION, MAX_LINUX_KVM_SOAK_ITERATIONS,
};
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[doc(hidden)]
pub use linux_kvm_service::{
    LinuxKvmRecoveryHostService, LinuxKvmRecoveryHostServiceConfig, LinuxKvmSoakHostService,
    LinuxKvmSoakHostServiceConfig,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use macos_hvf_host_smoke::{
    macos_hvf_host_service_smoke, MacosHvfArtifactEvidence, MacosHvfHostServiceSmokeConfig,
    MacosHvfHostServiceSmokeReport, MacosHvfOwnerDeathEvidence, MacosHvfPublicLifecycleEvidence,
    MacosHvfPublicSoakEvidence, MacosProcessIdentity, MACOS_HVF_HOST_SERVICE_SMOKE_SCHEMA_VERSION,
    MAX_MACOS_HVF_HOST_SERVICE_SOAK_ITERATIONS, MIN_MACOS_HVF_HOST_SERVICE_SOAK_ITERATIONS,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use macos_hvf_service::{MacosHvfHostService, MacosHvfHostServiceConfig};
pub use multi_container_report::{
    CgroupPathEvidence, InitializationEvidence, MultiContainerLifecycleEvidence,
    NamespaceJoinEvidence, NativeLinuxMultiContainerSmokeReport, NetworkModeEvidence,
    OciVmMultiContainerSmokeReport, PidSupervisionEvidence, RootfsMountEvidence,
    StorageVolumeEvidence, WindowsOciVmMultiContainerSmokeReport,
};
pub use native_checkpoint_report::{
    NativeLinuxCheckpointRestoreCrashPoint, NativeLinuxCheckpointSmokeReport,
    NATIVE_LINUX_CHECKPOINT_SMOKE_SCHEMA_VERSION,
};
#[cfg(target_os = "linux")]
pub use native_control::{
    NativeControlDescriptors, EXEC_LISTENER_FD, INIT_LOG_FD, PTY_LISTENER_FD,
};
#[cfg(target_os = "linux")]
pub use native_hook_recovery_smoke::{
    native_linux_hook_owner_death_resume, NativeLinuxHookOwnerDeathEvidence,
    NativeLinuxHookOwnerDeathSmokeReport, NativeLinuxProcessIdentity,
    NATIVE_LINUX_HOOK_OWNER_DEATH_EVIDENCE_SCHEMA_VERSION,
    NATIVE_LINUX_HOOK_OWNER_DEATH_SMOKE_SCHEMA_VERSION,
};
#[cfg(target_os = "linux")]
pub use native_linux_driver::NativeLinuxDriver;
pub use native_network_enforcement_report::{
    NativeLinuxNetworkEnforcementSmokeConfig, NativeLinuxNetworkEnforcementSmokeReport,
    NATIVE_LINUX_NETWORK_ENFORCEMENT_SMOKE_SCHEMA_VERSION,
};
#[cfg(target_os = "linux")]
pub use native_recovery_smoke::{
    native_linux_hook_owner_death_owner, native_linux_recovery_owner,
    native_linux_recovery_owner_with_cgroup_delegation,
    native_linux_recovery_owner_with_device_bootstrap, native_linux_recovery_resume,
    native_linux_recovery_resume_with_cgroup_delegation,
    native_linux_recovery_resume_with_device_bootstrap, NativeLinuxRecoveryOwnerReady,
    NativeLinuxRecoveryPoint, NativeLinuxRecoverySmokeReport,
    NATIVE_LINUX_RECOVERY_OWNER_READY_SCHEMA_VERSION, NATIVE_LINUX_RECOVERY_SMOKE_SCHEMA_VERSION,
};
#[cfg(target_os = "linux")]
pub use native_service::{
    NativeLinuxHostService, NativeLinuxHostServiceConfig, NativeLinuxService,
    NativeLinuxServiceConfig,
};
#[cfg(target_os = "linux")]
pub use native_smoke::native_linux_checkpoint_restore_owner;
pub use native_smoke::{
    native_linux_checkpoint_smoke, native_linux_fault_cleanup, native_linux_multi_container_smoke,
    native_linux_network_enforcement_smoke, native_linux_rootless_device_policy_smoke,
    native_linux_rootless_smoke, native_linux_rootless_smoke_with_cgroup_delegation,
    native_linux_rootless_smoke_with_cgroup_delegation_barrier,
    native_linux_rootless_smoke_with_device_bootstrap_barrier, native_linux_service_smoke,
    native_linux_smoke, native_linux_soak,
};
pub use oci_smoke::{
    macos_hvf_soak, oci_vm_close_stdin_reopen_replacement_at, oci_vm_delete_reopen_replacement_at,
    oci_vm_exec_reopen_replacement_at, oci_vm_fault_cleanup, oci_vm_file_reopen_replacement_at,
    oci_vm_filesystem_reopen_replacement_at, oci_vm_guest_isolation_smoke,
    oci_vm_kill_reopen_replacement_at, oci_vm_multi_container_smoke,
    oci_vm_pause_reopen_replacement_at, oci_vm_processes_reopen_replacement_at,
    oci_vm_read_output_reopen_replacement_at, oci_vm_reopen_replacement,
    oci_vm_reopen_replacement_at, oci_vm_resize_reopen_replacement_at,
    oci_vm_resume_reopen_replacement_at, oci_vm_signal_process_reopen_replacement_at, oci_vm_smoke,
    oci_vm_start_reopen_replacement_at, oci_vm_state_reopen_replacement_at,
    oci_vm_stats_reopen_replacement_at, oci_vm_transport_fault_cleanup,
    oci_vm_update_reopen_replacement_at, oci_vm_wait_process_reopen_replacement_at,
    oci_vm_wait_reopen_replacement_at, oci_vm_write_stdin_reopen_replacement_at,
    windows_oci_vm_multi_container_smoke,
};
pub use operation_reopen_replacement_report::{
    OciVmOperationReopenReplacementReport,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_CLOSE_STDIN_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_DELETE_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_EXEC_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_FILESYSTEM_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_FILE_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_PAUSE_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_PROCESSES_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_READ_OUTPUT_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_RESIZE_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_RESUME_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_SIGNAL_PROCESS_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_START_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_STATE_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_STATS_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_UPDATE_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_WAIT_PROCESS_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_WAIT_SCHEMA_VERSION,
    OCI_VM_OPERATION_REOPEN_REPLACEMENT_WRITE_STDIN_SCHEMA_VERSION,
};
pub use reopen_replacement_report::{
    OciVmReopenReplacementReport, OCI_VM_REOPEN_REPLACEMENT_SCHEMA_VERSION,
};
pub use report::{
    AgentVmSmokeReport, HvfSmokeReport, MacosHostCleanupEvidence, NativeLinuxRootlessSmokeReport,
    NativeLinuxSmokeReport, OciVmSmokeReport, WhpxSmokeReport,
};
pub use service::HostRuntimeService;
pub use soak_report::{
    NativeLinuxSoakConfig, NativeLinuxSoakOperationCounts, NativeLinuxSoakPauseResumeEvidence,
    NativeLinuxSoakReport, MAX_SOAK_CONCURRENT_CONTAINERS, MAX_SOAK_ITERATIONS,
    MAX_SOAK_OPERATION_TIMEOUT_MS, MIN_SOAK_CONCURRENT_CONTAINERS, MIN_SOAK_OPERATION_TIMEOUT_MS,
    NATIVE_LINUX_SOAK_SCHEMA_VERSION,
};
pub use transport_cleanup_report::{
    is_supported_guest_stage, is_supported_host_stage, is_supported_shutdown_stage,
    is_supported_transport_fault_stage, is_supported_transport_stage,
    OciVmTransportFaultCleanupReport, OCI_VM_TRANSPORT_FAULT_CLEANUP_SCHEMA_VERSION,
};
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[doc(hidden)]
pub use utility_vm_driver::operation_reopen::{
    linux_kvm_create_reopen_replacement, linux_kvm_delete_reopen_replacement,
    linux_kvm_exec_reopen_replacement, linux_kvm_kill_reopen_replacement,
    linux_kvm_pause_reopen_replacement, linux_kvm_processes_reopen_replacement,
    linux_kvm_read_output_reopen_replacement, linux_kvm_resume_reopen_replacement,
    linux_kvm_signal_process_reopen_replacement, linux_kvm_start_reopen_replacement,
    linux_kvm_state_reopen_replacement, linux_kvm_stats_reopen_replacement,
    linux_kvm_update_reopen_replacement, linux_kvm_wait_process_reopen_replacement,
    linux_kvm_wait_reopen_replacement, LinuxKvmCreateReopenConfig, LinuxKvmDeleteReopenConfig,
    LinuxKvmExecReopenConfig, LinuxKvmKillReopenConfig, LinuxKvmPauseReopenConfig,
    LinuxKvmProcessesReopenConfig, LinuxKvmReadOutputReopenConfig, LinuxKvmResumeReopenConfig,
    LinuxKvmSignalProcessReopenConfig, LinuxKvmStartReopenConfig, LinuxKvmStateReopenConfig,
    LinuxKvmStatsReopenConfig, LinuxKvmUpdateReopenConfig, LinuxKvmWaitProcessReopenConfig,
    LinuxKvmWaitReopenConfig,
};
pub use utility_vm_soak_report::{
    MacosHvfSoakConfig, MacosHvfSoakReport, MACOS_HVF_SOAK_CONCURRENT_CONTAINERS,
    MACOS_HVF_SOAK_SCHEMA_VERSION, MAX_MACOS_HVF_SOAK_ITERATIONS,
};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub use whpx_driver::{WhpxRuntimeDriver, WhpxRuntimeDriverConfig};
pub use whpx_driver_smoke::{
    whpx_driver_smoke, WhpxDriverSmokeReport, WHPX_DRIVER_SMOKE_SCHEMA_VERSION,
};
pub use whpx_recovery_smoke::{
    whpx_recovery_owner, whpx_recovery_resume, WhpxRecoveryOwnerConfig, WhpxRecoveryOwnerReady,
    WhpxRecoverySmokeReport, WHPX_RECOVERY_OWNER_READY_SCHEMA_VERSION,
    WHPX_RECOVERY_SMOKE_SCHEMA_VERSION,
};
#[cfg(windows)]
pub use windows_service::WindowsHostService;

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
