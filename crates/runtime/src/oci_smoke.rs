use std::path::Path;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_core::HostPlatform;

use crate::report::OciVmSmokeReport;
use crate::{
    LifecycleFaultPoint, MacosHvfSoakConfig, MacosHvfSoakReport, OciVmFaultCleanupReport,
    OciVmMultiContainerSmokeReport, OciVmTransportFaultCleanupReport,
    WindowsOciVmMultiContainerSmokeReport,
};

#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
mod utility_vm;

/// Exercise the fixed OCI core lifecycle inside one utility VM.
///
/// This diagnostic accepts only a bundle contained by the supplied VM
/// rootfs. The guest executor validates the exact bootstrap profile and
/// refuses every OCI property that it cannot enforce yet.
#[must_use]
pub async fn oci_vm_smoke(
    shim: &Path,
    vm_rootfs: &Path,
    bundle: &Path,
    console: &Path,
) -> OciVmSmokeReport {
    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    ))]
    {
        utility_vm::run(shim, vm_rootfs, bundle, console).await
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    {
        let _ = (shim, vm_rootfs, bundle, console);
        OciVmSmokeReport::unsupported(HostPlatform::current())
    }
}

/// Exercise two independently fenced containers inside one authenticated utility VM.
///
/// Both bundles must be distinct strict descendants of `vm_rootfs`.
#[must_use]
pub async fn oci_vm_multi_container_smoke(
    shim: &Path,
    vm_rootfs: &Path,
    bundle_a: &Path,
    bundle_b: &Path,
    console: &Path,
) -> OciVmMultiContainerSmokeReport {
    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    ))]
    {
        utility_vm::run_multi_container(shim, vm_rootfs, bundle_a, bundle_b, console).await
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    {
        let _ = (shim, vm_rootfs, bundle_a, bundle_b, console);
        OciVmMultiContainerSmokeReport::unsupported(HostPlatform::current())
    }
}

/// Repeatedly exercise the full two-container utility-VM profile on macOS HVF.
///
/// Each serial wave creates a fresh authenticated libkrun VM, exercises
/// lifecycle, generation fencing, namespace joins, rootfs enforcement, and
/// PID supervision, then proves host and guest resources returned to the same
/// baseline before the next wave begins. Console files are iteration-scoped
/// below the supplied existing directory and are never overwritten.
#[must_use]
pub async fn macos_hvf_soak(
    shim: &Path,
    vm_rootfs: &Path,
    bundle_a: &Path,
    bundle_b: &Path,
    console_directory: &Path,
    configuration: MacosHvfSoakConfig,
) -> MacosHvfSoakReport {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        utility_vm::run_macos_hvf_soak(
            shim,
            vm_rootfs,
            bundle_a,
            bundle_b,
            console_directory,
            configuration,
        )
        .await
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = (shim, vm_rootfs, bundle_a, bundle_b, console_directory);
        MacosHvfSoakReport::unsupported(HostPlatform::current(), configuration)
    }
}

/// Exercise two independently fenced containers in the Windows WHPX bootstrap profile.
///
/// This deliberately excludes user/time namespaces and ID-mapped mount
/// enforcement, which remain outside the qualified Windows utility kernel.
#[must_use]
pub async fn windows_oci_vm_multi_container_smoke(
    shim: &Path,
    vm_rootfs: &Path,
    bundle_a: &Path,
    bundle_b: &Path,
    console: &Path,
) -> WindowsOciVmMultiContainerSmokeReport {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        utility_vm::run_windows_multi_container(shim, vm_rootfs, bundle_a, bundle_b, console).await
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        let _ = (shim, vm_rootfs, bundle_a, bundle_b, console);
        WindowsOciVmMultiContainerSmokeReport::unsupported(HostPlatform::current())
    }
}

/// Interrupt a utility-VM lifecycle at one explicit boundary and prove cleanup.
///
/// This diagnostic deliberately skips the normal OCI delete operation. Closing
/// the authenticated session must shut down the guest executor, VM worker,
/// bridge endpoint, and runtime-owned transient state.
#[must_use]
pub async fn oci_vm_fault_cleanup(
    shim: &Path,
    vm_rootfs: &Path,
    bundle: &Path,
    console: &Path,
    fault: LifecycleFaultPoint,
) -> OciVmFaultCleanupReport {
    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    ))]
    {
        utility_vm::run_fault_cleanup(shim, vm_rootfs, bundle, console, fault).await
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    {
        let _ = (shim, vm_rootfs, bundle, console);
        OciVmFaultCleanupReport::unsupported(HostPlatform::current(), fault)
    }
}

/// Interrupt one real utility-VM `create` transport transition and prove cleanup.
///
/// This first real-host vertical slice accepts only the four host-side request
/// and response stages. It does not claim the guest-side or host-service reopen
/// portions of the complete transport recovery matrix.
#[must_use]
pub async fn oci_vm_transport_fault_cleanup(
    shim: &Path,
    vm_rootfs: &Path,
    bundle: &Path,
    console: &Path,
    stage: AgentTransportOperationStage,
) -> OciVmTransportFaultCleanupReport {
    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    ))]
    {
        utility_vm::run_transport_fault_cleanup(shim, vm_rootfs, bundle, console, stage).await
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    {
        let _ = (shim, vm_rootfs, bundle, console);
        OciVmTransportFaultCleanupReport::unsupported(HostPlatform::current(), stage)
    }
}
