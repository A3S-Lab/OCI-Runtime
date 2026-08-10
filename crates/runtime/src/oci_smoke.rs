use std::path::Path;

use a3s_oci_agent_protocol::{AgentTransportFaultStage, AgentTransportOperationStage};
use a3s_oci_core::HostPlatform;

use crate::report::OciVmSmokeReport;
use crate::{
    LifecycleFaultPoint, MacosHvfSoakConfig, MacosHvfSoakReport, OciVmFaultCleanupReport,
    OciVmMultiContainerSmokeReport, OciVmOperationReopenReplacementReport,
    OciVmReopenReplacementReport, OciVmTransportFaultCleanupReport,
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

/// Interrupt one real utility-VM transport transition and prove cleanup.
///
/// The diagnostic covers all nine Host/Guest `create` request-response stages
/// and both explicit Host shutdown stages. It does not claim durable
/// host-service reopen or utility-VM owner replacement.
#[must_use]
pub async fn oci_vm_transport_fault_cleanup(
    shim: &Path,
    vm_rootfs: &Path,
    bundle: &Path,
    console: &Path,
    stage: impl Into<AgentTransportFaultStage>,
) -> OciVmTransportFaultCleanupReport {
    let stage = stage.into();
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

/// Resume one interrupted durable create through a replacement macOS HVF owner.
///
/// The first VM is interrupted before its Create request is written. The
/// diagnostic then closes that VM, reopens the same durable host state around
/// a fresh authenticated VM, reuses the original OperationId and generation,
/// and force-deletes the completed container through the replacement owner.
#[must_use]
pub async fn oci_vm_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    bundle: &Path,
    console_directory: &Path,
) -> OciVmReopenReplacementReport {
    oci_vm_reopen_replacement_at(
        shim,
        vm_rootfs,
        bundle,
        console_directory,
        AgentTransportOperationStage::HostBeforeRequestWrite,
    )
    .await
}

/// Resume one transport-interrupted durable create through a replacement macOS HVF owner.
///
/// The selected stage may be any Host- or Guest-side Create request/response
/// transition. A fresh authenticated VM must recover or complete the original
/// durable operation and generation after the first owner disconnects.
#[must_use]
pub async fn oci_vm_reopen_replacement_at(
    shim: &Path,
    vm_rootfs: &Path,
    bundle: &Path,
    console_directory: &Path,
    stage: AgentTransportOperationStage,
) -> OciVmReopenReplacementReport {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        utility_vm::run_reopen_replacement(shim, vm_rootfs, bundle, console_directory, stage).await
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = (shim, vm_rootfs, bundle, console_directory);
        OciVmReopenReplacementReport::unsupported(HostPlatform::current(), stage)
    }
}

/// Reissue one interrupted State query through a replacement macOS HVF owner.
///
/// The selected Host or Guest transition interrupts a query against an exact
/// durable `created` generation. The first VM then closes completely, a fresh
/// owner rebuilds that pre-start process, and State must observe the recovered
/// record before force-delete cleanup.
#[must_use]
pub async fn oci_vm_state_reopen_replacement_at(
    shim: &Path,
    vm_rootfs: &Path,
    bundle: &Path,
    console_directory: &Path,
    stage: AgentTransportOperationStage,
) -> OciVmOperationReopenReplacementReport {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        utility_vm::run_state_reopen_replacement(shim, vm_rootfs, bundle, console_directory, stage)
            .await
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = (shim, vm_rootfs, bundle, console_directory);
        OciVmOperationReopenReplacementReport::unsupported_state(HostPlatform::current(), stage)
    }
}

/// Reissue one interrupted Start through a replacement macOS HVF owner.
///
/// Recovery rebuilds the exact pre-start process in every stage. When the
/// first response was already delivered, it also restarts that process and
/// rebinds the completed Create and Start journals to the fresh Guest PID.
#[must_use]
pub async fn oci_vm_start_reopen_replacement_at(
    shim: &Path,
    vm_rootfs: &Path,
    bundle: &Path,
    console_directory: &Path,
    stage: AgentTransportOperationStage,
) -> OciVmOperationReopenReplacementReport {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        utility_vm::run_start_reopen_replacement(shim, vm_rootfs, bundle, console_directory, stage)
            .await
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = (shim, vm_rootfs, bundle, console_directory);
        OciVmOperationReopenReplacementReport::unsupported_start(HostPlatform::current(), stage)
    }
}

/// Reissue one interrupted Kill through a replacement macOS HVF owner.
///
/// Recovery rebuilds the exact running process for every stage. When the
/// first response was already delivered, it also reconstructs the stopped
/// Guest tombstone before replaying the completed durable Kill journal.
#[must_use]
pub async fn oci_vm_kill_reopen_replacement_at(
    shim: &Path,
    vm_rootfs: &Path,
    bundle: &Path,
    console_directory: &Path,
    stage: AgentTransportOperationStage,
) -> OciVmOperationReopenReplacementReport {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        utility_vm::run_kill_reopen_replacement(shim, vm_rootfs, bundle, console_directory, stage)
            .await
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = (shim, vm_rootfs, bundle, console_directory);
        OciVmOperationReopenReplacementReport::unsupported_kill(HostPlatform::current(), stage)
    }
}

/// Reissue one interrupted stopped-only Delete through a replacement macOS HVF owner.
///
/// Before a Delete response is committed, recovery rebuilds the exact stopped
/// Guest tombstone and resumes the original journaled operation. After a
/// response is committed, the fresh owner must replay the completed journal
/// without rebuilding the workload or dispatching Delete again.
#[must_use]
pub async fn oci_vm_delete_reopen_replacement_at(
    shim: &Path,
    vm_rootfs: &Path,
    bundle: &Path,
    console_directory: &Path,
    stage: AgentTransportOperationStage,
) -> OciVmOperationReopenReplacementReport {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        utility_vm::run_delete_reopen_replacement(shim, vm_rootfs, bundle, console_directory, stage)
            .await
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = (shim, vm_rootfs, bundle, console_directory);
        OciVmOperationReopenReplacementReport::unsupported_delete(HostPlatform::current(), stage)
    }
}
