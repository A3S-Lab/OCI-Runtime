use std::path::{Path, PathBuf};

#[cfg(not(target_os = "linux"))]
use a3s_oci_core::HostPlatform;

use crate::{
    LifecycleFaultPoint, NativeLinuxFaultCleanupReport, NativeLinuxMultiContainerSmokeReport,
    NativeLinuxRootlessSmokeReport, NativeLinuxSmokeReport, NativeLinuxSoakConfig,
    NativeLinuxSoakReport,
};

#[cfg(target_os = "linux")]
mod linux;

/// Exercise the real native Linux driver through the public Rust SDK.
///
/// This diagnostic is an explicit experimental opt-in. Default feature
/// discovery remains `probe-only`.
pub async fn native_linux_smoke(
    init_executable: &Path,
    bundle: &Path,
    work_parent: &Path,
) -> NativeLinuxSmokeReport {
    #[cfg(target_os = "linux")]
    {
        linux::run(init_executable, bundle, work_parent).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (init_executable, bundle, work_parent);
        NativeLinuxSmokeReport::unsupported(HostPlatform::current())
    }
}

/// Exercise the complete native Linux lifecycle over the packaged Unix SDK service.
///
/// This gate binds the same single-container service used by A3S Box, connects
/// through [`a3s_oci_sdk::RuntimeClient::connect`], and verifies service-owned
/// descriptor, process, socket, and executor cleanup.
pub async fn native_linux_service_smoke(
    init_executable: &Path,
    bundle: &Path,
    work_parent: &Path,
) -> NativeLinuxSmokeReport {
    #[cfg(target_os = "linux")]
    {
        linux::run_service(init_executable, bundle, work_parent).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (init_executable, bundle, work_parent);
        NativeLinuxSmokeReport::unsupported(HostPlatform::current())
    }
}

/// Exercise the native Linux core lifecycle as an unprivileged host user.
///
/// The diagnostic requires helper-backed subordinate UID/GID mappings and a
/// bundle without a cgroup path. It fails closed when invoked as host root.
pub async fn native_linux_rootless_smoke(
    init_executable: &Path,
    bundle: &Path,
    work_parent: &Path,
) -> NativeLinuxRootlessSmokeReport {
    #[cfg(target_os = "linux")]
    {
        linux::run_rootless(init_executable, bundle, work_parent).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (init_executable, bundle, work_parent);
        NativeLinuxRootlessSmokeReport::unsupported(HostPlatform::current())
    }
}

/// Exercise two independently fenced containers through the native Rust SDK path.
///
/// The diagnostic uses distinct bundles, retains both create barriers
/// concurrently, recreates one container with the next durable generation,
/// and verifies that every mutation remains scoped to its exact container.
pub async fn native_linux_multi_container_smoke(
    init_executable: &Path,
    bundle_a: &Path,
    bundle_b: &Path,
    work_parent: &Path,
) -> NativeLinuxMultiContainerSmokeReport {
    #[cfg(target_os = "linux")]
    {
        linux::run_multi_container(init_executable, bundle_a, bundle_b, work_parent).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (init_executable, bundle_a, bundle_b, work_parent);
        NativeLinuxMultiContainerSmokeReport::unsupported(HostPlatform::current())
    }
}

/// Repeatedly exercise concurrent native Linux containers through lifecycle,
/// query, exec, pause/reopen/resume, termination, generation reuse, and cleanup.
///
/// Each concurrent slot requires its own writable bundle, rootfs, and cgroup
/// path. The versioned report records successful operation counts and fails
/// closed on process, descriptor, marker, executor, or session leakage.
pub async fn native_linux_soak(
    init_executable: &Path,
    bundles: &[PathBuf],
    work_parent: &Path,
    configuration: NativeLinuxSoakConfig,
) -> NativeLinuxSoakReport {
    #[cfg(target_os = "linux")]
    {
        linux::run_soak(init_executable, bundles, work_parent, configuration).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (init_executable, bundles, work_parent);
        NativeLinuxSoakReport::unsupported(HostPlatform::current(), configuration)
    }
}

/// Interrupt the native lifecycle at one explicit boundary and prove shutdown cleanup.
///
/// This diagnostic never calls the normal OCI delete operation. It verifies
/// that executor shutdown owns process and transient-state cleanup even after
/// create, start, or kill has completed.
pub async fn native_linux_fault_cleanup(
    init_executable: &Path,
    bundle: &Path,
    work_parent: &Path,
    fault: LifecycleFaultPoint,
) -> NativeLinuxFaultCleanupReport {
    #[cfg(target_os = "linux")]
    {
        linux::run_fault_cleanup(init_executable, bundle, work_parent, fault).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (init_executable, bundle, work_parent);
        NativeLinuxFaultCleanupReport::unsupported(HostPlatform::current(), fault)
    }
}
