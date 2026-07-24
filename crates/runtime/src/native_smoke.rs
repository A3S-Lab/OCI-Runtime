use std::path::Path;

#[cfg(not(target_os = "linux"))]
use a3s_oci_core::HostPlatform;

use crate::{LifecycleFaultPoint, NativeLinuxFaultCleanupReport, NativeLinuxSmokeReport};

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
