use std::path::Path;

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
use a3s_oci_core::HostPlatform;

use crate::report::OciVmSmokeReport;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod windows;

/// Exercise the fixed OCI create/start barrier inside one WHPX utility VM.
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
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        windows::run(shim, vm_rootfs, bundle, console).await
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        let _ = (shim, vm_rootfs, bundle, console);
        OciVmSmokeReport::unsupported(HostPlatform::current())
    }
}
