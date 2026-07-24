use std::path::Path;

#[cfg(not(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
)))]
use a3s_oci_core::HostPlatform;

use crate::report::OciVmSmokeReport;

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
