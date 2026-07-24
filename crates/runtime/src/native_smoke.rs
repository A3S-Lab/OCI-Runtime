use std::path::Path;

#[cfg(not(target_os = "linux"))]
use a3s_oci_core::HostPlatform;

use crate::NativeLinuxSmokeReport;

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
