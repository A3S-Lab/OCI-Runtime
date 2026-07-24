use std::path::Path;

#[cfg(not(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
)))]
use a3s_oci_core::HostPlatform;

use crate::report::AgentVmSmokeReport;

/// Boot the fixed guest-agent path and verify the authenticated host-to-guest path.
///
/// The runtime binds the protected endpoint before starting the isolated
/// libkrun shim. The endpoint accepts only that shim process, then protocol
/// negotiation authenticates the supplied guest agent with a one-time token.
#[must_use]
pub async fn agent_vm_smoke(shim: &Path, rootfs: &Path, console: &Path) -> AgentVmSmokeReport {
    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    ))]
    {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let cleanup = crate::host_cleanup::MacosHostCleanupTracker::capture();
        let report =
            match crate::agent_session::AgentVmSession::connect(shim, rootfs, console).await {
                Ok(session) => session.finish().await,
                Err(report) => report,
            };
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            let mut report = report;
            cleanup.apply(&mut report).await;
            report
        }
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            report
        }
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    {
        let _ = (shim, rootfs, console);
        AgentVmSmokeReport::unsupported(HostPlatform::current())
    }
}
