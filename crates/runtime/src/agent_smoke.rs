use std::path::Path;

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
use a3s_oci_core::HostPlatform;

use crate::report::AgentVmSmokeReport;

/// Boot the fixed guest-agent path and verify the authenticated host-to-guest path.
///
/// The runtime binds the protected endpoint before starting the isolated
/// libkrun shim. The endpoint accepts only that shim process, then protocol
/// negotiation authenticates the supplied guest agent with a one-time token.
#[must_use]
pub async fn agent_vm_smoke(shim: &Path, rootfs: &Path, console: &Path) -> AgentVmSmokeReport {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        match crate::agent_session::WindowsAgentVmSession::connect(shim, rootfs, console).await {
            Ok(session) => session.finish().await,
            Err(report) => report,
        }
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        let _ = (shim, rootfs, console);
        AgentVmSmokeReport::unsupported(HostPlatform::current())
    }
}
