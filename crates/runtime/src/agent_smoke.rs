use std::path::Path;

#[cfg(not(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
use a3s_oci_core::HostPlatform;

use crate::report::AgentVmSmokeReport;

/// Boot the fixed guest-agent path and verify the authenticated host-to-guest path.
///
/// The runtime binds the protected endpoint before starting the isolated
/// libkrun shim. The endpoint accepts only that shim process, then protocol
/// negotiation authenticates the supplied guest agent with a one-time token.
#[must_use]
pub async fn agent_vm_smoke(
    shim: &Path,
    rootfs: &Path,
    system_image_manifest: Option<&Path>,
    runtime_share: Option<&Path>,
    console: &Path,
) -> AgentVmSmokeReport {
    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let cleanup = crate::host_cleanup::MacosHostCleanupTracker::capture();
        let session = match runtime_share {
            Some(runtime_share) => {
                crate::agent_session::UtilityVmSession::connect_with_separate_runtime_share(
                    shim,
                    rootfs,
                    system_image_manifest,
                    runtime_share,
                    console,
                )
                .await
            }
            None => {
                crate::agent_session::UtilityVmSession::connect(
                    shim,
                    rootfs,
                    system_image_manifest,
                    console,
                )
                .await
            }
        };
        let report = match session {
            Ok(session) => {
                let negotiated_client = session.client();
                drop(negotiated_client);
                session.shutdown().await
            }
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
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            report
        }
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = (shim, rootfs, system_image_manifest, runtime_share, console);
        AgentVmSmokeReport::unsupported(HostPlatform::current())
    }
}

/// Exercise Linux KVM setup through a verified device/API probe, then stop
/// before the native VM-entry call.
///
/// This entry point exists only for real-host qualification. Production VM
/// sessions never enable the injected failure.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[doc(hidden)]
#[must_use]
pub async fn qualify_kvm_post_probe_failure(
    shim: &Path,
    rootfs: &Path,
    system_image_manifest: Option<&Path>,
    runtime_share: Option<&Path>,
    console: &Path,
) -> AgentVmSmokeReport {
    match crate::agent_session::AgentVmSession::connect_with_kvm_post_probe_failure(
        shim,
        rootfs,
        system_image_manifest,
        runtime_share,
        console,
    )
    .await
    {
        Ok(session) => session
            .finish_with_failure(
                "Linux KVM post-probe failure qualification unexpectedly reached the guest agent",
            )
            .await,
        Err(report) => report,
    }
}

/// Pause a Linux KVM worker after complete non-KVM configuration, let the
/// qualification harness mutate one named asset, and require fail-closed
/// reverification before `/dev/kvm` is opened.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[doc(hidden)]
#[must_use]
pub async fn qualify_kvm_compatibility_drift(
    shim: &Path,
    rootfs: &Path,
    system_image_manifest: Option<&Path>,
    runtime_share: Option<&Path>,
    console: &Path,
    case: &str,
) -> AgentVmSmokeReport {
    match crate::agent_session::AgentVmSession::connect_with_kvm_compatibility_drift(
        shim,
        rootfs,
        system_image_manifest,
        runtime_share,
        console,
        case,
    )
    .await
    {
        Ok(session) => session
            .finish_with_failure(format!(
                "Linux KVM compatibility-drift qualification {case} unexpectedly reached the guest agent"
            ))
            .await,
        Err(report) => report,
    }
}
