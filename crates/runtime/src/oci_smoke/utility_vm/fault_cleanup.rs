use std::path::Path;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::OciBundle;

use super::lifecycle::exercise_until_fault;
use super::{
    canonical_directory, fixed_rootfs, guest_path, path_exists, remove_marker, runtime_entries,
    target, unique_nonce, GUEST_RUNTIME_PREFIX, MARKER_NAME,
};
use crate::agent_session::AgentVmSession;
use crate::{LifecycleFaultPoint, OciVmFaultCleanupReport};

pub(super) async fn run(
    shim: &Path,
    vm_rootfs: &Path,
    bundle_directory: &Path,
    console: &Path,
    fault: LifecycleFaultPoint,
) -> OciVmFaultCleanupReport {
    let mut report = OciVmFaultCleanupReport::initial(HostPlatform::current(), fault);
    let vm_rootfs = match canonical_directory(vm_rootfs, "VM rootfs").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let bundle_directory = match canonical_directory(bundle_directory, "OCI bundle").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    if bundle_directory == vm_rootfs || !bundle_directory.starts_with(&vm_rootfs) {
        return failed(
            report,
            format!(
                "OCI bundle must be a strict descendant of VM rootfs {}: {}",
                vm_rootfs.display(),
                bundle_directory.display()
            ),
        );
    }

    let bundle = match OciBundle::load(&bundle_directory).await {
        Ok(bundle) => {
            report.bundle_loaded = true;
            bundle
        }
        Err(error) => return failed(report, format!("failed to load OCI bundle: {error}")),
    };
    let rootfs = match fixed_rootfs(&bundle).await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let marker = rootfs.join(MARKER_NAME);
    match path_exists(&marker).await {
        Ok(false) => {}
        Ok(true) => {
            return failed(
                report,
                format!(
                    "refusing to overwrite an existing OCI cleanup marker: {}",
                    marker.display()
                ),
            );
        }
        Err(reason) => return failed(report, reason),
    }

    let guest_bundle = match guest_path(&vm_rootfs, &bundle_directory) {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let baseline_runtime_entries = match runtime_entries(&vm_rootfs).await {
        Ok(entries) => entries,
        Err(reason) => return failed(report, reason),
    };
    let nonce = match unique_nonce() {
        Ok(nonce) => nonce,
        Err(reason) => return failed(report, reason),
    };
    let target = match target(&format!("fault-{nonce}")) {
        Ok(target) => target,
        Err(reason) => return failed(report, reason),
    };

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let cleanup = crate::host_cleanup::MacosHostCleanupTracker::capture();
    let session = match AgentVmSession::connect(shim, &vm_rootfs, console).await {
        Ok(session) => session,
        Err(bridge) => {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let bridge = {
                let mut bridge = bridge;
                cleanup.apply(&mut bridge).await;
                bridge
            };
            report.reason = bridge.reason.clone();
            report.bridge = bridge;
            return report;
        }
    };

    let exercise = exercise_until_fault(
        session.client(),
        &bundle,
        guest_bundle,
        &target,
        &nonce,
        &marker,
        &mut report.lifecycle,
    )
    .await;
    report.bridge = match &exercise {
        Ok(()) => session.finish().await,
        Err(reason) => session.finish_with_failure(reason).await,
    };
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    cleanup.apply(&mut report.bridge).await;

    match remove_marker(&marker).await {
        Ok(()) => match path_exists(&marker).await {
            Ok(exists) => {
                report.marker_removed = !exists;
                if exists {
                    append_reason(
                        &mut report,
                        format!("OCI cleanup marker remained: {}", marker.display()),
                    );
                }
            }
            Err(reason) => append_reason(&mut report, reason),
        },
        Err(reason) => append_reason(&mut report, reason),
    }
    match runtime_entries(&vm_rootfs).await {
        Ok(entries) => {
            report.guest_runtime_clean = entries == baseline_runtime_entries;
            if !report.guest_runtime_clean {
                append_reason(
                    &mut report,
                    format!(
                        "guest agent left {GUEST_RUNTIME_PREFIX} runtime directories after \
                         fault cleanup"
                    ),
                );
            }
        }
        Err(reason) => append_reason(&mut report, reason),
    }

    if let Err(reason) = exercise {
        append_reason(&mut report, reason);
    } else if !report.bridge.is_success() {
        let reason = report
            .bridge
            .reason
            .clone()
            .unwrap_or_else(|| "authenticated guest bridge cleanup failed".into());
        append_reason(&mut report, reason);
    }
    if report.evidence_succeeded() {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    }
    report
}

fn append_reason(report: &mut OciVmFaultCleanupReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

fn failed(
    mut report: OciVmFaultCleanupReport,
    reason: impl Into<String>,
) -> OciVmFaultCleanupReport {
    append_reason(&mut report, reason);
    report
}
