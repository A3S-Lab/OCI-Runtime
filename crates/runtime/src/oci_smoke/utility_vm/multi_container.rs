use std::path::Path;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::OciBundle;

use super::{
    canonical_directory, fixed_rootfs, guest_path, path_exists, remove_marker, runtime_entries,
    unique_nonce, GUEST_RUNTIME_PREFIX, MARKER_NAME,
};
use crate::agent_session::AgentVmSession;
use crate::OciVmMultiContainerSmokeReport;

mod lifecycle;
mod namespace_join;

use lifecycle::{best_effort_delete, exercise};

pub(super) async fn run(
    shim: &Path,
    vm_rootfs: &Path,
    bundle_a: &Path,
    bundle_b: &Path,
    console: &Path,
) -> OciVmMultiContainerSmokeReport {
    let mut report = OciVmMultiContainerSmokeReport::initial(HostPlatform::current());
    let vm_rootfs = match canonical_directory(vm_rootfs, "VM rootfs").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let bundle_a_directory = match canonical_directory(bundle_a, "first OCI bundle").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let bundle_b_directory = match canonical_directory(bundle_b, "second OCI bundle").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    for (label, bundle) in [
        ("first", &bundle_a_directory),
        ("second", &bundle_b_directory),
    ] {
        if bundle == &vm_rootfs || !bundle.starts_with(&vm_rootfs) {
            return failed(
                report,
                format!(
                    "{label} OCI bundle must be a strict descendant of VM rootfs {}: {}",
                    vm_rootfs.display(),
                    bundle.display()
                ),
            );
        }
    }
    report.lifecycle.distinct_bundle_directories = bundle_a_directory != bundle_b_directory;
    if !report.lifecycle.distinct_bundle_directories {
        return failed(
            report,
            "multi-container diagnostic requires two distinct OCI bundle directories",
        );
    }

    let bundle_a = match OciBundle::load(&bundle_a_directory).await {
        Ok(bundle) => bundle,
        Err(error) => {
            return failed(report, format!("failed to load first OCI bundle: {error}"));
        }
    };
    let bundle_b = match OciBundle::load(&bundle_b_directory).await {
        Ok(bundle) => bundle,
        Err(error) => {
            return failed(report, format!("failed to load second OCI bundle: {error}"));
        }
    };
    report.bundles_loaded = true;

    let rootfs_a = match fixed_rootfs(&bundle_a).await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let rootfs_b = match fixed_rootfs(&bundle_b).await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    report.lifecycle.distinct_rootfs_directories = rootfs_a != rootfs_b;
    if !report.lifecycle.distinct_rootfs_directories {
        return failed(
            report,
            "multi-container diagnostic requires two distinct root filesystems",
        );
    }
    let markers = [rootfs_a.join(MARKER_NAME), rootfs_b.join(MARKER_NAME)];
    for (label, marker) in [("first", &markers[0]), ("second", &markers[1])] {
        match path_exists(marker).await {
            Ok(false) => {}
            Ok(true) => {
                return failed(
                    report,
                    format!(
                        "refusing to overwrite the {label} existing marker: {}",
                        marker.display()
                    ),
                );
            }
            Err(reason) => return failed(report, reason),
        }
    }

    let guest_bundles = match (
        guest_path(&vm_rootfs, &bundle_a_directory),
        guest_path(&vm_rootfs, &bundle_b_directory),
    ) {
        (Ok(a), Ok(b)) => [a, b],
        (Err(reason), _) | (_, Err(reason)) => return failed(report, reason),
    };
    let baseline_runtime_entries = match runtime_entries(&vm_rootfs).await {
        Ok(entries) => entries,
        Err(reason) => return failed(report, reason),
    };
    let nonce = match unique_nonce() {
        Ok(nonce) => nonce,
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

    let exercise = async {
        exercise(
            session.client(),
            [&bundle_a, &bundle_b],
            guest_bundles.clone(),
            &nonce,
            [&markers[0], &markers[1]],
            &mut report,
        )
        .await?;
        namespace_join::exercise(
            session.client(),
            &bundle_a,
            &bundle_b,
            guest_bundles,
            &nonce,
            [&markers[0], &markers[1]],
            &mut report,
        )
        .await
    }
    .await;
    if exercise.is_err() {
        best_effort_delete(session.client(), &nonce).await;
    }
    report.bridge = match &exercise {
        Ok(()) => session.finish().await,
        Err(reason) => session.finish_with_failure(reason).await,
    };
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    cleanup.apply(&mut report.bridge).await;

    let mut markers_removed = true;
    for marker in &markers {
        if let Err(reason) = remove_marker(marker).await {
            markers_removed = false;
            append_reason(&mut report, reason);
        }
    }
    report.markers_removed = markers_removed;
    match runtime_entries(&vm_rootfs).await {
        Ok(entries) => {
            report.guest_runtime_clean = entries == baseline_runtime_entries;
            if !report.guest_runtime_clean {
                append_reason(
                    &mut report,
                    format!(
                        "guest agent left {GUEST_RUNTIME_PREFIX} runtime directories after shutdown"
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
            .unwrap_or_else(|| "authenticated guest bridge failed".into());
        append_reason(&mut report, reason);
    }

    if report.evidence_succeeded() && report.reason.is_none() {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    }
    report
}

fn append_reason(report: &mut OciVmMultiContainerSmokeReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

fn failed(
    mut report: OciVmMultiContainerSmokeReport,
    reason: impl Into<String>,
) -> OciVmMultiContainerSmokeReport {
    append_reason(&mut report, reason);
    report
}
