mod lifecycle;
mod probe;
mod profile;

use std::path::Path;
use std::sync::Arc;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::OciBundle;

use self::lifecycle::{exercise, QualificationContext};
use self::probe::{namespace_identity, probe_mechanism};
use self::profile::network_profile;
use super::filesystem::{
    canonical_directory, create_private_directory, fixed_rootfs, path_exists, remove_marker,
    unique_nonce,
};
use crate::{
    HostRuntimeService, NativeLinuxDriver, NativeLinuxNetworkEnforcementSmokeConfig,
    NativeLinuxNetworkEnforcementSmokeReport, RuntimeDriver,
};

const REDIRECT_MARKER_NAME: &str = ".a3s-oci-oar01-redirect";
const REJECTION_MARKER_NAME: &str = ".a3s-oci-oar01-rejection";

pub(super) async fn run(
    init_executable: &Path,
    bundle_directory: &Path,
    work_parent: &Path,
    configuration: NativeLinuxNetworkEnforcementSmokeConfig,
) -> NativeLinuxNetworkEnforcementSmokeReport {
    let mut report = NativeLinuxNetworkEnforcementSmokeReport::initial(HostPlatform::Linux);
    report.kvm_device_present = Path::new("/dev/kvm").exists();

    let work_parent = match canonical_directory(work_parent, "smoke work parent").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let bundle_directory = match canonical_directory(bundle_directory, "OCI bundle").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let init_executable = match tokio::fs::canonicalize(init_executable).await {
        Ok(path) => path,
        Err(error) => {
            return failed(
                report,
                format!(
                    "failed to resolve native init executable {}: {error}",
                    init_executable.display()
                ),
            );
        }
    };
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
    let redirect_marker = rootfs.join(REDIRECT_MARKER_NAME);
    let rejection_marker = rootfs.join(REJECTION_MARKER_NAME);
    for marker in [&redirect_marker, &rejection_marker] {
        match path_exists(marker).await {
            Ok(false) => {}
            Ok(true) => {
                return failed(
                    report,
                    format!(
                        "refusing to overwrite network-enforcement marker {}",
                        marker.display()
                    ),
                );
            }
            Err(reason) => return failed(report, reason),
        }
    }

    let profile = match network_profile(&bundle, &configuration) {
        Ok(profile) => profile,
        Err(reason) => return failed(report, reason),
    };
    report.attachment = Some(profile.attachment.clone());
    let namespace_before = match namespace_identity(&profile.namespace_path).await {
        Ok(identity) => identity,
        Err(reason) => return failed(report, reason),
    };
    match probe_mechanism(
        &profile.namespace_path,
        configuration.redirect_port(),
        configuration.rejected_port(),
    ) {
        Ok(()) => report.mechanism_verified_before_create = true,
        Err(reason) => return failed(report, reason),
    }

    let nonce = match unique_nonce() {
        Ok(nonce) => nonce,
        Err(reason) => return failed(report, reason),
    };
    let session_root = work_parent.join(format!("a3s-oci-native-oar01-{nonce}"));
    if let Err(reason) = create_private_directory(&session_root).await {
        return failed(report, reason);
    }
    let executor_parent = session_root.join("executor");
    if let Err(reason) = create_private_directory(&executor_parent).await {
        return cleanup_session(report, &session_root, reason).await;
    }
    let state_root = session_root.join("state");
    let driver = match NativeLinuxDriver::open_experimental(&executor_parent, init_executable).await
    {
        Ok(driver) => Arc::new(driver),
        Err(error) => {
            return cleanup_session(
                report,
                &session_root,
                format!("failed to open native Linux driver: {error}"),
            )
            .await;
        }
    };
    let executor_root = driver.executor_root().to_path_buf();
    let runtime_driver: Arc<dyn RuntimeDriver> = driver.clone();
    let service = match HostRuntimeService::open(&state_root, runtime_driver).await {
        Ok(service) => service,
        Err(error) => {
            let reason = format!("failed to open durable native runtime: {error}");
            cleanup_driver(
                &driver,
                &executor_root,
                [&redirect_marker, &rejection_marker],
                &session_root,
                &mut report,
            )
            .await;
            return failed(report, reason);
        }
    };

    let exercise = exercise(
        QualificationContext {
            service,
            driver: Arc::clone(&driver),
            state_root: &state_root,
            bundle: &bundle,
            profile: &profile,
            configuration: &configuration,
            nonce: &nonce,
            markers: [&redirect_marker, &rejection_marker],
            namespace_before,
        },
        &mut report,
    )
    .await;

    cleanup_driver(
        &driver,
        &executor_root,
        [&redirect_marker, &rejection_marker],
        &session_root,
        &mut report,
    )
    .await;
    if let Err(reason) = exercise {
        append_reason(&mut report, reason);
    }
    if report.evidence_succeeded() && report.reason.is_none() {
        report.status = CapabilityStatus::Available;
    }
    report
}

async fn cleanup_driver(
    driver: &NativeLinuxDriver,
    executor_root: &Path,
    markers: [&Path; 2],
    session_root: &Path,
    report: &mut NativeLinuxNetworkEnforcementSmokeReport,
) {
    if let Err(error) = driver.shutdown().await {
        append_reason(report, format!("native executor shutdown failed: {error}"));
    }
    match path_exists(executor_root).await {
        Ok(exists) => report.executor_runtime_clean = !exists,
        Err(reason) => append_reason(report, reason),
    }
    let mut markers_removed = true;
    for marker in markers {
        if let Err(reason) = remove_marker(marker).await {
            markers_removed = false;
            append_reason(report, reason);
        }
    }
    report.markers_removed = markers_removed;
    match tokio::fs::remove_dir_all(session_root).await {
        Ok(()) => match path_exists(session_root).await {
            Ok(exists) => report.session_root_clean = !exists,
            Err(reason) => append_reason(report, reason),
        },
        Err(error) => append_reason(
            report,
            format!(
                "failed to remove network-enforcement session {}: {error}",
                session_root.display()
            ),
        ),
    }
}

async fn cleanup_session(
    mut report: NativeLinuxNetworkEnforcementSmokeReport,
    session_root: &Path,
    reason: impl Into<String>,
) -> NativeLinuxNetworkEnforcementSmokeReport {
    append_reason(&mut report, reason);
    match tokio::fs::remove_dir_all(session_root).await {
        Ok(()) => report.session_root_clean = true,
        Err(error) => append_reason(
            &mut report,
            format!(
                "failed to remove network-enforcement session {}: {error}",
                session_root.display()
            ),
        ),
    }
    report
}

fn append_reason(report: &mut NativeLinuxNetworkEnforcementSmokeReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

fn failed(
    mut report: NativeLinuxNetworkEnforcementSmokeReport,
    reason: impl Into<String>,
) -> NativeLinuxNetworkEnforcementSmokeReport {
    append_reason(&mut report, reason);
    report
}
