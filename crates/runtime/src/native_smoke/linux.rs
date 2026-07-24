use std::path::Path;
use std::sync::Arc;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{OciBundle, RuntimeClient};

use crate::{HostRuntimeService, NativeLinuxDriver, NativeLinuxSmokeReport, RuntimeDriver};

mod filesystem;
mod lifecycle;

use filesystem::{
    canonical_directory, create_private_directory, fixed_rootfs, path_exists, remove_marker,
    unique_nonce, MARKER_NAME,
};
use lifecycle::{best_effort_delete, exercise};

pub(super) async fn run(
    init_executable: &Path,
    bundle_directory: &Path,
    work_parent: &Path,
) -> NativeLinuxSmokeReport {
    let mut report = NativeLinuxSmokeReport::initial(HostPlatform::Linux);
    report.kvm_device_present = Path::new("/dev/kvm").exists();

    let work_parent = match canonical_directory(work_parent, "smoke work parent").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let bundle_directory = match canonical_directory(bundle_directory, "OCI bundle").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
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
    let marker = rootfs.join(MARKER_NAME);
    match path_exists(&marker).await {
        Ok(false) => {}
        Ok(true) => {
            return failed(
                report,
                format!(
                    "refusing to overwrite an existing native smoke marker: {}",
                    marker.display()
                ),
            );
        }
        Err(reason) => return failed(report, reason),
    }

    let nonce = match unique_nonce() {
        Ok(nonce) => nonce,
        Err(reason) => return failed(report, reason),
    };
    let session_root = work_parent.join(format!("a3s-oci-native-smoke-{nonce}"));
    if let Err(reason) = create_private_directory(&session_root).await {
        return failed(report, reason);
    }
    let executor_parent = session_root.join("executor");
    if let Err(reason) = create_private_directory(&executor_parent).await {
        return cleanup_session(report, &session_root, reason).await;
    }

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
    let service = match HostRuntimeService::open(session_root.join("state"), runtime_driver).await {
        Ok(service) => service,
        Err(error) => {
            let reason = format!("failed to open durable native runtime: {error}");
            cleanup_driver(&driver, &executor_root, &marker, &session_root, &mut report).await;
            return failed(report, reason);
        }
    };
    let client = RuntimeClient::new(service.clone());

    let exercise = exercise(&client, &bundle, &nonce, &marker, &mut report).await;
    if exercise.is_err() {
        best_effort_delete(&client, &nonce).await;
    }
    drop(client);
    drop(service);

    cleanup_driver(&driver, &executor_root, &marker, &session_root, &mut report).await;
    if let Err(reason) = exercise {
        append_reason(&mut report, reason);
    }
    if report.lifecycle_succeeded() {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    }
    report
}

async fn cleanup_driver(
    driver: &NativeLinuxDriver,
    executor_root: &Path,
    marker: &Path,
    session_root: &Path,
    report: &mut NativeLinuxSmokeReport,
) {
    if let Err(error) = driver.shutdown().await {
        append_reason(report, format!("native executor shutdown failed: {error}"));
    }
    match path_exists(executor_root).await {
        Ok(exists) => report.executor_runtime_clean = !exists,
        Err(reason) => append_reason(report, reason),
    }
    match remove_marker(marker).await {
        Ok(()) => report.marker_removed = true,
        Err(reason) => append_reason(report, reason),
    }
    match tokio::fs::remove_dir_all(session_root).await {
        Ok(()) => match path_exists(session_root).await {
            Ok(exists) => report.session_root_clean = !exists,
            Err(reason) => append_reason(report, reason),
        },
        Err(error) => append_reason(
            report,
            format!(
                "failed to remove native smoke session {}: {error}",
                session_root.display()
            ),
        ),
    }
}

async fn cleanup_session(
    mut report: NativeLinuxSmokeReport,
    session_root: &Path,
    reason: impl Into<String>,
) -> NativeLinuxSmokeReport {
    append_reason(&mut report, reason);
    match tokio::fs::remove_dir_all(session_root).await {
        Ok(()) => report.session_root_clean = true,
        Err(error) => append_reason(
            &mut report,
            format!(
                "failed to remove native smoke session {}: {error}",
                session_root.display()
            ),
        ),
    }
    report
}

fn append_reason(report: &mut NativeLinuxSmokeReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

fn failed(mut report: NativeLinuxSmokeReport, reason: impl Into<String>) -> NativeLinuxSmokeReport {
    append_reason(&mut report, reason);
    report
}
