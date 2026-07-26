use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{ContainerId, LocalIpcEndpoint, OciBundle, RuntimeClient};
use tokio::time::timeout;

use crate::{
    HostRuntimeService, NativeLinuxDriver, NativeLinuxService, NativeLinuxServiceConfig,
    NativeLinuxSmokeReport, RuntimeDriver,
};

mod control_descriptors;
mod fault_cleanup;
mod filesystem;
mod lifecycle;
mod multi_container;
mod process;
mod rootless;

use control_descriptors::{enable_workload_verification, ControlDescriptorFixture};
use filesystem::{
    canonical_directory, create_private_directory, fixed_rootfs, path_exists, remove_marker,
    unique_nonce, MARKER_NAME,
};
use lifecycle::{best_effort_delete, exercise, exercise_bound_service, HOOK_TRACE_NAME};

const SERVICE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) async fn run_fault_cleanup(
    init_executable: &Path,
    bundle_directory: &Path,
    work_parent: &Path,
    fault: crate::LifecycleFaultPoint,
) -> crate::NativeLinuxFaultCleanupReport {
    fault_cleanup::run(init_executable, bundle_directory, work_parent, fault).await
}

pub(super) async fn run_multi_container(
    init_executable: &Path,
    bundle_a: &Path,
    bundle_b: &Path,
    work_parent: &Path,
) -> crate::NativeLinuxMultiContainerSmokeReport {
    multi_container::run(init_executable, bundle_a, bundle_b, work_parent).await
}

pub(super) async fn run_rootless(
    init_executable: &Path,
    bundle: &Path,
    work_parent: &Path,
) -> crate::NativeLinuxRootlessSmokeReport {
    rootless::run(init_executable, bundle, work_parent).await
}

pub(super) async fn run_service(
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
    let init_executable = match tokio::fs::canonicalize(init_executable).await {
        Ok(path) => path,
        Err(error) => {
            return failed(
                report,
                format!(
                    "failed to resolve native init executable {}: {error}",
                    init_executable.display()
                ),
            )
        }
    };
    let bundle = match OciBundle::load(&bundle_directory).await {
        Ok(bundle) => {
            report.bundle_loaded = true;
            bundle
        }
        Err(error) => return failed(report, format!("failed to load OCI bundle: {error}")),
    };
    let bundle = match enable_workload_verification(&bundle) {
        Ok(bundle) => bundle,
        Err(reason) => return failed(report, reason),
    };
    let rootfs = match fixed_rootfs(&bundle).await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let marker = rootfs.join(MARKER_NAME);
    let hook_trace = rootfs.join(HOOK_TRACE_NAME);
    match path_exists(&marker).await {
        Ok(false) => {}
        Ok(true) => {
            return failed(
                report,
                format!(
                    "refusing to overwrite an existing native smoke marker: {}",
                    marker.display()
                ),
            )
        }
        Err(reason) => return failed(report, reason),
    }

    let nonce = match unique_nonce() {
        Ok(nonce) => nonce,
        Err(reason) => return failed(report, reason),
    };
    let session_root = work_parent.join(format!("a3s-oci-native-service-smoke-{nonce}"));
    if let Err(reason) = create_private_directory(&session_root).await {
        return failed(report, reason);
    }
    let mut control_descriptors = match ControlDescriptorFixture::create(&session_root).await {
        Ok(fixture) => fixture,
        Err(reason) => return cleanup_session(report, &session_root, reason).await,
    };
    let descriptors = match control_descriptors.take_descriptors() {
        Ok(descriptors) => {
            report.control_descriptors_prepared = true;
            descriptors
        }
        Err(reason) => return cleanup_session(report, &session_root, reason).await,
    };
    let container_id = match ContainerId::new(format!("native-{nonce}")) {
        Ok(id) => id,
        Err(error) => {
            return cleanup_session(
                report,
                &session_root,
                format!("failed to construct native service container ID: {error}"),
            )
            .await
        }
    };
    let service_root = session_root.join("service");
    let config = match NativeLinuxServiceConfig::new(&service_root, &init_executable, container_id)
    {
        Ok(config) => config,
        Err(error) => {
            return cleanup_session(
                report,
                &session_root,
                format!("failed to configure native Linux service: {error}"),
            )
            .await
        }
    };
    let service = match NativeLinuxService::bind(config, descriptors).await {
        Ok(service) => service,
        Err(error) => {
            return cleanup_session(
                report,
                &session_root,
                format!("failed to bind native Linux service: {error}"),
            )
            .await
        }
    };
    let socket_path = service.socket_path().to_path_buf();
    let endpoint = match LocalIpcEndpoint::unix_socket(&socket_path) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            return cleanup_session(
                report,
                &session_root,
                format!("failed to configure native service SDK endpoint: {error}"),
            )
            .await
        }
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let mut service_task = tokio::spawn(service.serve_until(async move {
        let _ = shutdown_rx.await;
    }));
    let client = match RuntimeClient::connect(&endpoint).await {
        Ok(client) => client,
        Err(error) => {
            let _ = shutdown_tx.send(());
            let _ = service_task.await;
            return cleanup_session(
                report,
                &session_root,
                format!("failed to connect native service SDK transport: {error}"),
            )
            .await;
        }
    };

    let exercise = exercise_bound_service(
        &client,
        &bundle,
        &nonce,
        &marker,
        &hook_trace,
        &mut control_descriptors,
        &mut report,
    )
    .await;
    if exercise.is_err() {
        best_effort_delete(&client, &nonce).await;
    }
    drop(client);
    if shutdown_tx.send(()).is_err() {
        append_reason(
            &mut report,
            "native service stopped before shutdown was requested",
        );
    }
    match timeout(SERVICE_SHUTDOWN_TIMEOUT, &mut service_task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => append_reason(
            &mut report,
            format!("native service shutdown failed: {error}"),
        ),
        Ok(Err(error)) => append_reason(
            &mut report,
            format!("native service task failed to join: {error}"),
        ),
        Err(_) => {
            service_task.abort();
            let _ = service_task.await;
            append_reason(&mut report, "native service shutdown timed out");
        }
    }
    match path_exists(&socket_path).await {
        Ok(false) => {}
        Ok(true) => append_reason(
            &mut report,
            format!(
                "native service socket remained after shutdown: {}",
                socket_path.display()
            ),
        ),
        Err(reason) => append_reason(&mut report, reason),
    }
    match control_descriptors.verify_closed().await {
        Ok(()) => report.control_descriptors_closed_after_delete = true,
        Err(reason) => append_reason(&mut report, reason),
    }
    match directory_is_empty(&service_root.join("executor")).await {
        Ok(empty) => report.executor_runtime_clean = empty,
        Err(reason) => append_reason(&mut report, reason),
    }
    match remove_marker(&marker).await {
        Ok(()) => report.marker_removed = true,
        Err(reason) => append_reason(&mut report, reason),
    }
    match tokio::fs::remove_dir_all(&session_root).await {
        Ok(()) => match path_exists(&session_root).await {
            Ok(exists) => report.session_root_clean = !exists,
            Err(reason) => append_reason(&mut report, reason),
        },
        Err(error) => append_reason(
            &mut report,
            format!(
                "failed to remove native service smoke session {}: {error}",
                session_root.display()
            ),
        ),
    }
    if let Err(reason) = exercise {
        append_reason(&mut report, reason);
    }
    if report.lifecycle_succeeded() {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    }
    report
}

async fn directory_is_empty(path: &Path) -> Result<bool, String> {
    let mut entries = tokio::fs::read_dir(path).await.map_err(|error| {
        format!(
            "failed to inspect runtime directory {}: {error}",
            path.display()
        )
    })?;
    entries
        .next_entry()
        .await
        .map(|entry| entry.is_none())
        .map_err(|error| {
            format!(
                "failed to read runtime directory {}: {error}",
                path.display()
            )
        })
}

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
    let bundle = match enable_workload_verification(&bundle) {
        Ok(bundle) => bundle,
        Err(reason) => return failed(report, reason),
    };
    let rootfs = match fixed_rootfs(&bundle).await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let marker = rootfs.join(MARKER_NAME);
    let hook_trace = rootfs.join(HOOK_TRACE_NAME);
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
    let mut control_descriptors = match ControlDescriptorFixture::create(&session_root).await {
        Ok(fixture) => {
            report.control_descriptors_prepared = true;
            fixture
        }
        Err(reason) => return cleanup_session(report, &session_root, reason).await,
    };

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

    let exercise = exercise(
        &service,
        &bundle,
        &nonce,
        &marker,
        &hook_trace,
        &mut control_descriptors,
        &mut report,
    )
    .await;
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
