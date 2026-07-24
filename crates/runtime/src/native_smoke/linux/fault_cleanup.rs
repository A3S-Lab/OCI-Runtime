use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{OciBundle, RuntimeClient};
use tokio::time::{sleep, Instant};

use super::filesystem::{
    canonical_directory, create_private_directory, fixed_rootfs, path_exists, remove_marker,
    unique_nonce, MARKER_NAME,
};
use super::lifecycle::exercise_until_fault;
use crate::{
    HostRuntimeService, LifecycleFaultPoint, NativeLinuxDriver, NativeLinuxFaultCleanupReport,
    RuntimeDriver,
};

const PROCESS_REAP_TIMEOUT: Duration = Duration::from_secs(2);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(super) async fn run(
    init_executable: &Path,
    bundle_directory: &Path,
    work_parent: &Path,
    fault: LifecycleFaultPoint,
) -> NativeLinuxFaultCleanupReport {
    let mut report = NativeLinuxFaultCleanupReport::initial(HostPlatform::Linux, fault);
    report.kvm_device_present = Path::new("/dev/kvm").exists();

    let work_parent = match canonical_directory(work_parent, "cleanup work parent").await {
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
                    "refusing to overwrite an existing native cleanup marker: {}",
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
    let session_root = work_parent.join(format!("a3s-oci-native-fault-{nonce}"));
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
            append_reason(
                &mut report,
                format!("failed to open durable native runtime: {error}"),
            );
            cleanup_driver(&driver, &executor_root, &marker, &session_root, &mut report).await;
            return report;
        }
    };
    let client = RuntimeClient::new(service.clone());

    let exercise =
        exercise_until_fault(&client, &bundle, &nonce, &marker, &mut report.lifecycle).await;
    if let Ok(operations) = exercise.as_ref() {
        report.service_operations.clone_from(operations);
    }
    drop(client);
    drop(service);

    cleanup_driver(&driver, &executor_root, &marker, &session_root, &mut report).await;
    if let Err(reason) = exercise {
        append_reason(&mut report, reason);
    }
    if report.evidence_succeeded() {
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
    report: &mut NativeLinuxFaultCleanupReport,
) {
    match driver.shutdown().await {
        Ok(()) => report.executor_shutdown_succeeded = true,
        Err(error) => append_reason(report, format!("native executor shutdown failed: {error}")),
    }

    match process_reaped(report.lifecycle.created_pid).await {
        Ok(reaped) => {
            report.process_reaped = reaped;
            if !reaped {
                append_reason(
                    report,
                    format!(
                        "native init PID {:?} remained after executor shutdown",
                        report.lifecycle.created_pid
                    ),
                );
            }
        }
        Err(reason) => append_reason(report, reason),
    }
    match path_exists(executor_root).await {
        Ok(exists) => {
            report.executor_runtime_clean = !exists;
            if exists {
                append_reason(
                    report,
                    format!(
                        "native executor runtime root remained after shutdown: {}",
                        executor_root.display()
                    ),
                );
            }
        }
        Err(reason) => append_reason(report, reason),
    }

    match remove_marker(marker).await {
        Ok(()) => match path_exists(marker).await {
            Ok(exists) => {
                report.marker_removed = !exists;
                if exists {
                    append_reason(
                        report,
                        format!("native workload marker remained: {}", marker.display()),
                    );
                }
            }
            Err(reason) => append_reason(report, reason),
        },
        Err(reason) => append_reason(report, reason),
    }

    match tokio::fs::remove_dir_all(session_root).await {
        Ok(()) => match path_exists(session_root).await {
            Ok(exists) => {
                report.session_root_clean = !exists;
                if exists {
                    append_reason(
                        report,
                        format!(
                            "native cleanup session root remained: {}",
                            session_root.display()
                        ),
                    );
                }
            }
            Err(reason) => append_reason(report, reason),
        },
        Err(error) => append_reason(
            report,
            format!(
                "failed to remove native cleanup session {}: {error}",
                session_root.display()
            ),
        ),
    }
}

async fn cleanup_session(
    mut report: NativeLinuxFaultCleanupReport,
    session_root: &Path,
    reason: impl Into<String>,
) -> NativeLinuxFaultCleanupReport {
    append_reason(&mut report, reason);
    match tokio::fs::remove_dir_all(session_root).await {
        Ok(()) => match path_exists(session_root).await {
            Ok(exists) => report.session_root_clean = !exists,
            Err(reason) => append_reason(&mut report, reason),
        },
        Err(error) => append_reason(
            &mut report,
            format!(
                "failed to remove native cleanup session {}: {error}",
                session_root.display()
            ),
        ),
    }
    report
}

async fn process_reaped(process_id: Option<i32>) -> Result<bool, String> {
    let process_id =
        process_id.ok_or_else(|| "native cleanup has no created process ID".to_string())?;
    if process_id <= 0 {
        return Err(format!(
            "native cleanup received invalid process ID {process_id}"
        ));
    }
    let deadline = Instant::now() + PROCESS_REAP_TIMEOUT;
    loop {
        match process_exists(process_id) {
            Ok(false) => return Ok(true),
            Ok(true) if Instant::now() < deadline => sleep(PROCESS_POLL_INTERVAL).await,
            Ok(true) => return Ok(false),
            Err(error) => return Err(error),
        }
    }
}

fn process_exists(process_id: i32) -> Result<bool, String> {
    // SAFETY: signal zero changes no process state and checks only whether the
    // positive runtime-visible process identifier still exists.
    if unsafe { libc::kill(process_id, 0) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(false)
    } else if error.raw_os_error() == Some(libc::EPERM) {
        Ok(true)
    } else {
        Err(format!(
            "failed to inspect native init PID {process_id}: {error}"
        ))
    }
}

fn append_reason(report: &mut NativeLinuxFaultCleanupReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

fn failed(
    mut report: NativeLinuxFaultCleanupReport,
    reason: impl Into<String>,
) -> NativeLinuxFaultCleanupReport {
    append_reason(&mut report, reason);
    report
}
