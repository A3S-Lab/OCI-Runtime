use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{ContainerId, OciBundle, RuntimeClient};
use tokio::time::timeout;

use super::filesystem::{
    canonical_directory, create_private_directory, fixed_rootfs, path_exists, remove_marker,
    unique_nonce, MARKER_NAME,
};
use crate::{
    HostRuntimeService, NativeLinuxDriver, NativeLinuxSoakConfig, NativeLinuxSoakReport,
    RuntimeDriver,
};

mod wave;

use wave::{best_effort_delete, create_start_and_pause, recover_resume_and_delete, WaveContext};

pub(super) async fn run(
    init_executable: &Path,
    bundle_paths: &[PathBuf],
    work_parent: &Path,
    configuration: NativeLinuxSoakConfig,
) -> NativeLinuxSoakReport {
    let mut report = NativeLinuxSoakReport::initial(HostPlatform::Linux, configuration);
    report.kvm_device_present = Path::new("/dev/kvm").exists();
    if let Err(reason) = configuration.validate(bundle_paths.len()) {
        return failed(report, reason);
    }
    let concurrent = match usize::try_from(configuration.concurrent_containers) {
        Ok(value) => value,
        Err(_) => return failed(report, "soak concurrency does not fit this host"),
    };
    let timeout_duration = Duration::from_millis(configuration.operation_timeout_ms);

    let work_parent = match canonical_directory(work_parent, "soak work parent").await {
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

    let mut bundle_directories = BTreeSet::new();
    let mut rootfs_directories = BTreeSet::new();
    let mut cgroup_paths = BTreeSet::new();
    let mut bundles = Vec::with_capacity(concurrent);
    let mut markers = Vec::with_capacity(concurrent);
    for (slot, path) in bundle_paths.iter().take(concurrent).enumerate() {
        let directory = match canonical_directory(path, &format!("soak bundle {slot}")).await {
            Ok(path) => path,
            Err(reason) => return failed(report, reason),
        };
        if !bundle_directories.insert(directory.clone()) {
            return failed(
                report,
                format!("soak bundle {slot} duplicates another bundle directory"),
            );
        }
        let bundle = match OciBundle::load(&directory).await {
            Ok(bundle) => bundle,
            Err(error) => {
                return failed(
                    report,
                    format!("failed to load soak bundle {slot}: {error}"),
                );
            }
        };
        let rootfs = match fixed_rootfs(&bundle).await {
            Ok(path) => path,
            Err(reason) => return failed(report, reason),
        };
        if !rootfs_directories.insert(rootfs.clone()) {
            return failed(
                report,
                format!("soak bundle {slot} duplicates another root filesystem"),
            );
        }
        let Some(cgroup_path) = bundle
            .spec()
            .linux()
            .as_ref()
            .and_then(|linux| linux.cgroups_path().as_ref())
        else {
            return failed(
                report,
                format!("soak bundle {slot} must declare a cgroup path"),
            );
        };
        if !cgroup_paths.insert(cgroup_path.clone()) {
            return failed(
                report,
                format!("soak bundle {slot} duplicates another cgroup path"),
            );
        }
        let marker = rootfs.join(MARKER_NAME);
        match path_exists(&marker).await {
            Ok(false) => {}
            Ok(true) => {
                return failed(
                    report,
                    format!(
                        "refusing to overwrite an existing soak marker: {}",
                        marker.display()
                    ),
                );
            }
            Err(reason) => return failed(report, reason),
        }
        bundles.push(bundle);
        markers.push(marker);
    }
    report.bundles_loaded = u32::try_from(bundles.len()).unwrap_or(u32::MAX);
    report.distinct_bundles_and_rootfs = bundle_directories.len() == concurrent
        && rootfs_directories.len() == concurrent
        && cgroup_paths.len() == concurrent;

    let nonce = match unique_nonce() {
        Ok(nonce) => nonce,
        Err(reason) => return failed(report, reason),
    };
    let ids = match (0..concurrent)
        .map(|slot| {
            ContainerId::new(format!("native-soak-{slot}-{nonce}"))
                .map_err(|error| format!("failed to construct soak container {slot} ID: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(ids) => ids,
        Err(reason) => return failed(report, reason),
    };
    let session_root = work_parent.join(format!("a3s-oci-native-soak-{nonce}"));
    if let Err(reason) = create_private_directory(&session_root).await {
        return failed(report, reason);
    }
    let executor_parent = session_root.join("executor");
    if let Err(reason) = create_private_directory(&executor_parent).await {
        return cleanup_session(report, &session_root, reason).await;
    }

    let driver =
        match NativeLinuxDriver::open_experimental(&executor_parent, &init_executable).await {
            Ok(driver) => Arc::new(driver),
            Err(error) => {
                return cleanup_session(
                    report,
                    &session_root,
                    format!("failed to open native Linux soak driver: {error}"),
                )
                .await;
            }
        };
    let executor_root = driver.executor_root().to_path_buf();
    let state_root = session_root.join("state");
    let runtime_driver: Arc<dyn RuntimeDriver> = driver.clone();
    let service = match HostRuntimeService::open(&state_root, runtime_driver.clone()).await {
        Ok(service) => service,
        Err(error) => {
            let reason = format!("failed to open durable native soak runtime: {error}");
            cleanup_driver(
                &driver,
                &executor_root,
                &markers,
                &session_root,
                &mut report,
            )
            .await;
            return failed(report, reason);
        }
    };
    let client = RuntimeClient::new(service.clone());
    let features =
        match runtime_call(timeout_duration, "initial soak features", client.features()).await {
            Ok(features) => features,
            Err(reason) => {
                drop(client);
                drop(service);
                cleanup_driver(
                    &driver,
                    &executor_root,
                    &markers,
                    &session_root,
                    &mut report,
                )
                .await;
                return failed(report, reason);
            }
        };
    report.operation_counts.features = 1;
    report.service_operations = features.operations;
    report.baseline_child_processes = match direct_child_process_count().await {
        Ok(count) => Some(count),
        Err(reason) => {
            drop(client);
            drop(service);
            cleanup_driver(
                &driver,
                &executor_root,
                &markers,
                &session_root,
                &mut report,
            )
            .await;
            return failed(report, reason);
        }
    };

    let mut service = Some(service);
    let mut client = Some(client);
    let mut previous_targets = vec![None; concurrent];
    let mut failure = None;

    for iteration in 0..configuration.iterations {
        let wave = WaveContext {
            bundles: &bundles,
            ids: &ids,
            markers: &markers,
            nonce: &nonce,
            iteration,
            timeout: timeout_duration,
        };
        let Some(active_client) = client.as_ref() else {
            failure = Some("native soak client was unavailable before a wave".into());
            break;
        };
        let targets = match create_start_and_pause(
            active_client,
            &wave,
            &previous_targets,
            &mut report,
        )
        .await
        {
            Ok(targets) => targets,
            Err(reason) => {
                failure = Some(reason);
                break;
            }
        };

        drop(client.take());
        drop(service.take());
        let reopened = match HostRuntimeService::open(&state_root, runtime_driver.clone()).await {
            Ok(service) => service,
            Err(error) => {
                failure = Some(format!(
                    "failed to reopen durable soak service during iteration {iteration}: {error}"
                ));
                break;
            }
        };
        let reopened_client = RuntimeClient::new(reopened.clone());
        let reopened_features = match runtime_call(
            timeout_duration,
            "reopened soak features",
            reopened_client.features(),
        )
        .await
        {
            Ok(features) => features,
            Err(reason) => {
                service = Some(reopened);
                client = Some(reopened_client);
                failure = Some(reason);
                break;
            }
        };
        report.operation_counts.features += 1;
        if reopened_features.operations != report.service_operations {
            report.durable_recovery_verified = false;
            service = Some(reopened);
            client = Some(reopened_client);
            failure = Some("reopened soak service changed its operation inventory".into());
            break;
        }
        report.durable_reopens += 1;
        service = Some(reopened);
        client = Some(reopened_client);

        let Some(active_client) = client.as_ref() else {
            failure = Some("reopened native soak client was unavailable".into());
            break;
        };
        if let Err(reason) =
            recover_resume_and_delete(active_client, &wave, &targets, &mut report).await
        {
            report.durable_recovery_verified = false;
            failure = Some(reason);
            break;
        }

        if let Err(reason) =
            clean_wave_artifacts(&executor_root, &markers, &mut report, iteration).await
        {
            failure = Some(reason);
            break;
        }
        if let Err(reason) = verify_process_inventory(&mut report).await {
            failure = Some(reason);
            break;
        }
        if let Err(reason) = verify_descriptor_inventory(&mut report).await {
            failure = Some(reason);
            break;
        }

        previous_targets = targets.into_iter().map(Some).collect();
        report.completed_iterations += 1;
        report.completed_container_lifecycles += u64::from(configuration.concurrent_containers);
    }

    if let (Some(active_client), Some(reason)) = (client.as_ref(), failure.as_ref()) {
        best_effort_delete(active_client, &ids, &nonce, timeout_duration).await;
        append_reason(&mut report, reason.clone());
    }
    drop(client.take());
    drop(service.take());
    cleanup_driver(
        &driver,
        &executor_root,
        &markers,
        &session_root,
        &mut report,
    )
    .await;

    if failure.is_none() && report.evidence_succeeded() && report.reason.is_none() {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    }
    report
}

async fn clean_wave_artifacts(
    executor_root: &Path,
    markers: &[PathBuf],
    report: &mut NativeLinuxSoakReport,
    iteration: u32,
) -> Result<(), String> {
    for marker in markers {
        if let Err(reason) = remove_marker(marker).await {
            report.markers_removed_after_each_iteration = false;
            return Err(reason);
        }
        if path_exists(marker).await? {
            report.markers_removed_after_each_iteration = false;
            return Err(format!(
                "soak marker remained after iteration {iteration}: {}",
                marker.display()
            ));
        }
    }
    if !directory_is_empty(executor_root).await? {
        report.executor_empty_after_each_iteration = false;
        return Err(format!(
            "native executor root remained populated after soak iteration {iteration}"
        ));
    }
    Ok(())
}

async fn verify_process_inventory(report: &mut NativeLinuxSoakReport) -> Result<(), String> {
    let count = direct_child_process_count().await?;
    report.final_child_processes = Some(count);
    if Some(count) != report.baseline_child_processes {
        report.child_process_inventory_stable = false;
        return Err(format!(
            "direct child process inventory did not return to baseline: baseline={:?}, current={count}",
            report.baseline_child_processes
        ));
    }
    Ok(())
}

async fn verify_descriptor_inventory(report: &mut NativeLinuxSoakReport) -> Result<(), String> {
    let count = open_descriptor_count().await?;
    match report.steady_open_descriptors {
        None => report.steady_open_descriptors = Some(count),
        Some(steady) if steady == count => {}
        Some(steady) => {
            report.descriptor_inventory_stable = false;
            report.final_open_descriptors = Some(count);
            return Err(format!(
                "open descriptor inventory grew across clean soak waves: steady={steady}, current={count}"
            ));
        }
    }
    report.final_open_descriptors = Some(count);
    Ok(())
}

async fn cleanup_driver(
    driver: &NativeLinuxDriver,
    executor_root: &Path,
    markers: &[PathBuf],
    session_root: &Path,
    report: &mut NativeLinuxSoakReport,
) {
    if let Err(error) = driver.shutdown().await {
        append_reason(
            report,
            format!("native soak executor shutdown failed: {error}"),
        );
    }
    match path_exists(executor_root).await {
        Ok(exists) => report.executor_runtime_clean = !exists,
        Err(reason) => append_reason(report, reason),
    }
    for marker in markers {
        if let Err(reason) = remove_marker(marker).await {
            append_reason(report, reason);
        }
    }
    match tokio::fs::remove_dir_all(session_root).await {
        Ok(()) => match path_exists(session_root).await {
            Ok(exists) => report.session_root_clean = !exists,
            Err(reason) => append_reason(report, reason),
        },
        Err(error) => append_reason(
            report,
            format!(
                "failed to remove native soak session {}: {error}",
                session_root.display()
            ),
        ),
    }
}

async fn cleanup_session(
    mut report: NativeLinuxSoakReport,
    session_root: &Path,
    reason: impl Into<String>,
) -> NativeLinuxSoakReport {
    append_reason(&mut report, reason);
    match tokio::fs::remove_dir_all(session_root).await {
        Ok(()) => report.session_root_clean = true,
        Err(error) => append_reason(
            &mut report,
            format!(
                "failed to remove native soak session {}: {error}",
                session_root.display()
            ),
        ),
    }
    report
}

async fn directory_is_empty(path: &Path) -> Result<bool, String> {
    let mut entries = tokio::fs::read_dir(path).await.map_err(|error| {
        format!(
            "failed to inspect soak directory {}: {error}",
            path.display()
        )
    })?;
    entries
        .next_entry()
        .await
        .map(|entry| entry.is_none())
        .map_err(|error| format!("failed to read soak directory {}: {error}", path.display()))
}

async fn open_descriptor_count() -> Result<u64, String> {
    let mut entries = tokio::fs::read_dir("/proc/self/fd")
        .await
        .map_err(|error| format!("failed to open /proc/self/fd: {error}"))?;
    let mut count = 0_u64;
    while entries
        .next_entry()
        .await
        .map_err(|error| format!("failed to count /proc/self/fd: {error}"))?
        .is_some()
    {
        count += 1;
    }
    Ok(count)
}

async fn direct_child_process_count() -> Result<u64, String> {
    let mut tasks = tokio::fs::read_dir("/proc/self/task")
        .await
        .map_err(|error| format!("failed to open /proc/self/task: {error}"))?;
    let mut children = BTreeSet::new();
    while let Some(task) = tasks
        .next_entry()
        .await
        .map_err(|error| format!("failed to enumerate /proc/self/task: {error}"))?
    {
        let path = task.path().join("children");
        let contents = match tokio::fs::read_to_string(&path).await {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "failed to read child process inventory {}: {error}",
                    path.display()
                ));
            }
        };
        for pid in contents.split_whitespace() {
            let pid = pid.parse::<u32>().map_err(|error| {
                format!("invalid child PID {pid:?} in {}: {error}", path.display())
            })?;
            children.insert(pid);
        }
    }
    Ok(children.len() as u64)
}

async fn runtime_call<T>(
    timeout_duration: Duration,
    operation: &str,
    future: impl std::future::Future<Output = a3s_oci_sdk::Result<T>>,
) -> Result<T, String> {
    match timeout(timeout_duration, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(format!("{operation} failed: {error}")),
        Err(_) => Err(format!("{operation} timed out")),
    }
}

fn append_reason(report: &mut NativeLinuxSoakReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

fn failed(mut report: NativeLinuxSoakReport, reason: impl Into<String>) -> NativeLinuxSoakReport {
    append_reason(&mut report, reason);
    report
}
