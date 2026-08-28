use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{ContainerId, OciBundle, RuntimeClient, RuntimeOperation};
use tokio::time::timeout;

use super::filesystem::{
    canonical_directory, create_private_directory, fixed_rootfs, path_exists, unique_nonce,
    MARKER_NAME,
};
use crate::{
    HostRuntimeService, NativeLinuxDriver, NativeLinuxSoakConfig, NativeLinuxSoakReport,
    RuntimeDriver,
};

mod cleanup;
mod pause_resume;
mod wave;

use cleanup::{
    append_reason, clean_wave_artifacts, cleanup_driver, cleanup_session,
    direct_child_process_count, verify_descriptor_inventory, verify_process_inventory,
};
use pause_resume::{pause, progress_artifacts, replay_pause_and_resume, replay_resume};
use wave::{best_effort_delete, create_start_and_exercise, terminate_and_delete, WaveContext};

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
    let mut progress_markers = Vec::with_capacity(concurrent);
    let mut cleanup_markers = Vec::with_capacity(concurrent.saturating_mul(3));
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
        let progress_artifacts = progress_artifacts(&rootfs);
        for artifact in &progress_artifacts {
            match path_exists(artifact).await {
                Ok(false) => {}
                Ok(true) => {
                    return failed(
                        report,
                        format!(
                            "refusing to overwrite an existing soak progress artifact: {}",
                            artifact.display()
                        ),
                    );
                }
                Err(reason) => return failed(report, reason),
            }
        }
        bundles.push(bundle);
        markers.push(marker.clone());
        progress_markers.push(progress_artifacts[0].clone());
        cleanup_markers.push(marker);
        cleanup_markers.extend(progress_artifacts);
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
                &cleanup_markers,
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
                    &cleanup_markers,
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
                &cleanup_markers,
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
            progress_markers: &progress_markers,
            nonce: &nonce,
            iteration,
            timeout: timeout_duration,
        };
        let Some(active_client) = client.as_ref() else {
            failure = Some("native soak client was unavailable before a wave".into());
            break;
        };
        let targets =
            match create_start_and_exercise(active_client, &wave, &previous_targets, &mut report)
                .await
            {
                Ok(targets) => targets,
                Err(reason) => {
                    failure = Some(reason);
                    break;
                }
            };
        let paused = match pause(active_client, &wave, &targets, &mut report).await {
            Ok(paused) => paused,
            Err(reason) => {
                report.pause_resume_verified = false;
                failure = Some(reason);
                break;
            }
        };

        drop(client.take());
        drop(service.take());
        let (reopened, reopened_client) = match reopen_runtime(
            &state_root,
            runtime_driver.clone(),
            timeout_duration,
            &report.service_operations,
            iteration,
            "after Pause",
        )
        .await
        {
            Ok(reopened) => reopened,
            Err(reason) => {
                report.durable_recovery_verified = false;
                report.pause_resume_verified = false;
                failure = Some(reason);
                break;
            }
        };
        report.operation_counts.features += 1;
        report.durable_reopens += 1;
        service = Some(reopened);
        client = Some(reopened_client);

        let Some(active_client) = client.as_ref() else {
            failure = Some("reopened native soak client was unavailable".into());
            break;
        };
        let resumed = match replay_pause_and_resume(active_client, &wave, paused, &mut report).await
        {
            Ok(resumed) => resumed,
            Err(reason) => {
                report.durable_recovery_verified = false;
                report.pause_resume_verified = false;
                failure = Some(reason);
                break;
            }
        };

        drop(client.take());
        drop(service.take());
        let (reopened, reopened_client) = match reopen_runtime(
            &state_root,
            runtime_driver.clone(),
            timeout_duration,
            &report.service_operations,
            iteration,
            "after Resume",
        )
        .await
        {
            Ok(reopened) => reopened,
            Err(reason) => {
                report.durable_recovery_verified = false;
                report.pause_resume_verified = false;
                failure = Some(reason);
                break;
            }
        };
        report.operation_counts.features += 1;
        report.durable_reopens += 1;
        service = Some(reopened);
        client = Some(reopened_client);

        let Some(active_client) = client.as_ref() else {
            failure = Some("second reopened native soak client was unavailable".into());
            break;
        };
        let targets = match replay_resume(active_client, &wave, resumed, &mut report).await {
            Ok(targets) => targets,
            Err(reason) => {
                report.durable_recovery_verified = false;
                report.pause_resume_verified = false;
                failure = Some(reason);
                break;
            }
        };
        if let Err(reason) = terminate_and_delete(active_client, &wave, &targets, &mut report).await
        {
            failure = Some(reason);
            break;
        }

        if let Err(reason) =
            clean_wave_artifacts(&executor_root, &cleanup_markers, &mut report, iteration).await
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
        &cleanup_markers,
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

async fn reopen_runtime(
    state_root: &Path,
    runtime_driver: Arc<dyn RuntimeDriver>,
    timeout_duration: Duration,
    expected_operations: &[RuntimeOperation],
    iteration: u32,
    boundary: &str,
) -> Result<(HostRuntimeService, RuntimeClient), String> {
    let service = HostRuntimeService::open(state_root, runtime_driver)
        .await
        .map_err(|error| {
            format!(
                "failed to reopen durable soak service {boundary} during iteration {iteration}: {error}"
            )
    })?;
    let client = RuntimeClient::new(service.clone());
    let features_operation = format!("reopened soak features {boundary}");
    let features = runtime_call(timeout_duration, &features_operation, client.features()).await?;
    if features.operations != expected_operations {
        return Err(format!(
            "reopened soak service changed its operation inventory {boundary} during iteration {iteration}"
        ));
    }
    Ok((service, client))
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

fn failed(mut report: NativeLinuxSoakReport, reason: impl Into<String>) -> NativeLinuxSoakReport {
    append_reason(&mut report, reason);
    report
}
