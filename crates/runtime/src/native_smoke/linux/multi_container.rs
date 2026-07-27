use std::path::Path;
use std::sync::Arc;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{OciBundle, RuntimeClient};

use super::filesystem::{
    canonical_directory, create_private_directory, fixed_rootfs, path_exists, remove_marker,
    unique_nonce, MARKER_NAME,
};
use crate::{
    HostRuntimeService, NativeLinuxDriver, NativeLinuxMultiContainerSmokeReport, RuntimeDriver,
};

mod initialization;
mod lifecycle;
mod namespace_join;
mod rootfs_enforcement;
mod storage_volume;

use lifecycle::{best_effort_delete, exercise};

pub(super) async fn run(
    init_executable: &Path,
    bundle_a: &Path,
    bundle_b: &Path,
    work_parent: &Path,
) -> NativeLinuxMultiContainerSmokeReport {
    let mut report = NativeLinuxMultiContainerSmokeReport::initial(HostPlatform::Linux);
    report.kvm_device_present = Path::new("/dev/kvm").exists();

    let work_parent = match canonical_directory(work_parent, "smoke work parent").await {
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
    let marker_a = rootfs_a.join(MARKER_NAME);
    let marker_b = rootfs_b.join(MARKER_NAME);
    for (label, marker) in [("first", &marker_a), ("second", &marker_b)] {
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

    let nonce = match unique_nonce() {
        Ok(nonce) => nonce,
        Err(reason) => return failed(report, reason),
    };
    let session_root = work_parent.join(format!("a3s-oci-native-multi-{nonce}"));
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
            cleanup_driver(
                &driver,
                &executor_root,
                [&marker_a, &marker_b],
                &session_root,
                &mut report,
            )
            .await;
            return failed(report, reason);
        }
    };
    let client = RuntimeClient::new(service.clone());
    let rootfs_fixture =
        crate::rootfs_enforcement::RootfsEnforcementFixture::prepare_native(&bundle_b, &nonce)
            .await;
    let storage_fixture = storage_volume::StorageVolumeFixture::prepare(
        &bundle_a,
        &bundle_b,
        [&rootfs_a, &rootfs_b],
        &work_parent,
        &nonce,
    )
    .await;
    let initialization_fixture =
        initialization::InitializationFixture::prepare(&bundle_b, &rootfs_b, &session_root, &nonce)
            .await;

    let exercise = match (&rootfs_fixture, &storage_fixture, &initialization_fixture) {
        (Ok(rootfs_fixture), Ok(storage_fixture), Ok(initialization_fixture)) => {
            async {
                exercise(
                    &client,
                    [&bundle_a, &bundle_b],
                    &nonce,
                    [&marker_a, &marker_b],
                    &mut report,
                )
                .await?;
                namespace_join::exercise(
                    &client,
                    &bundle_a,
                    &bundle_b,
                    &nonce,
                    [&marker_a, &marker_b],
                    &mut report,
                )
                .await?;
                rootfs_enforcement::exercise(&client, rootfs_fixture, &nonce, &mut report).await?;
                storage_volume::exercise(&client, storage_fixture, &nonce, &mut report).await?;
                initialization::exercise(&client, initialization_fixture, &nonce, &mut report).await
            }
            .await
        }
        (Err(reason), _, _) | (_, Err(reason), _) | (_, _, Err(reason)) => Err(reason.clone()),
    };
    if exercise.is_err() {
        best_effort_delete(&client, &nonce).await;
    }
    drop(client);
    drop(service);

    cleanup_driver(
        &driver,
        &executor_root,
        [&marker_a, &marker_b],
        &session_root,
        &mut report,
    )
    .await;
    if let Ok(rootfs_fixture) = &rootfs_fixture {
        match rootfs_fixture.cleanup().await {
            Ok(removed) => report.rootfs_mount.artifacts_removed = removed,
            Err(reason) => append_reason(&mut report, reason),
        }
    }
    if let Ok(storage_fixture) = &storage_fixture {
        match storage_fixture.cleanup().await {
            Ok(removed) => report.storage_volumes.all_profiles_removed &= removed,
            Err(reason) => append_reason(&mut report, reason),
        }
    }
    if let Ok(initialization_fixture) = &initialization_fixture {
        match initialization_fixture.cleanup().await {
            Ok(removed) => report.initialization.all_profiles_removed &= removed,
            Err(reason) => append_reason(&mut report, reason),
        }
    }
    if let Err(reason) = exercise {
        append_reason(&mut report, reason);
    }
    if report.evidence_succeeded() && report.reason.is_none() {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    }
    report
}

async fn cleanup_driver(
    driver: &NativeLinuxDriver,
    executor_root: &Path,
    markers: [&Path; 2],
    session_root: &Path,
    report: &mut NativeLinuxMultiContainerSmokeReport,
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
                "failed to remove native multi-container session {}: {error}",
                session_root.display()
            ),
        ),
    }
}

async fn cleanup_session(
    mut report: NativeLinuxMultiContainerSmokeReport,
    session_root: &Path,
    reason: impl Into<String>,
) -> NativeLinuxMultiContainerSmokeReport {
    append_reason(&mut report, reason);
    match tokio::fs::remove_dir_all(session_root).await {
        Ok(()) => report.session_root_clean = true,
        Err(error) => append_reason(
            &mut report,
            format!(
                "failed to remove native multi-container session {}: {error}",
                session_root.display()
            ),
        ),
    }
    report
}

fn append_reason(report: &mut NativeLinuxMultiContainerSmokeReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

fn failed(
    mut report: NativeLinuxMultiContainerSmokeReport,
    reason: impl Into<String>,
) -> NativeLinuxMultiContainerSmokeReport {
    append_reason(&mut report, reason);
    report
}
