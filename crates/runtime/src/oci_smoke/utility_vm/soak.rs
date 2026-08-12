use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use a3s_oci_core::{CapabilityStatus, HostPlatform};

use super::{canonical_directory, multi_container};
use crate::{MacosHvfSoakConfig, MacosHvfSoakReport, OciVmMultiContainerSmokeReport};

pub(super) async fn run(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_a: &Path,
    bundle_b: &Path,
    console_directory: &Path,
    configuration: MacosHvfSoakConfig,
) -> MacosHvfSoakReport {
    let mut report = MacosHvfSoakReport::initial(HostPlatform::Macos, configuration);
    if let Err(reason) = configuration.validate() {
        return failed(report, reason);
    }
    let console_directory =
        match canonical_directory(console_directory, "soak console directory").await {
            Ok(path) => path,
            Err(reason) => return failed(report, reason),
        };

    let mut endpoint_names = BTreeSet::new();
    for iteration in 1..=configuration.iterations {
        let console = console_path(&console_directory, iteration);
        if let Err(reason) = require_absent_console(&console).await {
            return failed_iteration(report, iteration, reason);
        }
        let wave = multi_container::run(
            shim,
            vm_rootfs,
            Some(system_image_manifest),
            bundle_a,
            bundle_b,
            &console,
        )
        .await;
        if !wave.is_success() {
            let reason = wave
                .reason
                .clone()
                .or_else(|| wave.bridge.reason.clone())
                .unwrap_or_else(|| "utility-VM wave emitted incomplete evidence".into());
            return failed_iteration(
                report,
                iteration,
                format!("macOS HVF soak wave failed: {reason}"),
            );
        }
        if let Err(reason) =
            record_wave(&mut report, &wave, &console, iteration, &mut endpoint_names).await
        {
            return failed_iteration(report, iteration, reason);
        }
    }

    if report.evidence_succeeded() {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    } else {
        report.reason = Some("macOS HVF soak completed without full retained evidence".into());
    }
    report
}

async fn record_wave(
    report: &mut MacosHvfSoakReport,
    wave: &OciVmMultiContainerSmokeReport,
    console: &Path,
    iteration: u32,
    endpoint_names: &mut BTreeSet<String>,
) -> Result<(), String> {
    report.lifecycle_verified_every_iteration &= wave.lifecycle.is_success();
    report.namespace_join_verified_every_iteration &= wave.namespace_join.is_success();
    report.rootfs_mount_verified_every_iteration &= wave.rootfs_mount.is_success();
    report.pid_supervision_verified_every_iteration &= wave.pid_supervision.is_success();
    report.markers_removed_every_iteration &= wave.markers_removed;
    report.guest_runtime_clean_every_iteration &= wave.guest_runtime_clean;

    let cleanup = wave
        .bridge
        .macos_cleanup
        .as_ref()
        .ok_or_else(|| "successful macOS wave omitted host cleanup evidence".to_string())?;
    let before = cleanup
        .open_descriptors_before
        .ok_or_else(|| "macOS cleanup omitted its descriptor baseline".to_string())?;
    let after = cleanup
        .open_descriptors_after
        .ok_or_else(|| "macOS cleanup omitted its final descriptor count".to_string())?;
    report.host_cleanup_verified_every_iteration &= cleanup.is_success();
    match report.steady_open_descriptors {
        Some(steady) => report.descriptor_count_stable &= before == steady && after == steady,
        None => report.steady_open_descriptors = Some(before),
    }
    report.descriptor_count_stable &= before == after;
    report.final_open_descriptors = Some(after);

    let endpoint = wave
        .bridge
        .endpoint_name
        .as_ref()
        .ok_or_else(|| "successful macOS wave omitted its endpoint name".to_string())?;
    report.unique_endpoint_names &= endpoint_names.insert(endpoint.clone());

    let console_metadata = tokio::fs::symlink_metadata(console)
        .await
        .map_err(|error| {
            format!(
                "failed to inspect soak console {}: {error}",
                console.display()
            )
        })?;
    if !console_metadata.is_file() || console_metadata.file_type().is_symlink() {
        return Err(format!(
            "soak console is not a regular non-symlink file: {}",
            console.display()
        ));
    }

    report.completed_iterations = iteration;
    report.completed_vm_lifecycles += 1;
    report.completed_primary_container_generations += 3;
    report.console_files_created += 1;
    Ok(())
}

fn console_path(directory: &Path, iteration: u32) -> PathBuf {
    directory.join(format!("macos-hvf-soak-{iteration:05}.log"))
}

async fn require_absent_console(path: &Path) -> Result<(), String> {
    match tokio::fs::symlink_metadata(path).await {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(format!(
            "refusing to overwrite an existing soak console: {}",
            path.display()
        )),
        Err(error) => Err(format!(
            "failed to inspect soak console {}: {error}",
            path.display()
        )),
    }
}

fn failed(mut report: MacosHvfSoakReport, reason: impl Into<String>) -> MacosHvfSoakReport {
    report.reason = Some(reason.into());
    report
}

fn failed_iteration(
    mut report: MacosHvfSoakReport,
    iteration: u32,
    reason: impl Into<String>,
) -> MacosHvfSoakReport {
    report.failure_iteration = Some(iteration);
    report.reason = Some(reason.into());
    report
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::console_path;

    #[test]
    fn console_paths_are_iteration_scoped_and_sortable() {
        assert_eq!(
            console_path(Path::new("/tmp/consoles"), 7),
            Path::new("/tmp/consoles/macos-hvf-soak-00007.log")
        );
    }
}
