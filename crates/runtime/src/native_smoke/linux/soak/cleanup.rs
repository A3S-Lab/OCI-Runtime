use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::super::filesystem::{path_exists, remove_marker};
use crate::{NativeLinuxDriver, NativeLinuxSoakReport};

const EXECUTOR_OWNER_RECORD_NAME: &str = "owner.json";

pub(super) async fn clean_wave_artifacts(
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
    if !executor_has_only_owner_record(executor_root).await? {
        report.executor_empty_after_each_iteration = false;
        return Err(format!(
            "native executor root retained generation transients after soak iteration {iteration}"
        ));
    }
    Ok(())
}

pub(super) async fn verify_process_inventory(
    report: &mut NativeLinuxSoakReport,
) -> Result<(), String> {
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

pub(super) async fn verify_descriptor_inventory(
    report: &mut NativeLinuxSoakReport,
) -> Result<(), String> {
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

pub(super) async fn cleanup_driver(
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

pub(super) async fn cleanup_session(
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

async fn executor_has_only_owner_record(path: &Path) -> Result<bool, String> {
    let mut entries = tokio::fs::read_dir(path).await.map_err(|error| {
        format!(
            "failed to inspect native soak executor root {}: {error}",
            path.display()
        )
    })?;
    let mut owner_record_found = false;
    while let Some(entry) = entries.next_entry().await.map_err(|error| {
        format!(
            "failed to enumerate native soak executor root {}: {error}",
            path.display()
        )
    })? {
        if owner_record_found || entry.file_name() != EXECUTOR_OWNER_RECORD_NAME {
            return Ok(false);
        }
        let metadata = tokio::fs::symlink_metadata(entry.path())
            .await
            .map_err(|error| {
                format!(
                    "failed to inspect native soak executor owner record {}: {error}",
                    entry.path().display()
                )
            })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Ok(false);
        }
        owner_record_found = true;
    }
    Ok(owner_record_found)
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

pub(super) async fn direct_child_process_count() -> Result<u64, String> {
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

pub(super) fn append_reason(report: &mut NativeLinuxSoakReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}
