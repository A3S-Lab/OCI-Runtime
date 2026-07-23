use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use a3s_oci_agent_protocol::GuestPath;
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{ContainerId, ContainerTarget, Generation, OciBundle};
use tokio::io::AsyncReadExt;

use super::OciVmSmokeReport;
use crate::agent_session::WindowsAgentVmSession;

const MARKER_NAME: &str = ".a3s-oci-create-start-smoke";
const MAX_MARKER_BYTES: u64 = 1_024;
const GUEST_RUNTIME_PREFIX: &str = "a3s-oci-agent-";

mod lifecycle;

use lifecycle::{best_effort_delete, exercise};

pub(super) async fn run(
    shim: &Path,
    vm_rootfs: &Path,
    bundle_directory: &Path,
    console: &Path,
) -> OciVmSmokeReport {
    let mut report = OciVmSmokeReport::initial(HostPlatform::Windows);
    let vm_rootfs = match canonical_directory(vm_rootfs, "VM rootfs").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let bundle_directory = match canonical_directory(bundle_directory, "OCI bundle").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    if bundle_directory == vm_rootfs || !bundle_directory.starts_with(&vm_rootfs) {
        return failed(
            report,
            format!(
                "OCI bundle must be a strict descendant of VM rootfs {}: {}",
                vm_rootfs.display(),
                bundle_directory.display()
            ),
        );
    }

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
    match tokio::fs::symlink_metadata(&marker).await {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => {
            return failed(
                report,
                format!(
                    "refusing to overwrite an existing OCI smoke marker: {}",
                    marker.display()
                ),
            );
        }
        Err(error) => {
            return failed(
                report,
                format!(
                    "failed to inspect OCI smoke marker {}: {error}",
                    marker.display()
                ),
            );
        }
    }

    let guest_bundle = match guest_path(&vm_rootfs, &bundle_directory) {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let baseline_runtime_entries = match runtime_entries(&vm_rootfs).await {
        Ok(entries) => entries,
        Err(reason) => return failed(report, reason),
    };
    let nonce = match unique_nonce() {
        Ok(nonce) => nonce,
        Err(reason) => return failed(report, reason),
    };
    let target = match target(&nonce) {
        Ok(target) => target,
        Err(reason) => return failed(report, reason),
    };

    let session = match WindowsAgentVmSession::connect(shim, &vm_rootfs, console).await {
        Ok(session) => session,
        Err(bridge) => {
            report.reason = bridge.reason.clone();
            report.bridge = bridge;
            return report;
        }
    };

    let exercise = exercise(
        session.client(),
        &bundle,
        guest_bundle,
        &target,
        &nonce,
        &marker,
        &mut report,
    )
    .await;
    if exercise.is_err() {
        best_effort_delete(session.client(), &target, &nonce).await;
    }
    report.bridge = match &exercise {
        Ok(()) => session.finish().await,
        Err(reason) => session.finish_with_failure(reason).await,
    };

    match remove_marker(&marker).await {
        Ok(()) => report.marker_removed = true,
        Err(reason) => append_reason(&mut report, reason),
    }
    match runtime_entries(&vm_rootfs).await {
        Ok(entries) => {
            report.guest_runtime_clean = entries == baseline_runtime_entries;
            if !report.guest_runtime_clean {
                append_reason(
                    &mut report,
                    "guest agent left runtime directories after VM shutdown",
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

    if lifecycle_succeeded(&report) {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    }
    report
}

async fn fixed_rootfs(bundle: &OciBundle) -> Result<PathBuf, String> {
    let root = bundle
        .spec()
        .root()
        .as_ref()
        .ok_or_else(|| "OCI smoke bundle has no root filesystem".to_string())?;
    if root.path() != Path::new("rootfs") || root.readonly().unwrap_or(false) {
        return Err(
            "OCI smoke bundle must use writable normalized relative root.path `rootfs`".into(),
        );
    }
    let rootfs =
        canonical_directory(&bundle.directory().join(root.path()), "container rootfs").await?;
    if rootfs == bundle.directory() || !rootfs.starts_with(bundle.directory()) {
        return Err(format!(
            "container rootfs escapes OCI bundle {}: {}",
            bundle.directory().display(),
            rootfs.display()
        ));
    }
    Ok(rootfs)
}

async fn canonical_directory(path: &Path, description: &str) -> Result<PathBuf, String> {
    let canonical = tokio::fs::canonicalize(path).await.map_err(|error| {
        format!(
            "failed to resolve {description} {}: {error}",
            path.display()
        )
    })?;
    let metadata = tokio::fs::metadata(&canonical).await.map_err(|error| {
        format!(
            "failed to inspect {description} {}: {error}",
            canonical.display()
        )
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "{description} is not a directory: {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn guest_path(vm_rootfs: &Path, bundle: &Path) -> Result<GuestPath, String> {
    let relative = bundle.strip_prefix(vm_rootfs).map_err(|error| {
        format!(
            "failed to map OCI bundle {} into VM rootfs {}: {error}",
            bundle.display(),
            vm_rootfs.display()
        )
    })?;
    let mut components = Vec::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(format!(
                "OCI bundle has a non-normal guest path component: {}",
                bundle.display()
            ));
        };
        let component = component
            .to_str()
            .ok_or_else(|| format!("OCI bundle path is not valid Unicode: {}", bundle.display()))?;
        if component.contains(['/', '\\', '\0']) {
            return Err(format!(
                "OCI bundle has an invalid guest path component: {}",
                bundle.display()
            ));
        }
        components.push(component);
    }
    if components.is_empty() {
        return Err("OCI bundle cannot be the VM rootfs itself".into());
    }
    GuestPath::new(format!("/{}", components.join("/")))
        .map_err(|error| format!("failed to construct guest bundle path: {error}"))
}

fn target(nonce: &str) -> Result<ContainerTarget, String> {
    let id = ContainerId::new(format!("smoke-{nonce}"))
        .map_err(|error| format!("failed to construct smoke container ID: {error}"))?;
    Ok(ContainerTarget::exact(id, Generation(1)))
}

fn unique_nonce() -> Result<String, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before the Unix epoch: {error}"))?
        .as_nanos();
    Ok(format!("{}-{nanos}", std::process::id()))
}

async fn path_exists(path: &Path) -> Result<bool, String> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("failed to inspect {}: {error}", path.display())),
    }
}

async fn read_marker(path: &Path) -> Result<Vec<u8>, String> {
    let entry = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        format!(
            "failed to inspect OCI smoke marker {}: {error}",
            path.display()
        )
    })?;
    if !entry.is_file() || entry.file_type().is_symlink() {
        return Err("OCI smoke marker must be a regular non-symlink file".into());
    }
    let file = tokio::fs::File::open(path).await.map_err(|error| {
        format!(
            "failed to open OCI smoke marker {}: {error}",
            path.display()
        )
    })?;
    let metadata = file.metadata().await.map_err(|error| {
        format!(
            "failed to inspect OCI smoke marker {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_file() || metadata.len() > MAX_MARKER_BYTES {
        return Err(format!(
            "OCI smoke marker must be a regular file no larger than {MAX_MARKER_BYTES} bytes"
        ));
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_MARKER_BYTES + 1)
        .read_to_end(&mut contents)
        .await
        .map_err(|error| {
            format!(
                "failed to read OCI smoke marker {}: {error}",
                path.display()
            )
        })?;
    if contents.len() as u64 > MAX_MARKER_BYTES {
        return Err("OCI smoke marker exceeded its bounded size while reading".into());
    }
    Ok(contents)
}

async fn remove_marker(path: &Path) -> Result<(), String> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to remove OCI smoke marker {}: {error}",
            path.display()
        )),
    }
}

async fn runtime_entries(vm_rootfs: &Path) -> Result<BTreeSet<String>, String> {
    let runtime = vm_rootfs.join("run");
    let mut entries = tokio::fs::read_dir(&runtime).await.map_err(|error| {
        format!(
            "failed to inspect guest runtime directory {}: {error}",
            runtime.display()
        )
    })?;
    let mut matching = BTreeSet::new();
    while let Some(entry) = entries.next_entry().await.map_err(|error| {
        format!(
            "failed to enumerate guest runtime directory {}: {error}",
            runtime.display()
        )
    })? {
        let name = entry.file_name().into_string().map_err(|_| {
            format!(
                "guest runtime directory contains a non-Unicode entry: {}",
                runtime.display()
            )
        })?;
        if name.starts_with(GUEST_RUNTIME_PREFIX) {
            matching.insert(name);
        }
    }
    Ok(matching)
}

fn lifecycle_succeeded(report: &OciVmSmokeReport) -> bool {
    report.bundle_loaded
        && report.create_returned_created
        && report.create_replayed
        && report.created_pid.is_some_and(|pid| pid > 0)
        && report.marker_absent_after_create
        && report.start_released
        && report.running_observed
        && report.kill_delivered
        && report.kill_replayed
        && report.stopped_observed
        && report.marker_verified
        && report.delete_succeeded
        && report.delete_replayed
        && report.state_missing_after_delete
        && report.marker_removed
        && report.guest_runtime_clean
        && report.bridge.is_success()
}

fn append_reason(report: &mut OciVmSmokeReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

fn failed(mut report: OciVmSmokeReport, reason: impl Into<String>) -> OciVmSmokeReport {
    report.reason = Some(reason.into());
    report
}
