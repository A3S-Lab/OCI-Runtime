use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use a3s_oci_agent_protocol::GuestPath;
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{ContainerId, ContainerTarget, Generation, OciBundle};
use tokio::io::AsyncReadExt;

use super::OciVmSmokeReport;
use crate::agent_session::UtilityVmSession;

const MARKER_NAME: &str = ".a3s-oci-create-start-smoke";
const MAX_MARKER_BYTES: u64 = 1_024;
const GUEST_RUNTIME_PREFIX: &str = "a3s-oci-agent-";

mod fault_cleanup;
pub(crate) mod lifecycle;
mod multi_container;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod reopen_replacement;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod soak;
mod transport_fault_cleanup;

use lifecycle::{best_effort_delete, exercise};

pub(super) async fn run_fault_cleanup(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: Option<&Path>,
    runtime_share: Option<&Path>,
    bundle_directory: &Path,
    console: &Path,
    fault: crate::LifecycleFaultPoint,
) -> crate::OciVmFaultCleanupReport {
    fault_cleanup::run(
        shim,
        vm_rootfs,
        system_image_manifest,
        runtime_share,
        bundle_directory,
        console,
        fault,
    )
    .await
}

pub(super) async fn run_transport_fault_cleanup(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: Option<&Path>,
    runtime_share: Option<&Path>,
    bundle_directory: &Path,
    console: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportFaultStage,
) -> crate::OciVmTransportFaultCleanupReport {
    transport_fault_cleanup::run(
        shim,
        vm_rootfs,
        system_image_manifest,
        runtime_share,
        bundle_directory,
        console,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmReopenReplacementReport {
    reopen_replacement::run(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_state_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_state(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_start_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_start(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_kill_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_kill(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_delete_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_delete(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_wait_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_wait(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_exec_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_exec(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_signal_process_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_signal_process(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_wait_process_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_wait_process(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_pause_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_pause(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_processes_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_processes(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_read_output_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_read_output(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_close_stdin_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_close_stdin(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_resize_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_resize(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_file_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_file(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_filesystem_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_filesystem(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_write_stdin_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_write_stdin(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_resume_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_resume(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_stats_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_stats(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_update_reopen_replacement(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: a3s_oci_agent_protocol::AgentTransportOperationStage,
) -> crate::OciVmOperationReopenReplacementReport {
    reopen_replacement::run_update(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_directory,
        console_directory,
        stage,
    )
    .await
}

pub(super) async fn run_multi_container(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: Option<&Path>,
    runtime_share: Option<&Path>,
    bundle_a: &Path,
    bundle_b: &Path,
    console: &Path,
) -> crate::OciVmMultiContainerSmokeReport {
    multi_container::run(
        shim,
        vm_rootfs,
        system_image_manifest,
        runtime_share,
        bundle_a,
        bundle_b,
        console,
    )
    .await
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) async fn run_macos_hvf_soak(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_a: &Path,
    bundle_b: &Path,
    console_directory: &Path,
    configuration: crate::MacosHvfSoakConfig,
) -> crate::MacosHvfSoakReport {
    soak::run(
        shim,
        vm_rootfs,
        system_image_manifest,
        bundle_a,
        bundle_b,
        console_directory,
        configuration,
    )
    .await
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub(super) async fn run_windows_multi_container(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    runtime_share: &Path,
    bundle_a: &Path,
    bundle_b: &Path,
    console: &Path,
) -> crate::WindowsOciVmMultiContainerSmokeReport {
    multi_container::run_windows(
        shim,
        vm_rootfs,
        system_image_manifest,
        runtime_share,
        bundle_a,
        bundle_b,
        console,
    )
    .await
}

pub(super) async fn run(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: Option<&Path>,
    runtime_share: Option<&Path>,
    bundle_directory: &Path,
    console: &Path,
) -> OciVmSmokeReport {
    let mut report = OciVmSmokeReport::initial(HostPlatform::current());
    let vm_rootfs = match canonical_directory(vm_rootfs, "VM rootfs").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let separate_runtime_share = runtime_share.is_some();
    let runtime_share = match runtime_share {
        Some(path) => match canonical_directory(path, "VM runtime share").await {
            Ok(path) => path,
            Err(reason) => return failed(report, reason),
        },
        None => vm_rootfs.clone(),
    };
    let bundle_directory = match canonical_directory(bundle_directory, "OCI bundle").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    if bundle_directory == runtime_share || !bundle_directory.starts_with(&runtime_share) {
        return failed(
            report,
            format!(
                "OCI bundle must be a strict descendant of VM runtime share {}: {}",
                runtime_share.display(),
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

    let guest_bundle = match guest_path(&runtime_share, &bundle_directory) {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let baseline_runtime_entries = match runtime_entries(&runtime_share).await {
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

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let cleanup = crate::host_cleanup::MacosHostCleanupTracker::capture();
    let session_result = if separate_runtime_share {
        UtilityVmSession::connect_with_separate_runtime_share(
            shim,
            &vm_rootfs,
            system_image_manifest,
            &runtime_share,
            console,
        )
        .await
    } else {
        UtilityVmSession::connect(shim, &vm_rootfs, system_image_manifest, console).await
    };
    let session = match session_result {
        Ok(session) => session,
        Err(bridge) => {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let bridge = {
                let mut bridge = bridge;
                cleanup.apply(&mut bridge).await;
                bridge
            };
            report.reason = bridge.reason.clone();
            report.bridge = bridge;
            return report;
        }
    };

    let client = session.client();
    let exercise = exercise(
        &client,
        &bundle,
        guest_bundle,
        &target,
        &nonce,
        &marker,
        &mut report,
    )
    .await;
    if exercise.is_err() {
        best_effort_delete(&client, &target, &nonce).await;
    }
    report.bridge = match &exercise {
        Ok(()) => session.shutdown().await,
        Err(reason) => session.shutdown_with_failure(reason).await,
    };
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    cleanup.apply(&mut report.bridge).await;

    match remove_marker(&marker).await {
        Ok(()) => report.marker_removed = true,
        Err(reason) => append_reason(&mut report, reason),
    }
    match runtime_entries(&runtime_share).await {
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
    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    ))]
    let path = format!(
        "{}/{}",
        a3s_oci_agent_protocol::AGENT_RUNTIME_SHARE_GUEST_ROOT,
        components.join("/")
    );
    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    let path = format!("/{}", components.join("/"));
    GuestPath::new(path).map_err(|error| format!("failed to construct guest bundle path: {error}"))
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
        && report.processes_verified
        && report.process_io_verified
        && report.terminal_io_verified
        && report.file_transfer_verified
        && report.filesystem_operations_verified
        && report.resources_updated
        && report.stats_verified
        && report.pause_froze_workload
        && report.resume_advanced_workload
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
