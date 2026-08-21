use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use a3s_oci_core::CapabilityStatus;
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerId, ContainerTarget, CreateRequest, DeleteMode, DeleteRequest, ErrorCode, ExitStatus,
    Generation, IsolationRequest, KillRequest, ListRequest, OciBundle, RuntimeClient, Signal,
    StartRequest, StateRequest, WaitRequest,
};
use tokio::time::{timeout, Duration as TokioDuration};

use super::bundle;
use super::host::{self, HostServiceKind, HostServiceProcess};
use super::prepare::{persist_report, PreparedQualification, QualificationInputs};
use super::qualification::{
    call, operation, verify_qualification_scope, wait_for_marker, wait_for_vm_descendants,
};
use super::soak_report::{validate_iterations, LinuxKvmSoakReport, LinuxKvmSoakWaveEvidence};

const STATE_CALL_TIMEOUT: Duration = Duration::from_secs(20);
const MARKER_NAME: &str = ".a3s-oci-create-start-smoke";

/// Exact artifacts, private parent, and bound for one real KVM soak.
#[derive(Debug, Clone)]
pub struct LinuxKvmSoakSmokeConfig {
    pub host_service_executable: PathBuf,
    pub shim: PathBuf,
    pub system_image_manifest: PathBuf,
    pub bundle: PathBuf,
    pub work_parent: PathBuf,
    pub source_revision: Option<String>,
    pub iterations: u32,
}

/// Exercise sequential fresh KVM generations through one durable Host Service.
pub async fn run(config: LinuxKvmSoakSmokeConfig) -> LinuxKvmSoakReport {
    let architecture = std::env::consts::ARCH.to_string();
    let mut report =
        LinuxKvmSoakReport::initial(config.work_parent.clone(), architecture, config.iterations);
    if let Err(reason) = validate_iterations(config.iterations) {
        report.reason = Some(reason);
        return report;
    }
    let prepared = match PreparedQualification::open(
        QualificationInputs {
            host_service_executable: config.host_service_executable,
            shim: config.shim,
            system_image_manifest: config.system_image_manifest,
            bundle: config.bundle,
            work_parent: config.work_parent,
            source_revision: config.source_revision,
        },
        "kvm-soak",
        "Linux KVM soak qualification endpoint",
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(reason) => {
            report.reason = Some(reason);
            return report;
        }
    };
    report.evidence_root = prepared.evidence_root.clone();
    report.artifacts = prepared.artifacts.clone();
    if let Err(reason) = persist_report(&report.evidence_root, &report, "KVM soak report") {
        report.reason = Some(reason);
        return report;
    }

    if let Err(reason) = run_soak(&prepared, &mut report).await {
        report.reason = Some(reason);
        let _ = persist_report(&report.evidence_root, &report, "KVM soak report");
        return report;
    }
    report.status = CapabilityStatus::Available;
    if !report.is_success() {
        report.status = CapabilityStatus::Unavailable;
        report.reason = Some("Linux KVM soak report failed its final audit".to_string());
    }
    if let Err(reason) = persist_report(&report.evidence_root, &report, "KVM soak report") {
        report.status = CapabilityStatus::Unavailable;
        report.reason = Some(reason);
    }
    report
}

async fn run_soak(
    prepared: &PreparedQualification,
    report: &mut LinuxKvmSoakReport,
) -> Result<(), String> {
    let source = SourceProfile::open(&prepared.bundle).await?;
    report.source_cgroups_path = Some(source.cgroups_path.clone());
    let endpoint_baseline = host::endpoint_inventory()?;
    let mut service = HostServiceProcess::spawn(
        HostServiceKind::Soak,
        &prepared.executable,
        &prepared.service_root,
        &prepared.shim,
        &prepared.manifest,
        &prepared.evidence_root.join("service.stdout.log"),
        &prepared.evidence_root.join("service.stderr.log"),
    )
    .await?;
    let result =
        run_live_service(prepared, &source, &endpoint_baseline, &mut service, report).await;
    if result.is_err() {
        service.emergency_stop().await;
    }
    result
}

async fn run_live_service(
    prepared: &PreparedQualification,
    source: &SourceProfile,
    endpoint_baseline: &BTreeSet<PathBuf>,
    service: &mut HostServiceProcess,
    report: &mut LinuxKvmSoakReport,
) -> Result<(), String> {
    let service_identity = service.identity()?;
    report.host_service = Some(service_identity);
    report.socket_peer = Some(service.socket_peer()?.clone());
    let client = service.connect().await?;
    verify_qualification_scope(
        &client,
        crate::kvm_driver::LINUX_KVM_SOAK_QUALIFICATION_SCOPE,
    )
    .await?;
    report.qualification_scope_verified = true;
    let service_pid = service.pid()?;
    let descriptor_baseline = host::descriptor_inventory(service_pid)?;
    report.steady_open_descriptors = u32::try_from(descriptor_baseline.len()).ok();
    let runtime_root = prepared.service_root.join("runtime");
    let id = ContainerId::new(format!("kvm-soak-{}", prepared.nonce))
        .map_err(|error| format!("failed to construct KVM soak container ID: {error}"))?;
    let mut previous_target = None;

    for iteration in 1..=report.requested_iterations {
        let mut wave = LinuxKvmSoakWaveEvidence::initial(iteration, &source.cgroups_path);
        let wave_result = run_wave(
            WaveContext {
                client: &client,
                runtime_root: &runtime_root,
                source_bundle: &prepared.bundle,
                source_marker: &source.marker,
                cgroups_path: &source.cgroups_path,
                id: &id,
                nonce: &prepared.nonce,
                service_pid,
                descriptor_baseline: &descriptor_baseline,
                endpoint_baseline,
            },
            previous_target.as_ref(),
            &mut wave,
        )
        .await;
        if let Err(reason) = wave_result {
            report.failure_iteration = Some(iteration);
            report.waves.push(wave);
            best_effort_cleanup(&client, &prepared.nonce).await;
            drop(client);
            return Err(reason);
        }
        previous_target = wave.target.clone();
        report.waves.push(wave);
    }

    report.final_open_descriptors =
        u32::try_from(host::descriptor_inventory(service_pid)?.len()).ok();
    report.console_files_created = bundle::runtime_inventory(&runtime_root)?.console_files;
    drop(client);
    report.service_exit_success = service.terminate().await?;
    report.service_socket_removed = !prepared.service_root.join("runtime.sock").exists();
    if !report.service_exit_success || !report.service_socket_removed {
        return Err("Linux KVM soak Host Service did not shut down cleanly".to_string());
    }
    Ok(())
}

struct WaveContext<'a> {
    client: &'a RuntimeClient,
    runtime_root: &'a Path,
    source_bundle: &'a Path,
    source_marker: &'a Path,
    cgroups_path: &'a Path,
    id: &'a ContainerId,
    nonce: &'a str,
    service_pid: u32,
    descriptor_baseline: &'a BTreeSet<(u32, String)>,
    endpoint_baseline: &'a BTreeSet<PathBuf>,
}

async fn run_wave(
    context: WaveContext<'_>,
    previous_target: Option<&ContainerTarget>,
    wave: &mut LinuxKvmSoakWaveEvidence,
) -> Result<(), String> {
    let wave_nonce = format!("{}-{:05}", context.nonce, wave.iteration);
    let create_context = operation("kvm-soak", &wave_nonce, "create")?;
    let staged = bundle::stage(
        context.source_bundle,
        context.runtime_root,
        context.id,
        &create_context.operation_id,
    )
    .await?;
    let create = CreateRequest {
        context: create_context,
        id: context.id.clone(),
        bundle: staged.bundle,
        isolation: IsolationRequest::DedicatedVm,
        attachments: staged.attachments,
    };
    let created = call("KVM soak create", context.client.create(create.clone())).await?;
    let replayed = call("KVM soak replayed create", context.client.create(create)).await?;
    wave.create_replayed = created == replayed && !staged.directory.exists();
    if !wave.create_replayed || *created.state.status() != ContainerState::Created {
        return Err(format!(
            "KVM soak wave {} did not replay exact created state",
            wave.iteration
        ));
    }
    let target = ContainerTarget::exact(context.id.clone(), created.generation);
    wave.target = Some(target.clone());
    wave.created_config_digest = Some(created.config_digest);
    wave.generation_monotonic = match previous_target {
        Some(previous) => {
            let previous_generation = previous
                .generation
                .ok_or_else(|| "previous KVM soak target was not exact".to_string())?;
            target
                .generation
                .is_some_and(|generation| generation.0 == previous_generation.0.saturating_add(1))
        }
        None => target
            .generation
            .is_some_and(|generation| generation.0 == 1),
    };
    let stale_target = previous_target
        .cloned()
        .unwrap_or_else(|| ContainerTarget::exact(context.id.clone(), Generation(0)));
    wave.stale_generation_rejected = stale_target_rejected(context.client, &stale_target).await?;
    if !wave.generation_monotonic || !wave.stale_generation_rejected {
        return Err(format!(
            "KVM soak wave {} failed generation or stale-target fencing",
            wave.iteration
        ));
    }

    wave.live_vm_processes = wait_for_vm_descendants(context.service_pid).await?;
    let started = call(
        "KVM soak start",
        context.client.start(StartRequest {
            context: operation("kvm-soak", &wave_nonce, "start")?,
            target: target.clone(),
        }),
    )
    .await?;
    wave.start_returned_running = *started.state.status() == ContainerState::Running;
    if !wave.start_returned_running {
        return Err(format!(
            "KVM soak wave {} did not enter running state",
            wave.iteration
        ));
    }
    wait_for_marker(context.client, &target).await?;
    wave.init_marker_verified = true;

    let kill = KillRequest {
        context: operation("kvm-soak", &wave_nonce, "kill")?,
        target: target.clone(),
        signal: Signal::new(libc::SIGKILL)
            .map_err(|error| format!("failed to construct KVM soak SIGKILL: {error}"))?,
        all: false,
    };
    let killed = call("KVM soak kill", context.client.kill(kill.clone())).await?;
    wave.kill_replayed = call("KVM soak replayed kill", context.client.kill(kill)).await? == killed;
    let wait = WaitRequest {
        target: target.clone(),
        timeout_ms: Some(30_000),
    };
    let status = call("KVM soak wait", context.client.wait(wait.clone())).await?;
    wave.wait_status = Some(status.clone());
    wave.wait_replayed = call("KVM soak replayed wait", context.client.wait(wait)).await? == status;
    if !wave.kill_replayed
        || status
            != ExitStatus::signaled(libc::SIGKILL, false)
                .map_err(|error| format!("failed to construct KVM soak wait status: {error}"))?
        || !wave.wait_replayed
    {
        return Err(format!(
            "KVM soak wave {} did not retain kill/Wait replay",
            wave.iteration
        ));
    }

    let delete = DeleteRequest {
        context: operation("kvm-soak", &wave_nonce, "delete")?,
        target: target.clone(),
        mode: DeleteMode::StoppedOnly,
    };
    call("KVM soak delete", context.client.delete(delete.clone())).await?;
    call("KVM soak replayed delete", context.client.delete(delete)).await?;
    wave.delete_replayed = true;
    wave.state_removed = state_is_missing(context.client, &target).await?
        && call(
            "KVM soak list after delete",
            context.client.list(ListRequest::default()),
        )
        .await?
        .is_empty();
    wave.source_marker_absent = path_absent(context.source_marker).await?;
    wave.vm_processes_reaped = host::wait_for_processes_reaped(&wave.live_vm_processes).await?;
    wave.endpoint_inventory_restored =
        host::wait_for_endpoint_inventory(context.endpoint_baseline).await?;
    wave.descriptor_inventory_restored =
        host::wait_for_descriptor_inventory(context.service_pid, context.descriptor_baseline)
            .await?;
    let inventory = bundle::runtime_inventory(context.runtime_root)?;
    wave.bundle_handoffs_clean = inventory.bundle_handoffs_clean;
    wave.runtime_shares_clean = inventory.runtime_shares_clean;
    wave.recovery_reports_clean = inventory.recovery_reports_clean;
    wave.console_files_retained = inventory.console_files;
    wave.guest_cgroup_lifetime_bounded = !context.cgroups_path.as_os_str().is_empty()
        && wave.state_removed
        && wave.vm_processes_reaped
        && wave.runtime_shares_clean;
    if !wave.state_removed
        || !wave.source_marker_absent
        || !wave.vm_processes_reaped
        || !wave.endpoint_inventory_restored
        || !wave.descriptor_inventory_restored
        || !wave.bundle_handoffs_clean
        || !wave.runtime_shares_clean
        || !wave.recovery_reports_clean
        || !wave.guest_cgroup_lifetime_bounded
    {
        return Err(format!(
            "KVM soak wave {} did not restore process, descriptor, cgroup, endpoint, marker, and runtime baselines",
            wave.iteration
        ));
    }
    Ok(())
}

async fn stale_target_rejected(
    client: &RuntimeClient,
    target: &ContainerTarget,
) -> Result<bool, String> {
    match timeout(
        TokioDuration::from_secs(STATE_CALL_TIMEOUT.as_secs()),
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if matches!(error.code, ErrorCode::NotFound | ErrorCode::Conflict) => {
            Ok(true)
        }
        Ok(Err(error)) => Err(format!("stale KVM soak state failed unexpectedly: {error}")),
        Ok(Ok(_)) => Ok(false),
        Err(_) => Err("stale KVM soak state timed out".to_string()),
    }
}

async fn state_is_missing(
    client: &RuntimeClient,
    target: &ContainerTarget,
) -> Result<bool, String> {
    match timeout(
        TokioDuration::from_secs(STATE_CALL_TIMEOUT.as_secs()),
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => Ok(true),
        Ok(Err(error)) => Err(format!("KVM soak state after delete failed: {error}")),
        Ok(Ok(_)) => Ok(false),
        Err(_) => Err("KVM soak state after delete timed out".to_string()),
    }
}

async fn best_effort_cleanup(client: &RuntimeClient, nonce: &str) {
    let Ok(containers) = client.list(ListRequest::default()).await else {
        return;
    };
    for (index, container) in containers.into_iter().enumerate() {
        let Ok(context) = operation("kvm-soak-cleanup", nonce, &index.to_string()) else {
            continue;
        };
        let Ok(id) = ContainerId::new(container.state.id()) else {
            continue;
        };
        let _ = client
            .delete(DeleteRequest {
                context,
                target: ContainerTarget::exact(id, container.generation),
                mode: DeleteMode::Force,
            })
            .await;
    }
}

struct SourceProfile {
    marker: PathBuf,
    cgroups_path: PathBuf,
}

impl SourceProfile {
    async fn open(bundle_directory: &Path) -> Result<Self, String> {
        let bundle = OciBundle::load(bundle_directory)
            .await
            .map_err(|error| format!("failed to reload KVM soak bundle: {error}"))?;
        let root = bundle
            .spec()
            .root()
            .as_ref()
            .ok_or_else(|| "KVM soak bundle has no root filesystem".to_string())?;
        if root.path() != Path::new("rootfs") || root.readonly().unwrap_or(false) {
            return Err(
                "KVM soak bundle must use writable normalized relative root.path `rootfs`"
                    .to_string(),
            );
        }
        let rootfs = tokio::fs::canonicalize(bundle.directory().join(root.path()))
            .await
            .map_err(|error| format!("failed to resolve KVM soak rootfs: {error}"))?;
        if rootfs == bundle.directory() || !rootfs.starts_with(bundle.directory()) {
            return Err("KVM soak rootfs escapes its source bundle".to_string());
        }
        let cgroups_path = bundle
            .spec()
            .linux()
            .as_ref()
            .and_then(|linux| linux.cgroups_path().clone())
            .ok_or_else(|| "KVM soak bundle must declare a cgroupsPath".to_string())?;
        if cgroups_path.as_os_str().is_empty() {
            return Err("KVM soak bundle cgroupsPath is empty".to_string());
        }
        let marker = rootfs.join(MARKER_NAME);
        if !path_absent(&marker).await? {
            return Err(format!(
                "refusing to overwrite existing KVM soak marker {}",
                marker.display()
            ));
        }
        Ok(Self {
            marker,
            cgroups_path,
        })
    }
}

async fn path_absent(path: &Path) -> Result<bool, String> {
    match tokio::fs::symlink_metadata(path).await {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Ok(_) => Ok(false),
        Err(error) => Err(format!("failed to inspect {}: {error}", path.display())),
    }
}
