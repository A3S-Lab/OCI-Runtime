use std::path::{Path, PathBuf};
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerId, ContainerTarget, CreateRequest, DeleteMode, DeleteRequest, ErrorCode,
    IsolationRequest, KillRequest, ListRequest, ProcessesRequest, Signal, StartRequest,
    StateRequest, WaitRequest,
};
use tokio::time::{sleep, Instant};

use crate::kvm_live_session_binding::{
    authenticate_live, load_binding, KvmLiveSessionBinding, KVM_LIVE_SESSION_BINDING_FILE,
};
use crate::linux_kvm_recovery_smoke::bundle;
use crate::linux_kvm_recovery_smoke::host::{
    self, HostServiceKind, HostServiceProcess, HostServiceSpawnOptions,
};
use crate::linux_kvm_recovery_smoke::prepare::{
    persist_report, PreparedQualification, QualificationInputs,
};
use crate::linux_kvm_recovery_smoke::qualification::{
    call, operation, verify_qualification_scope, wait_for_marker, wait_for_vm_descendants,
};
use crate::linux_kvm_recovery_smoke::LinuxProcessIdentity;

use super::report::LinuxKvmLiveRecoverySmokeReport;

const LIVE_TIMEOUT: Duration = Duration::from_secs(25);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const SHORT_WAIT_MS: u64 = 500;

/// Exact artifacts and private parent for one Live KVM Host reopen run.
#[derive(Debug, Clone)]
pub struct LinuxKvmLiveRecoverySmokeConfig {
    pub host_service_executable: PathBuf,
    pub shim: PathBuf,
    pub system_image_manifest: PathBuf,
    pub bundle: PathBuf,
    pub work_parent: PathBuf,
    pub source_revision: Option<String>,
}

const DURABLE_SPAWN: HostServiceSpawnOptions = HostServiceSpawnOptions {
    durable_session_owner: true,
};

/// Kill one Live KVM Host Service; prove Guest survives and replacement reattaches Running.
pub async fn run(config: LinuxKvmLiveRecoverySmokeConfig) -> LinuxKvmLiveRecoverySmokeReport {
    let architecture = std::env::consts::ARCH.to_string();
    let mut report =
        LinuxKvmLiveRecoverySmokeReport::initial(config.work_parent.clone(), architecture);
    report.recovery.session_owner_mode_durable = true;
    let prepared = match PreparedQualification::open(
        QualificationInputs {
            host_service_executable: config.host_service_executable,
            shim: config.shim,
            system_image_manifest: config.system_image_manifest,
            bundle: config.bundle,
            work_parent: config.work_parent,
            source_revision: config.source_revision,
        },
        "kvm-live-recovery",
        "Linux KVM Live recovery qualification endpoint",
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
    if let Err(reason) = persist_report(&report.evidence_root, &report, "KVM Live recovery report") {
        report.reason = Some(reason);
        return report;
    }

    if let Err(reason) = run_live_recovery(&prepared, &mut report.recovery).await {
        report.recovery.reason = Some(reason.clone());
        report.reason = Some(reason);
        let _ = persist_report(&report.evidence_root, &report, "KVM Live recovery report");
        return report;
    }
    if !report.recovery.is_success() {
        let reason = "Linux KVM Live recovery evidence failed its completeness audit".to_string();
        report.recovery.reason = Some(reason.clone());
        report.reason = Some(reason);
        let _ = persist_report(&report.evidence_root, &report, "KVM Live recovery report");
        return report;
    }
    report.status = a3s_oci_core::CapabilityStatus::Available;
    report.case_count = 1;
    if !report.is_success() {
        report.status = a3s_oci_core::CapabilityStatus::Unavailable;
        report.case_count = 0;
        report.reason = Some("Linux KVM Live recovery report failed its final audit".to_string());
    }
    if let Err(reason) = persist_report(&report.evidence_root, &report, "KVM Live recovery report") {
        report.status = a3s_oci_core::CapabilityStatus::Unavailable;
        report.case_count = 0;
        report.reason = Some(reason);
    }
    report
}

async fn run_live_recovery(
    prepared: &PreparedQualification,
    evidence: &mut super::report::LinuxKvmLiveRecoveryEvidence,
) -> Result<(), String> {
    let runtime_root = prepared.service_root.join("runtime");
    let endpoint_baseline = host::endpoint_inventory()?;
    let mut first = HostServiceProcess::spawn_with_options(
        HostServiceKind::Recovery,
        &prepared.executable,
        &prepared.service_root,
        &prepared.shim,
        &prepared.manifest,
        &prepared.evidence_root.join("first.stdout.log"),
        &prepared.evidence_root.join("first.stderr.log"),
        DURABLE_SPAWN,
    )
    .await?;
    let first_result =
        run_first_owner(prepared, &runtime_root, &endpoint_baseline, &first, evidence).await;
    if first_result.is_err() {
        emergency_reap_survivors(evidence).await;
        first.emergency_stop().await;
    }
    first_result?;

    let first_socket = host::socket_identity(first.socket_path())?;
    first.sigkill().await?;
    evidence.host_service_sigkill_delivered = true;
    evidence.first_host_service_reaped = true;
    evidence.stale_socket_retained = host::socket_identity(first.socket_path())? == first_socket;
    if !evidence.stale_socket_retained {
        emergency_reap_survivors(evidence).await;
        return Err("SIGKILLed Host Service did not leave its exact stale socket".to_string());
    }

    // Opposite of stopped-only: Guest / session-owner must still be live.
    sleep(Duration::from_millis(200)).await;
    evidence.live_vm_processes_reaped =
        !host::processes_still_live(&evidence.live_vm_processes)?;
    evidence.guest_survived_host_sigkill = host::processes_still_live(&evidence.live_vm_processes)?;
    if evidence.live_vm_processes_reaped || !evidence.guest_survived_host_sigkill {
        return Err(
            "Live session-owner/shim were reaped after Host SIGKILL (expected survival)".to_string(),
        );
    }

    let binding = load_live_binding(&runtime_root, evidence)?;
    authenticate_live(&binding)
        .map_err(|error| format!("Live binding failed authentication after Host SIGKILL: {error}"))?;
    evidence.live_binding_authenticated_after_kill = true;
    retain_binding_identities(evidence, &binding)?;

    let mut replacement = HostServiceProcess::spawn_with_options(
        HostServiceKind::Recovery,
        &prepared.executable,
        &prepared.service_root,
        &prepared.shim,
        &prepared.manifest,
        &prepared.evidence_root.join("replacement.stdout.log"),
        &prepared.evidence_root.join("replacement.stderr.log"),
        DURABLE_SPAWN,
    )
    .await?;
    let replacement_result =
        run_replacement(prepared, &runtime_root, &mut replacement, evidence).await;
    if replacement_result.is_err() {
        emergency_reap_survivors(evidence).await;
        replacement.emergency_stop().await;
    }
    replacement_result
}

async fn run_first_owner(
    prepared: &PreparedQualification,
    runtime_root: &Path,
    endpoint_baseline: &std::collections::BTreeSet<PathBuf>,
    first: &HostServiceProcess,
    evidence: &mut super::report::LinuxKvmLiveRecoveryEvidence,
) -> Result<(), String> {
    let identity = first.identity()?;
    evidence.first_host_service = Some(identity);
    evidence.first_socket_peer = Some(first.socket_peer()?.clone());
    let client = first.connect().await?;
    verify_qualification_scope(
        &client,
        crate::kvm_driver::LINUX_KVM_RECOVERY_QUALIFICATION_SCOPE,
    )
    .await?;
    evidence.qualification_scope_verified = true;
    let id = ContainerId::new(format!("kvm-live-owner-{}", prepared.nonce))
        .map_err(|error| format!("failed to construct Live recovery container ID: {error}"))?;
    let context = operation("kvm-live-recovery", &prepared.nonce, "create")?;
    let staged = bundle::stage(&prepared.bundle, runtime_root, &id, &context.operation_id).await?;
    let create = CreateRequest {
        context,
        id: id.clone(),
        bundle: staged.bundle,
        isolation: IsolationRequest::DedicatedVm,
        attachments: staged.attachments,
    };
    let created = call("KVM Live recovery create", client.create(create.clone())).await?;
    let replayed = call("KVM Live recovery replayed create", client.create(create)).await?;
    evidence.create_replayed = created == replayed && !staged.directory.exists();
    if !evidence.create_replayed || *created.state.status() != ContainerState::Created {
        return Err("KVM Live recovery Create did not replay the exact created state".to_string());
    }
    let target = ContainerTarget::exact(id, created.generation);
    evidence.target = Some(target.clone());
    evidence.created_config_digest = Some(created.config_digest);
    let started = call(
        "KVM Live recovery start",
        client.start(StartRequest {
            context: operation("kvm-live-recovery", &prepared.nonce, "start")?,
            target: target.clone(),
        }),
    )
    .await?;
    evidence.start_returned_running = *started.state.status() == ContainerState::Running;
    if !evidence.start_returned_running {
        return Err("KVM Live recovery Start did not return running state".to_string());
    }
    evidence.init_pid_before = started
        .state
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0);
    if evidence.init_pid_before.is_none() {
        return Err("KVM Live recovery Start did not retain a live init PID".to_string());
    }
    wait_for_marker(&client, &target).await?;
    evidence.init_marker_verified = true;
    evidence.live_vm_processes = wait_for_vm_descendants(first.pid()?).await?;
    let binding = wait_for_live_binding(runtime_root).await?;
    evidence.live_binding_published = true;
    retain_binding_identities(evidence, &binding)?;
    evidence.authenticated_endpoint_consumed =
        host::wait_for_endpoint_inventory(endpoint_baseline).await?;
    if !evidence.authenticated_endpoint_consumed {
        return Err("live KVM session retained its one-shot endpoint".to_string());
    }
    drop(client);
    Ok(())
}

async fn run_replacement(
    prepared: &PreparedQualification,
    runtime_root: &Path,
    replacement: &mut HostServiceProcess,
    evidence: &mut super::report::LinuxKvmLiveRecoveryEvidence,
) -> Result<(), String> {
    let identity = replacement.identity()?;
    evidence.replacement_host_service = Some(identity);
    evidence.replacement_socket_peer = Some(replacement.socket_peer()?.clone());
    evidence.replacement_socket_new_owner =
        evidence.first_socket_peer != evidence.replacement_socket_peer;
    if !evidence.replacement_socket_new_owner {
        return Err("replacement socket kept the first owner identity".to_string());
    }
    let client = replacement.connect().await?;
    evidence.replacement_connected = true;
    verify_qualification_scope(
        &client,
        crate::kvm_driver::LINUX_KVM_RECOVERY_QUALIFICATION_SCOPE,
    )
    .await?;
    let target = evidence
        .target
        .clone()
        .ok_or_else(|| "Live recovery target disappeared before replacement".to_string())?;
    let recovered = call(
        "replacement KVM Live state",
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await?;
    evidence.replacement_state_running = *recovered.state.status() == ContainerState::Running
        && recovered.generation == target.generation.expect("target is exact")
        && evidence
            .created_config_digest
            .as_deref()
            .is_some_and(|digest| recovered.config_digest == digest)
        && recovered.state.pid().is_some();
    evidence.init_pid_after = recovered
        .state
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0);
    evidence.init_identity_unchanged = evidence.init_pid_before == evidence.init_pid_after
        && evidence.init_pid_before.is_some()
        && host::processes_still_live(&[
            evidence
                .session_owner_identity
                .clone()
                .ok_or_else(|| "session-owner identity missing".to_string())?,
            evidence
                .shim_identity
                .clone()
                .ok_or_else(|| "shim identity missing".to_string())?,
        ])?;
    if !evidence.replacement_state_running || !evidence.init_identity_unchanged {
        return Err(
            "replacement did not reattach Running with continuous init/session-owner identity"
                .to_string(),
        );
    }

    let processes = call(
        "replacement KVM Live process inventory",
        client.processes(ProcessesRequest {
            target: target.clone(),
        }),
    )
    .await?;
    evidence.process_inventory_nonempty = !processes.is_empty();
    if !evidence.process_inventory_nonempty {
        return Err("replacement Live process inventory was empty".to_string());
    }

    evidence.no_invented_exit_status =
        assert_no_invented_exit(&client, &target, runtime_root).await?;
    if !evidence.no_invented_exit_status {
        return Err("replacement invented an exit status for a still-running Guest".to_string());
    }

    call(
        "replacement Live kill",
        client.kill(KillRequest {
            context: operation("kvm-live-recovery", &prepared.nonce, "kill")?,
            target: target.clone(),
            signal: Signal::new(libc::SIGKILL)
                .map_err(|error| format!("failed to construct SIGKILL: {error}"))?,
            all: true,
        }),
    )
    .await?;
    let status = call(
        "replacement Live wait after kill",
        client.wait(WaitRequest {
            target: target.clone(),
            timeout_ms: Some(20_000),
        }),
    )
    .await?;
    let _ = status;
    call(
        "replacement Live stopped-only delete",
        client.delete(DeleteRequest {
            context: operation("kvm-live-recovery", &prepared.nonce, "delete")?,
            target: target.clone(),
            mode: DeleteMode::StoppedOnly,
        }),
    )
    .await?;
    evidence.force_cleanup_succeeded = !prepared
        .service_root
        .join("state/containers")
        .join(target.id.as_str())
        .exists()
        && call(
            "replacement list after Live delete",
            client.list(ListRequest::default()),
        )
        .await?
        .is_empty();
    if !evidence.force_cleanup_succeeded {
        return Err("replacement Live delete did not remove durable state".to_string());
    }
    drop(client);
    evidence.replacement_exit_success = replacement.terminate().await?;
    evidence.replacement_socket_removed = !prepared.service_root.join("runtime.sock").exists();
    evidence.service_restart_recovered = evidence.replacement_exit_success
        && evidence.replacement_socket_removed
        && evidence.replacement_state_running
        && evidence.init_identity_unchanged
        && evidence.no_invented_exit_status;
    if !evidence.service_restart_recovered {
        return Err("replacement Host Service did not shut down cleanly after Live reopen".to_string());
    }
    Ok(())
}

async fn assert_no_invented_exit(
    client: &a3s_oci_sdk::RuntimeClient,
    target: &ContainerTarget,
    runtime_root: &Path,
) -> Result<bool, String> {
    let wait = WaitRequest {
        target: target.clone(),
        timeout_ms: Some(SHORT_WAIT_MS),
    };
    match tokio::time::timeout(Duration::from_secs(5), client.wait(wait)).await {
        Ok(Ok(_status)) => {
            // A completed wait while state is Running invents terminal evidence.
            Ok(false)
        }
        Ok(Err(error)) => {
            let acceptable = matches!(
                error.code,
                ErrorCode::DeadlineExceeded | ErrorCode::Unavailable
            ) || error.message.to_ascii_lowercase().contains("timeout")
                || error.message.to_ascii_lowercase().contains("deadline");
            if !acceptable {
                return Err(format!(
                    "short Live wait failed unexpectedly with {:?}: {}",
                    error.code, error.message
                ));
            }
            Ok(!sigkill_recovery_report_present(runtime_root, target)?)
        }
        Err(_) => Ok(!sigkill_recovery_report_present(runtime_root, target)?),
    }
}

fn sigkill_recovery_report_present(
    runtime_root: &Path,
    target: &ContainerTarget,
) -> Result<bool, String> {
    let generation = target
        .generation
        .ok_or_else(|| "Live recovery report check requires an exact generation".to_string())?;
    let path = runtime_root
        .join("recovery")
        .join(format!("{}-{}.json", target.id, generation.0));
    match std::fs::symlink_metadata(&path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("failed to inspect recovery report {}: {error}", path.display())),
    }
}

fn retain_binding_identities(
    evidence: &mut super::report::LinuxKvmLiveRecoveryEvidence,
    binding: &KvmLiveSessionBinding,
) -> Result<(), String> {
    let owner = identity_from_binding(
        binding.session_owner.pid,
        binding.session_owner.start_time_ticks,
        "session-owner",
    )?;
    let shim = identity_from_binding(
        binding.shim.pid,
        binding.shim.start_time_ticks,
        "shim",
    )?;
    if let Some(previous) = evidence.session_owner_identity.as_ref() {
        if previous.pid != owner.pid || previous.start_time_ticks != owner.start_time_ticks {
            return Err("Live binding session-owner identity drifted".to_string());
        }
    }
    if let Some(previous) = evidence.shim_identity.as_ref() {
        if previous.pid != shim.pid || previous.start_time_ticks != shim.start_time_ticks {
            return Err("Live binding shim identity drifted".to_string());
        }
    }
    evidence.session_owner_identity = Some(owner);
    evidence.shim_identity = Some(shim);
    Ok(())
}

fn identity_from_binding(
    pid: i32,
    start_time_ticks: u64,
    role: &str,
) -> Result<LinuxProcessIdentity, String> {
    let pid = u32::try_from(pid).map_err(|error| format!("{role} pid is invalid: {error}"))?;
    let inventory_path = PathBuf::from(format!("/proc/{pid}/stat"));
    let encoded = std::fs::read_to_string(&inventory_path)
        .map_err(|error| format!("failed to read {role} identity: {error}"))?;
    let open = encoded
        .find('(')
        .ok_or_else(|| format!("{role} stat has no command start"))?;
    let close = encoded
        .rfind(')')
        .ok_or_else(|| format!("{role} stat has no command end"))?;
    let command = encoded[open + 1..close].to_string();
    let fields = encoded[close + 1..].split_whitespace().collect::<Vec<_>>();
    if fields.len() <= 19 {
        return Err(format!("{role} stat is truncated"));
    }
    let parent_pid = fields[1]
        .parse::<u32>()
        .map_err(|error| format!("invalid {role} parent PID: {error}"))?;
    let process_group_id = fields[2]
        .parse::<u32>()
        .map_err(|error| format!("invalid {role} process group: {error}"))?;
    let observed_start = fields[19]
        .parse::<u64>()
        .map_err(|error| format!("invalid {role} start time: {error}"))?;
    if observed_start != start_time_ticks {
        return Err(format!(
            "{role} start-time drifted from binding ({start_time_ticks} vs {observed_start})"
        ));
    }
    Ok(LinuxProcessIdentity {
        pid,
        parent_pid,
        process_group_id,
        start_time_ticks,
        command,
    })
}

fn load_live_binding(
    runtime_root: &Path,
    evidence: &super::report::LinuxKvmLiveRecoveryEvidence,
) -> Result<KvmLiveSessionBinding, String> {
    let path = find_live_binding_path(runtime_root)?;
    let binding = load_binding(&path)
        .map_err(|error| format!("failed to load Live binding {}: {error}", path.display()))?;
    if let (Some(owner), Some(shim)) = (
        evidence.session_owner_identity.as_ref(),
        evidence.shim_identity.as_ref(),
    ) {
        if owner.pid as i32 != binding.session_owner.pid
            || owner.start_time_ticks != binding.session_owner.start_time_ticks
            || shim.pid as i32 != binding.shim.pid
            || shim.start_time_ticks != binding.shim.start_time_ticks
        {
            return Err("Live binding identities do not match retained session-owner/shim".to_string());
        }
    }
    Ok(binding)
}

async fn wait_for_live_binding(runtime_root: &Path) -> Result<KvmLiveSessionBinding, String> {
    let deadline = Instant::now() + LIVE_TIMEOUT;
    loop {
        if let Ok(path) = find_live_binding_path(runtime_root) {
            match load_binding(&path) {
                Ok(binding) => {
                    authenticate_live(&binding).map_err(|error| {
                        format!("published Live binding failed authentication: {error}")
                    })?;
                    return Ok(binding);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "failed to load published Live binding {}: {error}",
                        path.display()
                    ))
                }
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for published KVM Live session binding".to_string());
        }
        sleep(POLL_INTERVAL).await;
    }
}

fn find_live_binding_path(runtime_root: &Path) -> Result<PathBuf, String> {
    let shares = runtime_root.join("shares");
    let mut found = Vec::new();
    walk_for_binding(&shares, &mut found)?;
    match found.as_slice() {
        [path] => Ok(path.clone()),
        [] => Err(format!(
            "no {} under {}",
            KVM_LIVE_SESSION_BINDING_FILE,
            shares.display()
        )),
        _ => Err(format!(
            "multiple Live bindings under {}: {}",
            shares.display(),
            found.len()
        )),
    }
}

fn walk_for_binding(root: &Path, found: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "failed to enumerate {}: {error}",
                root.display()
            ))
        }
    };
    for entry in entries {
        let entry = entry.map_err(|error| format!("failed to inspect share entry: {error}"))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
        if file_type.is_dir() {
            walk_for_binding(&path, found)?;
        } else if entry.file_name() == KVM_LIVE_SESSION_BINDING_FILE {
            found.push(path);
        }
    }
    Ok(())
}

async fn emergency_reap_survivors(evidence: &super::report::LinuxKvmLiveRecoveryEvidence) {
    for process in &evidence.live_vm_processes {
        let Ok(pid) = libc::pid_t::try_from(process.pid) else {
            continue;
        };
        // SAFETY: best-effort cleanup of retained Live survivors after a failed gate.
        unsafe {
            let _ = libc::kill(pid, libc::SIGKILL);
        }
    }
    if let Some(owner) = evidence.session_owner_identity.as_ref() {
        if let Ok(pid) = libc::pid_t::try_from(owner.pid) {
            unsafe {
                let _ = libc::kill(pid, libc::SIGKILL);
            }
        }
    }
    let _ = host::wait_for_processes_reaped(&evidence.live_vm_processes).await;
}
