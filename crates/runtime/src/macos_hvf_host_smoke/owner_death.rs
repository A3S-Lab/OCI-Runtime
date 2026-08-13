use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use a3s_oci_agent_protocol::AgentRecoveryReport;
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerId, ContainerTarget, CreateRequest, DeleteMode, DeleteRequest, ExitStatus,
    IsolationRequest, ListRequest, ProcessesRequest, StartRequest, StateRequest, WaitRequest,
};
use tokio::time::{sleep, Instant};

use super::cleanup;
use super::host::{self, HostServiceProcess};
use super::lifecycle;
use super::report::MacosHvfOwnerDeathEvidence;

const RECOVERY_TIMEOUT: Duration = Duration::from_secs(25);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

pub(super) struct OwnerDeathConfig<'a> {
    pub(super) executable: &'a Path,
    pub(super) service_root: &'a Path,
    pub(super) shim: &'a Path,
    pub(super) manifest: &'a Path,
    pub(super) source_bundle: &'a Path,
    pub(super) stdout: &'a Path,
    pub(super) stderr: &'a Path,
    pub(super) replacement_stdout: &'a Path,
    pub(super) replacement_stderr: &'a Path,
    pub(super) nonce: &'a str,
}

pub(super) async fn run(
    config: OwnerDeathConfig<'_>,
    evidence: &mut MacosHvfOwnerDeathEvidence,
) -> Result<(), String> {
    let runtime_root = config.service_root.join("runtime");
    let endpoint_baseline = host::endpoint_inventory()?;
    let mut first = HostServiceProcess::spawn(
        config.executable,
        config.service_root,
        config.shim,
        config.manifest,
        config.stdout,
        config.stderr,
    )
    .await?;
    let result = run_first_owner(
        &config,
        &runtime_root,
        &endpoint_baseline,
        &mut first,
        evidence,
    )
    .await;
    if result.is_err() {
        first.emergency_stop().await;
    }
    result?;

    let first_socket = host::socket_identity(first.socket_path())?;
    first.sigkill().await?;
    evidence.host_service_sigkill_delivered = true;
    evidence.first_host_service_reaped = true;
    evidence.stale_socket_retained = host::socket_identity(first.socket_path())? == first_socket;
    if !evidence.stale_socket_retained {
        return Err("SIGKILLed Host Service did not leave its exact stale socket inode".into());
    }

    evidence.live_vm_processes_reaped =
        host::wait_for_processes_reaped(&evidence.live_vm_processes).await?;
    if !evidence.live_vm_processes_reaped {
        return Err("Host Service owner death left an exact shim or VM worker alive".into());
    }
    evidence.endpoint_inventory_restored = wait_for_endpoint_baseline(&endpoint_baseline).await?;
    if !evidence.endpoint_inventory_restored {
        return Err("Host Service owner death left a guest-agent endpoint behind".into());
    }
    let target = evidence
        .target
        .as_ref()
        .ok_or_else(|| "owner-death target was not retained".to_string())?;
    let recovery_path = cleanup::recovery_report_path(&runtime_root, target)?;
    let expected_config_digest = evidence
        .created_config_digest
        .as_deref()
        .ok_or_else(|| "owner-death create digest was not retained".to_string())?;
    evidence.authenticated_recovery_report_retained =
        verify_recovery_report(&recovery_path, target, expected_config_digest).await?;
    if !evidence.authenticated_recovery_report_retained {
        return Err("authenticated owner-death recovery report was not retained".into());
    }

    let mut replacement = HostServiceProcess::spawn(
        config.executable,
        config.service_root,
        config.shim,
        config.manifest,
        config.replacement_stdout,
        config.replacement_stderr,
    )
    .await?;
    let replacement_result = run_replacement(
        &config,
        &runtime_root,
        &endpoint_baseline,
        first_socket,
        &mut replacement,
        evidence,
    )
    .await;
    if replacement_result.is_err() {
        replacement.emergency_stop().await;
    }
    replacement_result
}

async fn run_first_owner(
    config: &OwnerDeathConfig<'_>,
    runtime_root: &Path,
    endpoint_baseline: &std::collections::BTreeSet<std::path::PathBuf>,
    first: &mut HostServiceProcess,
    evidence: &mut MacosHvfOwnerDeathEvidence,
) -> Result<(), String> {
    let first_pid = first.pid()?;
    evidence.first_host_service_pid = Some(first_pid);
    let client = first.connect().await?;
    let id = ContainerId::new(format!("hvf-owner-death-{}", config.nonce))
        .map_err(|error| format!("failed to construct owner-death container ID: {error}"))?;
    let context = lifecycle::operation(config.nonce, "owner-create")?;
    let staged = super::bundle::stage(
        config.source_bundle,
        runtime_root,
        &id,
        &context.operation_id,
    )
    .await?;
    let create = CreateRequest {
        context,
        id: id.clone(),
        bundle: staged.bundle,
        isolation: IsolationRequest::DedicatedVm,
        attachments: staged.attachments,
    };
    let created =
        lifecycle::call("owner-death public create", client.create(create.clone())).await?;
    let replayed = lifecycle::call("owner-death replayed create", client.create(create)).await?;
    if created != replayed || *created.state.status() != ContainerState::Created {
        return Err(
            "owner-death create did not preserve the created barrier and exact replay".into(),
        );
    }
    let target = ContainerTarget::exact(id, created.generation);
    evidence.target = Some(target.clone());
    evidence.created_config_digest = Some(created.config_digest.clone());
    let started = lifecycle::call(
        "owner-death public start",
        client.start(StartRequest {
            context: lifecycle::operation(config.nonce, "owner-start")?,
            target: target.clone(),
        }),
    )
    .await?;
    if *started.state.status() != ContainerState::Running {
        return Err("owner-death start did not return a live generation".into());
    }
    lifecycle::wait_for_marker(&client, &target).await?;
    let descendants = lifecycle::wait_for_vm_descendants(first_pid).await?;
    if descendants.len() < 2
        || descendants
            .iter()
            .any(|process| process.process_group_id == first_pid)
    {
        return Err(
            "owner-death process inventory did not expose a private shim/worker group".into(),
        );
    }
    evidence.live_vm_processes = descendants;
    evidence.authenticated_endpoint_consumed =
        wait_for_endpoint_baseline(endpoint_baseline).await?;
    if !evidence.authenticated_endpoint_consumed {
        return Err(
            "authenticated live owner-death generation retained its guest-agent endpoint".into(),
        );
    }
    drop(client);
    Ok(())
}

async fn run_replacement(
    config: &OwnerDeathConfig<'_>,
    runtime_root: &Path,
    endpoint_baseline: &std::collections::BTreeSet<std::path::PathBuf>,
    first_socket: (u64, u64),
    replacement: &mut HostServiceProcess,
    evidence: &mut MacosHvfOwnerDeathEvidence,
) -> Result<(), String> {
    let replacement_pid = replacement.pid()?;
    evidence.replacement_host_service_pid = Some(replacement_pid);
    evidence.replacement_socket_new_inode =
        host::socket_identity(replacement.socket_path())? != first_socket;
    if !evidence.replacement_socket_new_inode {
        return Err("replacement Host Service reused the stale socket inode".into());
    }
    let client = replacement.connect().await?;
    evidence.replacement_connected = true;
    let descriptors_before = host::descriptor_inventory(replacement_pid)?;
    evidence.open_descriptors_before = u32::try_from(descriptors_before.len()).ok();
    let target = evidence
        .target
        .clone()
        .ok_or_else(|| "owner-death target disappeared before replacement".to_string())?;
    let recovered = lifecycle::call(
        "replacement recovered state",
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await?;
    evidence.exact_stopped_state_recovered = *recovered.state.status() == ContainerState::Stopped
        && recovered.generation == target.generation.expect("owner target is exact")
        && evidence
            .created_config_digest
            .as_deref()
            .is_some_and(|digest| recovered.config_digest == digest)
        && recovered.state.pid().is_none();
    evidence.process_inventory_empty = lifecycle::call(
        "replacement recovered process inventory",
        client.processes(ProcessesRequest {
            target: target.clone(),
        }),
    )
    .await?
    .is_empty();
    let wait = WaitRequest {
        target: target.clone(),
        timeout_ms: Some(20_000),
    };
    let status = lifecycle::call("replacement recovered wait", client.wait(wait.clone())).await?;
    evidence.recovered_wait_status = Some(status.clone());
    evidence.recovered_wait_replayed =
        lifecycle::call("replacement replayed recovered wait", client.wait(wait)).await? == status;
    let expected = ExitStatus::signaled(libc::SIGKILL, false)
        .map_err(|error| format!("failed to construct owner-death SIGKILL status: {error}"))?;
    if !evidence.exact_stopped_state_recovered
        || !evidence.process_inventory_empty
        || status != expected
        || !evidence.recovered_wait_replayed
    {
        return Err("replacement Host Service did not recover exact stopped/SIGKILL state".into());
    }
    lifecycle::call(
        "replacement stopped-only delete",
        client.delete(DeleteRequest {
            context: lifecycle::operation(config.nonce, "owner-delete")?,
            target: target.clone(),
            mode: DeleteMode::StoppedOnly,
        }),
    )
    .await?;
    evidence.stopped_delete_succeeded = true;
    evidence.durable_state_removed =
        cleanup::durable_container_removed(config.service_root, &target)?
            && lifecycle::call(
                "replacement list after delete",
                client.list(ListRequest::default()),
            )
            .await?
            .is_empty();
    evidence.replacement_descriptor_inventory_restored =
        host::wait_for_descriptor_inventory(replacement_pid, &descriptors_before).await?;
    let descriptors_after = host::descriptor_inventory(replacement_pid)?;
    evidence.open_descriptors_after = u32::try_from(descriptors_after.len()).ok();
    let inventory = cleanup::inventory(runtime_root)?;
    evidence.bundle_handoffs_clean = inventory.bundle_handoffs_clean;
    evidence.runtime_shares_clean = inventory.runtime_shares_clean;
    evidence.recovery_reports_clean = inventory.recovery_reports_clean;
    if !evidence.durable_state_removed
        || !evidence.replacement_descriptor_inventory_restored
        || !evidence.bundle_handoffs_clean
        || !evidence.runtime_shares_clean
        || !evidence.recovery_reports_clean
        || !host::wait_for_endpoint_inventory(endpoint_baseline).await?
    {
        return Err("replacement delete did not restore owner-death cleanup baselines".into());
    }
    drop(client);
    evidence.replacement_exit_success = replacement.terminate().await?;
    evidence.replacement_socket_removed = cleanup::socket_absent(config.service_root)?;
    if !evidence.replacement_exit_success || !evidence.replacement_socket_removed {
        return Err("replacement Host Service did not shut down cleanly".into());
    }
    Ok(())
}

async fn verify_recovery_report(
    path: &Path,
    target: &ContainerTarget,
    expected_config_digest: &str,
) -> Result<bool, String> {
    let deadline = Instant::now() + RECOVERY_TIMEOUT;
    loop {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                // SAFETY: geteuid has no preconditions or failure result.
                let uid = unsafe { libc::geteuid() };
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != uid
                    || metadata.permissions().mode() & 0o777 != 0o600
                {
                    return Ok(false);
                }
                let encoded = std::fs::read(path).map_err(|error| {
                    format!("failed to read recovery report {}: {error}", path.display())
                })?;
                let report = AgentRecoveryReport::from_json(&encoded)
                    .map_err(|error| format!("retained recovery report is invalid: {error}"))?;
                return Ok(report.records().iter().any(|record| {
                    record.target == *target
                        && record.config_digest == expected_config_digest
                        && record.init_exit_status
                            == ExitStatus::signaled(libc::SIGKILL, false)
                                .expect("fixed SIGKILL status is valid")
                }));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "failed to inspect recovery report {}: {error}",
                    path.display()
                ));
            }
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_endpoint_baseline(
    baseline: &std::collections::BTreeSet<std::path::PathBuf>,
) -> Result<bool, String> {
    let deadline = Instant::now() + RECOVERY_TIMEOUT;
    loop {
        if host::endpoint_inventory()? == *baseline {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(POLL_INTERVAL).await;
    }
}
