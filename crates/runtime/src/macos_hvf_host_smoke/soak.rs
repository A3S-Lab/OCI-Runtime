use std::collections::{BTreeSet, HashSet};
use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerId, ContainerTarget, CreateRequest, DeleteMode, DeleteRequest, ErrorCode, ExitStatus,
    IsolationRequest, KillRequest, OperationContext, OperationId, RuntimeClient, Signal,
    StartRequest, StateRequest, WaitRequest,
};
use tokio::time::timeout;

use super::cleanup;
use super::host::{self, HostServiceProcess};
use super::lifecycle;
use super::report::MacosHvfPublicSoakEvidence;

const CALL_TIMEOUT: Duration = Duration::from_secs(20);

pub(super) struct SoakConfig<'a> {
    pub(super) executable: &'a Path,
    pub(super) service_root: &'a Path,
    pub(super) shim: &'a Path,
    pub(super) manifest: &'a Path,
    pub(super) source_bundle: &'a Path,
    pub(super) stdout: &'a Path,
    pub(super) stderr: &'a Path,
    pub(super) nonce: &'a str,
    pub(super) iterations: u32,
}

pub(super) async fn run(
    config: SoakConfig<'_>,
    evidence: &mut MacosHvfPublicSoakEvidence,
) -> Result<(), String> {
    let runtime_root = config.service_root.join("runtime");
    let endpoint_baseline = host::endpoint_inventory()?;
    let console_baseline = cleanup::inventory(&runtime_root)?.console_files;
    let mut service = HostServiceProcess::spawn(
        config.executable,
        config.service_root,
        config.shim,
        config.manifest,
        config.stdout,
        config.stderr,
    )
    .await?;
    let service_pid = service.pid()?;
    evidence.host_service_pid = Some(service_pid);
    let client = service.connect().await?;
    let descriptor_baseline = host::descriptor_inventory(service_pid)?;
    evidence.steady_open_descriptors = u32::try_from(descriptor_baseline.len()).ok();
    let id = ContainerId::new(format!("hvf-public-soak-{}", config.nonce))
        .map_err(|error| format!("failed to construct public soak container ID: {error}"))?;
    let mut previous_target = None;
    let mut unique_identities = HashSet::new();
    for iteration in 1..=config.iterations {
        if let Err(reason) = run_iteration(
            &client,
            &runtime_root,
            config.source_bundle,
            &id,
            config.nonce,
            iteration,
            service_pid,
            &descriptor_baseline,
            &endpoint_baseline,
            &mut previous_target,
            &mut unique_identities,
            evidence,
        )
        .await
        {
            evidence.failure_iteration = Some(iteration);
            lifecycle::best_effort_delete(&client, &id, config.nonce).await;
            drop(client);
            service.emergency_stop().await;
            return Err(reason);
        }
    }

    evidence.unique_vm_processes = unique_identities.len() == evidence.vm_processes.len();
    evidence.final_open_descriptors =
        u32::try_from(host::descriptor_inventory(service_pid)?.len()).ok();
    drop(client);
    evidence.service_exit_success = service.terminate().await?;
    evidence.service_socket_removed = cleanup::socket_absent(config.service_root)?;
    let console_after = cleanup::inventory(&runtime_root)?.console_files;
    evidence.console_files_created =
        u32::try_from(console_after.difference(&console_baseline).count()).unwrap_or(u32::MAX);
    if !evidence.unique_vm_processes
        || !evidence.service_exit_success
        || !evidence.service_socket_removed
        || evidence.console_files_created < config.iterations
    {
        return Err("public Host Service soak final evidence was incomplete".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_iteration(
    client: &RuntimeClient,
    runtime_root: &Path,
    source_bundle: &Path,
    id: &ContainerId,
    nonce: &str,
    iteration: u32,
    service_pid: u32,
    descriptor_baseline: &BTreeSet<(i32, u32)>,
    endpoint_baseline: &BTreeSet<std::path::PathBuf>,
    previous_target: &mut Option<ContainerTarget>,
    unique_identities: &mut HashSet<(u32, u64)>,
    evidence: &mut MacosHvfPublicSoakEvidence,
) -> Result<(), String> {
    let wave = format!("{nonce}-{iteration:05}");
    let create_context = operation(&wave, "create")?;
    let staged = super::bundle::stage(
        source_bundle,
        runtime_root,
        id,
        &create_context.operation_id,
    )
    .await?;
    let create = CreateRequest {
        context: create_context,
        id: id.clone(),
        bundle: staged.bundle,
        isolation: IsolationRequest::DedicatedVm,
        attachments: staged.attachments,
    };
    let created = lifecycle::call("public soak create", client.create(create.clone())).await?;
    let target = ContainerTarget::exact(id.clone(), created.generation);
    let replayed = lifecycle::call("public soak replayed create", client.create(create)).await?;
    if created != replayed || *created.state.status() != ContainerState::Created {
        return Err("public soak create did not preserve exact created replay".into());
    }
    evidence.create_replays_verified += 1;

    let generation_valid = match previous_target.as_ref() {
        Some(previous) => {
            let previous_generation = previous.generation.expect("previous soak target is exact");
            created.generation.0 == previous_generation.0.saturating_add(1)
                && stale_target_rejected(client, previous).await?
        }
        None => created.generation.0 == 1,
    };
    evidence.generation_monotonic_every_iteration &= generation_valid;
    evidence.stale_generation_rejected_every_iteration &= generation_valid;
    if !generation_valid {
        return Err(format!(
            "public soak generation or stale fence failed at wave {iteration}"
        ));
    }

    let vm_processes = lifecycle::wait_for_vm_descendants(service_pid).await?;
    if vm_processes.len() < 2 {
        return Err(format!(
            "public soak wave {iteration} did not expose shim and worker"
        ));
    }
    for process in &vm_processes {
        if !unique_identities.insert((process.pid, process.start_time_unix_us)) {
            evidence.unique_vm_processes = false;
            return Err(format!(
                "public soak wave {iteration} reused process incarnation {}:{}",
                process.pid, process.start_time_unix_us
            ));
        }
    }
    evidence.vm_processes.extend(vm_processes.clone());

    let started = lifecycle::call(
        "public soak start",
        client.start(StartRequest {
            context: operation(&wave, "start")?,
            target: target.clone(),
        }),
    )
    .await?;
    if *started.state.status() != ContainerState::Running {
        return Err(format!(
            "public soak wave {iteration} did not enter running"
        ));
    }
    lifecycle::wait_for_marker(client, &target).await?;

    let kill = KillRequest {
        context: operation(&wave, "kill")?,
        target: target.clone(),
        signal: Signal::new(libc::SIGKILL)
            .map_err(|error| format!("failed to construct soak SIGKILL: {error}"))?,
        all: false,
    };
    let killed = lifecycle::call("public soak kill", client.kill(kill.clone())).await?;
    if lifecycle::call("public soak replayed kill", client.kill(kill)).await? != killed {
        return Err(format!("public soak wave {iteration} did not replay kill"));
    }
    evidence.kill_replays_verified += 1;
    let wait = WaitRequest {
        target: target.clone(),
        timeout_ms: Some(30_000),
    };
    let status = lifecycle::call("public soak wait", client.wait(wait.clone())).await?;
    if lifecycle::call("public soak replayed wait", client.wait(wait)).await? != status
        || status
            != ExitStatus::signaled(libc::SIGKILL, false)
                .map_err(|error| format!("failed to construct soak status: {error}"))?
    {
        return Err(format!(
            "public soak wave {iteration} did not retain SIGKILL wait replay"
        ));
    }
    evidence.wait_replays_verified += 1;
    let delete = DeleteRequest {
        context: operation(&wave, "delete")?,
        target: target.clone(),
        mode: DeleteMode::StoppedOnly,
    };
    lifecycle::call("public soak delete", client.delete(delete.clone())).await?;
    lifecycle::call("public soak replayed delete", client.delete(delete)).await?;
    evidence.delete_replays_verified += 1;
    if !lifecycle::state_is_missing(client, target.clone()).await? {
        return Err(format!(
            "public soak wave {iteration} retained deleted state"
        ));
    }

    let processes_reaped = host::wait_for_processes_reaped(&vm_processes).await?;
    evidence.vm_processes_reaped_every_iteration &= processes_reaped;
    let endpoints_restored = host::wait_for_endpoint_inventory(endpoint_baseline).await?;
    evidence.endpoint_inventory_restored_every_iteration &= endpoints_restored;
    let descriptors_restored =
        host::wait_for_descriptor_inventory(service_pid, descriptor_baseline).await?;
    evidence.descriptor_inventory_stable_every_iteration &= descriptors_restored;
    let inventory = cleanup::inventory(runtime_root)?;
    let transients_clean = inventory.bundle_handoffs_clean
        && inventory.runtime_shares_clean
        && inventory.recovery_reports_clean;
    evidence.transients_clean_every_iteration &= transients_clean;
    if !processes_reaped || !endpoints_restored || !descriptors_restored || !transients_clean {
        return Err(format!(
            "public soak wave {iteration} did not restore cleanup baselines"
        ));
    }
    evidence.completed_iterations += 1;
    evidence.completed_vm_generations += 1;
    *previous_target = Some(target);
    Ok(())
}

async fn stale_target_rejected(
    client: &RuntimeClient,
    target: &ContainerTarget,
) -> Result<bool, String> {
    match timeout(
        CALL_TIMEOUT,
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if matches!(error.code, ErrorCode::NotFound | ErrorCode::Conflict) => {
            Ok(true)
        }
        Ok(Err(error)) => Err(format!(
            "stale public soak state failed unexpectedly: {error}"
        )),
        Ok(Ok(_)) => Ok(false),
        Err(_) => Err("stale public soak state timed out".into()),
    }
}

fn operation(nonce: &str, suffix: &str) -> Result<OperationContext, String> {
    OperationId::new(format!("hvf-soak-{nonce}-{suffix}"))
        .map(OperationContext::new)
        .map_err(|error| format!("failed to construct public soak operation ID: {error}"))
}
