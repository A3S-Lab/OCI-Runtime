use std::collections::BTreeSet;
use std::future::Future;
use std::path::Path;
use std::time::Duration;

use a3s_oci_core::HostPlatform;
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerId, ContainerOperationRequest, ContainerTarget, CreateRequest, DeleteMode,
    DeleteRequest, Error, ErrorCode, EventsRequest, ExitStatus, IsolationClass, IsolationRequest,
    KillRequest, ListRequest, OperationContext, OperationId, ProcessTarget, ProcessesRequest,
    RuntimeClient, RuntimeEventKind, RuntimeOperation, Signal, StartRequest, StateRequest,
    StatsRequest, UpdateRequest, WaitRequest, MAX_EVENT_BATCH_ITEMS,
    RUNTIME_BUNDLE_HANDOFF_EXTENSION, RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION,
};
use tokio::time::{sleep, timeout, Instant};

use super::bundle;
use super::report::MacosHvfPublicLifecycleEvidence;

const CALL_TIMEOUT: Duration = Duration::from_secs(20);
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const MARKER_CONTENTS: &[u8] = b"a3s-oci-create-start-user-time-v1\n";
const MARKER_PATH: &str = "/.a3s-oci-create-start-smoke";
const PROGRESS_PATH: &str = "/.a3s-oci-public-host-progress";

pub(super) struct LifecycleOutcome {
    pub(super) target: ContainerTarget,
    pub(super) vm_processes: Vec<super::report::MacosProcessIdentity>,
}

pub(super) async fn run(
    client: &RuntimeClient,
    source_bundle: &Path,
    runtime_root: &Path,
    host_pid: u32,
    nonce: &str,
    evidence: &mut MacosHvfPublicLifecycleEvidence,
) -> Result<LifecycleOutcome, String> {
    evidence.host_service_pid = Some(host_pid);
    verify_features(client, evidence).await?;
    record_operation(evidence, RuntimeOperation::Features);

    let id = ContainerId::new(format!("hvf-public-{nonce}"))
        .map_err(|error| format!("failed to construct lifecycle container ID: {error}"))?;
    let create_context = operation(nonce, "create")?;
    let staged = bundle::stage(
        source_bundle,
        runtime_root,
        &id,
        &create_context.operation_id,
    )
    .await?;
    evidence.bundle_handoff_staged = staged.directory.is_dir();
    let create = CreateRequest {
        context: create_context,
        id: id.clone(),
        bundle: staged.bundle,
        isolation: IsolationRequest::DedicatedVm,
        attachments: staged.attachments,
    };
    let created = call("public HVF create", client.create(create.clone())).await?;
    record_operation(evidence, RuntimeOperation::Create);
    evidence.create_returned_created = *created.state.status() == ContainerState::Created;
    if !evidence.create_returned_created {
        return Err("public HVF create did not preserve the OCI created barrier".into());
    }
    let target = ContainerTarget::exact(id, created.generation);
    evidence.bundle_handoff_consumed = !staged.directory.exists();
    let replayed = call("replayed public HVF create", client.create(create)).await?;
    evidence.create_replayed = replayed == created;
    if !evidence.create_replayed {
        return Err("public HVF create did not replay exactly".into());
    }

    evidence.state_exact_after_create = call(
        "public HVF state after create",
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await?
        == created;
    record_operation(evidence, RuntimeOperation::State);
    let listed = call(
        "public HVF list after create",
        client.list(ListRequest::default()),
    )
    .await?;
    let filtered = call(
        "filtered public HVF list after create",
        client.list(ListRequest {
            isolation: Some(IsolationClass::DedicatedVm),
        }),
    )
    .await?;
    record_operation(evidence, RuntimeOperation::List);
    evidence.list_exact_after_create = listed == [created.clone()] && filtered == [created.clone()];
    if !evidence.state_exact_after_create || !evidence.list_exact_after_create {
        return Err("public HVF state/list did not retain the exact created generation".into());
    }

    let vm_processes = wait_for_vm_descendants(host_pid).await?;
    let started = call(
        "public HVF start",
        client.start(StartRequest {
            context: operation(nonce, "start")?,
            target: target.clone(),
        }),
    )
    .await?;
    record_operation(evidence, RuntimeOperation::Start);
    evidence.start_returned_running = *started.state.status() == ContainerState::Running;
    if !evidence.start_returned_running {
        return Err("public HVF start did not return running".into());
    }
    wait_for_marker(client, &target).await?;
    evidence.init_marker_verified = true;

    crate::runtime_client_process_smoke::exercise_process_io(client, &target, nonce).await?;
    evidence.process_io_verified = true;
    evidence.exec_lifecycle_verified = true;
    evidence.wait_process_verified = true;
    evidence.read_output_verified = true;
    evidence.write_stdin_verified = true;
    evidence.close_stdin_verified = true;
    for operation in [
        RuntimeOperation::Exec,
        RuntimeOperation::WriteStdin,
        RuntimeOperation::CloseStdin,
        RuntimeOperation::WaitProcess,
        RuntimeOperation::ReadOutput,
    ] {
        record_operation(evidence, operation);
    }
    crate::runtime_client_process_smoke::exercise_terminal_io(client, &target, nonce).await?;
    evidence.terminal_io_verified = true;
    evidence.resize_verified = true;
    record_operation(evidence, RuntimeOperation::Resize);
    crate::filesystem_smoke::exercise_runtime(client, &target, nonce).await?;
    evidence.file_transfer_verified = true;
    evidence.filesystem_operations_verified = true;
    record_operation(evidence, RuntimeOperation::File);
    record_operation(evidence, RuntimeOperation::Filesystem);

    let worker = crate::runtime_client_process_smoke::exercise_before_init_exit(
        client,
        &target,
        nonce,
        PROGRESS_PATH,
    )
    .await?;
    evidence.signal_process_verified = true;
    record_operation(evidence, RuntimeOperation::SignalProcess);
    exercise_control_plane(client, &target, &worker, nonce, evidence).await?;
    evidence.wait_timeout_enforced = wait_times_out_while_running(client, &target).await?;
    record_operation(evidence, RuntimeOperation::Wait);
    if !evidence.wait_timeout_enforced {
        return Err("public HVF wait returned while init remained running".into());
    }

    let kill = KillRequest {
        context: operation(nonce, "kill")?,
        target: target.clone(),
        signal: Signal::new(libc::SIGKILL)
            .map_err(|error| format!("failed to construct lifecycle signal: {error}"))?,
        all: false,
    };
    let killed = call("public HVF kill", client.kill(kill.clone())).await?;
    record_operation(evidence, RuntimeOperation::Kill);
    evidence.kill_replayed = call("replayed public HVF kill", client.kill(kill)).await? == killed;
    let wait = WaitRequest {
        target: target.clone(),
        timeout_ms: Some(LIFECYCLE_TIMEOUT.as_millis() as u64),
    };
    let status = call("public HVF wait", client.wait(wait.clone())).await?;
    evidence.wait_status = Some(status.clone());
    evidence.wait_replayed = call("replayed public HVF wait", client.wait(wait)).await? == status;
    let expected = ExitStatus::signaled(libc::SIGKILL, false)
        .map_err(|error| format!("failed to construct expected init status: {error}"))?;
    if status != expected || !evidence.kill_replayed || !evidence.wait_replayed {
        return Err("public HVF kill/wait did not preserve exact replay and SIGKILL status".into());
    }
    crate::runtime_client_process_smoke::verify_after_init_exit(client, &target, worker, &status)
        .await?;

    let delete = DeleteRequest {
        context: operation(nonce, "delete")?,
        target: target.clone(),
        mode: DeleteMode::StoppedOnly,
    };
    call("public HVF delete", client.delete(delete.clone())).await?;
    call("replayed public HVF delete", client.delete(delete)).await?;
    record_operation(evidence, RuntimeOperation::Delete);
    evidence.delete_replayed = true;
    evidence.events_verified = verify_events(client, &target).await?;
    record_operation(evidence, RuntimeOperation::Events);
    evidence.state_removed = state_is_missing(client, target.clone()).await?;
    if !evidence.events_verified || !evidence.state_removed {
        return Err("public HVF delete did not retain events or remove exact state".into());
    }
    evidence.list_empty_after_delete = call(
        "public HVF list after delete",
        client.list(ListRequest::default()),
    )
    .await?
    .is_empty();
    if !super::host::wait_for_processes_reaped(&vm_processes).await? {
        return Err("first public HVF generation left a shim or worker process behind".into());
    }

    let recreate_context = operation(nonce, "recreate")?;
    let staged = bundle::stage(
        source_bundle,
        runtime_root,
        &target.id,
        &recreate_context.operation_id,
    )
    .await?;
    let recreated = call(
        "public HVF recreate",
        client.create(CreateRequest {
            context: recreate_context,
            id: target.id.clone(),
            bundle: staged.bundle,
            isolation: IsolationRequest::DedicatedVm,
            attachments: staged.attachments,
        }),
    )
    .await?;
    let recreated_processes = wait_for_vm_descendants(host_pid).await?;
    evidence.generation_monotonic = recreated.generation.0
        == target
            .generation
            .expect("lifecycle target is exact")
            .0
            .checked_add(1)
            .ok_or_else(|| "lifecycle generation overflowed".to_string())?;
    evidence.stale_generation_rejected = match timeout(
        CALL_TIMEOUT,
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if matches!(error.code, ErrorCode::NotFound | ErrorCode::Conflict) => true,
        Ok(Err(error)) => return Err(public_error("stale-generation state", &error)),
        Ok(Ok(_)) => false,
        Err(_) => return Err("stale-generation state timed out".into()),
    };
    let recreated_target = ContainerTarget::exact(target.id.clone(), recreated.generation);
    call(
        "delete recreated public HVF generation",
        client.delete(DeleteRequest {
            context: operation(nonce, "delete-recreated")?,
            target: recreated_target,
            mode: DeleteMode::Force,
        }),
    )
    .await?;
    evidence.recreated_generation_deleted = true;
    evidence.list_empty_after_delete &= call(
        "public HVF list after recreate delete",
        client.list(ListRequest::default()),
    )
    .await?
    .is_empty();
    if !super::host::wait_for_processes_reaped(&recreated_processes).await? {
        return Err("recreated public HVF generation left a shim or worker process behind".into());
    }
    let mut all_vm_processes = vm_processes;
    all_vm_processes.extend(recreated_processes);
    Ok(LifecycleOutcome {
        target,
        vm_processes: all_vm_processes,
    })
}

async fn verify_features(
    client: &RuntimeClient,
    evidence: &mut MacosHvfPublicLifecycleEvidence,
) -> Result<(), String> {
    let info = call("public HVF features", client.features()).await?;
    let expected = expected_operations();
    evidence.advertised_operations = info.operations.clone();
    evidence.features_verified = info.operations == expected
        && info.attachments.supports_extension(
            RUNTIME_BUNDLE_HANDOFF_EXTENSION,
            RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION,
        )
        && info.drivers.drivers.len() == 1
        && info.drivers.drivers[0].driver == a3s_oci_core::DriverKind::LibkrunHvf
        && info.drivers.drivers[0].isolation_classes == [IsolationClass::DedicatedVm];
    if !evidence.features_verified {
        return Err(
            "public HVF feature inventory did not match the fixed 23-operation contract".into(),
        );
    }
    Ok(())
}

fn expected_operations() -> Vec<RuntimeOperation> {
    let mut operations = crate::agent_driver::AGENT_DRIVER_OPERATIONS.to_vec();
    operations.extend([
        RuntimeOperation::Features,
        RuntimeOperation::List,
        RuntimeOperation::Events,
    ]);
    operations.sort();
    operations
}

async fn exercise_control_plane(
    client: &RuntimeClient,
    target: &ContainerTarget,
    worker: &ProcessTarget,
    nonce: &str,
    evidence: &mut MacosHvfPublicLifecycleEvidence,
) -> Result<(), String> {
    let processes = call(
        "public HVF process inventory",
        client.processes(ProcessesRequest {
            target: target.clone(),
        }),
    )
    .await?;
    evidence.process_inventory_verified =
        crate::oci_smoke::utility_vm::lifecycle::process_inventory_is_exact(
            &processes, target, worker,
        );
    record_operation(evidence, RuntimeOperation::Processes);
    if !evidence.process_inventory_verified {
        return Err("public HVF process inventory was not exact".into());
    }

    let update = UpdateRequest {
        context: operation(nonce, "update")?,
        target: target.clone(),
        resources: crate::oci_smoke::utility_vm::lifecycle::resource_profile(HostPlatform::Macos)?,
    };
    let updated = call("public HVF update", client.update(update.clone())).await?;
    evidence.resources_updated = call("replayed public HVF update", client.update(update)).await?
        == updated
        && *updated.state.status() == ContainerState::Running;
    record_operation(evidence, RuntimeOperation::Update);
    let first = call(
        "public HVF stats",
        client.stats(StatsRequest {
            target: target.clone(),
        }),
    )
    .await?;
    let second = call(
        "repeated public HVF stats",
        client.stats(StatsRequest {
            target: target.clone(),
        }),
    )
    .await?;
    evidence.stats_verified =
        crate::oci_smoke::utility_vm::lifecycle::resource_stats_are_exact(&first, &second, target);
    record_operation(evidence, RuntimeOperation::Stats);

    let pause = ContainerOperationRequest {
        context: operation(nonce, "pause")?,
        target: target.clone(),
    };
    let paused = call("public HVF pause", client.pause(pause.clone())).await?;
    evidence.pause_verified = paused.is_paused()
        && call("replayed public HVF pause", client.pause(pause)).await? == paused;
    record_operation(evidence, RuntimeOperation::Pause);
    let resume = ContainerOperationRequest {
        context: operation(nonce, "resume")?,
        target: target.clone(),
    };
    let resumed = call("public HVF resume", client.resume(resume.clone())).await?;
    evidence.resume_verified = !resumed.is_paused()
        && call("replayed public HVF resume", client.resume(resume)).await? == resumed;
    record_operation(evidence, RuntimeOperation::Resume);
    if !evidence.resources_updated
        || !evidence.stats_verified
        || !evidence.pause_verified
        || !evidence.resume_verified
    {
        return Err("public HVF control-plane operations were incomplete".into());
    }
    Ok(())
}

pub(super) async fn verify_events(
    client: &RuntimeClient,
    target: &ContainerTarget,
) -> Result<bool, String> {
    let batch = call(
        "public HVF events",
        client.events(EventsRequest {
            container: Some(target.clone()),
            after_sequence: 0,
            limit: MAX_EVENT_BATCH_ITEMS,
            wait_timeout_ms: None,
        }),
    )
    .await?;
    let events = &batch.events;
    if events.len() < 12
        || events.first().map(|event| event.kind) != Some(RuntimeEventKind::ContainerCreating)
        || events.get(1).map(|event| event.kind) != Some(RuntimeEventKind::ContainerCreated)
        || events.get(2).map(|event| event.kind) != Some(RuntimeEventKind::ContainerStarted)
        || events.last().map(|event| event.kind) != Some(RuntimeEventKind::ContainerDeleted)
        || events.iter().any(|event| event.container != *target)
        || events
            .windows(2)
            .any(|window| window[1].sequence != window[0].sequence + 1)
        || events.last().map(|event| event.sequence) != Some(batch.next_sequence)
    {
        return Ok(false);
    }
    for (kind, expected) in [
        (RuntimeEventKind::ContainerCreating, 1),
        (RuntimeEventKind::ContainerCreated, 1),
        (RuntimeEventKind::ContainerStarted, 1),
        (RuntimeEventKind::ContainerStopped, 1),
        (RuntimeEventKind::ContainerDeleted, 1),
        (RuntimeEventKind::ContainerPaused, 1),
        (RuntimeEventKind::ContainerResumed, 1),
        (RuntimeEventKind::ResourcesUpdated, 1),
    ] {
        if events.iter().filter(|event| event.kind == kind).count() != expected {
            return Ok(false);
        }
    }
    let created = events
        .iter()
        .filter(|event| event.kind == RuntimeEventKind::ProcessCreated)
        .count();
    let started = events
        .iter()
        .filter(|event| event.kind == RuntimeEventKind::ProcessStarted)
        .count();
    let exited = events
        .iter()
        .filter(|event| event.kind == RuntimeEventKind::ProcessExited)
        .count();
    Ok(created > 0 && created == started && exited > created)
}

pub(super) async fn wait_times_out_while_running(
    client: &RuntimeClient,
    target: &ContainerTarget,
) -> Result<bool, String> {
    match timeout(
        CALL_TIMEOUT,
        client.wait(WaitRequest {
            target: target.clone(),
            timeout_ms: Some(50),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::DeadlineExceeded => Ok(true),
        Ok(Err(error)) => Err(public_error("bounded public HVF wait", &error)),
        Ok(Ok(_)) => Ok(false),
        Err(_) => Err("bounded public HVF wait exceeded outer timeout".into()),
    }
}

pub(super) async fn state_is_missing(
    client: &RuntimeClient,
    target: ContainerTarget,
) -> Result<bool, String> {
    match timeout(CALL_TIMEOUT, client.state(StateRequest { target })).await {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => Ok(true),
        Ok(Err(error)) => Err(public_error("public HVF state after delete", &error)),
        Ok(Ok(_)) => Ok(false),
        Err(_) => Err("public HVF state after delete timed out".into()),
    }
}

pub(super) async fn wait_for_marker(
    client: &RuntimeClient,
    target: &ContainerTarget,
) -> Result<(), String> {
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        let state = call(
            "public HVF state while waiting for init marker",
            client.state(StateRequest {
                target: target.clone(),
            }),
        )
        .await?;
        if *state.state.status() != ContainerState::Running {
            return Err(format!(
                "public HVF generation left running before marker: {}",
                state.state.status()
            ));
        }
        match client
            .file(a3s_oci_sdk::FileRequest {
                target: target.clone(),
                op: a3s_oci_sdk::FileOp::Download,
                path: MARKER_PATH.to_string(),
                data: None,
                user: None,
                context: None,
            })
            .await
        {
            Ok(response) => {
                use base64::{engine::general_purpose::STANDARD, Engine as _};
                let decoded = response
                    .data
                    .as_deref()
                    .map(|value| STANDARD.decode(value))
                    .transpose()
                    .map_err(|error| format!("init marker was not valid base64: {error}"))?;
                if decoded.as_deref() == Some(MARKER_CONTENTS) {
                    return Ok(());
                }
                return Err("public HVF init marker contents were unexpected".into());
            }
            Err(error) if error.code == ErrorCode::NotFound => {}
            Err(error) => return Err(public_error("read public HVF init marker", &error)),
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for public HVF init marker".into());
        }
        sleep(POLL_INTERVAL).await;
    }
}

pub(super) async fn wait_for_vm_descendants(
    host_pid: u32,
) -> Result<Vec<super::report::MacosProcessIdentity>, String> {
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        let processes = super::host::process_descendants(host_pid)?;
        if processes.len() >= 2 {
            return Ok(processes);
        }
        if Instant::now() >= deadline {
            return Err("public Host Service did not expose shim and worker descendants".into());
        }
        sleep(POLL_INTERVAL).await;
    }
}

fn record_operation(evidence: &mut MacosHvfPublicLifecycleEvidence, operation: RuntimeOperation) {
    let mut operations = evidence
        .exercised_operations
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    operations.insert(operation);
    evidence.exercised_operations = operations.into_iter().collect();
}

pub(super) fn operation(nonce: &str, suffix: &str) -> Result<OperationContext, String> {
    OperationId::new(format!("hvf-public-{nonce}-{suffix}"))
        .map(OperationContext::new)
        .map_err(|error| format!("failed to construct public HVF operation ID: {error}"))
}

pub(super) async fn call<T>(
    label: &str,
    future: impl Future<Output = a3s_oci_sdk::Result<T>>,
) -> Result<T, String> {
    match timeout(CALL_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(public_error(label, &error)),
        Err(_) => Err(format!("{label} timed out")),
    }
}

fn public_error(label: &str, error: &Error) -> String {
    format!("{label} failed with {:?}: {}", error.code, error.message)
}

pub(super) async fn best_effort_delete(client: &RuntimeClient, id: &ContainerId, nonce: &str) {
    let Ok(context) = operation(nonce, "emergency-delete") else {
        return;
    };
    let _ = timeout(
        CALL_TIMEOUT,
        client.delete(DeleteRequest {
            context,
            target: ContainerTarget::current(id.clone()),
            mode: DeleteMode::Force,
        }),
    )
    .await;
}
