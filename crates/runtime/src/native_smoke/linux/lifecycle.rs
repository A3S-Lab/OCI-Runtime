use std::future::Future;
use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, LinuxResources, State};
use a3s_oci_sdk::{
    ContainerId, ContainerOperationRequest, ContainerTarget, CreateAttachments, CreateRequest,
    DeleteMode, DeleteRequest, Error, ErrorCode, EventsRequest, ExitStatus, IsolationRequest,
    KillRequest, ListRequest, OciBundle, OciRuntimeService, OperationContext, OperationId,
    ProcessIo, ProcessTarget, ProcessesRequest, RuntimeClient, RuntimeEventKind, Signal,
    StartRequest, StateRequest, StatsRequest, UpdateRequest, WaitRequest,
};
use tokio::time::{sleep, timeout, Instant};

use super::control_descriptors::ControlDescriptorFixture;
use super::filesystem::{path_exists, read_marker, MARKER_CONTENTS};
use super::process;
use crate::marker::{exact_marker_state, ExactMarkerState};
use crate::{
    FaultInjectionEvidence, HostRuntimeService, LifecycleFaultPoint, NativeLinuxSmokeReport,
};

const CALL_TIMEOUT: Duration = Duration::from_secs(15);
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const FREEZER_OBSERVATION_DELAY: Duration = Duration::from_millis(1_250);
const PROGRESS_PATH: &str = "/.a3s-oci-native-smoke";
pub(super) const HOOK_TRACE_NAME: &str = ".a3s-oci-hook-trace";
const UPDATED_MEMORY_LIMIT: u64 = 512 * 1024 * 1024;

struct ExerciseInput<'a> {
    bundle: &'a OciBundle,
    nonce: &'a str,
    marker: &'a Path,
    hook_trace: &'a Path,
}

pub(super) async fn exercise(
    service: &HostRuntimeService,
    bundle: &OciBundle,
    nonce: &str,
    marker: &Path,
    hook_trace: &Path,
    control_descriptors: &mut ControlDescriptorFixture,
    report: &mut NativeLinuxSmokeReport,
) -> Result<(), String> {
    let client = RuntimeClient::new(service.clone());
    exercise_client(
        &client,
        Some(service),
        ExerciseInput {
            bundle,
            nonce,
            marker,
            hook_trace,
        },
        control_descriptors,
        report,
    )
    .await
}

pub(super) async fn exercise_bound_service(
    client: &RuntimeClient,
    bundle: &OciBundle,
    nonce: &str,
    marker: &Path,
    hook_trace: &Path,
    control_descriptors: &mut ControlDescriptorFixture,
    report: &mut NativeLinuxSmokeReport,
) -> Result<(), String> {
    exercise_client(
        client,
        None,
        ExerciseInput {
            bundle,
            nonce,
            marker,
            hook_trace,
        },
        control_descriptors,
        report,
    )
    .await
}

async fn exercise_client(
    client: &RuntimeClient,
    direct_service: Option<&HostRuntimeService>,
    input: ExerciseInput<'_>,
    control_descriptors: &mut ControlDescriptorFixture,
    report: &mut NativeLinuxSmokeReport,
) -> Result<(), String> {
    let ExerciseInput {
        bundle,
        nonce,
        marker,
        hook_trace,
    } = input;
    let features = native_call("features", client.features()).await?;
    report.service_operations = features.operations;
    report.hook_phases = features.oci.hooks().clone().unwrap_or_default();

    let id = ContainerId::new(format!("native-{nonce}"))
        .map_err(|error| format!("failed to construct native smoke container ID: {error}"))?;
    let create = CreateRequest {
        context: operation(nonce, "create")?,
        id: id.clone(),
        bundle: bundle.clone(),
        isolation: IsolationRequest::SharedHostKernel,
        attachments: CreateAttachments::from_bundle(
            bundle,
            ProcessIo {
                stdin: a3s_oci_sdk::IoMode::Null,
                stdout: a3s_oci_sdk::IoMode::Null,
                stderr: a3s_oci_sdk::IoMode::Null,
                terminal_size: None,
            },
        )
        .map_err(|error| format!("failed to derive native create attachments: {error}"))?,
    };
    let mut dedicated = create.clone();
    dedicated.isolation = IsolationRequest::DedicatedVm;
    report.dedicated_vm_rejected_before_create =
        dedicated_vm_is_rejected(client, dedicated).await?;
    if !report.dedicated_vm_rejected_before_create {
        return Err("native runtime accepted dedicated-VM isolation".into());
    }

    let (created, replayed) = if let Some(service) = direct_service {
        let descriptors = control_descriptors.take_descriptors()?;
        let created = native_call(
            "create with native control descriptors",
            service.create_with_native_control_descriptors(create.clone(), descriptors.clone()),
        )
        .await?;
        let replayed = native_call(
            "replayed create with native control descriptors",
            service.create_with_native_control_descriptors(create.clone(), descriptors),
        )
        .await?;
        (created, replayed)
    } else {
        let created = native_call(
            "create over native service transport",
            client.create(create.clone()),
        )
        .await?;
        let replayed = native_call(
            "replayed create over native service transport",
            client.create(create.clone()),
        )
        .await?;
        (created, replayed)
    };
    report.create_returned_created = *created.state.status() == ContainerState::Created;
    report.created_pid = *created.state.pid();
    if !report.create_returned_created {
        return Err("native create did not preserve the OCI created barrier".into());
    }
    let target = ContainerTarget::exact(id, created.generation);
    let observed = native_call(
        "state after create",
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await?;
    if observed != created {
        return Err("native state after create did not match the created response".into());
    }
    report.create_replayed = replayed == created;
    if !report.create_replayed {
        return Err("native runtime did not exactly replay create".into());
    }
    report.create_without_control_descriptors_rejected = match direct_service {
        Some(service) => create_without_descriptors_is_rejected(service, create).await?,
        None => bound_service_rejects_other_container(client, create, nonce).await?,
    };
    if !report.create_without_control_descriptors_rejected {
        return Err("descriptor-bearing create replayed without its logical schema".into());
    }
    let listed = native_call("list after create", client.list(ListRequest::default())).await?;
    let filtered = native_call(
        "filtered list after create",
        client.list(ListRequest {
            isolation: Some(a3s_oci_sdk::IsolationClass::SharedHostKernel),
        }),
    )
    .await?;
    let excluded = native_call(
        "excluded list after create",
        client.list(ListRequest {
            isolation: Some(a3s_oci_sdk::IsolationClass::DedicatedVm),
        }),
    )
    .await?;
    report.list_visible_after_create =
        listed == [created.clone()] && filtered == [created.clone()] && excluded.is_empty();
    if !report.list_visible_after_create {
        return Err("native durable list did not return the exact created container".into());
    }
    report.marker_absent_after_create = !path_exists(marker).await?;
    if !report.marker_absent_after_create {
        return Err("native workload ran before OCI start".into());
    }

    let started = native_call(
        "start",
        client.start(StartRequest {
            context: operation(nonce, "start")?,
            target: target.clone(),
        }),
    )
    .await?;
    report.start_released = *started.state.status() == ContainerState::Running;
    if !report.start_released {
        return Err("native start did not leave the workload running".into());
    }
    wait_for_marker(client, &target, marker, report).await?;
    control_descriptors.verify_listeners().await?;
    report.control_listener_connectivity_verified = true;
    control_descriptors.verify_init_log().await?;
    report.control_init_log_verified = true;
    process::exercise_process_io(client, &target, nonce).await?;
    report.process_io_verified = true;
    process::exercise_terminal_io(client, &target, nonce).await?;
    report.terminal_io_verified = true;
    crate::filesystem_smoke::exercise_runtime(client, &target, nonce).await?;
    report.file_transfer_verified = true;
    report.filesystem_operations_verified = true;
    let cleanup_process =
        process::exercise_before_init_exit(client, &target, nonce, PROGRESS_PATH).await?;
    exercise_control_plane(client, &target, &cleanup_process, nonce, marker, report).await?;
    report.wait_timeout_enforced = wait_times_out_while_running(client, &target).await?;
    if !report.wait_timeout_enforced {
        return Err("native wait returned before the running init process exited".into());
    }

    let kill = KillRequest {
        context: operation(nonce, "kill")?,
        target: target.clone(),
        // Use an uncatchable signal to prove that the retained workload pidfd
        // and both internal supervisors preserve an exact signal result.
        signal: Signal::new(libc::SIGKILL)
            .map_err(|error| format!("failed to construct native smoke signal: {error}"))?,
        all: false,
    };
    let killed = native_call("kill", client.kill(kill.clone())).await?;
    report.kill_delivered = matches!(
        *killed.state.status(),
        ContainerState::Running | ContainerState::Stopped
    );
    if !report.kill_delivered {
        return Err("native kill returned an unexpected lifecycle state".into());
    }
    let replayed_kill = native_call("replayed kill", client.kill(kill)).await?;
    report.kill_replayed = replayed_kill == killed;
    if !report.kill_replayed {
        return Err("native runtime did not exactly replay kill".into());
    }
    let wait = WaitRequest {
        target: target.clone(),
        timeout_ms: Some(
            u64::try_from(LIFECYCLE_TIMEOUT.as_millis())
                .map_err(|_| "native lifecycle timeout does not fit wait request".to_string())?,
        ),
    };
    let waited = native_call("wait", client.wait(wait.clone())).await?;
    let expected_exit = ExitStatus::signaled(libc::SIGKILL, false)
        .map_err(|error| format!("failed to construct expected native exit status: {error}"))?;
    report.wait_exit_status = Some(waited.clone());
    if waited != expected_exit {
        return Err(format!(
            "native wait returned {waited:?}, expected {expected_exit:?}"
        ));
    }
    let replayed_wait = native_call("repeated wait", client.wait(wait)).await?;
    report.wait_replayed = replayed_wait == waited;
    if !report.wait_replayed {
        return Err("native repeated wait returned a different exit status".into());
    }
    process::verify_after_init_exit(client, &target, cleanup_process, &waited).await?;
    report.stopped_observed = wait_until_stopped(client, &target).await?;

    let delete = DeleteRequest {
        context: operation(nonce, "delete")?,
        target: target.clone(),
        mode: DeleteMode::StoppedOnly,
    };
    native_call("delete", client.delete(delete.clone())).await?;
    report.delete_succeeded = true;
    native_call("replayed delete", client.delete(delete)).await?;
    report.delete_replayed = true;
    report.events_verified = verify_runtime_events(client, &target).await?;
    if !report.events_verified {
        return Err("native durable runtime events were incomplete or out of order".into());
    }
    report.hooks_verified =
        verify_hook_trace(hook_trace, bundle, target.id.as_str(), report.created_pid).await?;
    if !report.hooks_verified {
        return Err("native OCI hooks did not preserve exact order and state".into());
    }
    report.state_missing_after_delete = state_is_missing(client, target).await?;
    if !report.state_missing_after_delete {
        return Err("native state remained visible after delete".into());
    }
    report.list_empty_after_delete =
        native_call("list after delete", client.list(ListRequest::default()))
            .await?
            .is_empty();
    if !report.list_empty_after_delete {
        return Err("native durable list retained a deleted container".into());
    }
    if direct_service.is_some() {
        control_descriptors.verify_closed().await?;
        report.control_descriptors_closed_after_delete = true;
    }
    Ok(())
}

pub(crate) async fn verify_runtime_events(
    client: &RuntimeClient,
    target: &ContainerTarget,
) -> Result<bool, String> {
    let batch = native_call(
        "runtime events",
        client.events(EventsRequest {
            container: Some(target.clone()),
            after_sequence: 0,
            limit: a3s_oci_sdk::MAX_EVENT_BATCH_ITEMS,
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
    if created == 0 || created != started || exited < created + 1 {
        return Ok(false);
    }

    let tail = native_call(
        "runtime event cursor tail",
        client.events(EventsRequest {
            container: Some(target.clone()),
            after_sequence: batch.next_sequence,
            limit: 1,
            wait_timeout_ms: None,
        }),
    )
    .await?;
    Ok(tail.events.is_empty() && tail.next_sequence == batch.next_sequence)
}

async fn create_without_descriptors_is_rejected(
    service: &HostRuntimeService,
    request: CreateRequest,
) -> Result<bool, String> {
    match service.create(request).await {
        Err(error) if error.code == ErrorCode::FailedPrecondition => Ok(true),
        Err(error) => Err(native_error(
            "retry descriptor-bearing create without descriptors",
            &error,
        )),
        Ok(_) => Ok(false),
    }
}

async fn bound_service_rejects_other_container(
    client: &RuntimeClient,
    mut request: CreateRequest,
    nonce: &str,
) -> Result<bool, String> {
    request.id = ContainerId::new(format!("native-other-{nonce}"))
        .map_err(|error| format!("failed to construct alternate container ID: {error}"))?;
    request.context = operation(nonce, "create-other")?;
    match client.create(request).await {
        Err(error) if error.code == ErrorCode::PermissionDenied => Ok(true),
        Err(error) => Err(native_error(
            "create a second bound-service container",
            &error,
        )),
        Ok(_) => Ok(false),
    }
}

async fn verify_hook_trace(
    path: &Path,
    bundle: &OciBundle,
    container_id: &str,
    pid: Option<i32>,
) -> Result<bool, String> {
    let pid = pid.ok_or_else(|| "native hook verification requires the created PID".to_string())?;
    let trace = tokio::fs::read_to_string(path).await.map_err(|error| {
        format!(
            "failed to read native OCI hook trace {}: {error}",
            path.display()
        )
    })?;
    let expected = [
        ("prestart", ContainerState::Creating, Some(pid)),
        ("createRuntime", ContainerState::Creating, Some(pid)),
        ("createContainer", ContainerState::Creating, Some(pid)),
        ("startContainer", ContainerState::Created, Some(pid)),
        ("poststart", ContainerState::Running, Some(pid)),
        ("poststop", ContainerState::Stopped, None),
    ];
    let lines = trace.lines().collect::<Vec<_>>();
    if lines.len() != expected.len() {
        return Ok(false);
    }
    for (line, (phase, status, expected_pid)) in lines.iter().zip(expected) {
        let Some((actual_phase, encoded_state)) = line.split_once(' ') else {
            return Ok(false);
        };
        if actual_phase != phase {
            return Ok(false);
        }
        let state: State = serde_json::from_str(encoded_state)
            .map_err(|error| format!("native {phase} hook emitted invalid OCI state: {error}"))?;
        if state.version() != bundle.spec().version()
            || state.id() != container_id
            || *state.status() != status
            || *state.pid() != expected_pid
            || state.bundle() != bundle.directory()
            || state.annotations() != bundle.spec().annotations()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn exercise_control_plane(
    client: &RuntimeClient,
    target: &ContainerTarget,
    worker: &ProcessTarget,
    nonce: &str,
    marker: &Path,
    report: &mut NativeLinuxSmokeReport,
) -> Result<(), String> {
    wait_for_marker_change(marker, MARKER_CONTENTS).await?;
    let processes = native_call(
        "process inventory before pause",
        client.processes(ProcessesRequest {
            target: target.clone(),
        }),
    )
    .await?;
    report.processes_verified = process_inventory_is_exact(&processes, target, worker);
    if !report.processes_verified {
        return Err(
            "native process inventory did not contain exactly the live init and exec".into(),
        );
    }

    let update = UpdateRequest {
        context: operation(nonce, "update")?,
        target: target.clone(),
        resources: resource_profile()?,
    };
    let updated = native_call("update resources", client.update(update.clone())).await?;
    report.resources_updated = updated
        == native_call("replayed resource update", client.update(update)).await?
        && *updated.state.status() == ContainerState::Running
        && !updated.is_paused();
    if !report.resources_updated {
        return Err("native resource update was not exact or idempotent".into());
    }
    let first_stats = native_call(
        "resource stats",
        client.stats(StatsRequest {
            target: target.clone(),
        }),
    )
    .await?;
    let second_stats = native_call(
        "repeated resource stats",
        client.stats(StatsRequest {
            target: target.clone(),
        }),
    )
    .await?;
    report.stats_verified = resource_stats_are_exact(&first_stats, &second_stats, target);
    if !report.stats_verified {
        return Err("native resource stats did not match the updated cgroup".into());
    }

    let pause = ContainerOperationRequest {
        context: operation(nonce, "pause")?,
        target: target.clone(),
    };
    let paused = native_call("pause", client.pause(pause.clone())).await?;
    if !paused.is_paused()
        || native_call("replayed pause", client.pause(pause)).await? != paused
        || !native_call(
            "state while paused",
            client.state(StateRequest {
                target: target.clone(),
            }),
        )
        .await?
        .is_paused()
    {
        return Err("native pause did not expose an exact durable frozen state".into());
    }
    let paused_processes = native_call(
        "process inventory while paused",
        client.processes(ProcessesRequest {
            target: target.clone(),
        }),
    )
    .await?;
    if !process_inventory_is_exact(&paused_processes, target, worker) {
        return Err("native pause changed the live process inventory".into());
    }

    let frozen_progress = read_marker(marker).await?;
    sleep(FREEZER_OBSERVATION_DELAY).await;
    report.pause_froze_workload = read_marker(marker).await? == frozen_progress;
    if !report.pause_froze_workload {
        return Err("native workload advanced while its cgroup was frozen".into());
    }

    let resume = ContainerOperationRequest {
        context: operation(nonce, "resume")?,
        target: target.clone(),
    };
    let resumed = native_call("resume", client.resume(resume.clone())).await?;
    if resumed.is_paused()
        || native_call("replayed resume", client.resume(resume)).await? != resumed
        || native_call(
            "state after resume",
            client.state(StateRequest {
                target: target.clone(),
            }),
        )
        .await?
        .is_paused()
    {
        return Err("native resume did not expose an exact durable running state".into());
    }
    wait_for_marker_change(marker, &frozen_progress).await?;
    report.resume_advanced_workload = true;
    Ok(())
}

fn resource_profile() -> Result<LinuxResources, String> {
    serde_json::from_value(serde_json::json!({
        "memory": {
            "limit": UPDATED_MEMORY_LIMIT,
            "reservation": 64 * 1024 * 1024,
            "swap": 1024 * 1024 * 1024
        },
        "cpu": {
            "shares": 512,
            "quota": 50000,
            "period": 100000,
            "cpus": "0",
            "mems": "0"
        },
        "pids": {"limit": 64}
    }))
    .map_err(|error| format!("failed to construct native resource profile: {error}"))
}

fn resource_stats_are_exact(
    first: &a3s_oci_sdk::ContainerStats,
    second: &a3s_oci_sdk::ContainerStats,
    target: &ContainerTarget,
) -> bool {
    first.target == *target
        && second.target == *target
        && first.timestamp_unix_ns > 0
        && second.timestamp_unix_ns >= first.timestamp_unix_ns
        && first.cpu.usage_ns > 0
        && second.cpu.usage_ns >= first.cpu.usage_ns
        && first.memory.limit_bytes == Some(UPDATED_MEMORY_LIMIT)
        && second.memory.limit_bytes == Some(UPDATED_MEMORY_LIMIT)
        && first.memory.usage_bytes <= UPDATED_MEMORY_LIMIT
        && second.memory.usage_bytes <= UPDATED_MEMORY_LIMIT
        && first.process_count >= 2
        && second.process_count >= 2
        && first.metrics.contains_key("memory.events.oom_kill")
        && first.metrics.contains_key("pids.events.max")
        && second.metrics.contains_key("memory.events.oom_kill")
        && second.metrics.contains_key("pids.events.max")
}

fn process_inventory_is_exact(
    processes: &[a3s_oci_sdk::ProcessRecord],
    target: &ContainerTarget,
    worker: &ProcessTarget,
) -> bool {
    processes.len() == 2
        && processes.iter().all(|process| {
            process.target.container == *target
                && process.pid.is_some_and(|pid| pid > 0)
                && !process.terminal
        })
        && processes
            .iter()
            .any(|process| process.target.process_id.is_init())
        && processes.iter().any(|process| process.target == *worker)
}

async fn wait_for_marker_change(marker: &Path, previous: &[u8]) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        let current = read_marker(marker).await?;
        if current != previous {
            return Ok(current);
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for native workload progress".into());
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_times_out_while_running(
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
        Ok(Err(error)) => Err(native_error("bounded wait while running", &error)),
        Ok(Ok(status)) => Err(format!(
            "bounded wait returned {status:?} while the native workload was running"
        )),
        Err(_) => Err("bounded native wait exceeded its outer call timeout".into()),
    }
}

pub(super) async fn exercise_until_fault(
    client: &RuntimeClient,
    bundle: &OciBundle,
    nonce: &str,
    marker: &Path,
    evidence: &mut FaultInjectionEvidence,
) -> Result<Vec<a3s_oci_sdk::RuntimeOperation>, String> {
    let operations = native_call("features", client.features()).await?.operations;
    let id = ContainerId::new(format!("native-fault-{nonce}"))
        .map_err(|error| format!("failed to construct native fault container ID: {error}"))?;
    let create = CreateRequest {
        context: fault_operation(nonce, "create")?,
        id: id.clone(),
        bundle: bundle.clone(),
        isolation: IsolationRequest::SharedHostKernel,
        attachments: CreateAttachments::from_bundle(
            bundle,
            ProcessIo {
                stdin: a3s_oci_sdk::IoMode::Null,
                stdout: a3s_oci_sdk::IoMode::Null,
                stderr: a3s_oci_sdk::IoMode::Null,
                terminal_size: None,
            },
        )
        .map_err(|error| format!("failed to derive native fault attachments: {error}"))?,
    };
    let created = native_call("fault create", client.create(create)).await?;
    if *created.state.status() != ContainerState::Created {
        return Err("native fault create did not preserve the OCI created barrier".into());
    }
    evidence.create_completed = true;
    evidence.created_pid = *created.state.pid();
    let target = ContainerTarget::exact(id, created.generation);
    let observed = native_call(
        "fault state after create",
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await?;
    if observed != created {
        return Err("native fault state after create did not match create".into());
    }
    evidence.marker_absent_after_create = !path_exists(marker).await?;
    if !evidence.marker_absent_after_create {
        return Err("native fault workload ran before OCI start".into());
    }
    if evidence.requested_fault == LifecycleFaultPoint::AfterCreate {
        evidence.injected_fault = Some(LifecycleFaultPoint::AfterCreate);
        return Ok(operations);
    }

    let started = native_call(
        "fault start",
        client.start(StartRequest {
            context: fault_operation(nonce, "start")?,
            target: target.clone(),
        }),
    )
    .await?;
    if *started.state.status() != ContainerState::Running {
        return Err("native fault start did not leave the workload running".into());
    }
    evidence.start_completed = true;
    wait_for_exact_marker(client, &target, marker).await?;
    evidence.marker_verified_after_start = true;
    if evidence.requested_fault == LifecycleFaultPoint::AfterStart {
        evidence.injected_fault = Some(LifecycleFaultPoint::AfterStart);
        return Ok(operations);
    }

    let killed = native_call(
        "fault kill",
        client.kill(KillRequest {
            context: fault_operation(nonce, "kill")?,
            target,
            signal: Signal::new(libc::SIGKILL)
                .map_err(|error| format!("failed to construct native fault signal: {error}"))?,
            all: false,
        }),
    )
    .await?;
    if !matches!(
        *killed.state.status(),
        ContainerState::Running | ContainerState::Stopped
    ) {
        return Err("native fault kill returned an unexpected lifecycle state".into());
    }
    evidence.kill_completed = true;
    evidence.injected_fault = Some(LifecycleFaultPoint::AfterKill);
    Ok(operations)
}

async fn dedicated_vm_is_rejected(
    client: &RuntimeClient,
    request: CreateRequest,
) -> Result<bool, String> {
    match timeout(CALL_TIMEOUT, client.create(request)).await {
        Ok(Err(error)) if error.code == ErrorCode::Unsupported => Ok(true),
        Ok(Err(error)) => Err(native_error("dedicated-VM create", &error)),
        Ok(Ok(_)) => Ok(false),
        Err(_) => Err("dedicated-VM create timed out".into()),
    }
}

pub(super) async fn best_effort_delete(client: &RuntimeClient, nonce: &str) {
    let Ok(id) = ContainerId::new(format!("native-{nonce}")) else {
        return;
    };
    let Ok(context) = operation(nonce, "cleanup") else {
        return;
    };
    let _ = timeout(
        CALL_TIMEOUT,
        client.delete(DeleteRequest {
            context,
            target: ContainerTarget::current(id),
            mode: DeleteMode::Force,
        }),
    )
    .await;
}

async fn wait_for_marker(
    client: &RuntimeClient,
    target: &ContainerTarget,
    marker: &Path,
    report: &mut NativeLinuxSmokeReport,
) -> Result<(), String> {
    wait_for_exact_marker(client, target, marker).await?;
    report.running_observed = true;
    report.marker_verified = true;
    Ok(())
}

async fn wait_for_exact_marker(
    client: &RuntimeClient,
    target: &ContainerTarget,
    marker: &Path,
) -> Result<(), String> {
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        let state = native_call(
            "state while waiting for marker",
            client.state(StateRequest {
                target: target.clone(),
            }),
        )
        .await?;
        match *state.state.status() {
            ContainerState::Running => {}
            status => {
                return Err(format!(
                    "native runtime reported unexpected state {status} before kill"
                ));
            }
        }
        if path_exists(marker).await? {
            match exact_marker_state(&read_marker(marker).await?, MARKER_CONTENTS) {
                ExactMarkerState::Complete => return Ok(()),
                ExactMarkerState::InProgress => {}
                ExactMarkerState::Mismatch => {
                    return Err("native workload produced unexpected marker contents".into());
                }
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for native workload marker".into());
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_until_stopped(
    client: &RuntimeClient,
    target: &ContainerTarget,
) -> Result<bool, String> {
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        let state = native_call(
            "state while waiting for stop",
            client.state(StateRequest {
                target: target.clone(),
            }),
        )
        .await?;
        match *state.state.status() {
            ContainerState::Stopped => return Ok(true),
            ContainerState::Running if Instant::now() < deadline => sleep(POLL_INTERVAL).await,
            ContainerState::Running => {
                return Err("timed out waiting for native workload to stop".into());
            }
            status => {
                return Err(format!(
                    "native runtime reported unexpected state {status} after kill"
                ));
            }
        }
    }
}

async fn state_is_missing(client: &RuntimeClient, target: ContainerTarget) -> Result<bool, String> {
    match timeout(CALL_TIMEOUT, client.state(StateRequest { target })).await {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => Ok(true),
        Ok(Err(error)) => Err(native_error("state after delete", &error)),
        Ok(Ok(_)) => Ok(false),
        Err(_) => Err("native state after delete timed out".into()),
    }
}

async fn native_call<T>(
    operation: &str,
    future: impl Future<Output = a3s_oci_sdk::Result<T>>,
) -> Result<T, String> {
    match timeout(CALL_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(native_error(operation, &error)),
        Err(_) => Err(format!("{operation} timed out")),
    }
}

fn native_error(operation: &str, error: &Error) -> String {
    format!(
        "{operation} failed with {:?}: {}",
        error.code, error.message
    )
}

fn operation(nonce: &str, name: &str) -> Result<OperationContext, String> {
    let id = OperationId::new(format!("native-{nonce}-{name}"))
        .map_err(|error| format!("failed to construct {name} operation ID: {error}"))?;
    Ok(OperationContext::new(id))
}

fn fault_operation(nonce: &str, name: &str) -> Result<OperationContext, String> {
    let id = OperationId::new(format!("native-fault-{nonce}-{name}"))
        .map_err(|error| format!("failed to construct fault {name} operation ID: {error}"))?;
    Ok(OperationContext::new(id))
}
