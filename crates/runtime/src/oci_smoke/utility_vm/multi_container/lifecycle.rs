use std::future::Future;
use std::path::Path;
use std::time::Duration;

use a3s_oci_agent_protocol::{
    AgentBundle, AgentClient, AgentCreateRequest, AgentDeleteRequest, AgentKillRequest,
    AgentStartRequest, AgentState, AgentStateRequest, GuestPath,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerId, ContainerTarget, DeleteMode, Error, ErrorCode, Generation, IoMode, OciBundle,
    OperationContext, OperationId, ProcessIo, Signal,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{sleep, timeout, Instant};

use super::super::{path_exists, read_marker, remove_marker};
use crate::OciVmMultiContainerSmokeReport;

const CALL_TIMEOUT: Duration = Duration::from_secs(15);
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const LINUX_SIGTERM: i32 = 15;
const MARKER_CONTENTS: &[u8] = b"a3s-oci-create-start-v1\n";

pub(super) trait AgentStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AgentStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(super) async fn exercise<T: AgentStream>(
    client: &AgentClient<T>,
    bundles: [&OciBundle; 2],
    guest_bundles: [GuestPath; 2],
    nonce: &str,
    markers: [&Path; 2],
    report: &mut OciVmMultiContainerSmokeReport,
) -> Result<(), String> {
    let target_a1 = target(nonce, "a", 1)?;
    let target_b = target(nonce, "b", 1)?;
    let create_a = create_request(
        nonce,
        "a-create-1",
        target_a1.clone(),
        bundles[0],
        guest_bundles[0].clone(),
    )?;
    let create_b = create_request(
        nonce,
        "b-create-1",
        target_b.clone(),
        bundles[1],
        guest_bundles[1].clone(),
    )?;

    let created_a = guest_call("create container A", client.create(create_a.clone())).await?;
    let replayed_a =
        guest_call("replay create container A", client.create(create_a.clone())).await?;
    let created_b = guest_call("create container B", client.create(create_b.clone())).await?;
    let replayed_b =
        guest_call("replay create container B", client.create(create_b.clone())).await?;
    report.lifecycle.create_replays_exact = replayed_a == created_a && replayed_b == created_b;
    require(
        report.lifecycle.create_replays_exact,
        "create replay changed a result",
    )?;
    require_created(&created_a, "container A")?;
    require_created(&created_b, "container B")?;
    report.lifecycle.initial_generation_a = Some(1);
    report.lifecycle.initial_generation_b = Some(1);
    report.lifecycle.created_pid_a = created_a.pid();
    report.lifecycle.created_pid_b = created_b.pid();
    report.lifecycle.distinct_created_pids = match (
        report.lifecycle.created_pid_a,
        report.lifecycle.created_pid_b,
    ) {
        (Some(a), Some(b)) => a > 0 && b > 0 && a != b,
        _ => false,
    };
    require(
        report.lifecycle.distinct_created_pids,
        "containers did not receive distinct positive PIDs",
    )?;
    assert_state(client, &target_a1, &created_a, "container A after create").await?;
    assert_state(client, &target_b, &created_b, "container B after create").await?;
    report.lifecycle.both_created_before_start = true;
    report.lifecycle.both_markers_absent_before_start =
        !path_exists(markers[0]).await? && !path_exists(markers[1]).await?;
    require(
        report.lifecycle.both_markers_absent_before_start,
        "a workload marker existed before either start",
    )?;

    let start_a = start_request(nonce, "a-start-1", target_a1.clone(), bundles[0])?;
    let started_a = guest_call("start container A", client.start(start_a.clone())).await?;
    require_running(&started_a, "container A")?;
    report.lifecycle.start_a_replayed =
        guest_call("replay start container A", client.start(start_a)).await? == started_a;
    require(
        report.lifecycle.start_a_replayed,
        "container A start replay changed its result",
    )?;
    wait_for_marker(client, &target_a1, markers[0]).await?;
    report.lifecycle.marker_a_verified = true;
    report.lifecycle.b_unchanged_after_a_start =
        state_equals(client, &target_b, &created_b, "container B after A start").await?;
    report.lifecycle.marker_b_absent_after_a_start = !path_exists(markers[1]).await?;
    require(
        report.lifecycle.b_unchanged_after_a_start
            && report.lifecycle.marker_b_absent_after_a_start,
        "starting container A changed container B",
    )?;

    let kill_a = kill_request(nonce, "a-kill-1", target_a1.clone())?;
    let killed_a = guest_call("kill container A", client.kill(kill_a.clone())).await?;
    require_kill_state(&killed_a, "container A")?;
    report.lifecycle.kill_a_replayed =
        guest_call("replay kill container A", client.kill(kill_a)).await? == killed_a;
    require(
        report.lifecycle.kill_a_replayed,
        "container A kill replay changed its result",
    )?;
    report.lifecycle.a_stopped = wait_until_stopped(client, &target_a1).await?;
    report.lifecycle.b_unchanged_after_a_kill =
        state_equals(client, &target_b, &created_b, "container B after A kill").await?;
    report.lifecycle.marker_b_absent_after_a_kill = !path_exists(markers[1]).await?;
    require(
        report.lifecycle.b_unchanged_after_a_kill && report.lifecycle.marker_b_absent_after_a_kill,
        "killing container A changed container B",
    )?;

    let delete_a1 = delete_request(
        nonce,
        "a-delete-1",
        target_a1.clone(),
        DeleteMode::StoppedOnly,
    )?;
    guest_call("delete container A", client.delete(delete_a1.clone())).await?;
    guest_call("replay delete container A", client.delete(delete_a1)).await?;
    report.lifecycle.delete_a_replayed = true;
    report.lifecycle.a_missing_after_delete =
        state_is_missing(client, &target_a1, "container A after delete").await?;
    report.lifecycle.b_unchanged_after_a_delete =
        state_equals(client, &target_b, &created_b, "container B after A delete").await?;
    require(
        report.lifecycle.a_missing_after_delete && report.lifecycle.b_unchanged_after_a_delete,
        "deleting container A changed retained state",
    )?;
    remove_marker(markers[0]).await?;

    let stale_create = create_request(
        nonce,
        "a-stale-create",
        target_a1.clone(),
        bundles[0],
        guest_bundles[0].clone(),
    )?;
    report.lifecycle.stale_generation_rejected =
        operation_conflicts(client.create(stale_create), "stale generation create").await?;
    require(
        report.lifecycle.stale_generation_rejected,
        "guest accepted a stale generation after delete",
    )?;

    let target_a2 = target(nonce, "a", 2)?;
    let recreate_a = create_request(
        nonce,
        "a-create-2",
        target_a2.clone(),
        bundles[0],
        guest_bundles[0].clone(),
    )?;
    let recreated_a = guest_call("recreate container A", client.create(recreate_a.clone())).await?;
    require_created(&recreated_a, "recreated container A")?;
    report.lifecycle.recreate_a_replayed =
        guest_call("replay recreate container A", client.create(recreate_a)).await? == recreated_a;
    report.lifecycle.recreated_generation_a = Some(2);
    report.lifecycle.generation_a_monotonic = true;
    report.lifecycle.marker_a_absent_after_recreate = !path_exists(markers[0]).await?;
    require(
        report.lifecycle.recreate_a_replayed && report.lifecycle.marker_a_absent_after_recreate,
        "container A recreation did not preserve its start barrier",
    )?;

    let mut cross_container_create = create_b.clone();
    cross_container_create.context = create_a.context;
    report.lifecycle.cross_container_operation_rejected = operation_conflicts(
        client.create(cross_container_create),
        "cross-container operation replay",
    )
    .await?;
    report.lifecycle.b_unchanged_after_replay_conflict = state_equals(
        client,
        &target_b,
        &created_b,
        "container B after replay conflict",
    )
    .await?;
    require(
        report.lifecycle.cross_container_operation_rejected
            && report.lifecycle.b_unchanged_after_replay_conflict,
        "cross-container operation replay mutated container B",
    )?;

    let delete_a2 = delete_request(nonce, "a-delete-2", target_a2.clone(), DeleteMode::Force)?;
    guest_call(
        "delete recreated container A",
        client.delete(delete_a2.clone()),
    )
    .await?;
    guest_call(
        "replay delete recreated container A",
        client.delete(delete_a2),
    )
    .await?;
    report.lifecycle.recreated_a_deleted =
        state_is_missing(client, &target_a2, "recreated container A").await?
            && state_equals(
                client,
                &target_b,
                &created_b,
                "container B after A recreate delete",
            )
            .await?;
    require(
        report.lifecycle.recreated_a_deleted,
        "deleting recreated container A changed container B",
    )?;

    let start_b = start_request(nonce, "b-start-1", target_b.clone(), bundles[1])?;
    let started_b = guest_call("start container B", client.start(start_b.clone())).await?;
    require_running(&started_b, "container B")?;
    report.lifecycle.start_b_replayed =
        guest_call("replay start container B", client.start(start_b)).await? == started_b;
    require(
        report.lifecycle.start_b_replayed,
        "container B start replay changed its result",
    )?;
    wait_for_marker(client, &target_b, markers[1]).await?;
    report.lifecycle.marker_b_verified = true;

    let kill_b = kill_request(nonce, "b-kill-1", target_b.clone())?;
    let killed_b = guest_call("kill container B", client.kill(kill_b.clone())).await?;
    require_kill_state(&killed_b, "container B")?;
    report.lifecycle.kill_b_replayed =
        guest_call("replay kill container B", client.kill(kill_b)).await? == killed_b;
    require(
        report.lifecycle.kill_b_replayed,
        "container B kill replay changed its result",
    )?;
    report.lifecycle.b_stopped = wait_until_stopped(client, &target_b).await?;

    let delete_b = delete_request(
        nonce,
        "b-delete-1",
        target_b.clone(),
        DeleteMode::StoppedOnly,
    )?;
    guest_call("delete container B", client.delete(delete_b.clone())).await?;
    guest_call("replay delete container B", client.delete(delete_b)).await?;
    report.lifecycle.delete_b_replayed = true;
    report.lifecycle.b_missing_after_delete =
        state_is_missing(client, &target_b, "container B after delete").await?;
    require(
        report.lifecycle.b_missing_after_delete,
        "container B remained visible after delete",
    )?;
    Ok(())
}

pub(super) async fn best_effort_delete<T: AgentStream>(client: &AgentClient<T>, nonce: &str) {
    for label in ["a", "b"] {
        let (Ok(generation_two), Ok(context)) = (
            target(nonce, label, 2),
            operation(nonce, &format!("{label}-cleanup")),
        ) else {
            continue;
        };
        let _ = timeout(
            CALL_TIMEOUT,
            client.delete(AgentDeleteRequest {
                context,
                target: generation_two,
                mode: DeleteMode::Force,
            }),
        )
        .await;
        let Ok(generation_one) = target(nonce, label, 1) else {
            continue;
        };
        let Ok(context) = operation(nonce, &format!("{label}-cleanup-1")) else {
            continue;
        };
        let _ = timeout(
            CALL_TIMEOUT,
            client.delete(AgentDeleteRequest {
                context,
                target: generation_one,
                mode: DeleteMode::Force,
            }),
        )
        .await;
    }
}

fn create_request(
    nonce: &str,
    operation_name: &str,
    target: ContainerTarget,
    bundle: &OciBundle,
    guest_bundle: GuestPath,
) -> Result<AgentCreateRequest, String> {
    Ok(AgentCreateRequest {
        context: operation(nonce, operation_name)?,
        target,
        bundle: AgentBundle::new(bundle, guest_bundle),
        io: null_io(),
    })
}

fn start_request(
    nonce: &str,
    operation_name: &str,
    target: ContainerTarget,
    bundle: &OciBundle,
) -> Result<AgentStartRequest, String> {
    Ok(AgentStartRequest {
        context: operation(nonce, operation_name)?,
        target,
        expected_config_digest: bundle.config_digest().to_string(),
    })
}

fn kill_request(
    nonce: &str,
    operation_name: &str,
    target: ContainerTarget,
) -> Result<AgentKillRequest, String> {
    Ok(AgentKillRequest {
        context: operation(nonce, operation_name)?,
        target,
        signal: Signal::new(LINUX_SIGTERM)
            .map_err(|error| format!("failed to construct multi-container signal: {error}"))?,
        all: false,
    })
}

fn delete_request(
    nonce: &str,
    operation_name: &str,
    target: ContainerTarget,
    mode: DeleteMode,
) -> Result<AgentDeleteRequest, String> {
    Ok(AgentDeleteRequest {
        context: operation(nonce, operation_name)?,
        target,
        mode,
    })
}

async fn assert_state<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
    expected: &AgentState,
    description: &str,
) -> Result<(), String> {
    require(
        state_equals(client, target, expected, description).await?,
        format!("{description} changed unexpectedly"),
    )
}

async fn state_equals<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
    expected: &AgentState,
    description: &str,
) -> Result<bool, String> {
    let observed = guest_call(
        description,
        client.state(AgentStateRequest {
            target: target.clone(),
        }),
    )
    .await?;
    Ok(&observed == expected)
}

async fn wait_for_marker<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
    marker: &Path,
) -> Result<(), String> {
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        let state = guest_call(
            "state while waiting for multi-container marker",
            client.state(AgentStateRequest {
                target: target.clone(),
            }),
        )
        .await?;
        require(
            state.status() == ContainerState::Running,
            format!(
                "guest reported {} while waiting for its marker",
                state.status()
            ),
        )?;
        if path_exists(marker).await? {
            return require(
                read_marker(marker).await? == MARKER_CONTENTS,
                "workload produced unexpected marker contents",
            );
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for multi-container workload marker".into());
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_until_stopped<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
) -> Result<bool, String> {
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        let state = guest_call(
            "state while waiting for multi-container stop",
            client.state(AgentStateRequest {
                target: target.clone(),
            }),
        )
        .await?;
        match state.status() {
            ContainerState::Stopped => return Ok(true),
            ContainerState::Running if Instant::now() < deadline => sleep(POLL_INTERVAL).await,
            ContainerState::Running => {
                return Err("timed out waiting for multi-container workload to stop".into());
            }
            status => {
                return Err(format!(
                    "guest reported unexpected state {status} after kill"
                ));
            }
        }
    }
}

async fn state_is_missing<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
    description: &str,
) -> Result<bool, String> {
    match timeout(
        CALL_TIMEOUT,
        client.state(AgentStateRequest {
            target: target.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => Ok(true),
        Ok(Err(error)) => Err(guest_error(description, &error)),
        Ok(Ok(_)) => Ok(false),
        Err(_) => Err(format!("{description} state timed out")),
    }
}

async fn operation_conflicts<T>(
    future: impl Future<Output = a3s_oci_sdk::Result<T>>,
    description: &str,
) -> Result<bool, String> {
    match timeout(CALL_TIMEOUT, future).await {
        Ok(Err(error))
            if matches!(
                error.code,
                ErrorCode::Conflict | ErrorCode::FailedPrecondition
            ) =>
        {
            Ok(true)
        }
        Ok(Err(error)) => Err(guest_error(description, &error)),
        Ok(Ok(_)) => Ok(false),
        Err(_) => Err(format!("{description} timed out")),
    }
}

async fn guest_call<T>(
    operation_name: &str,
    future: impl Future<Output = a3s_oci_sdk::Result<T>>,
) -> Result<T, String> {
    match timeout(CALL_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(guest_error(operation_name, &error)),
        Err(_) => Err(format!("{operation_name} timed out")),
    }
}

fn require_created(state: &AgentState, description: &str) -> Result<(), String> {
    require(
        state.status() == ContainerState::Created,
        format!("{description} did not preserve the created barrier"),
    )
}

fn require_running(state: &AgentState, description: &str) -> Result<(), String> {
    require(
        state.status() == ContainerState::Running,
        format!("{description} did not enter running"),
    )
}

fn require_kill_state(state: &AgentState, description: &str) -> Result<(), String> {
    require(
        matches!(
            state.status(),
            ContainerState::Running | ContainerState::Stopped
        ),
        format!("{description} kill returned {}", state.status()),
    )
}

fn require(condition: bool, message: impl Into<String>) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn target(nonce: &str, label: &str, generation: u64) -> Result<ContainerTarget, String> {
    let id = ContainerId::new(format!("smoke-multi-{label}-{nonce}"))
        .map_err(|error| format!("failed to construct container {label} ID: {error}"))?;
    Ok(ContainerTarget::exact(id, Generation(generation)))
}

fn operation(nonce: &str, name: &str) -> Result<OperationContext, String> {
    let id = OperationId::new(format!("smoke-multi-{nonce}-{name}"))
        .map_err(|error| format!("failed to construct {name} operation ID: {error}"))?;
    Ok(OperationContext::new(id))
}

fn null_io() -> ProcessIo {
    ProcessIo {
        stdin: IoMode::Null,
        stdout: IoMode::Null,
        stderr: IoMode::Null,
        terminal_size: None,
    }
}

fn guest_error(operation_name: &str, error: &Error) -> String {
    format!(
        "{operation_name} failed with {:?}: {}",
        error.code, error.message
    )
}
