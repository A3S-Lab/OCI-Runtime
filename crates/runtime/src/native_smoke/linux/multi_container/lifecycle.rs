use std::future::Future;
use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerId, ContainerRecord, ContainerTarget, CreateAttachments, CreateRequest, DeleteMode,
    DeleteRequest, Error, ErrorCode, ExitStatus, IsolationRequest, KillRequest, OciBundle,
    OperationContext, OperationId, ProcessIo, RuntimeClient, Signal, StartRequest, StateRequest,
    WaitRequest,
};
use tokio::time::{sleep, timeout, Instant};

use super::super::filesystem::{path_exists, read_marker, remove_marker, MARKER_CONTENTS};
use crate::marker::{exact_marker_state, ExactMarkerState};
use crate::NativeLinuxMultiContainerSmokeReport;

const CALL_TIMEOUT: Duration = Duration::from_secs(15);
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

pub(super) async fn exercise(
    client: &RuntimeClient,
    bundles: [&OciBundle; 2],
    nonce: &str,
    markers: [&Path; 2],
    report: &mut NativeLinuxMultiContainerSmokeReport,
) -> Result<(), String> {
    report.service_operations = native_call("features", client.features()).await?.operations;

    let id_a = container_id(nonce, "a")?;
    let id_b = container_id(nonce, "b")?;
    let create_a = create_request(nonce, "a-create-1", id_a.clone(), bundles[0])?;
    let create_b = create_request(nonce, "b-create-1", id_b.clone(), bundles[1])?;

    let created_a = native_call("create container A", client.create(create_a.clone())).await?;
    let replayed_a =
        native_call("replay create container A", client.create(create_a.clone())).await?;
    let created_b = native_call("create container B", client.create(create_b.clone())).await?;
    let replayed_b =
        native_call("replay create container B", client.create(create_b.clone())).await?;
    report.lifecycle.create_replays_exact = replayed_a == created_a && replayed_b == created_b;
    require(
        report.lifecycle.create_replays_exact,
        "create replay changed a result",
    )?;

    require_created(&created_a, "container A")?;
    require_created(&created_b, "container B")?;
    let target_a1 = ContainerTarget::exact(id_a.clone(), created_a.generation);
    let target_b = ContainerTarget::exact(id_b.clone(), created_b.generation);
    report.lifecycle.initial_generation_a = Some(created_a.generation.0);
    report.lifecycle.initial_generation_b = Some(created_b.generation.0);
    report.lifecycle.created_pid_a = *created_a.state.pid();
    report.lifecycle.created_pid_b = *created_b.state.pid();
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

    let start_a = StartRequest {
        context: operation(nonce, "a-start-1")?,
        target: target_a1.clone(),
    };
    let started_a = native_call("start container A", client.start(start_a.clone())).await?;
    require_running(&started_a, "container A")?;
    let replayed_start_a = native_call("replay start container A", client.start(start_a)).await?;
    report.lifecycle.start_a_replayed = replayed_start_a == started_a;
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
    report.lifecycle.wait_a_did_not_block_b =
        wait_does_not_block_state(client, &target_a1, &target_b, &created_b).await?;
    require(
        report.lifecycle.wait_a_did_not_block_b,
        "waiting on running container A blocked container B state",
    )?;

    let kill_a = kill_request(nonce, "a-kill-1", target_a1.clone())?;
    let killed_a = native_call("kill container A", client.kill(kill_a.clone())).await?;
    require_kill_state(&killed_a, "container A")?;
    let replayed_kill_a = native_call("replay kill container A", client.kill(kill_a)).await?;
    report.lifecycle.kill_a_replayed = replayed_kill_a == killed_a;
    require(
        report.lifecycle.kill_a_replayed,
        "container A kill replay changed its result",
    )?;
    let waited_a = native_call(
        "wait for container A",
        client.wait(wait_request(target_a1.clone())),
    )
    .await?;
    let expected_exit = ExitStatus::signaled(libc::SIGKILL, false)
        .map_err(|error| format!("failed to construct expected native exit status: {error}"))?;
    require(
        waited_a == expected_exit,
        format!("container A wait returned {waited_a:?}, expected {expected_exit:?}"),
    )?;
    report.lifecycle.wait_status_a = Some(waited_a.clone());
    report.lifecycle.wait_a_replayed = native_call(
        "repeat wait for container A",
        client.wait(wait_request(target_a1.clone())),
    )
    .await?
        == waited_a;
    require(
        report.lifecycle.wait_a_replayed,
        "container A repeated wait changed its result",
    )?;
    report.lifecycle.a_stopped = wait_until_stopped(client, &target_a1).await?;
    report.lifecycle.b_unchanged_after_a_kill =
        state_equals(client, &target_b, &created_b, "container B after A kill").await?;
    report.lifecycle.marker_b_absent_after_a_kill = !path_exists(markers[1]).await?;
    require(
        report.lifecycle.b_unchanged_after_a_kill && report.lifecycle.marker_b_absent_after_a_kill,
        "killing container A changed container B",
    )?;

    let delete_a1 = DeleteRequest {
        context: operation(nonce, "a-delete-1")?,
        target: target_a1.clone(),
        mode: DeleteMode::StoppedOnly,
    };
    native_call("delete container A", client.delete(delete_a1.clone())).await?;
    native_call(
        "replay delete container A",
        client.delete(delete_a1.clone()),
    )
    .await?;
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

    let recreate_a = create_request(nonce, "a-create-2", id_a.clone(), bundles[0])?;
    let recreated_a =
        native_call("recreate container A", client.create(recreate_a.clone())).await?;
    require_created(&recreated_a, "recreated container A")?;
    let replayed_recreate_a =
        native_call("replay recreate container A", client.create(recreate_a)).await?;
    report.lifecycle.recreate_a_replayed = replayed_recreate_a == recreated_a;
    report.lifecycle.recreated_generation_a = Some(recreated_a.generation.0);
    report.lifecycle.generation_a_monotonic =
        recreated_a.generation.0 == created_a.generation.0 + 1;
    report.lifecycle.marker_a_absent_after_recreate = !path_exists(markers[0]).await?;
    require(
        report.lifecycle.recreate_a_replayed
            && report.lifecycle.generation_a_monotonic
            && report.lifecycle.marker_a_absent_after_recreate,
        "container A recreation did not preserve generation and start barriers",
    )?;
    let target_a2 = ContainerTarget::exact(id_a, recreated_a.generation);
    report.lifecycle.stale_generation_rejected = state_is_stale(client, &target_a1).await?;
    require(
        report.lifecycle.stale_generation_rejected,
        "container A stale generation remained usable after recreation",
    )?;

    let mut cross_container_create = create_b.clone();
    cross_container_create.context = create_a.context;
    report.lifecycle.cross_container_operation_rejected =
        operation_conflicts(client.create(cross_container_create)).await?;
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

    let delete_a2 = DeleteRequest {
        context: operation(nonce, "a-delete-2")?,
        target: target_a2.clone(),
        mode: DeleteMode::Force,
    };
    native_call(
        "delete recreated container A",
        client.delete(delete_a2.clone()),
    )
    .await?;
    native_call(
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

    let start_b = StartRequest {
        context: operation(nonce, "b-start-1")?,
        target: target_b.clone(),
    };
    let started_b = native_call("start container B", client.start(start_b.clone())).await?;
    require_running(&started_b, "container B")?;
    report.lifecycle.start_b_replayed =
        native_call("replay start container B", client.start(start_b)).await? == started_b;
    require(
        report.lifecycle.start_b_replayed,
        "container B start replay changed its result",
    )?;
    wait_for_marker(client, &target_b, markers[1]).await?;
    report.lifecycle.marker_b_verified = true;

    let kill_b = kill_request(nonce, "b-kill-1", target_b.clone())?;
    let killed_b = native_call("kill container B", client.kill(kill_b.clone())).await?;
    require_kill_state(&killed_b, "container B")?;
    report.lifecycle.kill_b_replayed =
        native_call("replay kill container B", client.kill(kill_b)).await? == killed_b;
    require(
        report.lifecycle.kill_b_replayed,
        "container B kill replay changed its result",
    )?;
    let waited_b = native_call(
        "wait for container B",
        client.wait(wait_request(target_b.clone())),
    )
    .await?;
    require(
        waited_b == expected_exit,
        format!("container B wait returned {waited_b:?}, expected {expected_exit:?}"),
    )?;
    report.lifecycle.wait_status_b = Some(waited_b.clone());
    report.lifecycle.wait_b_replayed = native_call(
        "repeat wait for container B",
        client.wait(wait_request(target_b.clone())),
    )
    .await?
        == waited_b;
    require(
        report.lifecycle.wait_b_replayed,
        "container B repeated wait changed its result",
    )?;
    report.lifecycle.b_stopped = wait_until_stopped(client, &target_b).await?;

    let delete_b = DeleteRequest {
        context: operation(nonce, "b-delete-1")?,
        target: target_b.clone(),
        mode: DeleteMode::StoppedOnly,
    };
    native_call("delete container B", client.delete(delete_b.clone())).await?;
    native_call("replay delete container B", client.delete(delete_b)).await?;
    report.lifecycle.delete_b_replayed = true;
    report.lifecycle.b_missing_after_delete =
        state_is_missing(client, &target_b, "container B after delete").await?;
    require(
        report.lifecycle.b_missing_after_delete,
        "container B remained visible after delete",
    )?;
    Ok(())
}

pub(super) fn wait_request(target: ContainerTarget) -> WaitRequest {
    WaitRequest {
        target,
        timeout_ms: Some(15_000),
    }
}

async fn wait_does_not_block_state(
    client: &RuntimeClient,
    waiting: &ContainerTarget,
    observed: &ContainerTarget,
    expected: &ContainerRecord,
) -> Result<bool, String> {
    let wait = client.wait(WaitRequest {
        target: waiting.clone(),
        timeout_ms: Some(300),
    });
    let state = async {
        sleep(Duration::from_millis(50)).await;
        timeout(
            Duration::from_millis(200),
            client.state(StateRequest {
                target: observed.clone(),
            }),
        )
        .await
    };
    let (wait_result, state_result) = tokio::join!(wait, state);
    let wait_timed_out =
        matches!(wait_result, Err(error) if error.code == ErrorCode::DeadlineExceeded);
    let state_unchanged = match state_result {
        Ok(Ok(record)) => &record == expected,
        Ok(Err(error)) => {
            return Err(native_error(
                "container B state during container A wait",
                &error,
            ));
        }
        Err(_) => false,
    };
    Ok(wait_timed_out && state_unchanged)
}

pub(super) async fn best_effort_delete(client: &RuntimeClient, nonce: &str) {
    for label in [
        "a",
        "b",
        "namespace-donor",
        "namespace-wrong-type",
        "namespace-non-mount",
        "namespace-mount",
        "network-host",
        "rootfs-enforcement",
        "volume-writer",
        "volume-reader",
        "volume-persist",
        "init-inline",
        "init-script",
        "init-direct",
        "init-nonzero",
        "hook-create-failure",
        "hook-start-failure",
        "hook-timeout",
        "hook-poststop",
    ] {
        let (Ok(id), Ok(context)) = (
            container_id(nonce, label),
            operation(nonce, &format!("{label}-cleanup")),
        ) else {
            continue;
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
}

pub(super) fn create_request(
    nonce: &str,
    operation_name: &str,
    id: ContainerId,
    bundle: &OciBundle,
) -> Result<CreateRequest, String> {
    Ok(CreateRequest {
        context: operation(nonce, operation_name)?,
        id,
        bundle: bundle.clone(),
        isolation: IsolationRequest::SharedHostKernel,
        attachments: CreateAttachments::from_bundle(bundle, null_io()).map_err(|error| {
            format!("failed to derive multi-container create attachments: {error}")
        })?,
    })
}

pub(super) fn kill_request(
    nonce: &str,
    operation_name: &str,
    target: ContainerTarget,
) -> Result<KillRequest, String> {
    Ok(KillRequest {
        context: operation(nonce, operation_name)?,
        target,
        signal: Signal::new(libc::SIGKILL)
            .map_err(|error| format!("failed to construct multi-container signal: {error}"))?,
        all: false,
    })
}

async fn assert_state(
    client: &RuntimeClient,
    target: &ContainerTarget,
    expected: &ContainerRecord,
    description: &str,
) -> Result<(), String> {
    require(
        state_equals(client, target, expected, description).await?,
        format!("{description} changed unexpectedly"),
    )
}

pub(super) async fn state_equals(
    client: &RuntimeClient,
    target: &ContainerTarget,
    expected: &ContainerRecord,
    description: &str,
) -> Result<bool, String> {
    let observed = native_call(
        description,
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await?;
    Ok(&observed == expected)
}

pub(super) async fn wait_for_marker(
    client: &RuntimeClient,
    target: &ContainerTarget,
    marker: &Path,
) -> Result<(), String> {
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        let state = native_call(
            "state while waiting for multi-container marker",
            client.state(StateRequest {
                target: target.clone(),
            }),
        )
        .await?;
        require(
            *state.state.status() == ContainerState::Running,
            format!(
                "container reported {} while waiting for its marker",
                state.state.status()
            ),
        )?;
        if path_exists(marker).await? {
            match exact_marker_state(&read_marker(marker).await?, MARKER_CONTENTS) {
                ExactMarkerState::Complete => return Ok(()),
                ExactMarkerState::InProgress => {}
                ExactMarkerState::Mismatch => {
                    return Err("workload produced unexpected marker contents".into());
                }
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for multi-container workload marker".into());
        }
        sleep(POLL_INTERVAL).await;
    }
}

pub(super) async fn wait_until_stopped(
    client: &RuntimeClient,
    target: &ContainerTarget,
) -> Result<bool, String> {
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        let state = native_call(
            "state while waiting for multi-container stop",
            client.state(StateRequest {
                target: target.clone(),
            }),
        )
        .await?;
        match *state.state.status() {
            ContainerState::Stopped => return Ok(true),
            ContainerState::Running if Instant::now() < deadline => sleep(POLL_INTERVAL).await,
            ContainerState::Running => {
                return Err("timed out waiting for multi-container workload to stop".into());
            }
            status => {
                return Err(format!(
                    "container reported unexpected state {status} after kill"
                ));
            }
        }
    }
}

pub(super) async fn state_is_missing(
    client: &RuntimeClient,
    target: &ContainerTarget,
    description: &str,
) -> Result<bool, String> {
    match timeout(
        CALL_TIMEOUT,
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => Ok(true),
        Ok(Err(error)) => Err(native_error(description, &error)),
        Ok(Ok(_)) => Ok(false),
        Err(_) => Err(format!("{description} state timed out")),
    }
}

async fn state_is_stale(client: &RuntimeClient, target: &ContainerTarget) -> Result<bool, String> {
    match timeout(
        CALL_TIMEOUT,
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if matches!(error.code, ErrorCode::Conflict) => Ok(true),
        Ok(Err(error)) => Err(native_error("stale generation state", &error)),
        Ok(Ok(_)) => Ok(false),
        Err(_) => Err("stale generation state timed out".into()),
    }
}

async fn operation_conflicts<T>(
    future: impl Future<Output = a3s_oci_sdk::Result<T>>,
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
        Ok(Err(error)) => Err(native_error("cross-container operation replay", &error)),
        Ok(Ok(_)) => Ok(false),
        Err(_) => Err("cross-container operation replay timed out".into()),
    }
}

pub(super) async fn native_call<T>(
    operation_name: &str,
    future: impl Future<Output = a3s_oci_sdk::Result<T>>,
) -> Result<T, String> {
    match timeout(CALL_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(native_error(operation_name, &error)),
        Err(_) => Err(format!("{operation_name} timed out")),
    }
}

pub(super) fn require_created(record: &ContainerRecord, description: &str) -> Result<(), String> {
    require(
        *record.state.status() == ContainerState::Created,
        format!("{description} did not preserve the created barrier"),
    )
}

pub(super) fn require_running(record: &ContainerRecord, description: &str) -> Result<(), String> {
    require(
        *record.state.status() == ContainerState::Running,
        format!("{description} did not enter running"),
    )
}

pub(super) fn require_kill_state(
    record: &ContainerRecord,
    description: &str,
) -> Result<(), String> {
    require(
        matches!(
            *record.state.status(),
            ContainerState::Running | ContainerState::Stopped
        ),
        format!("{description} kill returned {}", record.state.status()),
    )
}

pub(super) fn require(condition: bool, message: impl Into<String>) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

pub(super) fn container_id(nonce: &str, label: &str) -> Result<ContainerId, String> {
    ContainerId::new(format!("native-multi-{label}-{nonce}"))
        .map_err(|error| format!("failed to construct container {label} ID: {error}"))
}

pub(super) fn operation(nonce: &str, name: &str) -> Result<OperationContext, String> {
    let id = OperationId::new(format!("native-multi-{nonce}-{name}"))
        .map_err(|error| format!("failed to construct {name} operation ID: {error}"))?;
    Ok(OperationContext::new(id))
}

pub(super) fn null_io() -> ProcessIo {
    ProcessIo {
        stdin: a3s_oci_sdk::IoMode::Null,
        stdout: a3s_oci_sdk::IoMode::Null,
        stderr: a3s_oci_sdk::IoMode::Null,
        terminal_size: None,
    }
}

fn native_error(operation_name: &str, error: &Error) -> String {
    format!(
        "{operation_name} failed with {:?}: {}",
        error.code, error.message
    )
}
