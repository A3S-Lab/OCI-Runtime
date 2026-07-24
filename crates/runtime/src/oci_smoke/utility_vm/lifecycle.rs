use std::future::Future;
use std::path::Path;
use std::time::Duration;

use a3s_oci_agent_protocol::{
    AgentBundle, AgentClient, AgentCreateRequest, AgentDeleteRequest, AgentKillRequest,
    AgentStartRequest, AgentStateRequest, GuestPath,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, DeleteMode, Error, ErrorCode, IoMode, OciBundle, OperationContext,
    OperationId, ProcessIo, Signal,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{sleep, timeout, Instant};

use super::{path_exists, read_marker, OciVmSmokeReport};
use crate::{FaultInjectionEvidence, LifecycleFaultPoint};

const GUEST_CALL_TIMEOUT: Duration = Duration::from_secs(15);
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(15);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const LINUX_SIGTERM: i32 = 15;
const MARKER_CONTENTS: &[u8] = b"a3s-oci-create-start-v1\n";

pub(super) trait AgentStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AgentStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(super) async fn exercise<T: AgentStream>(
    client: &AgentClient<T>,
    bundle: &OciBundle,
    guest_bundle: GuestPath,
    target: &ContainerTarget,
    nonce: &str,
    marker: &Path,
    report: &mut OciVmSmokeReport,
) -> Result<(), String> {
    let create = AgentCreateRequest {
        context: operation(nonce, "create")?,
        target: target.clone(),
        bundle: AgentBundle::new(bundle, guest_bundle),
        io: null_io(),
    };
    let created = guest_call("create", client.create(create.clone())).await?;
    report.create_returned_created = created.status() == ContainerState::Created;
    report.created_pid = created.pid();
    if !report.create_returned_created {
        return Err("guest create did not preserve the OCI created barrier".into());
    }

    let observed = guest_call(
        "state after create",
        client.state(AgentStateRequest {
            target: target.clone(),
        }),
    )
    .await?;
    if observed != created {
        return Err("guest state after create did not match the created response".into());
    }
    let replayed = guest_call("replayed create", client.create(create)).await?;
    report.create_replayed = replayed == created;
    if !report.create_replayed {
        return Err("guest did not exactly replay the create result".into());
    }
    report.marker_absent_after_create = !path_exists(marker).await?;
    if !report.marker_absent_after_create {
        return Err("configured process ran before the OCI start request".into());
    }

    let started = guest_call(
        "start",
        client.start(AgentStartRequest {
            context: operation(nonce, "start")?,
            target: target.clone(),
            expected_config_digest: bundle.config_digest().to_string(),
        }),
    )
    .await?;
    report.start_released = started.status() == ContainerState::Running;
    if !report.start_released {
        return Err("guest start did not leave the fixed workload running".into());
    }

    wait_for_running_marker(client, target, marker, report).await?;

    let kill = AgentKillRequest {
        context: operation(nonce, "kill")?,
        target: target.clone(),
        signal: Signal::new(LINUX_SIGTERM)
            .map_err(|error| format!("invalid smoke signal: {error}"))?,
        all: false,
    };
    let killed = guest_call("kill", client.kill(kill.clone())).await?;
    report.kill_delivered = matches!(
        killed.status(),
        ContainerState::Running | ContainerState::Stopped
    );
    if !report.kill_delivered {
        return Err("guest kill returned an unexpected lifecycle state".into());
    }
    let replayed_kill = guest_call("replayed kill", client.kill(kill)).await?;
    report.kill_replayed = replayed_kill == killed;
    if !report.kill_replayed {
        return Err("guest did not exactly replay the kill result".into());
    }
    report.stopped_observed = wait_until_stopped(client, target).await?;

    let delete = AgentDeleteRequest {
        context: operation(nonce, "delete")?,
        target: target.clone(),
        mode: DeleteMode::StoppedOnly,
    };
    guest_call("delete", client.delete(delete.clone())).await?;
    report.delete_succeeded = true;
    guest_call("replayed delete", client.delete(delete)).await?;
    report.delete_replayed = true;
    report.state_missing_after_delete = state_is_missing(client, target).await?;
    if !report.state_missing_after_delete {
        return Err("guest state remained visible after delete".into());
    }
    Ok(())
}

pub(super) async fn exercise_until_fault<T: AgentStream>(
    client: &AgentClient<T>,
    bundle: &OciBundle,
    guest_bundle: GuestPath,
    target: &ContainerTarget,
    nonce: &str,
    marker: &Path,
    evidence: &mut FaultInjectionEvidence,
) -> Result<(), String> {
    let created = guest_call(
        "fault create",
        client.create(AgentCreateRequest {
            context: fault_operation(nonce, "create")?,
            target: target.clone(),
            bundle: AgentBundle::new(bundle, guest_bundle),
            io: null_io(),
        }),
    )
    .await?;
    if created.status() != ContainerState::Created {
        return Err("guest fault create did not preserve the OCI created barrier".into());
    }
    evidence.create_completed = true;
    evidence.created_pid = created.pid();
    let observed = guest_call(
        "fault state after create",
        client.state(AgentStateRequest {
            target: target.clone(),
        }),
    )
    .await?;
    if observed != created {
        return Err("guest fault state after create did not match create".into());
    }
    evidence.marker_absent_after_create = !path_exists(marker).await?;
    if !evidence.marker_absent_after_create {
        return Err("guest fault workload ran before OCI start".into());
    }
    if evidence.requested_fault == LifecycleFaultPoint::AfterCreate {
        evidence.injected_fault = Some(LifecycleFaultPoint::AfterCreate);
        return Ok(());
    }

    let started = guest_call(
        "fault start",
        client.start(AgentStartRequest {
            context: fault_operation(nonce, "start")?,
            target: target.clone(),
            expected_config_digest: bundle.config_digest().to_string(),
        }),
    )
    .await?;
    if started.status() != ContainerState::Running {
        return Err("guest fault start did not leave the workload running".into());
    }
    evidence.start_completed = true;
    wait_for_exact_marker(client, target, marker).await?;
    evidence.marker_verified_after_start = true;
    if evidence.requested_fault == LifecycleFaultPoint::AfterStart {
        evidence.injected_fault = Some(LifecycleFaultPoint::AfterStart);
        return Ok(());
    }

    let killed = guest_call(
        "fault kill",
        client.kill(AgentKillRequest {
            context: fault_operation(nonce, "kill")?,
            target: target.clone(),
            signal: Signal::new(LINUX_SIGTERM)
                .map_err(|error| format!("invalid fault cleanup signal: {error}"))?,
            all: false,
        }),
    )
    .await?;
    if !matches!(
        killed.status(),
        ContainerState::Running | ContainerState::Stopped
    ) {
        return Err("guest fault kill returned an unexpected lifecycle state".into());
    }
    evidence.kill_completed = true;
    evidence.injected_fault = Some(LifecycleFaultPoint::AfterKill);
    Ok(())
}

async fn wait_for_running_marker<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
    marker: &Path,
    report: &mut OciVmSmokeReport,
) -> Result<(), String> {
    wait_for_exact_marker(client, target, marker).await?;
    report.running_observed = true;
    report.marker_verified = true;
    Ok(())
}

async fn wait_for_exact_marker<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
    marker: &Path,
) -> Result<(), String> {
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        let state = guest_call(
            "state while waiting for running marker",
            client.state(AgentStateRequest {
                target: target.clone(),
            }),
        )
        .await?;
        match state.status() {
            ContainerState::Running => {}
            status => {
                return Err(format!(
                    "guest reported unexpected state {status} before kill"
                ));
            }
        }
        if path_exists(marker).await? {
            if read_marker(marker).await? == MARKER_CONTENTS {
                return Ok(());
            }
            return Err("configured process produced unexpected marker contents".into());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for the running workload marker".into());
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
            "state while waiting for stop",
            client.state(AgentStateRequest {
                target: target.clone(),
            }),
        )
        .await?;
        match state.status() {
            ContainerState::Stopped => return Ok(true),
            ContainerState::Running if Instant::now() < deadline => sleep(POLL_INTERVAL).await,
            ContainerState::Running => {
                return Err("timed out waiting for configured process to stop".into());
            }
            status => {
                return Err(format!(
                    "guest reported unexpected state {status} after start"
                ));
            }
        }
    }
}

async fn state_is_missing<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
) -> Result<bool, String> {
    match timeout(
        GUEST_CALL_TIMEOUT,
        client.state(AgentStateRequest {
            target: target.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => Ok(true),
        Ok(Err(error)) => Err(guest_error("state after delete", &error)),
        Ok(Ok(_)) => Ok(false),
        Err(_) => Err("state after delete timed out".into()),
    }
}

pub(super) async fn best_effort_delete<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
    nonce: &str,
) {
    let Ok(context) = operation(nonce, "cleanup") else {
        return;
    };
    let _ = timeout(
        CLEANUP_TIMEOUT,
        client.delete(AgentDeleteRequest {
            context,
            target: target.clone(),
            mode: DeleteMode::Force,
        }),
    )
    .await;
}

async fn guest_call<T>(
    operation: &str,
    future: impl Future<Output = a3s_oci_sdk::Result<T>>,
) -> Result<T, String> {
    match timeout(GUEST_CALL_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(guest_error(operation, &error)),
        Err(_) => Err(format!("{operation} timed out")),
    }
}

fn guest_error(operation: &str, error: &Error) -> String {
    format!(
        "{operation} failed with {:?}: {}",
        error.code, error.message
    )
}

fn operation(nonce: &str, name: &str) -> Result<OperationContext, String> {
    let id = OperationId::new(format!("smoke-{nonce}-{name}"))
        .map_err(|error| format!("failed to construct {name} operation ID: {error}"))?;
    Ok(OperationContext::new(id))
}

fn fault_operation(nonce: &str, name: &str) -> Result<OperationContext, String> {
    let id = OperationId::new(format!("fault-smoke-{nonce}-{name}"))
        .map_err(|error| format!("failed to construct fault {name} operation ID: {error}"))?;
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
