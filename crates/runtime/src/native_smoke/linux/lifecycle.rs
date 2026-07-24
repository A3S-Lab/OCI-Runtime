use std::future::Future;
use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerId, ContainerTarget, CreateRequest, DeleteMode, DeleteRequest, Error, ErrorCode,
    IsolationRequest, KillRequest, OciBundle, OperationContext, OperationId, ProcessIo,
    RuntimeClient, Signal, StartRequest, StateRequest,
};
use tokio::time::{sleep, timeout, Instant};

use super::filesystem::{path_exists, read_marker, MARKER_CONTENTS};
use crate::NativeLinuxSmokeReport;

const CALL_TIMEOUT: Duration = Duration::from_secs(15);
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

pub(super) async fn exercise(
    client: &RuntimeClient,
    bundle: &OciBundle,
    nonce: &str,
    marker: &Path,
    report: &mut NativeLinuxSmokeReport,
) -> Result<(), String> {
    report.service_operations = native_call("features", client.features()).await?.operations;

    let id = ContainerId::new(format!("native-{nonce}"))
        .map_err(|error| format!("failed to construct native smoke container ID: {error}"))?;
    let create = CreateRequest {
        context: operation(nonce, "create")?,
        id: id.clone(),
        bundle: bundle.clone(),
        isolation: IsolationRequest::SharedHostKernel,
        io: ProcessIo {
            stdin: a3s_oci_sdk::IoMode::Null,
            stdout: a3s_oci_sdk::IoMode::Null,
            stderr: a3s_oci_sdk::IoMode::Null,
            terminal_size: None,
        },
    };
    let created = native_call("create", client.create(create.clone())).await?;
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
    let replayed = native_call("replayed create", client.create(create)).await?;
    report.create_replayed = replayed == created;
    if !report.create_replayed {
        return Err("native runtime did not exactly replay create".into());
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

    let kill = KillRequest {
        context: operation(nonce, "kill")?,
        target: target.clone(),
        signal: Signal::new(libc::SIGTERM)
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
    report.state_missing_after_delete = state_is_missing(client, target).await?;
    if !report.state_missing_after_delete {
        return Err("native state remained visible after delete".into());
    }
    Ok(())
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
            ContainerState::Running => report.running_observed = true,
            status => {
                return Err(format!(
                    "native runtime reported unexpected state {status} before kill"
                ));
            }
        }
        if path_exists(marker).await? {
            report.marker_verified = read_marker(marker).await? == MARKER_CONTENTS;
            if report.marker_verified {
                return Ok(());
            }
            return Err("native workload produced unexpected marker contents".into());
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
