use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::{
    ContainerTarget, Generation, OperationContext, ProcessTarget, Signal, SignalProcessRequest,
};
use serde::Deserialize;
use tokio::process::Child;
use tonic::transport::Channel;

use super::{
    launch_replacement_while_containerd_suspended, stop_replacement, Bootstrap,
    RehydratedTerminalExec,
};
use crate::faults;
use crate::support::{
    containerd_main_pid, qualification_error, read_runtime_identity, restart_containerd,
    task_process, TestResult, STATUS_RUNNING,
};

const EXEC_ID: &str = "rehydrated-terminal-exec";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingSignalEvidence {
    sequence: u64,
    signal: Signal,
    all: bool,
}

#[derive(Debug)]
struct SignalJournalEvidence {
    schema_version: u64,
    completed_sequence: u64,
    pending: Option<PendingSignalEvidence>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn qualify(
    config: &crate::support::QualificationConfig,
    id: &str,
    bundle: &Path,
    binary: &Path,
    bootstrap: &Bootstrap,
    identity: &crate::support::RuntimeIdentity,
    exec: &RehydratedTerminalExec,
    mut old_replacement: Child,
) -> TestResult<(Channel, Child)> {
    let baseline = read_exec_signal_journal(bundle, EXEC_ID).await?;
    if baseline.schema_version != 9
        || baseline.completed_sequence != 0
        || baseline.pending.is_some()
    {
        return Err(qualification_error(format!(
            "exec signal journal before committed replacement was {baseline:?}; expected schema 9, sequence 0, and no pending signal"
        ))
        .into());
    }

    let pending_sequence = 1;
    let old_shim_pid = old_replacement
        .id()
        .ok_or_else(|| qualification_error("committed-signal shim has no PID"))?;
    let host_pid = faults::find_runtime_host_pid(config).await?;
    let mut suspended_host =
        faults::SuspendedProcess::stop(host_pid, "committed-signal A3S OCI host service")?;
    let signal_address = bootstrap.address.clone();
    let signal_id = id.to_string();
    let mut signal_call =
        tokio::spawn(async move { shim_signal(&signal_address, &signal_id, libc::SIGSTOP).await });

    wait_for_pending_signal(
        bundle,
        baseline.completed_sequence,
        pending_sequence,
        libc::SIGSTOP,
        &mut signal_call,
    )
    .await?;
    let suspended_shim =
        faults::SuspendedProcess::stop(old_shim_pid, "committed-signal original shim")?;
    suspended_host.resume("committed-signal A3S OCI host service")?;
    commit_runtime_exec_signal(config, id, identity, pending_sequence, libc::SIGSTOP).await?;

    let containerd_pid = containerd_main_pid(config).await?;
    faults::send_signal(containerd_pid, libc::SIGSTOP, "committed-signal containerd")?;
    let mut replacement = None;
    let relaunch = async {
        suspended_shim.kill("committed-signal original shim")?;
        wait_for_killed_child(&mut old_replacement, "committed-signal original shim").await?;
        launch_replacement_while_containerd_suspended(
            config,
            id,
            bundle,
            binary,
            bootstrap,
            containerd_pid,
            &mut replacement,
        )
        .await
    }
    .await;
    let _ = faults::send_signal(containerd_pid, libc::SIGCONT, "committed-signal containerd");
    if let Err(error) = relaunch {
        signal_call.abort();
        let _ = signal_call.await;
        let _ = old_replacement.start_kill();
        let _ = old_replacement.wait().await;
        stop_replacement(&mut replacement).await;
        let recovery = restart_containerd(config, "failed-committed-signal-rehydration").await;
        return match recovery {
            Ok(_) => Err(error),
            Err(recovery_error) => Err(qualification_error(format!(
                "committed process signal replacement failed: {error}; containerd recovery also failed: {recovery_error}"
            ))
            .into()),
        };
    }

    let replacement = replacement.ok_or_else(|| {
        qualification_error("committed-signal relaunch omitted its child process")
    })?;
    let replacement_pid = replacement
        .id()
        .ok_or_else(|| qualification_error("committed-signal replacement has no PID"))?;
    let channel = restart_containerd(config, "committed-signal-shim-rehydration").await?;
    match tokio::time::timeout(Duration::from_secs(5), signal_call).await {
        Ok(Ok(Err(_))) => {}
        Ok(Ok(Ok(()))) => {
            return Err(qualification_error(
                "original Kill response survived after its frozen shim was killed",
            )
            .into());
        }
        Ok(Err(error)) => {
            return Err(qualification_error(format!(
                "original Kill task failed before reporting its lost response: {error}"
            ))
            .into());
        }
        Err(_) => {
            return Err(qualification_error(
                "original Kill call did not observe shim replacement within 5 seconds",
            )
            .into());
        }
    }

    let restored = task_process(config, &channel, id, EXEC_ID).await?;
    super::super::expect_process(
        &restored,
        STATUS_RUNNING,
        Some(exec.pid),
        "terminal exec after committed signal replacement",
    )?;
    if read_runtime_identity(config, id).await? != *identity {
        return Err(qualification_error(
            "committed process signal replacement changed the task incarnation or generation",
        )
        .into());
    }
    let observed_shim_pid = faults::find_exact_shim_pid(config, id).await?;
    if observed_shim_pid != replacement_pid {
        return Err(qualification_error(format!(
            "containerd connected committed-signal shim PID {observed_shim_pid}, expected {replacement_pid}"
        ))
        .into());
    }
    wait_for_completed_signal(bundle, pending_sequence).await?;
    wait_for_process_stopped(exec.pid, true, "committed SIGSTOP replay").await?;

    shim_signal(&bootstrap.address, id, libc::SIGCONT).await?;
    wait_for_completed_signal(bundle, 2).await?;
    wait_for_process_stopped(exec.pid, false, "SIGCONT after committed replay").await?;

    shim_signal(&bootstrap.address, id, libc::SIGSTOP).await?;
    wait_for_completed_signal(bundle, 3).await?;
    wait_for_process_stopped(exec.pid, true, "SIGSTOP after intervening SIGCONT").await?;

    shim_signal(&bootstrap.address, id, libc::SIGCONT).await?;
    wait_for_completed_signal(bundle, 4).await?;
    wait_for_process_stopped(exec.pid, false, "final SIGCONT").await?;

    let final_state = read_exec_signal_journal(bundle, EXEC_ID).await?;
    if final_state.completed_sequence != 4 || final_state.pending.is_some() {
        return Err(qualification_error(format!(
            "SIGSTOP→SIGCONT→SIGSTOP→SIGCONT did not finish at sequence 4: {final_state:?}"
        ))
        .into());
    }

    Ok((channel, replacement))
}

async fn wait_for_pending_signal(
    bundle: &Path,
    completed_sequence: u64,
    pending_sequence: u64,
    signal: i32,
    signal_call: &mut tokio::task::JoinHandle<TestResult<()>>,
) -> TestResult<()> {
    let expected = PendingSignalEvidence {
        sequence: pending_sequence,
        signal: Signal::new(signal).map_err(|error| {
            qualification_error(format!("validate pending signal evidence: {error}"))
        })?,
        all: false,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let evidence = read_exec_signal_journal(bundle, EXEC_ID).await?;
        if evidence.schema_version == 9
            && evidence.completed_sequence == completed_sequence
            && evidence.pending.as_ref() == Some(&expected)
        {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(qualification_error(format!(
                "exec signal journal did not retain pending sequence {pending_sequence}: {evidence:?}"
            ))
            .into());
        }
        tokio::select! {
            result = &mut *signal_call => {
                return match result {
                    Ok(Ok(())) => Err(qualification_error(
                        "Kill returned before its durable request reached the suspended Runtime",
                    ).into()),
                    Ok(Err(error)) => Err(qualification_error(format!(
                        "Kill failed before its durable request reached the suspended Runtime: {error}"
                    )).into()),
                    Err(error) => Err(qualification_error(format!(
                        "Kill task failed before its durable request reached the suspended Runtime: {error}"
                    )).into()),
                };
            }
            () = tokio::time::sleep(Duration::from_millis(10).min(remaining)) => {}
        }
    }
}

async fn wait_for_completed_signal(bundle: &Path, sequence: u64) -> TestResult<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let evidence = read_exec_signal_journal(bundle, EXEC_ID).await?;
        if evidence.schema_version == 9
            && evidence.completed_sequence == sequence
            && evidence.pending.is_none()
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(qualification_error(format!(
                "exec signal journal did not commit sequence {sequence}: {evidence:?}"
            ))
            .into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn read_exec_signal_journal(
    bundle: &Path,
    exec_id: &str,
) -> TestResult<SignalJournalEvidence> {
    let path = bundle.join("a3s-oci-shim-v1.json");
    let document: serde_json::Value = serde_json::from_slice(
        &tokio::fs::read(&path)
            .await
            .map_err(|error| qualification_error(format!("read shim metadata: {error}")))?,
    )
    .map_err(|error| qualification_error(format!("decode shim metadata: {error}")))?;
    let exec = document["execs"]
        .as_array()
        .and_then(|execs| {
            execs
                .iter()
                .find(|exec| exec["exec_id"].as_str() == Some(exec_id))
        })
        .ok_or_else(|| qualification_error(format!("shim metadata omitted exec {exec_id}")))?;
    Ok(SignalJournalEvidence {
        schema_version: document["schema_version"]
            .as_u64()
            .ok_or_else(|| qualification_error("shim metadata omitted schema_version"))?,
        completed_sequence: exec["signal_sequence"].as_u64().unwrap_or(0),
        pending: serde_json::from_value(
            exec.get("pending_signal")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .map_err(|error| {
            qualification_error(format!(
                "decode shim metadata pending signal for exec {exec_id}: {error}"
            ))
        })?,
    })
}

async fn wait_for_process_stopped(pid: u32, expected: bool, context: &str) -> TestResult<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let status = tokio::fs::read_to_string(format!("/proc/{pid}/status"))
            .await
            .map_err(|error| {
                qualification_error(format!(
                    "read process {pid} status during {context}: {error}"
                ))
            })?;
        let state = status
            .lines()
            .find_map(|line| line.strip_prefix("State:"))
            .and_then(|value| value.trim().chars().next())
            .ok_or_else(|| {
                qualification_error(format!(
                    "process {pid} status omitted State during {context}"
                ))
            })?;
        let stopped = matches!(state, 'T' | 't');
        if stopped == expected {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(qualification_error(format!(
                "process {pid} state remained {state} during {context}; expected stopped={expected}"
            ))
            .into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn commit_runtime_exec_signal(
    config: &crate::support::QualificationConfig,
    task_id: &str,
    identity: &crate::support::RuntimeIdentity,
    sequence: u64,
    signal: i32,
) -> TestResult<()> {
    let client = faults::runtime_client(config).await?;
    let request = SignalProcessRequest {
        context: OperationContext::new(faults::containerd_exec_operation_id(
            &config.namespace,
            task_id,
            &identity.incarnation,
            EXEC_ID,
            1,
            &format!("signal-{sequence}"),
        )?),
        process: ProcessTarget {
            container: ContainerTarget::exact(
                identity.container_id.clone(),
                Generation(identity.generation),
            ),
            process_id: faults::containerd_process_id(&config.namespace, task_id, EXEC_ID, 1)?,
        },
        signal: Signal::new(signal).map_err(|error| {
            qualification_error(format!("validate committed process signal: {error}"))
        })?,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.signal_process(request.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact Runtime SignalProcess before shim replacement: {error}"
                ))
                .into());
            }
        }
    }
}

async fn shim_signal(address: &str, id: &str, signal: i32) -> TestResult<()> {
    let client = containerd_shim_protos::ttrpc::asynchronous::Client::connect(address)
        .await
        .map_err(|error| {
            qualification_error(format!(
                "connect committed-signal shim at {address}: {error}"
            ))
        })?;
    let task = containerd_shim_protos::shim::shim_ttrpc_async::TaskClient::new(client);
    let mut request = containerd_shim_protos::api::KillRequest::new();
    request.set_id(id.to_string());
    request.set_exec_id(EXEC_ID.to_string());
    request.set_signal(u32::try_from(signal).map_err(|_| {
        qualification_error(format!("signal {signal} does not fit containerd u32"))
    })?);
    task.kill(
        containerd_shim_protos::ttrpc::context::Context::default(),
        &request,
    )
    .await
    .map_err(|error| -> crate::support::TestError {
        qualification_error(format!(
            "invoke Kill through shim {address} for {id}/{EXEC_ID}: {error}"
        ))
        .into()
    })?;
    Ok(())
}

async fn wait_for_killed_child(child: &mut Child, context: &str) -> TestResult<()> {
    match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => {
            Err(qualification_error(format!("wait for {context} after SIGKILL: {error}")).into())
        }
        Err(_) => Err(qualification_error(format!(
            "{context} did not exit within 5 seconds after SIGKILL"
        ))
        .into()),
    }
}
