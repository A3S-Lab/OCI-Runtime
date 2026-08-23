use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::{
    ContainerRecord, ContainerTarget, Generation, KillRequest, OperationContext, Signal,
};
use serde::Deserialize;
use tokio::process::Child;
use tonic::transport::Channel;

use super::{
    launch_replacement_while_containerd_suspended, stop_replacement, wait_for_process_stopped,
    Bootstrap, RehydratedTerminalExec,
};
use crate::faults;
use crate::support::{
    containerd_main_pid, qualification_error, read_runtime_identity, restart_containerd,
    task_process, QualificationConfig, RuntimeIdentity, TestResult, STATUS_RUNNING,
};

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
    config: &QualificationConfig,
    id: &str,
    bundle: &Path,
    binary: &Path,
    bootstrap: &Bootstrap,
    identity: &RuntimeIdentity,
    init_pid: u32,
    exec: &RehydratedTerminalExec,
    mut old_replacement: Child,
) -> TestResult<(Channel, Child)> {
    let baseline = read_task_signal_journal(bundle).await?;
    if baseline.schema_version != 9
        || baseline.completed_sequence != 0
        || baseline.pending.is_some()
    {
        return Err(qualification_error(format!(
            "init signal journal before committed replacement was {baseline:?}; expected schema 9, sequence 0, and no pending signal"
        ))
        .into());
    }

    let pending_sequence = 1;
    let old_shim_pid = old_replacement
        .id()
        .ok_or_else(|| qualification_error("committed-Kill shim has no PID"))?;
    let host_pid = faults::find_runtime_host_pid(config).await?;
    let mut suspended_host =
        faults::SuspendedProcess::stop(host_pid, "committed-Kill A3S OCI host service")?;
    let kill_address = bootstrap.address.clone();
    let kill_id = id.to_string();
    let mut kill_call =
        tokio::spawn(async move { shim_kill(&kill_address, &kill_id, libc::SIGSTOP, true).await });

    wait_for_pending_signal(
        bundle,
        baseline.completed_sequence,
        pending_sequence,
        libc::SIGSTOP,
        true,
        &mut kill_call,
    )
    .await?;
    let suspended_shim =
        faults::SuspendedProcess::stop(old_shim_pid, "committed-Kill original shim")?;
    suspended_host.resume("committed-Kill A3S OCI host service")?;
    commit_runtime_kill(config, id, identity, pending_sequence, libc::SIGSTOP, true).await?;

    let containerd_pid = containerd_main_pid(config).await?;
    faults::send_signal(containerd_pid, libc::SIGSTOP, "committed-Kill containerd")?;
    let mut replacement = None;
    let relaunch = async {
        suspended_shim.kill("committed-Kill original shim")?;
        wait_for_killed_child(&mut old_replacement, "committed-Kill original shim").await?;
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
    let _ = faults::send_signal(containerd_pid, libc::SIGCONT, "committed-Kill containerd");
    if let Err(error) = relaunch {
        kill_call.abort();
        let _ = kill_call.await;
        let _ = old_replacement.start_kill();
        let _ = old_replacement.wait().await;
        stop_replacement(&mut replacement).await;
        let recovery = restart_containerd(config, "failed-committed-Kill-rehydration").await;
        return match recovery {
            Ok(_) => Err(error),
            Err(recovery_error) => Err(qualification_error(format!(
                "committed Kill replacement failed: {error}; containerd recovery also failed: {recovery_error}"
            ))
            .into()),
        };
    }

    let replacement = replacement
        .ok_or_else(|| qualification_error("committed-Kill relaunch omitted its child process"))?;
    let replacement_pid = replacement
        .id()
        .ok_or_else(|| qualification_error("committed-Kill replacement has no PID"))?;
    let channel = restart_containerd(config, "committed-Kill-shim-rehydration").await?;
    require_lost_kill_response(kill_call).await?;

    super::super::expect_process(
        &task_process(config, &channel, id, "").await?,
        STATUS_RUNNING,
        Some(init_pid),
        "init after committed Kill replacement",
    )?;
    super::super::expect_process(
        &task_process(config, &channel, id, "rehydrated-terminal-exec").await?,
        STATUS_RUNNING,
        Some(exec.pid),
        "terminal exec after committed init Kill replacement",
    )?;
    if read_runtime_identity(config, id).await? != *identity {
        return Err(qualification_error(
            "committed Kill replacement changed the task incarnation or generation",
        )
        .into());
    }
    let observed_shim_pid = faults::find_exact_shim_pid(config, id).await?;
    if observed_shim_pid != replacement_pid {
        return Err(qualification_error(format!(
            "containerd connected committed-Kill shim PID {observed_shim_pid}, expected {replacement_pid}"
        ))
        .into());
    }
    wait_for_completed_signal(bundle, pending_sequence).await?;
    wait_for_process_stopped(init_pid, true, "committed all=true SIGSTOP replay for init").await?;
    wait_for_process_stopped(exec.pid, true, "committed all=true SIGSTOP replay for exec").await?;

    shim_kill(&bootstrap.address, id, libc::SIGCONT, true).await?;
    wait_for_completed_signal(bundle, 2).await?;
    wait_for_process_stopped(init_pid, false, "all=true SIGCONT for init").await?;
    wait_for_process_stopped(exec.pid, false, "all=true SIGCONT for exec").await?;

    shim_kill(&bootstrap.address, id, libc::SIGSTOP, false).await?;
    wait_for_completed_signal(bundle, 3).await?;
    wait_for_process_stopped(init_pid, true, "all=false SIGSTOP for init").await?;
    wait_for_process_stopped(exec.pid, false, "all=false SIGSTOP isolation for exec").await?;

    shim_kill(&bootstrap.address, id, libc::SIGCONT, false).await?;
    wait_for_completed_signal(bundle, 4).await?;
    wait_for_process_stopped(init_pid, false, "all=false SIGCONT for init").await?;
    wait_for_process_stopped(exec.pid, false, "final exec running state").await?;

    let final_state = read_task_signal_journal(bundle).await?;
    if final_state.schema_version != 9
        || final_state.completed_sequence != 4
        || final_state.pending.is_some()
    {
        return Err(qualification_error(format!(
            "init SIGSTOP→SIGCONT→SIGSTOP→SIGCONT did not finish at schema 9, sequence 4: {final_state:?}"
        ))
        .into());
    }

    Ok((channel, replacement))
}

pub(super) async fn wait_for_pending_signal(
    bundle: &Path,
    completed_sequence: u64,
    pending_sequence: u64,
    signal: i32,
    all: bool,
    kill_call: &mut tokio::task::JoinHandle<TestResult<()>>,
) -> TestResult<()> {
    let expected = PendingSignalEvidence {
        sequence: pending_sequence,
        signal: Signal::new(signal).map_err(|error| {
            qualification_error(format!("validate pending Kill evidence: {error}"))
        })?,
        all,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let evidence = read_task_signal_journal(bundle).await?;
        if evidence.schema_version == 9
            && evidence.completed_sequence == completed_sequence
            && evidence.pending.as_ref() == Some(&expected)
        {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(qualification_error(format!(
                "init signal journal did not retain pending sequence {pending_sequence}: {evidence:?}"
            ))
            .into());
        }
        tokio::select! {
            result = &mut *kill_call => {
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
        let evidence = read_task_signal_journal(bundle).await?;
        if evidence.schema_version == 9
            && evidence.completed_sequence == sequence
            && evidence.pending.is_none()
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(qualification_error(format!(
                "init signal journal did not commit sequence {sequence}: {evidence:?}"
            ))
            .into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn read_task_signal_journal(bundle: &Path) -> TestResult<SignalJournalEvidence> {
    let path = bundle.join("a3s-oci-shim-v1.json");
    let document: serde_json::Value = serde_json::from_slice(
        &tokio::fs::read(&path)
            .await
            .map_err(|error| qualification_error(format!("read shim metadata: {error}")))?,
    )
    .map_err(|error| qualification_error(format!("decode shim metadata: {error}")))?;
    Ok(SignalJournalEvidence {
        schema_version: document["schema_version"]
            .as_u64()
            .ok_or_else(|| qualification_error("shim metadata omitted schema_version"))?,
        completed_sequence: document["signal_sequence"].as_u64().unwrap_or(0),
        pending: serde_json::from_value(
            document
                .get("pending_signal")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .map_err(|error| {
            qualification_error(format!(
                "decode shim metadata pending signal for init: {error}"
            ))
        })?,
    })
}

pub(super) async fn commit_runtime_kill(
    config: &QualificationConfig,
    task_id: &str,
    identity: &RuntimeIdentity,
    sequence: u64,
    signal: i32,
    all: bool,
) -> TestResult<ContainerRecord> {
    let client = faults::runtime_client(config).await?;
    let request = KillRequest {
        context: OperationContext::new(faults::containerd_operation_id(
            &config.namespace,
            task_id,
            &identity.incarnation,
            &format!("kill-{sequence}"),
        )?),
        target: ContainerTarget::exact(
            identity.container_id.clone(),
            Generation(identity.generation),
        ),
        signal: Signal::new(signal).map_err(|error| {
            qualification_error(format!("validate committed Runtime Kill signal: {error}"))
        })?,
        all,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.kill(request.clone()).await {
            Ok(record) => return Ok(record),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact Runtime Kill before shim replacement: {error}"
                ))
                .into());
            }
        }
    }
}

pub(super) async fn shim_kill(address: &str, id: &str, signal: i32, all: bool) -> TestResult<()> {
    let client = containerd_shim_protos::ttrpc::asynchronous::Client::connect(address)
        .await
        .map_err(|error| {
            qualification_error(format!("connect committed-Kill shim at {address}: {error}"))
        })?;
    let task = containerd_shim_protos::shim::shim_ttrpc_async::TaskClient::new(client);
    let mut request = containerd_shim_protos::api::KillRequest::new();
    request.set_id(id.to_string());
    request.set_signal(u32::try_from(signal).map_err(|_| {
        qualification_error(format!("signal {signal} does not fit containerd u32"))
    })?);
    request.set_all(all);
    task.kill(
        containerd_shim_protos::ttrpc::context::Context::default(),
        &request,
    )
    .await
    .map_err(|error| -> crate::support::TestError {
        qualification_error(format!(
            "invoke Kill through shim {address} for {id} with all={all}: {error}"
        ))
        .into()
    })?;
    Ok(())
}

pub(super) async fn require_lost_kill_response(
    kill_call: tokio::task::JoinHandle<TestResult<()>>,
) -> TestResult<()> {
    match tokio::time::timeout(Duration::from_secs(5), kill_call).await {
        Ok(Ok(Err(_))) => Ok(()),
        Ok(Ok(Ok(()))) => Err(qualification_error(
            "original Kill response survived after its frozen shim was killed",
        )
        .into()),
        Ok(Err(error)) => Err(qualification_error(format!(
            "original Kill task failed before reporting its lost response: {error}"
        ))
        .into()),
        Err(_) => Err(qualification_error(
            "original Kill call did not observe shim replacement within 5 seconds",
        )
        .into()),
    }
}

pub(super) async fn wait_for_killed_child(child: &mut Child, context: &str) -> TestResult<()> {
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
