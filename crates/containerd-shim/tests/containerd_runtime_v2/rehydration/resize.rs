use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::{
    ContainerTarget, Generation, OperationContext, ProcessTarget, ResizeRequest, TerminalSize,
};
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::process::Child;
use tonic::transport::Channel;

use super::{
    launch_replacement_while_containerd_suspended, read_exec_stdin_journal, stop_replacement,
    wait_for_exec_stdin_sequence, Bootstrap, RehydratedTerminalExec,
};
use crate::faults;
use crate::support::{
    containerd_main_pid, qualification_error, read_runtime_identity, restart_containerd,
    task_process, TestResult, STATUS_RUNNING,
};

const EXEC_ID: &str = "rehydrated-terminal-exec";
const COMMITTED_SIZE: TerminalSize = TerminalSize {
    width: 166,
    height: 52,
};
const INTERMEDIATE_SIZE: TerminalSize = TerminalSize {
    width: 177,
    height: 55,
};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingResizeEvidence {
    sequence: u64,
    size: TerminalSize,
}

#[derive(Debug)]
struct ResizeJournalEvidence {
    schema_version: u64,
    completed_sequence: u64,
    pending: Option<PendingResizeEvidence>,
    terminal_size: Option<TerminalSize>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn qualify(
    config: &crate::support::QualificationConfig,
    id: &str,
    bundle: &Path,
    binary: &Path,
    bootstrap: &Bootstrap,
    identity: &crate::support::RuntimeIdentity,
    exec: &mut RehydratedTerminalExec,
    mut old_replacement: Child,
) -> TestResult<(Channel, Child, u64)> {
    let baseline = read_exec_resize_journal(bundle, EXEC_ID).await?;
    if baseline.schema_version != 6
        || baseline.completed_sequence != 2
        || baseline.pending.is_some()
        || baseline.terminal_size
            != Some(TerminalSize {
                width: 143,
                height: 47,
            })
    {
        return Err(qualification_error(format!(
            "terminal resize journal before committed replacement was {baseline:?}; expected schema 6, sequence 2, no pending resize, and 143x47"
        ))
        .into());
    }
    let pending_sequence = baseline
        .completed_sequence
        .checked_add(1)
        .ok_or_else(|| qualification_error("terminal resize sequence overflow"))?;
    let old_shim_pid = old_replacement
        .id()
        .ok_or_else(|| qualification_error("committed-resize shim has no PID"))?;
    let host_pid = faults::find_runtime_host_pid(config).await?;
    let mut suspended_host =
        faults::SuspendedProcess::stop(host_pid, "committed-resize A3S OCI host service")?;
    let resize_address = bootstrap.address.clone();
    let resize_id = id.to_string();
    let mut resize_call =
        tokio::spawn(async move { shim_resize(&resize_address, &resize_id, COMMITTED_SIZE).await });

    wait_for_pending_resize(
        bundle,
        baseline.completed_sequence,
        pending_sequence,
        COMMITTED_SIZE,
        &mut resize_call,
    )
    .await?;
    let suspended_shim =
        faults::SuspendedProcess::stop(old_shim_pid, "committed-resize original shim")?;
    suspended_host.resume("committed-resize A3S OCI host service")?;
    commit_runtime_exec_resize(config, id, identity, pending_sequence, COMMITTED_SIZE).await?;

    let containerd_pid = containerd_main_pid(config).await?;
    faults::send_signal(containerd_pid, libc::SIGSTOP, "committed-resize containerd")?;
    let mut replacement = None;
    let relaunch = async {
        suspended_shim.kill("committed-resize original shim")?;
        wait_for_killed_child(&mut old_replacement, "committed-resize original shim").await?;
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
    let _ = faults::send_signal(containerd_pid, libc::SIGCONT, "committed-resize containerd");
    if let Err(error) = relaunch {
        resize_call.abort();
        let _ = resize_call.await;
        let _ = old_replacement.start_kill();
        let _ = old_replacement.wait().await;
        stop_replacement(&mut replacement).await;
        let recovery = restart_containerd(config, "failed-committed-resize-rehydration").await;
        return match recovery {
            Ok(_) => Err(error),
            Err(recovery_error) => Err(qualification_error(format!(
                "committed terminal resize replacement failed: {error}; containerd recovery also failed: {recovery_error}"
            ))
            .into()),
        };
    }

    let replacement = replacement.ok_or_else(|| {
        qualification_error("committed-resize relaunch omitted its child process")
    })?;
    let replacement_pid = replacement
        .id()
        .ok_or_else(|| qualification_error("committed-resize replacement has no PID"))?;
    let channel = restart_containerd(config, "committed-resize-shim-rehydration").await?;
    match tokio::time::timeout(Duration::from_secs(5), resize_call).await {
        Ok(Ok(Err(_))) => {}
        Ok(Ok(Ok(()))) => {
            return Err(qualification_error(
                "original ResizePty response survived after its frozen shim was killed",
            )
            .into());
        }
        Ok(Err(error)) => {
            return Err(qualification_error(format!(
                "original ResizePty task failed before reporting its lost response: {error}"
            ))
            .into());
        }
        Err(_) => {
            return Err(qualification_error(
                "original ResizePty call did not observe shim replacement within 5 seconds",
            )
            .into());
        }
    }

    let restored = task_process(config, &channel, id, EXEC_ID).await?;
    super::super::expect_process(
        &restored,
        STATUS_RUNNING,
        Some(exec.pid),
        "terminal exec after committed resize replacement",
    )?;
    if read_runtime_identity(config, id).await? != *identity {
        return Err(qualification_error(
            "committed terminal resize replacement changed the task incarnation or generation",
        )
        .into());
    }
    let observed_shim_pid = faults::find_exact_shim_pid(config, id).await?;
    if observed_shim_pid != replacement_pid {
        return Err(qualification_error(format!(
            "containerd connected committed-resize shim PID {observed_shim_pid}, expected {replacement_pid}"
        ))
        .into());
    }
    wait_for_completed_resize(bundle, pending_sequence, COMMITTED_SIZE).await?;

    verify_terminal_size(bundle, exec, COMMITTED_SIZE, "committed resize replay").await?;
    shim_resize(&bootstrap.address, id, COMMITTED_SIZE).await?;
    let same_size = read_exec_resize_journal(bundle, EXEC_ID).await?;
    if same_size.completed_sequence != pending_sequence
        || same_size.pending.is_some()
        || same_size.terminal_size != Some(COMMITTED_SIZE)
    {
        return Err(qualification_error(format!(
            "same-size resize retry advanced durable state: {same_size:?}"
        ))
        .into());
    }

    shim_resize(&bootstrap.address, id, INTERMEDIATE_SIZE).await?;
    let intermediate_sequence = pending_sequence
        .checked_add(1)
        .ok_or_else(|| qualification_error("intermediate resize sequence overflow"))?;
    wait_for_completed_resize(bundle, intermediate_sequence, INTERMEDIATE_SIZE).await?;
    verify_terminal_size(bundle, exec, INTERMEDIATE_SIZE, "A→B intermediate resize").await?;

    shim_resize(&bootstrap.address, id, COMMITTED_SIZE).await?;
    let final_sequence = intermediate_sequence
        .checked_add(1)
        .ok_or_else(|| qualification_error("final resize sequence overflow"))?;
    wait_for_completed_resize(bundle, final_sequence, COMMITTED_SIZE).await?;
    let stdin_sequence =
        verify_terminal_size(bundle, exec, COMMITTED_SIZE, "A→B→A final resize").await?;
    let final_state = read_exec_resize_journal(bundle, EXEC_ID).await?;
    if final_state.completed_sequence != final_sequence
        || final_state.pending.is_some()
        || final_state.terminal_size != Some(COMMITTED_SIZE)
    {
        return Err(qualification_error(format!(
            "A→B→A resize did not finish at A with a fresh sequence: {final_state:?}"
        ))
        .into());
    }

    Ok((channel, replacement, stdin_sequence))
}

async fn wait_for_pending_resize(
    bundle: &Path,
    completed_sequence: u64,
    pending_sequence: u64,
    size: TerminalSize,
    resize_call: &mut tokio::task::JoinHandle<TestResult<()>>,
) -> TestResult<()> {
    let expected = PendingResizeEvidence {
        sequence: pending_sequence,
        size,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let evidence = read_exec_resize_journal(bundle, EXEC_ID).await?;
        if evidence.schema_version == 6
            && evidence.completed_sequence == completed_sequence
            && evidence.pending.as_ref() == Some(&expected)
        {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(qualification_error(format!(
                "terminal resize journal did not retain pending sequence {pending_sequence}: {evidence:?}"
            ))
            .into());
        }
        tokio::select! {
            result = &mut *resize_call => {
                return match result {
                    Ok(Ok(())) => Err(qualification_error(
                        "ResizePty returned before its durable request reached the suspended Runtime",
                    ).into()),
                    Ok(Err(error)) => Err(qualification_error(format!(
                        "ResizePty failed before its durable request reached the suspended Runtime: {error}"
                    )).into()),
                    Err(error) => Err(qualification_error(format!(
                        "ResizePty task failed before its durable request reached the suspended Runtime: {error}"
                    )).into()),
                };
            }
            () = tokio::time::sleep(Duration::from_millis(10).min(remaining)) => {}
        }
    }
}

async fn wait_for_completed_resize(
    bundle: &Path,
    sequence: u64,
    size: TerminalSize,
) -> TestResult<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let evidence = read_exec_resize_journal(bundle, EXEC_ID).await?;
        if evidence.schema_version == 6
            && evidence.completed_sequence == sequence
            && evidence.pending.is_none()
            && evidence.terminal_size == Some(size)
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(qualification_error(format!(
                "terminal resize journal did not commit sequence {sequence} at {}x{}: {evidence:?}",
                size.width, size.height
            ))
            .into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn read_exec_resize_journal(
    bundle: &Path,
    exec_id: &str,
) -> TestResult<ResizeJournalEvidence> {
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
    Ok(ResizeJournalEvidence {
        schema_version: document["schema_version"]
            .as_u64()
            .ok_or_else(|| qualification_error("shim metadata omitted schema_version"))?,
        completed_sequence: exec["resize_sequence"].as_u64().unwrap_or(0),
        pending: serde_json::from_value(
            exec.get("pending_resize")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .map_err(|error| {
            qualification_error(format!(
                "decode shim metadata pending resize for exec {exec_id}: {error}"
            ))
        })?,
        terminal_size: serde_json::from_value(
            exec.get("terminal_size")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .map_err(|error| {
            qualification_error(format!(
                "decode shim metadata terminal size for exec {exec_id}: {error}"
            ))
        })?,
    })
}

async fn verify_terminal_size(
    bundle: &Path,
    exec: &mut RehydratedTerminalExec,
    size: TerminalSize,
    context: &str,
) -> TestResult<u64> {
    let before = read_exec_stdin_journal(bundle, EXEC_ID).await?;
    if before.pending.is_some() || before.close_state != "open" {
        return Err(qualification_error(format!(
            "cannot query {context} with stdin journal {before:?}"
        ))
        .into());
    }
    let expected_sequence = before
        .completed_sequence
        .checked_add(1)
        .ok_or_else(|| qualification_error("terminal stdin sequence overflow"))?;
    let stdin = exec.stdin.as_mut().ok_or_else(|| {
        qualification_error(format!("terminal stdin disappeared before {context}"))
    })?;
    stdin.write_all(b"__a3s_size__\n").await.map_err(|error| {
        qualification_error(format!(
            "request terminal dimensions for {context}: {error}"
        ))
    })?;
    stdin.flush().await.map_err(|error| {
        qualification_error(format!(
            "flush terminal dimension request for {context}: {error}"
        ))
    })?;
    crate::terminal::expect_line(
        &mut exec.output,
        &format!("{} {}", size.height, size.width),
        context,
    )
    .await?;
    wait_for_exec_stdin_sequence(bundle, EXEC_ID, expected_sequence).await?;
    Ok(expected_sequence)
}

async fn commit_runtime_exec_resize(
    config: &crate::support::QualificationConfig,
    task_id: &str,
    identity: &crate::support::RuntimeIdentity,
    sequence: u64,
    size: TerminalSize,
) -> TestResult<()> {
    let client = faults::runtime_client(config).await?;
    let request = ResizeRequest {
        context: OperationContext::new(faults::containerd_exec_operation_id(
            &config.namespace,
            task_id,
            &identity.incarnation,
            EXEC_ID,
            &format!("resize-{sequence}"),
        )?),
        process: ProcessTarget {
            container: ContainerTarget::exact(
                identity.container_id.clone(),
                Generation(identity.generation),
            ),
            process_id: faults::containerd_process_id(&config.namespace, task_id, EXEC_ID)?,
        },
        size,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.resize(request.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact Runtime Resize before shim replacement: {error}"
                ))
                .into());
            }
        }
    }
}

async fn shim_resize(address: &str, id: &str, size: TerminalSize) -> TestResult<()> {
    let client = containerd_shim_protos::ttrpc::asynchronous::Client::connect(address)
        .await
        .map_err(|error| {
            qualification_error(format!(
                "connect committed-resize shim at {address}: {error}"
            ))
        })?;
    let task = containerd_shim_protos::shim::shim_ttrpc_async::TaskClient::new(client);
    let mut request = containerd_shim_protos::api::ResizePtyRequest::new();
    request.set_id(id.to_string());
    request.set_exec_id(EXEC_ID.to_string());
    request.set_width(u32::from(size.width));
    request.set_height(u32::from(size.height));
    task.resize_pty(
        containerd_shim_protos::ttrpc::context::Context::default(),
        &request,
    )
    .await
    .map_err(|error| -> crate::support::TestError {
        qualification_error(format!(
            "invoke ResizePty through shim {address} for {id}/{EXEC_ID}: {error}"
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
