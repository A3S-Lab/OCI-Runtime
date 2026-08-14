use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::{
    CloseStdinRequest, ContainerTarget, Generation, OperationContext, ProcessTarget,
};
use tokio::process::Child;
use tonic::transport::Channel;

use super::{
    launch_replacement_while_containerd_suspended, read_exec_stdin_journal, stop_replacement,
    Bootstrap, RehydratedTerminalExec,
};
use crate::faults;
use crate::support::{
    containerd_main_pid, qualification_error, read_runtime_identity, restart_containerd,
    task_process, TestResult, STATUS_RUNNING,
};

const EXEC_ID: &str = "rehydrated-terminal-exec";

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
    stdin_sequence: u64,
) -> TestResult<(Channel, Child)> {
    let old_shim_pid = old_replacement
        .id()
        .ok_or_else(|| qualification_error("committed-close shim has no PID"))?;
    let host_pid = faults::find_runtime_host_pid(config).await?;
    let mut suspended_host =
        faults::SuspendedProcess::stop(host_pid, "committed-close A3S OCI host service")?;

    let close_address = bootstrap.address.clone();
    let close_id = id.to_string();
    let mut close_call =
        tokio::spawn(async move { shim_close_io(&close_address, &close_id).await });

    wait_for_close_request(bundle, stdin_sequence, &mut close_call).await?;
    let suspended_shim =
        faults::SuspendedProcess::stop(old_shim_pid, "committed-close original shim")?;
    suspended_host.resume("committed-close A3S OCI host service")?;
    commit_runtime_exec_close(config, id, identity).await?;

    let containerd_pid = containerd_main_pid(config).await?;
    faults::send_signal(containerd_pid, libc::SIGSTOP, "committed-close containerd")?;
    let mut replacement = None;
    let relaunch = async {
        suspended_shim.kill("committed-close original shim")?;
        wait_for_killed_child(&mut old_replacement, "committed-close original shim").await?;
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
    let _ = faults::send_signal(containerd_pid, libc::SIGCONT, "committed-close containerd");
    if let Err(error) = relaunch {
        close_call.abort();
        let _ = close_call.await;
        let _ = old_replacement.start_kill();
        let _ = old_replacement.wait().await;
        stop_replacement(&mut replacement).await;
        let recovery = restart_containerd(config, "failed-committed-close-rehydration").await;
        return match recovery {
            Ok(_) => Err(error),
            Err(recovery_error) => Err(qualification_error(format!(
                "committed stdin close replacement failed: {error}; containerd recovery also failed: {recovery_error}"
            ))
            .into()),
        };
    }

    let replacement = replacement
        .ok_or_else(|| qualification_error("committed-close relaunch omitted its child process"))?;
    let replacement_pid = replacement
        .id()
        .ok_or_else(|| qualification_error("committed-close replacement has no PID"))?;
    let channel = restart_containerd(config, "committed-close-shim-rehydration").await?;
    match tokio::time::timeout(Duration::from_secs(5), close_call).await {
        Ok(Ok(Err(_))) => {}
        Ok(Ok(Ok(()))) => {
            return Err(qualification_error(
                "original CloseIO response survived after its frozen shim was killed",
            )
            .into());
        }
        Ok(Err(error)) => {
            return Err(qualification_error(format!(
                "original CloseIO task failed before reporting its lost response: {error}"
            ))
            .into());
        }
        Err(_) => {
            return Err(qualification_error(
                "original CloseIO call did not observe shim replacement within 5 seconds",
            )
            .into());
        }
    }

    let restored = task_process(config, &channel, id, EXEC_ID).await?;
    super::super::expect_process(
        &restored,
        STATUS_RUNNING,
        Some(exec.pid),
        "terminal exec after committed stdin close replacement",
    )?;
    if read_runtime_identity(config, id).await? != *identity {
        return Err(qualification_error(
            "committed stdin close replacement changed the task incarnation or generation",
        )
        .into());
    }
    let observed_shim_pid = faults::find_exact_shim_pid(config, id).await?;
    if observed_shim_pid != replacement_pid {
        return Err(qualification_error(format!(
            "containerd connected committed-close shim PID {observed_shim_pid}, expected {replacement_pid}"
        ))
        .into());
    }
    wait_for_close_state(bundle, stdin_sequence, "closed").await?;
    crate::terminal::expect_line(
        &mut exec.output,
        "stdin-closed",
        "committed stdin close after shim replacement",
    )
    .await?;

    shim_close_io(&bootstrap.address, id).await?;
    if let Ok(line) =
        tokio::time::timeout(Duration::from_millis(200), exec.output.next_line()).await
    {
        let line = line.map_err(|error| {
            qualification_error(format!("read output after committed-close replay: {error}"))
        })?;
        return Err(qualification_error(format!(
            "committed-close replay produced unexpected terminal output {line:?}"
        ))
        .into());
    }

    Ok((channel, replacement))
}

async fn wait_for_close_state(
    bundle: &Path,
    stdin_sequence: u64,
    expected: &str,
) -> TestResult<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let evidence = read_exec_stdin_journal(bundle, EXEC_ID).await?;
        if evidence.schema_version == 7
            && evidence.completed_sequence == stdin_sequence
            && evidence.pending.is_none()
            && evidence.close_state == expected
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(qualification_error(format!(
                "terminal stdin journal did not reach {expected}: {evidence:?}"
            ))
            .into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_close_request(
    bundle: &Path,
    stdin_sequence: u64,
    close_call: &mut tokio::task::JoinHandle<TestResult<()>>,
) -> TestResult<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let evidence = read_exec_stdin_journal(bundle, EXEC_ID).await?;
        if evidence.schema_version == 7
            && evidence.completed_sequence == stdin_sequence
            && evidence.pending.is_none()
            && evidence.close_state == "closing"
        {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(qualification_error(format!(
                "terminal stdin journal did not reach closing: {evidence:?}"
            ))
            .into());
        }
        tokio::select! {
            result = &mut *close_call => {
                return match result {
                    Ok(Ok(())) => Err(qualification_error(
                        "CloseIO returned before its durable close reached the suspended Runtime",
                    ).into()),
                    Ok(Err(error)) => Err(qualification_error(format!(
                        "CloseIO failed before its durable close reached the suspended Runtime: {error}"
                    )).into()),
                    Err(error) => Err(qualification_error(format!(
                        "CloseIO task failed before its durable close reached the suspended Runtime: {error}"
                    )).into()),
                };
            }
            () = tokio::time::sleep(Duration::from_millis(10).min(remaining)) => {}
        }
    }
}

async fn commit_runtime_exec_close(
    config: &crate::support::QualificationConfig,
    task_id: &str,
    identity: &crate::support::RuntimeIdentity,
) -> TestResult<()> {
    let client = faults::runtime_client(config).await?;
    let request = CloseStdinRequest {
        context: OperationContext::new(faults::containerd_exec_operation_id(
            &config.namespace,
            task_id,
            &identity.incarnation,
            EXEC_ID,
            "close-stdin",
        )?),
        process: ProcessTarget {
            container: ContainerTarget::exact(
                identity.container_id.clone(),
                Generation(identity.generation),
            ),
            process_id: faults::containerd_process_id(&config.namespace, task_id, EXEC_ID)?,
        },
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.close_stdin(request.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact Runtime CloseStdin before shim replacement: {error}"
                ))
                .into());
            }
        }
    }
}

async fn shim_close_io(address: &str, id: &str) -> TestResult<()> {
    let client = containerd_shim_protos::ttrpc::asynchronous::Client::connect(address)
        .await
        .map_err(|error| {
            qualification_error(format!(
                "connect committed-close shim at {address}: {error}"
            ))
        })?;
    let task = containerd_shim_protos::shim::shim_ttrpc_async::TaskClient::new(client);
    let mut request = containerd_shim_protos::api::CloseIORequest::new();
    request.set_id(id.to_string());
    request.set_exec_id(EXEC_ID.to_string());
    request.set_stdin(true);
    task.close_io(
        containerd_shim_protos::ttrpc::context::Context::default(),
        &request,
    )
    .await
    .map_err(|error| -> crate::support::TestError {
        qualification_error(format!(
            "invoke CloseIO through shim {address} for {id}/{EXEC_ID}: {error}"
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
