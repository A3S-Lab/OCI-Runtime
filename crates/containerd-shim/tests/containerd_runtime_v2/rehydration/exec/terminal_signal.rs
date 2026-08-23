use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::{
    ContainerTarget, ExitStatus, Generation, OperationContext, ProcessTarget, ProcessesRequest,
    Signal, SignalProcessRequest, WaitProcessRequest as RuntimeWaitProcessRequest,
};
use serde::Deserialize;
use tokio::process::Child;
use tonic::transport::Channel;

use super::super::{
    kill::wait_for_killed_child, launch_replacement_while_containerd_suspended, stop_replacement,
    wait_for_pid_exit, Bootstrap,
};
use super::{EXEC_EXIT_STATUS, EXEC_ID};
use crate::api::{TasksClient, WaitRequest};
use crate::faults;
use crate::support::{
    containerd_main_pid, expect_process, namespaced, qualification_error, read_runtime_identity,
    restart_containerd, rpc_error, task_process, QualificationConfig, RuntimeIdentity, TestResult,
    STATUS_RUNNING, STATUS_STOPPED,
};

const SIGNAL_SEQUENCE: u64 = 1;

#[derive(Debug, Deserialize)]
struct ShimEvidence {
    schema_version: u64,
    execs: Vec<ExecEvidence>,
}

#[derive(Debug, Deserialize)]
struct ExecEvidence {
    exec_id: String,
    stage: String,
    #[serde(default)]
    signal_sequence: u64,
    #[serde(default)]
    pending_signal: Option<PendingSignalEvidence>,
    exit: Option<ExitStatus>,
    exited_at_unix_nanos: Option<u128>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingSignalEvidence {
    sequence: u64,
    signal: Signal,
    all: bool,
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
    exec_pid: u32,
    mut old_replacement: Child,
) -> TestResult<(Channel, Child)> {
    require_signal_journal(bundle, None).await?;
    let host_pid = faults::find_runtime_host_pid(config).await?;
    let mut suspended_host = faults::SuspendedProcess::stop(
        host_pid,
        "committed terminal-SignalProcess A3S OCI host service",
    )?;
    let signal_address = bootstrap.address.clone();
    let signal_id = id.to_string();
    let mut signal_call =
        tokio::spawn(async move { shim_signal(&signal_address, &signal_id, libc::SIGTERM).await });
    wait_for_pending_signal(bundle, &mut signal_call).await?;

    let old_shim_pid = old_replacement
        .id()
        .ok_or_else(|| qualification_error("committed terminal-SignalProcess shim has no PID"))?;
    let suspended_shim = faults::SuspendedProcess::stop(
        old_shim_pid,
        "committed terminal-SignalProcess original shim",
    )?;
    suspended_host.resume("committed terminal-SignalProcess A3S OCI host service")?;

    let target = exact_exec_target(config, id, identity)?;
    commit_runtime_signal(config, id, identity, &target).await?;
    let runtime_exit = exact_runtime_wait_process(config, &target).await?;
    require_exit(
        &runtime_exit,
        "exact Runtime WaitProcess after committed terminal SignalProcess",
    )?;
    require_runtime_exec_absent(config, identity, &target).await?;
    wait_for_pid_exit(exec_pid, "committed terminal-SignalProcess exec").await?;

    let containerd_pid = containerd_main_pid(config).await?;
    faults::send_signal(
        containerd_pid,
        libc::SIGSTOP,
        "committed terminal-SignalProcess containerd",
    )?;
    let mut replacement = None;
    let relaunch = async {
        suspended_shim.kill("committed terminal-SignalProcess original shim")?;
        wait_for_killed_child(
            &mut old_replacement,
            "committed terminal-SignalProcess original shim",
        )
        .await?;
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
    let _ = faults::send_signal(
        containerd_pid,
        libc::SIGCONT,
        "committed terminal-SignalProcess containerd",
    );
    if let Err(error) = relaunch {
        signal_call.abort();
        let _ = signal_call.await;
        let _ = old_replacement.start_kill();
        let _ = old_replacement.wait().await;
        stop_replacement(&mut replacement).await;
        let recovery = restart_containerd(
            config,
            "failed-committed-terminal-SignalProcess-rehydration",
        )
        .await;
        return match recovery {
            Ok(_) => Err(error),
            Err(recovery_error) => Err(qualification_error(format!(
                "committed terminal SignalProcess replacement failed: {error}; containerd recovery also failed: {recovery_error}"
            ))
            .into()),
        };
    }

    let replacement = replacement.ok_or_else(|| {
        qualification_error("committed terminal-SignalProcess relaunch omitted its child process")
    })?;
    let replacement_pid = replacement.id().ok_or_else(|| {
        qualification_error("committed terminal-SignalProcess replacement has no PID")
    })?;
    require_signal_journal(bundle, Some(&runtime_exit)).await?;
    if read_runtime_identity(config, id).await? != *identity {
        return Err(qualification_error(
            "committed terminal SignalProcess replacement changed the task incarnation or generation",
        )
        .into());
    }
    let observed_shim_pid = faults::find_exact_shim_pid(config, id).await?;
    if observed_shim_pid != replacement_pid {
        return Err(qualification_error(format!(
            "committed terminal-SignalProcess shim PID was {observed_shim_pid}, expected replacement PID {replacement_pid}"
        ))
        .into());
    }
    let replacement_exit = shim_wait(bootstrap, id).await?;
    if replacement_exit != EXEC_EXIT_STATUS {
        return Err(qualification_error(format!(
            "replacement shim exec Wait returned {replacement_exit}, expected {EXEC_EXIT_STATUS}"
        ))
        .into());
    }

    let channel =
        restart_containerd(config, "committed-terminal-SignalProcess-shim-rehydration").await?;
    require_lost_signal_response(signal_call).await?;
    expect_process(
        &task_process(config, &channel, id, "").await?,
        STATUS_RUNNING,
        Some(init_pid),
        "init after committed terminal SignalProcess replacement",
    )?;
    let exec = task_process(config, &channel, id, EXEC_ID).await?;
    expect_process(
        &exec,
        STATUS_STOPPED,
        None,
        "exec after committed terminal SignalProcess replacement",
    )?;
    if exec.exit_status != EXEC_EXIT_STATUS {
        return Err(qualification_error(format!(
            "rehydrated stopped exec reported exit {}, expected {EXEC_EXIT_STATUS}",
            exec.exit_status
        ))
        .into());
    }
    let waited = TasksClient::new(channel.clone())
        .wait(namespaced(
            WaitRequest {
                container_id: id.to_string(),
                exec_id: EXEC_ID.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("wait committed terminal-SignalProcess exec", error))?
        .into_inner();
    if waited.exit_status != EXEC_EXIT_STATUS {
        return Err(qualification_error(format!(
            "containerd Wait after terminal-SignalProcess replacement returned {}, expected {EXEC_EXIT_STATUS}",
            waited.exit_status
        ))
        .into());
    }
    Ok((channel, replacement))
}

async fn wait_for_pending_signal(
    bundle: &Path,
    signal_call: &mut tokio::task::JoinHandle<TestResult<()>>,
) -> TestResult<()> {
    let expected = PendingSignalEvidence {
        sequence: SIGNAL_SEQUENCE,
        signal: Signal::new(libc::SIGTERM).map_err(|error| {
            qualification_error(format!("validate pending terminal exec signal: {error}"))
        })?,
        all: false,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let evidence = read_exec_evidence(bundle).await?;
        if evidence.signal_sequence == 0 && evidence.pending_signal.as_ref() == Some(&expected) {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(qualification_error(format!(
                "exec signal journal did not retain pending terminal sequence {SIGNAL_SEQUENCE}: {evidence:?}"
            ))
            .into());
        }
        tokio::select! {
            result = &mut *signal_call => {
                return match result {
                    Ok(Ok(())) => Err(qualification_error(
                        "terminal SignalProcess returned before its durable request reached the suspended Runtime",
                    ).into()),
                    Ok(Err(error)) => Err(qualification_error(format!(
                        "terminal SignalProcess failed before its durable request reached the suspended Runtime: {error}"
                    )).into()),
                    Err(error) => Err(qualification_error(format!(
                        "terminal SignalProcess task failed before its durable request reached the suspended Runtime: {error}"
                    )).into()),
                };
            }
            () = tokio::time::sleep(Duration::from_millis(10).min(remaining)) => {}
        }
    }
}

async fn require_signal_journal(
    bundle: &Path,
    expected_exit: Option<&ExitStatus>,
) -> TestResult<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let evidence = read_exec_evidence(bundle).await?;
        let valid = match expected_exit {
            None => {
                evidence.stage == "started"
                    && evidence.signal_sequence == 0
                    && evidence.pending_signal.is_none()
                    && evidence.exit.is_none()
                    && evidence.exited_at_unix_nanos.is_none()
            }
            Some(exit) => {
                evidence.stage == "exited"
                    && evidence.signal_sequence == SIGNAL_SEQUENCE
                    && evidence.pending_signal.is_none()
                    && evidence.exit.as_ref() == Some(exit)
                    && evidence.exited_at_unix_nanos.is_some_and(|value| value > 0)
            }
        };
        if valid {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(qualification_error(format!(
                "committed terminal-SignalProcess journal did not reach its expected state: {evidence:?}"
            ))
            .into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn read_exec_evidence(bundle: &Path) -> TestResult<ExecEvidence> {
    let document: ShimEvidence = serde_json::from_slice(
        &tokio::fs::read(bundle.join("a3s-oci-shim-v1.json"))
            .await
            .map_err(|error| qualification_error(format!("read shim metadata: {error}")))?,
    )
    .map_err(|error| qualification_error(format!("decode shim metadata: {error}")))?;
    if document.schema_version != 9 {
        return Err(qualification_error(format!(
            "committed terminal-SignalProcess requires shim metadata schema 9, observed {}",
            document.schema_version
        ))
        .into());
    }
    document
        .execs
        .into_iter()
        .find(|exec| exec.exec_id == EXEC_ID)
        .ok_or_else(|| qualification_error(format!("shim metadata omitted exec {EXEC_ID}")).into())
}

async fn commit_runtime_signal(
    config: &QualificationConfig,
    task_id: &str,
    identity: &RuntimeIdentity,
    target: &ProcessTarget,
) -> TestResult<()> {
    let request = SignalProcessRequest {
        context: OperationContext::new(faults::containerd_exec_operation_id(
            &config.namespace,
            task_id,
            &identity.incarnation,
            EXEC_ID,
            1,
            &format!("signal-{SIGNAL_SEQUENCE}"),
        )?),
        process: target.clone(),
        signal: Signal::new(libc::SIGTERM).map_err(|error| {
            qualification_error(format!("validate committed terminal exec signal: {error}"))
        })?,
    };
    let client = faults::runtime_client(config).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.signal_process(request.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact Runtime terminal SignalProcess before shim replacement: {error}"
                ))
                .into());
            }
        }
    }
}

async fn exact_runtime_wait_process(
    config: &QualificationConfig,
    target: &ProcessTarget,
) -> TestResult<ExitStatus> {
    faults::runtime_client(config)
        .await?
        .wait_process(RuntimeWaitProcessRequest {
            process: target.clone(),
            timeout_ms: Some(5_000),
        })
        .await
        .map_err(|error| {
            qualification_error(format!("wait for exact Runtime exec exit: {error}")).into()
        })
}

async fn require_runtime_exec_absent(
    config: &QualificationConfig,
    identity: &RuntimeIdentity,
    target: &ProcessTarget,
) -> TestResult<()> {
    let inventory = faults::runtime_client(config)
        .await?
        .processes(ProcessesRequest {
            target: ContainerTarget::exact(
                identity.container_id.clone(),
                Generation(identity.generation),
            ),
        })
        .await
        .map_err(|error| {
            qualification_error(format!(
                "read Runtime inventory after terminal SignalProcess: {error}"
            ))
        })?;
    if inventory.iter().any(|process| process.target == *target) {
        return Err(qualification_error(format!(
            "Runtime inventory retained exited exec {target:?}: {inventory:?}"
        ))
        .into());
    }
    Ok(())
}

fn exact_exec_target(
    config: &QualificationConfig,
    task_id: &str,
    identity: &RuntimeIdentity,
) -> TestResult<ProcessTarget> {
    Ok(ProcessTarget {
        container: ContainerTarget::exact(
            identity.container_id.clone(),
            Generation(identity.generation),
        ),
        process_id: faults::containerd_process_id(&config.namespace, task_id, EXEC_ID, 1)?,
    })
}

fn require_exit(exit: &ExitStatus, context: &str) -> TestResult<()> {
    if exit.exit_code != Some(i32::try_from(EXEC_EXIT_STATUS).expect("bounded exit status"))
        || exit.signal.is_some()
        || exit.oom_killed
    {
        return Err(qualification_error(format!(
            "{context} returned {exit:?}; expected normal exit {EXEC_EXIT_STATUS}"
        ))
        .into());
    }
    Ok(())
}

async fn require_lost_signal_response(
    signal_call: tokio::task::JoinHandle<TestResult<()>>,
) -> TestResult<()> {
    match tokio::time::timeout(Duration::from_secs(5), signal_call).await {
        Ok(Ok(Err(_))) => Ok(()),
        Ok(Ok(Ok(()))) => Err(qualification_error(
            "original terminal SignalProcess response survived after its frozen shim was killed",
        )
        .into()),
        Ok(Err(error)) => Err(qualification_error(format!(
            "original terminal SignalProcess task failed before reporting its lost response: {error}"
        ))
        .into()),
        Err(_) => Err(qualification_error(
            "original terminal SignalProcess call did not observe shim replacement within 5 seconds",
        )
        .into()),
    }
}

async fn shim_signal(address: &str, id: &str, signal: i32) -> TestResult<()> {
    let client = containerd_shim_protos::ttrpc::asynchronous::Client::connect(address)
        .await
        .map_err(|error| {
            qualification_error(format!(
                "connect committed terminal-SignalProcess shim at {address}: {error}"
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
    .map(drop)
    .map_err(|error| {
        qualification_error(format!(
            "invoke terminal SignalProcess through shim {address} for {id}/{EXEC_ID}: {error}"
        ))
        .into()
    })
}

async fn shim_wait(bootstrap: &Bootstrap, id: &str) -> TestResult<u32> {
    let client = containerd_shim_protos::ttrpc::asynchronous::Client::connect(&bootstrap.address)
        .await
        .map_err(|error| {
            qualification_error(format!(
                "connect committed terminal-SignalProcess replacement shim at {}: {error}",
                bootstrap.address
            ))
        })?;
    let task = containerd_shim_protos::shim::shim_ttrpc_async::TaskClient::new(client);
    let mut request = containerd_shim_protos::api::WaitRequest::new();
    request.set_id(id.to_string());
    request.set_exec_id(EXEC_ID.to_string());
    task.wait(
        containerd_shim_protos::ttrpc::context::Context::default(),
        &request,
    )
    .await
    .map(|response| response.exit_status())
    .map_err(|error| {
        qualification_error(format!(
            "invoke exec Wait through replacement shim {} for {id}/{EXEC_ID}: {error}",
            bootstrap.address
        ))
        .into()
    })
}
