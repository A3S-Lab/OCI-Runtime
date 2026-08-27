use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerRecord, ContainerTarget, ExitStatus, Generation, WaitRequest as RuntimeWaitRequest,
};
use serde::Deserialize;

use super::{
    kill, launch_replacement_while_containerd_suspended, lifecycle, load_bootstrap,
    load_shim_binary, stop_replacement, wait_for_pid_exit, wait_for_replacement_exit,
};
use crate::api::{CreateTaskRequest, DeleteTaskRequest, StartRequest, TasksClient, WaitRequest};
use crate::faults;
use crate::support::{
    connect_ready, containerd_main_pid, create_container, delete_container, expect_process,
    namespaced, optional_task_process, qualification_error, read_runtime_identity,
    restart_containerd, rpc_error, task_process, task_rootfs, wait_for_bundle_removal,
    QualificationConfig, RuntimeIdentity, TestResult, STATUS_RUNNING, STATUS_STOPPED,
};

const TERMINAL_EXIT_CODE: i32 = 42;

#[derive(Debug, Deserialize)]
struct TerminalKillEvidence {
    schema_version: u64,
    #[serde(default)]
    signal_sequence: u64,
    #[serde(default)]
    pending_signal: Option<serde_json::Value>,
    exit: Option<ExitStatus>,
    exited_at_unix_nanos: Option<u128>,
}

pub(super) async fn qualify_committed_terminal_init_kill(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let id = format!("{prefix}-committed-terminal-kill-rehydrate");
    create_container(config, &id).await?;
    let channel = connect_ready(config).await?;
    let rootfs = task_rootfs(config, &channel, &id).await?;
    let created = TasksClient::new(channel.clone())
        .create(namespaced(
            CreateTaskRequest {
                container_id: id.clone(),
                rootfs,
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("create committed terminal-Kill task", error))?
        .into_inner();
    if created.pid == 0 {
        return Err(
            qualification_error("committed terminal-Kill task Create returned PID zero").into(),
        );
    }
    let started = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: id.clone(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("start committed terminal-Kill task", error))?
        .into_inner();
    if started.pid != created.pid {
        return Err(qualification_error(format!(
            "committed terminal-Kill task PID changed from {} to {} at Start",
            created.pid, started.pid
        ))
        .into());
    }
    expect_process(
        &task_process(config, &channel, &id, "").await?,
        STATUS_RUNNING,
        Some(created.pid),
        "init before committed terminal Kill",
    )?;

    let bundle = config.bundle(&id);
    let identity = read_runtime_identity(config, &id).await?;
    let bootstrap = load_bootstrap(&bundle).await?;
    let binary = load_shim_binary(&bundle).await?;
    let running = lifecycle::exact_runtime_state(config, &identity).await?;
    validate_running_record(&running, &identity, created.pid)?;

    let host_pid = faults::find_runtime_host_pid(config).await?;
    let mut suspended_host =
        faults::SuspendedProcess::stop(host_pid, "committed terminal-Kill A3S OCI host service")?;
    let kill_address = bootstrap.address.clone();
    let kill_id = id.clone();
    let mut kill_call =
        tokio::spawn(
            async move { kill::shim_kill(&kill_address, &kill_id, libc::SIGTERM, true).await },
        );
    kill::wait_for_pending_signal(&bundle, 0, 1, libc::SIGTERM, true, &mut kill_call).await?;
    let old_shim_pid = faults::find_exact_shim_pid(config, &id).await?;
    let suspended_shim =
        faults::SuspendedProcess::stop(old_shim_pid, "committed terminal-Kill original shim")?;
    suspended_host.resume("committed terminal-Kill A3S OCI host service")?;
    let committed =
        kill::commit_runtime_kill(config, &id, &identity, 1, libc::SIGTERM, true).await?;
    validate_stable_record(&running, &committed, &identity)?;
    let runtime_exit = exact_runtime_wait(config, &identity).await?;
    require_exit(
        &runtime_exit,
        "exact Runtime Wait after committed terminal Kill",
    )?;
    let stopped = lifecycle::exact_runtime_state(config, &identity).await?;
    validate_stopped_record(&running, &stopped, &identity)?;
    wait_for_pid_exit(created.pid, "committed terminal-Kill init").await?;

    let containerd_pid = containerd_main_pid(config).await?;
    faults::send_signal(
        containerd_pid,
        libc::SIGSTOP,
        "committed terminal-Kill containerd",
    )?;
    let mut replacement = None;
    let relaunch = async {
        suspended_shim.kill("committed terminal-Kill original shim")?;
        wait_for_pid_exit(old_shim_pid, "committed terminal-Kill original shim").await?;
        launch_replacement_while_containerd_suspended(
            config,
            &id,
            &bundle,
            &binary,
            &bootstrap,
            containerd_pid,
            &mut replacement,
        )
        .await
    }
    .await;
    let _ = faults::send_signal(
        containerd_pid,
        libc::SIGCONT,
        "committed terminal-Kill containerd",
    );
    if let Err(error) = relaunch {
        kill_call.abort();
        let _ = kill_call.await;
        stop_replacement(&mut replacement).await;
        let recovery =
            restart_containerd(config, "failed-committed-terminal-Kill-rehydration").await;
        return match recovery {
            Ok(_) => Err(error),
            Err(recovery_error) => Err(qualification_error(format!(
                "committed terminal Kill replacement failed: {error}; containerd recovery also failed: {recovery_error}"
            ))
            .into()),
        };
    }

    let mut replacement = replacement.ok_or_else(|| {
        qualification_error("committed terminal-Kill relaunch omitted its child process")
    })?;
    let replacement_pid = replacement
        .id()
        .ok_or_else(|| qualification_error("committed terminal-Kill replacement has no PID"))?;
    wait_for_settled_terminal_kill(&bundle, &runtime_exit).await?;
    if read_runtime_identity(config, &id).await? != identity {
        return Err(qualification_error(
            "committed terminal Kill replacement changed the task incarnation or generation",
        )
        .into());
    }
    let observed_shim_pid = faults::find_exact_shim_pid(config, &id).await?;
    if observed_shim_pid != replacement_pid {
        return Err(qualification_error(format!(
            "committed terminal-Kill shim PID was {observed_shim_pid}, expected replacement PID {replacement_pid}"
        ))
        .into());
    }
    let replacement_exit = shim_wait(&bootstrap.address, &id).await?;
    if replacement_exit != u32::try_from(TERMINAL_EXIT_CODE).expect("positive exit code") {
        return Err(qualification_error(format!(
            "replacement shim Wait returned {replacement_exit}, expected {TERMINAL_EXIT_CODE}"
        ))
        .into());
    }

    let channel = restart_containerd(config, "committed-terminal-Kill-shim-rehydration").await?;
    kill::require_lost_kill_response(kill_call).await?;
    match optional_task_process(config, &channel, &id, "").await? {
        Some(process) => {
            expect_process(
                &process,
                STATUS_STOPPED,
                None,
                "init after committed terminal Kill replacement",
            )?;
            if process.exit_status != u32::try_from(TERMINAL_EXIT_CODE).expect("positive exit code")
            {
                return Err(qualification_error(format!(
                    "rehydrated stopped init reported exit {}, expected {TERMINAL_EXIT_CODE}",
                    process.exit_status
                ))
                .into());
            }
            let waited = TasksClient::new(channel.clone())
                .wait(namespaced(
                    WaitRequest {
                        container_id: id.clone(),
                        ..Default::default()
                    },
                    &config.namespace,
                )?)
                .await
                .map_err(|error| rpc_error("wait committed terminal-Kill task", error))?
                .into_inner();
            if waited.exit_status != u32::try_from(TERMINAL_EXIT_CODE).expect("positive exit code")
            {
                return Err(qualification_error(format!(
                    "containerd Wait after terminal-Kill replacement returned {}, expected {TERMINAL_EXIT_CODE}",
                    waited.exit_status
                ))
                .into());
            }
            let deleted = TasksClient::new(channel)
                .delete(namespaced(
                    DeleteTaskRequest {
                        container_id: id.clone(),
                    },
                    &config.namespace,
                )?)
                .await
                .map_err(|error| rpc_error("delete committed terminal-Kill task", error))?
                .into_inner();
            if deleted.exit_status != u32::try_from(TERMINAL_EXIT_CODE).expect("positive exit code")
            {
                return Err(qualification_error(format!(
                    "containerd Delete after terminal-Kill replacement returned {}, expected {TERMINAL_EXIT_CODE}",
                    deleted.exit_status
                ))
                .into());
            }
        }
        None => wait_for_bundle_removal(config, &id).await?,
    }
    delete_container(config, &id).await?;
    wait_for_replacement_exit(&mut replacement).await
}

async fn exact_runtime_wait(
    config: &QualificationConfig,
    identity: &RuntimeIdentity,
) -> TestResult<ExitStatus> {
    faults::runtime_client(config)
        .await?
        .wait(RuntimeWaitRequest {
            target: ContainerTarget::exact(
                identity.container_id.clone(),
                Generation(identity.generation),
            ),
            timeout_ms: Some(5_000),
        })
        .await
        .map_err(|error| {
            qualification_error(format!("wait for exact Runtime exit: {error}")).into()
        })
}

fn validate_running_record(
    record: &ContainerRecord,
    identity: &RuntimeIdentity,
    pid: u32,
) -> TestResult<()> {
    let expected_pid = i32::try_from(pid).map_err(|_| {
        qualification_error(format!(
            "containerd PID {pid} does not fit the OCI State PID field"
        ))
    })?;
    if record.state.id() != identity.container_id.as_str()
        || record.generation.0 != identity.generation
        || *record.state.status() != ContainerState::Running
        || *record.state.pid() != Some(expected_pid)
    {
        return Err(qualification_error(format!(
            "runtime record before committed terminal Kill was {record:?}; expected exact running generation {} with PID {pid}",
            identity.generation
        ))
        .into());
    }
    Ok(())
}

fn validate_stable_record(
    before: &ContainerRecord,
    after: &ContainerRecord,
    identity: &RuntimeIdentity,
) -> TestResult<()> {
    if after.state.id() != identity.container_id.as_str()
        || after.generation != before.generation
        || after.driver != before.driver
        || after.isolation != before.isolation
        || after.config_digest != before.config_digest
        || after.attachments_digest != before.attachments_digest
    {
        return Err(qualification_error(format!(
            "committed terminal Kill changed the exact Runtime identity: before={before:?} after={after:?}"
        ))
        .into());
    }
    Ok(())
}

fn validate_stopped_record(
    before: &ContainerRecord,
    after: &ContainerRecord,
    identity: &RuntimeIdentity,
) -> TestResult<()> {
    validate_stable_record(before, after, identity)?;
    if *after.state.status() != ContainerState::Stopped || after.state.pid().is_some() {
        return Err(qualification_error(format!(
            "Runtime record after committed terminal Kill was {after:?}; expected Stopped without a live PID"
        ))
        .into());
    }
    Ok(())
}

fn require_exit(exit: &ExitStatus, context: &str) -> TestResult<()> {
    if exit.exit_code != Some(TERMINAL_EXIT_CODE) || exit.signal.is_some() || exit.oom_killed {
        return Err(qualification_error(format!(
            "{context} returned {exit:?}; expected normal exit {TERMINAL_EXIT_CODE}"
        ))
        .into());
    }
    Ok(())
}

async fn wait_for_settled_terminal_kill(
    bundle: &Path,
    expected_exit: &ExitStatus,
) -> TestResult<()> {
    let path = bundle.join("a3s-oci-shim-v1.json");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let evidence: TerminalKillEvidence = serde_json::from_slice(
            &tokio::fs::read(&path)
                .await
                .map_err(|error| qualification_error(format!("read shim metadata: {error}")))?,
        )
        .map_err(|error| qualification_error(format!("decode shim metadata: {error}")))?;
        if evidence.schema_version == 10
            && evidence.signal_sequence == 1
            && evidence.pending_signal.is_none()
            && evidence.exit.as_ref() == Some(expected_exit)
            && evidence.exited_at_unix_nanos.is_some_and(|value| value > 0)
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(qualification_error(format!(
                "replacement did not settle committed terminal Kill from durable Runtime exit: {evidence:?}"
            ))
            .into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn shim_wait(address: &str, id: &str) -> TestResult<u32> {
    let client = containerd_shim_protos::ttrpc::asynchronous::Client::connect(address)
        .await
        .map_err(|error| {
            qualification_error(format!(
                "connect committed terminal-Kill shim at {address}: {error}"
            ))
        })?;
    let task = containerd_shim_protos::shim::shim_ttrpc_async::TaskClient::new(client);
    let mut request = containerd_shim_protos::api::WaitRequest::new();
    request.set_id(id.to_string());
    task.wait(
        containerd_shim_protos::ttrpc::context::Context::default(),
        &request,
    )
    .await
    .map(|response| response.exit_status())
    .map_err(|error| {
        qualification_error(format!(
            "invoke Wait through replacement shim {address} for {id}: {error}"
        ))
        .into()
    })
}
