use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerRecord, ContainerTarget, Generation, OperationContext,
    StartRequest as RuntimeStartRequest, StateRequest,
};

use super::{
    launch_replacement_while_containerd_suspended, load_bootstrap, load_shim_binary,
    stop_replacement, wait_for_pid_exit, wait_for_replacement_exit,
};
use crate::api::{
    CreateTaskRequest, DeleteTaskRequest, KillRequest, StartRequest, TasksClient, WaitRequest,
};
use crate::faults;
use crate::support::{
    connect_ready, containerd_main_pid, create_container, delete_container, expect_process,
    namespaced, qualification_error, read_runtime_identity, restart_containerd, rpc_error,
    task_process, task_rootfs, QualificationConfig, RuntimeIdentity, TestResult, STATUS_RUNNING,
};

pub(super) async fn qualify_committed_init_start(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let id = format!("{prefix}-committed-start-rehydrate");
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
        .map_err(|error| rpc_error("create committed-Start rehydration task", error))?
        .into_inner();
    if created.pid == 0 {
        return Err(
            qualification_error("committed-Start rehydration Create returned PID zero").into(),
        );
    }

    let bundle = config.bundle(&id);
    let identity = read_runtime_identity(config, &id).await?;
    let bootstrap = load_bootstrap(&bundle).await?;
    let binary = load_shim_binary(&bundle).await?;
    let before = exact_runtime_state(config, &identity).await?;
    validate_created_record(&before, &identity, created.pid)?;

    let host_pid = faults::find_runtime_host_pid(config).await?;
    let mut suspended_host =
        faults::SuspendedProcess::stop(host_pid, "committed-Start A3S OCI host service")?;
    let start_address = bootstrap.address.clone();
    let start_id = id.clone();
    let mut start_call =
        tokio::spawn(async move { shim_start(&start_address, &start_id, "").await });
    if tokio::time::timeout(Duration::from_millis(100), &mut start_call)
        .await
        .is_ok()
    {
        return Err(qualification_error(
            "Start completed while the exact A3S OCI host service was suspended",
        )
        .into());
    }

    let old_shim_pid = faults::find_exact_shim_pid(config, &id).await?;
    let suspended_shim =
        faults::SuspendedProcess::stop(old_shim_pid, "committed-Start original shim")?;
    suspended_host.resume("committed-Start A3S OCI host service")?;
    let committed = commit_runtime_start(config, &id, &identity).await?;
    validate_started_record(&before, &committed, &identity, created.pid)?;

    let containerd_pid = containerd_main_pid(config).await?;
    faults::send_signal(containerd_pid, libc::SIGSTOP, "committed-Start containerd")?;
    let mut replacement = None;
    let relaunch = async {
        suspended_shim.kill("committed-Start original shim")?;
        wait_for_pid_exit(old_shim_pid, "committed-Start original shim").await?;
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
    let _ = faults::send_signal(containerd_pid, libc::SIGCONT, "committed-Start containerd");
    if let Err(error) = relaunch {
        start_call.abort();
        let _ = start_call.await;
        stop_replacement(&mut replacement).await;
        let recovery = restart_containerd(config, "failed-committed-Start-rehydration").await;
        return match recovery {
            Ok(_) => Err(error),
            Err(recovery_error) => Err(qualification_error(format!(
                "committed Start replacement failed: {error}; containerd recovery also failed: {recovery_error}"
            ))
            .into()),
        };
    }

    let mut replacement = replacement
        .ok_or_else(|| qualification_error("committed-Start relaunch omitted its child process"))?;
    let replacement_pid = replacement
        .id()
        .ok_or_else(|| qualification_error("committed-Start replacement has no PID"))?;
    let channel = restart_containerd(config, "committed-Start-shim-rehydration").await?;
    require_lost_start_response(start_call, "init").await?;

    expect_process(
        &task_process(config, &channel, &id, "").await?,
        STATUS_RUNNING,
        Some(created.pid),
        "task after committed Start replacement",
    )?;
    if read_runtime_identity(config, &id).await? != identity {
        return Err(qualification_error(
            "committed Start replacement changed the task incarnation or generation",
        )
        .into());
    }
    let observed_shim_pid = faults::find_exact_shim_pid(config, &id).await?;
    if observed_shim_pid != replacement_pid {
        return Err(qualification_error(format!(
            "containerd connected committed-Start shim PID {observed_shim_pid}, expected {replacement_pid}"
        ))
        .into());
    }

    let replayed = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: id.clone(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("replay Start through replacement shim", error))?
        .into_inner();
    if replayed.pid != created.pid {
        return Err(qualification_error(format!(
            "replayed Start returned PID {}, expected original PID {}",
            replayed.pid, created.pid
        ))
        .into());
    }
    let after_replay = exact_runtime_state(config, &identity).await?;
    validate_started_record(&before, &after_replay, &identity, created.pid)?;

    TasksClient::new(channel.clone())
        .kill(namespaced(
            KillRequest {
                container_id: id.clone(),
                signal: 9,
                all: true,
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("kill committed-Start rehydration task", error))?;
    let exit = TasksClient::new(channel.clone())
        .wait(namespaced(
            WaitRequest {
                container_id: id.clone(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("wait committed-Start rehydration task", error))?
        .into_inner();
    if exit.exit_status != 137 {
        return Err(qualification_error(format!(
            "committed-Start rehydration task exited {}, expected 137",
            exit.exit_status
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
        .map_err(|error| rpc_error("delete committed-Start rehydration task", error))?
        .into_inner();
    if deleted.exit_status != 137 {
        return Err(qualification_error(format!(
            "committed-Start rehydration Delete returned {}, expected 137",
            deleted.exit_status
        ))
        .into());
    }
    delete_container(config, &id).await?;
    wait_for_replacement_exit(&mut replacement).await
}

pub(super) async fn exact_runtime_state(
    config: &QualificationConfig,
    identity: &RuntimeIdentity,
) -> TestResult<ContainerRecord> {
    faults::runtime_client(config)
        .await?
        .state(StateRequest {
            target: ContainerTarget::exact(
                identity.container_id.clone(),
                Generation(identity.generation),
            ),
        })
        .await
        .map_err(|error| qualification_error(format!("read exact runtime state: {error}")).into())
}

async fn commit_runtime_start(
    config: &QualificationConfig,
    task_id: &str,
    identity: &RuntimeIdentity,
) -> TestResult<ContainerRecord> {
    let client = faults::runtime_client(config).await?;
    let request = RuntimeStartRequest {
        context: OperationContext::new(faults::containerd_operation_id(
            &config.namespace,
            task_id,
            &identity.incarnation,
            "start",
        )?),
        target: ContainerTarget::exact(
            identity.container_id.clone(),
            Generation(identity.generation),
        ),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.start(request.clone()).await {
            Ok(record) => return Ok(record),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact Runtime Start before shim replacement: {error}"
                ))
                .into());
            }
        }
    }
}

pub(super) async fn shim_start(address: &str, id: &str, exec_id: &str) -> TestResult<()> {
    let client = containerd_shim_protos::ttrpc::asynchronous::Client::connect(address)
        .await
        .map_err(|error| {
            qualification_error(format!(
                "connect committed-Start shim at {address}: {error}"
            ))
        })?;
    let task = containerd_shim_protos::shim::shim_ttrpc_async::TaskClient::new(client);
    let mut request = containerd_shim_protos::api::StartRequest::new();
    request.set_id(id.to_string());
    request.set_exec_id(exec_id.to_string());
    task.start(
        containerd_shim_protos::ttrpc::context::Context::default(),
        &request,
    )
    .await
    .map(drop)
    .map_err(|error| {
        qualification_error(format!(
            "invoke Start through shim {address} for {id} exec {exec_id:?}: {error}"
        ))
        .into()
    })
}

pub(super) async fn require_lost_start_response(
    start_call: tokio::task::JoinHandle<TestResult<()>>,
    process: &str,
) -> TestResult<()> {
    match tokio::time::timeout(Duration::from_secs(5), start_call).await {
        Ok(Ok(Err(_))) => Ok(()),
        Ok(Ok(Ok(()))) => Err(qualification_error(format!(
            "original {process} Start response survived after its frozen shim was killed"
        ))
        .into()),
        Ok(Err(error)) => Err(qualification_error(format!(
            "original {process} Start task failed before reporting its lost response: {error}"
        ))
        .into()),
        Err(_) => Err(qualification_error(format!(
            "original {process} Start call did not observe shim replacement within 5 seconds"
        ))
        .into()),
    }
}

fn validate_created_record(
    record: &ContainerRecord,
    identity: &RuntimeIdentity,
    expected_pid: u32,
) -> TestResult<()> {
    if record.generation != Generation(identity.generation)
        || *record.state.status() != ContainerState::Created
        || record.state.pid().and_then(|pid| u32::try_from(pid).ok()) != Some(expected_pid)
    {
        return Err(qualification_error(format!(
            "pre-Start runtime state was generation {}, status {}, PID {:?}; expected generation {}, created, PID {expected_pid}",
            record.generation.0,
            record.state.status(),
            record.state.pid(),
            identity.generation
        ))
        .into());
    }
    Ok(())
}

fn validate_started_record(
    before: &ContainerRecord,
    record: &ContainerRecord,
    identity: &RuntimeIdentity,
    expected_pid: u32,
) -> TestResult<()> {
    if record.generation != Generation(identity.generation)
        || *record.state.status() != ContainerState::Running
        || record.state.pid().and_then(|pid| u32::try_from(pid).ok()) != Some(expected_pid)
        || record.driver != before.driver
        || record.isolation != before.isolation
        || record.config_digest != before.config_digest
        || record.attachments_digest != before.attachments_digest
    {
        return Err(qualification_error(format!(
            "committed Start returned generation {}, status {}, PID {:?}, driver {:?}, isolation {:?}; expected generation {}, running, PID {expected_pid}, driver {:?}, isolation {:?}, and unchanged configuration/attachments",
            record.generation.0,
            record.state.status(),
            record.state.pid(),
            record.driver,
            record.isolation,
            identity.generation,
            before.driver,
            before.isolation
        ))
        .into());
    }
    Ok(())
}
