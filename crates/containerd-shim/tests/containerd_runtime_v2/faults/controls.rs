use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, LinuxResources};
use a3s_oci_sdk::{
    ContainerOperationRequest, ContainerRecord, ContainerTarget, Generation, OperationContext,
    StatsRequest, UpdateRequest, PIDS_LIMIT_METRIC,
};
use tonic::transport::Channel;

use crate::api::{
    ContainersClient, CreateTaskRequest, GetContainerRequest, PauseTaskRequest, TasksClient,
};
use crate::support::*;

use super::shared::{containerd_operation_id, runtime_client};
use super::{find_exact_shim_pid, signal_kill, wait_for_runtime_absence, wait_for_shim_cleanup};

struct RunningTask {
    id: String,
    channel: Channel,
    pid: u32,
    identity: RuntimeIdentity,
}

pub(super) async fn qualify_pause_effect_committed_shim_sigkill(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let task = create_running_task(config, format!("{prefix}-shim-kill-pause-committed")).await?;
    let paused = pause_runtime_generation(config, &task).await?;
    if paused.generation != Generation(task.identity.generation)
        || *paused.state.status() != ContainerState::Running
        || !paused.is_paused()
    {
        return Err(qualification_error(format!(
            "stable runtime Pause returned generation {}, status {}, paused={}; expected generation {}, running and paused",
            paused.generation.0,
            paused.state.status(),
            paused.is_paused(),
            task.identity.generation
        ))
        .into());
    }
    cleanup_after_shim_death(config, task, "Pause").await
}

pub(super) async fn qualify_resume_effect_committed_shim_sigkill(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let task = create_running_task(config, format!("{prefix}-shim-kill-resume-committed")).await?;
    TasksClient::new(task.channel.clone())
        .pause(namespaced(
            PauseTaskRequest {
                container_id: task.id.clone(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("pause resume-committed task", error))?;
    expect_process(
        &task_process(config, &task.channel, &task.id, "").await?,
        STATUS_PAUSED,
        Some(task.pid),
        "resume-committed task before direct Resume",
    )?;

    let resumed = resume_runtime_generation(config, &task).await?;
    if resumed.generation != Generation(task.identity.generation)
        || *resumed.state.status() != ContainerState::Running
        || resumed.is_paused()
    {
        return Err(qualification_error(format!(
            "stable runtime Resume returned generation {}, status {}, paused={}; expected generation {}, running and unpaused",
            resumed.generation.0,
            resumed.state.status(),
            resumed.is_paused(),
            task.identity.generation
        ))
        .into());
    }
    cleanup_after_shim_death(config, task, "Resume").await
}

pub(super) async fn qualify_update_effect_committed_shim_sigkill(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    const EXPECTED_PIDS_LIMIT: u64 = 63;

    let task = create_running_task(config, format!("{prefix}-shim-kill-update-committed")).await?;
    let resources: LinuxResources = serde_json::from_value(serde_json::json!({
        "pids": {"limit": EXPECTED_PIDS_LIMIT}
    }))
    .map_err(|error| qualification_error(format!("build committed Update resources: {error}")))?;
    let updated = update_runtime_generation(config, &task, resources).await?;
    if updated.generation != Generation(task.identity.generation)
        || *updated.state.status() != ContainerState::Running
    {
        return Err(qualification_error(format!(
            "stable runtime Update returned generation {} and status {}; expected generation {} and running",
            updated.generation.0,
            updated.state.status(),
            task.identity.generation
        ))
        .into());
    }
    let stats = runtime_client(config)
        .await?
        .stats(StatsRequest {
            target: ContainerTarget::exact(
                task.identity.container_id.clone(),
                Generation(task.identity.generation),
            ),
        })
        .await
        .map_err(|error| {
            qualification_error(format!(
                "read stats after committed runtime Update: {error}"
            ))
        })?;
    if stats.metrics.get(PIDS_LIMIT_METRIC) != Some(&EXPECTED_PIDS_LIMIT) {
        return Err(qualification_error(format!(
            "committed runtime Update reported {}={:?}, expected {EXPECTED_PIDS_LIMIT}",
            PIDS_LIMIT_METRIC,
            stats.metrics.get(PIDS_LIMIT_METRIC)
        ))
        .into());
    }
    cleanup_after_shim_death(config, task, "Update").await
}

async fn create_running_task(config: &QualificationConfig, id: String) -> TestResult<RunningTask> {
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
        .map_err(|error| rpc_error("create committed-control task", error))?
        .into_inner();
    let started = TasksClient::new(channel.clone())
        .start(namespaced(
            crate::api::StartRequest {
                container_id: id.clone(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("start committed-control task", error))?
        .into_inner();
    if created.pid == 0 || started.pid != created.pid {
        return Err(qualification_error(format!(
            "committed-control task {id} PIDs were create={} and start={}; expected one stable nonzero PID",
            created.pid, started.pid
        ))
        .into());
    }
    Ok(RunningTask {
        identity: read_runtime_identity(config, &id).await?,
        id,
        channel,
        pid: started.pid,
    })
}

async fn cleanup_after_shim_death(
    config: &QualificationConfig,
    task: RunningTask,
    operation: &str,
) -> TestResult<()> {
    let shim_pid = find_exact_shim_pid(config, &task.id).await?;
    signal_kill(shim_pid)?;
    wait_for_shim_cleanup(config, &task.channel, &task.id, shim_pid, &[task.pid]).await?;
    wait_for_runtime_absence(config, task.identity.container_id).await?;
    ContainersClient::new(task.channel)
        .get(namespaced(
            GetContainerRequest {
                id: task.id.clone(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| {
            rpc_error(
                &format!(
                    "read caller-owned metadata after committed runtime {operation} and shim SIGKILL"
                ),
                error,
            )
        })?;
    delete_container(config, &task.id).await
}

async fn pause_runtime_generation(
    config: &QualificationConfig,
    task: &RunningTask,
) -> TestResult<ContainerRecord> {
    let client = runtime_client(config).await?;
    let request = ContainerOperationRequest {
        context: OperationContext::new(containerd_operation_id(
            &config.namespace,
            &task.id,
            &task.identity.incarnation,
            "pause",
        )?),
        target: ContainerTarget::exact(
            task.identity.container_id.clone(),
            Generation(task.identity.generation),
        ),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.pause(request.clone()).await {
            Ok(record) => return Ok(record),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact runtime Pause before shim death: {error}"
                ))
                .into());
            }
        }
    }
}

async fn resume_runtime_generation(
    config: &QualificationConfig,
    task: &RunningTask,
) -> TestResult<ContainerRecord> {
    let client = runtime_client(config).await?;
    let request = ContainerOperationRequest {
        context: OperationContext::new(containerd_operation_id(
            &config.namespace,
            &task.id,
            &task.identity.incarnation,
            "resume",
        )?),
        target: ContainerTarget::exact(
            task.identity.container_id.clone(),
            Generation(task.identity.generation),
        ),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.resume(request.clone()).await {
            Ok(record) => return Ok(record),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact runtime Resume before shim death: {error}"
                ))
                .into());
            }
        }
    }
}

async fn update_runtime_generation(
    config: &QualificationConfig,
    task: &RunningTask,
    resources: LinuxResources,
) -> TestResult<ContainerRecord> {
    let client = runtime_client(config).await?;
    let request = UpdateRequest {
        context: OperationContext::new(containerd_operation_id(
            &config.namespace,
            &task.id,
            &task.identity.incarnation,
            "update",
        )?),
        target: ContainerTarget::exact(
            task.identity.container_id.clone(),
            Generation(task.identity.generation),
        ),
        resources,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.update(request.clone()).await {
            Ok(record) => return Ok(record),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact runtime Update before shim death: {error}"
                ))
                .into());
            }
        }
    }
}
