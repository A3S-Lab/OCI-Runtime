use tonic::transport::Channel;

use super::api::{
    CreateTaskRequest, DeleteTaskRequest, KillRequest, StartRequest, TasksClient, WaitRequest,
};
use super::support::*;

struct RunningTask {
    id: String,
    pid: u32,
    identity: RuntimeIdentity,
}

pub(crate) async fn qualify_parallel_tasks(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let ids = [
        format!("{prefix}-parallel-0"),
        format!("{prefix}-parallel-1"),
        format!("{prefix}-parallel-2"),
        format!("{prefix}-parallel-3"),
    ];
    for id in &ids {
        create_container(config, id).await?;
    }
    let channel = connect_ready(config).await?;
    let (first, second, third, fourth) = tokio::try_join!(
        create_and_start(config, channel.clone(), ids[0].clone()),
        create_and_start(config, channel.clone(), ids[1].clone()),
        create_and_start(config, channel.clone(), ids[2].clone()),
        create_and_start(config, channel.clone(), ids[3].clone()),
    )?;
    let tasks = [first, second, third, fourth];
    for (index, task) in tasks.iter().enumerate() {
        if tasks[..index]
            .iter()
            .any(|other| other.identity == task.identity)
        {
            return Err(qualification_error(format!(
                "parallel task {} reused another task's runtime identity",
                task.id
            ))
            .into());
        }
    }

    let channel = restart_containerd(config, "parallel-running").await?;
    for task in &tasks {
        expect_process(
            &task_process(config, &channel, &task.id, "").await?,
            STATUS_RUNNING,
            Some(task.pid),
            &format!("parallel task {} after containerd restart", task.id),
        )?;
        if read_runtime_identity(config, &task.id).await? != task.identity {
            return Err(qualification_error(format!(
                "parallel task {} changed runtime identity across restart",
                task.id
            ))
            .into());
        }
    }

    tokio::try_join!(
        stop_and_delete(config, channel.clone(), &tasks[0]),
        stop_and_delete(config, channel.clone(), &tasks[1]),
        stop_and_delete(config, channel.clone(), &tasks[2]),
        stop_and_delete(config, channel, &tasks[3]),
    )?;
    for id in &ids {
        delete_container(config, id).await?;
    }
    Ok(())
}

async fn create_and_start(
    config: &QualificationConfig,
    channel: Channel,
    id: String,
) -> TestResult<RunningTask> {
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
        .map_err(|error| rpc_error("create parallel task", error))?
        .into_inner();
    let started = TasksClient::new(channel)
        .start(namespaced(
            StartRequest {
                container_id: id.clone(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("start parallel task", error))?
        .into_inner();
    if created.pid == 0 || started.pid != created.pid {
        return Err(qualification_error(format!(
            "parallel task {id} PIDs were create={} and start={}; expected one stable nonzero PID",
            created.pid, started.pid
        ))
        .into());
    }
    Ok(RunningTask {
        identity: read_runtime_identity(config, &id).await?,
        id,
        pid: started.pid,
    })
}

async fn stop_and_delete(
    config: &QualificationConfig,
    channel: Channel,
    task: &RunningTask,
) -> TestResult<()> {
    TasksClient::new(channel.clone())
        .kill(namespaced(
            KillRequest {
                container_id: task.id.clone(),
                signal: 9,
                all: true,
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("kill parallel task", error))?;
    let exit = TasksClient::new(channel.clone())
        .wait(namespaced(
            WaitRequest {
                container_id: task.id.clone(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("wait parallel task", error))?
        .into_inner();
    if exit.exit_status != 137 {
        return Err(qualification_error(format!(
            "parallel task {} exited {}, expected 137",
            task.id, exit.exit_status
        ))
        .into());
    }
    let deleted = TasksClient::new(channel)
        .delete(namespaced(
            DeleteTaskRequest {
                container_id: task.id.clone(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("delete parallel task", error))?
        .into_inner();
    if deleted.exit_status != 137 {
        return Err(qualification_error(format!(
            "parallel task {} Delete returned {}, expected 137",
            task.id, deleted.exit_status
        ))
        .into());
    }
    Ok(())
}
