#![cfg(target_os = "linux")]

use std::time::{SystemTime, UNIX_EPOCH};

#[path = "containerd_runtime_v2/api.rs"]
mod api;
#[path = "containerd_runtime_v2/faults.rs"]
mod faults;
#[path = "containerd_runtime_v2/parallel.rs"]
mod parallel;
#[path = "containerd_runtime_v2/rehydration.rs"]
mod rehydration;
#[path = "containerd_runtime_v2/stdio.rs"]
mod stdio;
#[path = "containerd_runtime_v2/support.rs"]
mod support;
#[path = "containerd_runtime_v2/terminal.rs"]
mod terminal;

use api::{
    CreateTaskRequest, DeleteProcessRequest, DeleteTaskRequest, ExecProcessRequest, KillRequest,
    ListPidsRequest, MetricsRequest, PauseTaskRequest, ResumeTaskRequest, StartRequest,
    TasksClient, UpdateTaskRequest, WaitRequest,
};
use prost_types::Any;
use support::*;
use tonic::transport::Channel;

const PROCESS_SPEC_TYPE: &str = "types.containerd.io/opencontainers/runtime-spec/1/Process";
const LINUX_RESOURCES_TYPE: &str =
    "types.containerd.io/opencontainers/runtime-spec/1/LinuxResources";

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires root, a live A3S OCI host service, containerd, ctr, and permission to restart containerd"]
async fn real_containerd_runtime_v2_qualification() -> TestResult<()> {
    let config = QualificationConfig::from_environment()?;
    require_root().await?;
    require_command("ctr").await?;
    require_command("systemctl").await?;
    connect_ready(&config).await?;

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| qualification_error(format!("system clock precedes Unix epoch: {error}")))?
        .as_nanos();
    let prefix = format!("a3s-r7-{}-{nonce:x}", std::process::id());
    let lifecycle_id = format!("{prefix}-lifecycle");
    let result = qualify(&config, &prefix, &lifecycle_id).await;
    let cleanup = cleanup_exact(&config, &prefix).await;
    match (result, cleanup) {
        (Err(error), Err(cleanup_error)) => Err(qualification_error(format!(
            "qualification failed: {error}; cleanup also failed: {cleanup_error}"
        ))
        .into()),
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

async fn qualify(config: &QualificationConfig, prefix: &str, lifecycle_id: &str) -> TestResult<()> {
    stdio::qualify_ctr_stdio(config, prefix).await?;
    create_container(config, lifecycle_id).await?;

    let mut channel = connect_ready(config).await?;
    let rootfs = task_rootfs(config, &channel, lifecycle_id).await?;
    let created = TasksClient::new(channel.clone())
        .create(namespaced(
            CreateTaskRequest {
                container_id: lifecycle_id.to_string(),
                rootfs,
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("create task", error))?
        .into_inner();
    if created.pid == 0 {
        return Err(qualification_error("containerd task Create returned PID zero").into());
    }
    expect_process(
        &task_process(config, &channel, lifecycle_id, "").await?,
        STATUS_CREATED,
        Some(created.pid),
        "created init",
    )?;
    let first_identity = read_runtime_identity(config, lifecycle_id).await?;

    channel = restart_containerd(config, "init-created").await?;
    expect_process(
        &task_process(config, &channel, lifecycle_id, "").await?,
        STATUS_CREATED,
        Some(created.pid),
        "created init after containerd restart",
    )?;

    let started = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: lifecycle_id.to_string(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("start init", error))?
        .into_inner();
    if started.pid != created.pid {
        return Err(qualification_error(format!(
            "init PID changed across Create/Start: {} -> {}",
            created.pid, started.pid
        ))
        .into());
    }
    expect_process(
        &task_process(config, &channel, lifecycle_id, "").await?,
        STATUS_RUNNING,
        Some(created.pid),
        "running init",
    )?;

    qualify_controls(config, &channel, lifecycle_id).await?;
    channel = restart_containerd(config, "init-running").await?;
    expect_process(
        &task_process(config, &channel, lifecycle_id, "").await?,
        STATUS_RUNNING,
        Some(created.pid),
        "running init after containerd restart",
    )?;

    qualify_exec_restart_boundaries(config, &mut channel, lifecycle_id).await?;
    terminal::qualify_terminal_exec_after_restart(config, &mut channel, lifecycle_id).await?;

    let init_wait = WaitRequest {
        container_id: lifecycle_id.to_string(),
        ..Default::default()
    };
    TasksClient::new(channel.clone())
        .kill(namespaced(
            KillRequest {
                container_id: lifecycle_id.to_string(),
                signal: 15,
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("signal init", error))?;
    let exit = TasksClient::new(channel.clone())
        .wait(namespaced(init_wait, &config.namespace)?)
        .await
        .map_err(|error| rpc_error("wait init", error))?
        .into_inner();
    if exit.exit_status != 42 {
        return Err(qualification_error(format!(
            "init SIGTERM exit status was {}, expected 42",
            exit.exit_status
        ))
        .into());
    }

    channel = restart_containerd(config, "init-stopped").await?;
    match optional_task_process(config, &channel, lifecycle_id, "").await? {
        Some(stopped) => {
            expect_process(&stopped, STATUS_STOPPED, None, "stopped init after restart")?;
            if stopped.exit_status != 42 {
                return Err(qualification_error(format!(
                    "rehydrated stopped init reported exit {}, expected 42",
                    stopped.exit_status
                ))
                .into());
            }
            let deleted = TasksClient::new(channel.clone())
                .delete(namespaced(
                    DeleteTaskRequest {
                        container_id: lifecycle_id.to_string(),
                    },
                    &config.namespace,
                )?)
                .await
                .map_err(|error| rpc_error("delete stopped task", error))?
                .into_inner();
            if deleted.exit_status != 42 {
                return Err(qualification_error(format!(
                    "Delete returned exit {}, expected 42",
                    deleted.exit_status
                ))
                .into());
            }
        }
        None => {
            // containerd 2.2 classifies an already-stopped shim as leaked
            // during daemon recovery. It calls DeleteShim, which replays the
            // shim's durable exit and force-cleans the exact runtime
            // generation. The container metadata remains caller-owned.
            wait_for_bundle_removal(config, lifecycle_id).await?;
        }
    }
    delete_container(config, lifecycle_id).await?;

    create_container(config, lifecycle_id).await?;
    channel = connect_ready(config).await?;
    let rootfs = task_rootfs(config, &channel, lifecycle_id).await?;
    TasksClient::new(channel.clone())
        .create(namespaced(
            CreateTaskRequest {
                container_id: lifecycle_id.to_string(),
                rootfs,
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("recreate task identity", error))?;
    let second_identity = read_runtime_identity(config, lifecycle_id).await?;
    if first_identity.incarnation == second_identity.incarnation {
        return Err(qualification_error(
            "recreated containerd task reused its prior incarnation identity",
        )
        .into());
    }
    if first_identity.generation == second_identity.generation {
        return Err(qualification_error(
            "recreated containerd task reused its prior runtime generation",
        )
        .into());
    }

    let second_start = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: lifecycle_id.to_string(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("start recreated task", error))?
        .into_inner();
    TasksClient::new(channel.clone())
        .kill(namespaced(
            KillRequest {
                container_id: lifecycle_id.to_string(),
                signal: 9,
                all: true,
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("kill recreated task", error))?;
    let forced_exit = TasksClient::new(channel.clone())
        .wait(namespaced(
            WaitRequest {
                container_id: lifecycle_id.to_string(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("wait recreated task", error))?
        .into_inner();
    if second_start.pid == 0 || forced_exit.exit_status != 137 {
        return Err(qualification_error(format!(
            "forced recreated task result was pid={}, exit={}; expected nonzero PID and 137",
            second_start.pid, forced_exit.exit_status
        ))
        .into());
    }
    TasksClient::new(channel)
        .delete(namespaced(
            DeleteTaskRequest {
                container_id: lifecycle_id.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("delete recreated task", error))?;
    delete_container(config, lifecycle_id).await?;
    rehydration::qualify_manual_shim_rehydration(config, prefix).await?;
    faults::qualify_shim_sigkill(config, prefix).await?;
    parallel::qualify_parallel_tasks(config, prefix).await?;
    Ok(())
}

async fn qualify_controls(
    config: &QualificationConfig,
    channel: &Channel,
    id: &str,
) -> TestResult<()> {
    let metrics = TasksClient::new(channel.clone())
        .metrics(namespaced(
            MetricsRequest {
                filters: vec![format!("id=={id}")],
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("read task metrics", error))?
        .into_inner();
    if metrics.metrics.len() != 1 || metrics.metrics[0].id != id {
        return Err(qualification_error(format!(
            "metrics returned identities {:?}, expected only {id}",
            metrics
                .metrics
                .iter()
                .map(|metric| metric.id.as_str())
                .collect::<Vec<_>>()
        ))
        .into());
    }

    TasksClient::new(channel.clone())
        .update(namespaced(
            UpdateTaskRequest {
                container_id: id.to_string(),
                resources: Some(Any {
                    type_url: LINUX_RESOURCES_TYPE.to_string(),
                    value: br#"{"pids":{"limit":64}}"#.to_vec(),
                }),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("update task resources", error))?;

    TasksClient::new(channel.clone())
        .pause(namespaced(
            PauseTaskRequest {
                container_id: id.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("pause task", error))?;
    expect_process(
        &task_process(config, channel, id, "").await?,
        STATUS_PAUSED,
        None,
        "paused init",
    )?;
    TasksClient::new(channel.clone())
        .resume(namespaced(
            ResumeTaskRequest {
                container_id: id.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("resume task", error))?;
    expect_process(
        &task_process(config, channel, id, "").await?,
        STATUS_RUNNING,
        None,
        "resumed init",
    )?;

    let pids = TasksClient::new(channel.clone())
        .list_pids(namespaced(
            ListPidsRequest {
                container_id: id.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("list task PIDs", error))?
        .into_inner();
    if pids.processes.is_empty() || pids.processes.iter().any(|process| process.pid == 0) {
        return Err(
            qualification_error("task PID inventory was empty or contained PID zero").into(),
        );
    }
    Ok(())
}

async fn qualify_exec_restart_boundaries(
    config: &QualificationConfig,
    channel: &mut Channel,
    id: &str,
) -> TestResult<()> {
    let exec_id = "restart-exec";
    let spec = serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0},
        "args": [
            "/bin/sh",
            "-c",
            "trap 'exit 7' TERM; while :; do sleep 1; done"
        ],
        "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    });
    TasksClient::new(channel.clone())
        .exec(namespaced(
            ExecProcessRequest {
                container_id: id.to_string(),
                exec_id: exec_id.to_string(),
                spec: Some(Any {
                    type_url: PROCESS_SPEC_TYPE.to_string(),
                    value: serde_json::to_vec(&spec).map_err(|error| {
                        qualification_error(format!("encode exec process: {error}"))
                    })?,
                }),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("add exec", error))?;
    expect_process(
        &task_process(config, channel, id, exec_id).await?,
        STATUS_CREATED,
        Some(0),
        "added exec",
    )?;

    *channel = restart_containerd(config, "exec-added").await?;
    expect_process(
        &task_process(config, channel, id, exec_id).await?,
        STATUS_CREATED,
        Some(0),
        "added exec after containerd restart",
    )?;

    let started = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: id.to_string(),
                exec_id: exec_id.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("start exec", error))?
        .into_inner();
    if started.pid == 0 {
        return Err(qualification_error("exec Start returned PID zero").into());
    }
    expect_process(
        &task_process(config, channel, id, exec_id).await?,
        STATUS_RUNNING,
        Some(started.pid),
        "running exec",
    )?;

    *channel = restart_containerd(config, "exec-running").await?;
    expect_process(
        &task_process(config, channel, id, exec_id).await?,
        STATUS_RUNNING,
        Some(started.pid),
        "running exec after containerd restart",
    )?;

    TasksClient::new(channel.clone())
        .kill(namespaced(
            KillRequest {
                container_id: id.to_string(),
                exec_id: exec_id.to_string(),
                signal: 15,
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("signal exec", error))?;
    let exit = TasksClient::new(channel.clone())
        .wait(namespaced(
            WaitRequest {
                container_id: id.to_string(),
                exec_id: exec_id.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("wait exec", error))?
        .into_inner();
    if exit.exit_status != 7 {
        return Err(qualification_error(format!(
            "exec SIGTERM exit status was {}, expected 7",
            exit.exit_status
        ))
        .into());
    }

    *channel = restart_containerd(config, "exec-stopped").await?;
    let stopped = task_process(config, channel, id, exec_id).await?;
    expect_process(&stopped, STATUS_STOPPED, None, "stopped exec after restart")?;
    if stopped.exit_status != 7 {
        return Err(qualification_error(format!(
            "rehydrated stopped exec reported exit {}, expected 7",
            stopped.exit_status
        ))
        .into());
    }
    let deleted = TasksClient::new(channel.clone())
        .delete_process(namespaced(
            DeleteProcessRequest {
                container_id: id.to_string(),
                exec_id: exec_id.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("delete exec", error))?
        .into_inner();
    if deleted.exit_status != 7 {
        return Err(qualification_error(format!(
            "exec Delete returned exit {}, expected 7",
            deleted.exit_status
        ))
        .into());
    }
    Ok(())
}
