use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, Process};
use a3s_oci_sdk::{
    ContainerRecord, ContainerTarget, DeleteMode, DeleteRequest as RuntimeDeleteRequest,
    ExecRequest as RuntimeExecRequest, Generation, IoMode, KillRequest as RuntimeKillRequest,
    OperationContext, ProcessIo, ProcessRecord, Signal, StartRequest as RuntimeStartRequest,
};
use prost_types::Any;

use crate::api::{
    ContainersClient, CreateTaskRequest, ExecProcessRequest, GetContainerRequest, KillRequest,
    StartRequest, TasksClient, WaitRequest,
};
use crate::support::*;

use super::shared::{
    containerd_exec_operation_id, containerd_operation_id, containerd_process_id, runtime_client,
};
use super::{find_exact_shim_pid, signal_kill, wait_for_runtime_absence, wait_for_shim_cleanup};

pub(super) async fn qualify_start_effect_committed_shim_sigkill(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let id = format!("{prefix}-shim-kill-start-committed");
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
        .map_err(|error| rpc_error("create start-committed task", error))?
        .into_inner();
    if created.pid == 0 {
        return Err(qualification_error("start-committed task Create returned PID zero").into());
    }

    let identity = read_runtime_identity(config, &id).await?;
    let started = start_runtime_generation(config, &id, &identity).await?;
    if started.generation != Generation(identity.generation)
        || *started.state.status() != ContainerState::Running
        || started.state.pid().and_then(|pid| u32::try_from(pid).ok()) != Some(created.pid)
    {
        return Err(qualification_error(format!(
            "stable runtime Start returned generation {}, status {}, PID {:?}; expected generation {}, running, PID {}",
            started.generation.0,
            started.state.status(),
            started.state.pid(),
            identity.generation,
            created.pid
        ))
        .into());
    }

    let shim_pid = find_exact_shim_pid(config, &id).await?;
    signal_kill(shim_pid)?;
    wait_for_shim_cleanup(config, &channel, &id, shim_pid, &[created.pid]).await?;
    wait_for_runtime_absence(config, identity.container_id).await?;
    ContainersClient::new(channel)
        .get(namespaced(
            GetContainerRequest { id: id.clone() },
            &config.namespace,
        )?)
        .await
        .map_err(|error| {
            rpc_error(
                "read caller-owned metadata after committed runtime Start and shim SIGKILL",
                error,
            )
        })?;
    delete_container(config, &id).await
}

pub(super) async fn qualify_delete_effect_committed_shim_sigkill(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let id = format!("{prefix}-shim-kill-delete-committed");
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
        .map_err(|error| rpc_error("create delete-committed task", error))?
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
        .map_err(|error| rpc_error("start delete-committed task", error))?
        .into_inner();
    if created.pid == 0 || started.pid != created.pid {
        return Err(qualification_error(format!(
            "delete-committed task PIDs were create={} and start={}; expected one stable nonzero PID",
            created.pid, started.pid
        ))
        .into());
    }
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
        .map_err(|error| rpc_error("kill delete-committed task", error))?;
    let exit = TasksClient::new(channel.clone())
        .wait(namespaced(
            WaitRequest {
                container_id: id.clone(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("wait delete-committed task", error))?
        .into_inner();
    if exit.exit_status != 137 {
        return Err(qualification_error(format!(
            "delete-committed task exited {}, expected 137",
            exit.exit_status
        ))
        .into());
    }

    let identity = read_runtime_identity(config, &id).await?;
    delete_runtime_generation(config, &id, &identity).await?;
    wait_for_runtime_absence(config, identity.container_id.clone()).await?;
    let shim_pid = find_exact_shim_pid(config, &id).await?;
    signal_kill(shim_pid)?;
    wait_for_shim_cleanup(config, &channel, &id, shim_pid, &[started.pid]).await?;
    ContainersClient::new(channel)
        .get(namespaced(
            GetContainerRequest { id: id.clone() },
            &config.namespace,
        )?)
        .await
        .map_err(|error| {
            rpc_error(
                "read caller-owned metadata after committed runtime Delete and shim SIGKILL",
                error,
            )
        })?;
    delete_container(config, &id).await
}

pub(super) async fn qualify_exec_effect_committed_shim_sigkill(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let id = format!("{prefix}-shim-kill-exec-committed");
    let exec_id = "committed-exec";
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
        .map_err(|error| rpc_error("create exec-committed task", error))?
        .into_inner();
    let started = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: id.clone(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("start exec-committed task", error))?
        .into_inner();
    if created.pid == 0 || started.pid != created.pid {
        return Err(qualification_error(format!(
            "exec-committed task PIDs were create={} and start={}; expected one stable nonzero PID",
            created.pid, started.pid
        ))
        .into());
    }

    let process_value = serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0},
        "args": ["/bin/sh", "-c", "while :; do sleep 1; done"],
        "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    });
    let process: Process = serde_json::from_value(process_value.clone())
        .map_err(|error| qualification_error(format!("decode committed Exec process: {error}")))?;
    TasksClient::new(channel.clone())
        .exec(namespaced(
            ExecProcessRequest {
                container_id: id.clone(),
                exec_id: exec_id.to_string(),
                spec: Some(Any {
                    type_url: crate::PROCESS_SPEC_TYPE.to_string(),
                    value: serde_json::to_vec(&process_value).map_err(|error| {
                        qualification_error(format!("encode committed Exec process: {error}"))
                    })?,
                }),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("add exec-committed process", error))?;
    expect_process(
        &task_process(config, &channel, &id, exec_id).await?,
        STATUS_CREATED,
        Some(0),
        "exec-committed process before direct Runtime Exec",
    )?;

    let identity = read_runtime_identity(config, &id).await?;
    let process = exec_runtime_process(config, &id, exec_id, &identity, process).await?;
    let process_pid = process
        .pid
        .filter(|pid| *pid != 0)
        .ok_or_else(|| qualification_error("committed Runtime Exec returned PID zero"))?;
    if process.target.container.id != identity.container_id
        || process.target.container.generation != Some(Generation(identity.generation))
        || process.target.process_id != containerd_process_id(&config.namespace, &id, exec_id)?
        || process.terminal
    {
        return Err(qualification_error(
            "committed Runtime Exec changed the generation, process identity, or terminal mode",
        )
        .into());
    }

    let shim_pid = find_exact_shim_pid(config, &id).await?;
    signal_kill(shim_pid)?;
    wait_for_shim_cleanup(config, &channel, &id, shim_pid, &[started.pid, process_pid]).await?;
    wait_for_runtime_absence(config, identity.container_id).await?;
    ContainersClient::new(channel)
        .get(namespaced(
            GetContainerRequest { id: id.clone() },
            &config.namespace,
        )?)
        .await
        .map_err(|error| {
            rpc_error(
                "read caller-owned metadata after committed Runtime Exec and shim SIGKILL",
                error,
            )
        })?;
    delete_container(config, &id).await
}

pub(super) async fn qualify_kill_effect_committed_shim_sigkill(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let id = format!("{prefix}-shim-kill-kill-committed");
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
        .map_err(|error| rpc_error("create kill-committed task", error))?
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
        .map_err(|error| rpc_error("start kill-committed task", error))?
        .into_inner();
    if created.pid == 0 || started.pid != created.pid {
        return Err(qualification_error(format!(
            "kill-committed task PIDs were create={} and start={}; expected one stable nonzero PID",
            created.pid, started.pid
        ))
        .into());
    }

    let identity = read_runtime_identity(config, &id).await?;
    let killed = kill_runtime_generation(config, &id, &identity, libc::SIGSTOP, false).await?;
    if killed.generation != Generation(identity.generation)
        || *killed.state.status() != ContainerState::Running
        || killed.state.pid().and_then(|pid| u32::try_from(pid).ok()) != Some(started.pid)
    {
        return Err(qualification_error(format!(
            "stable runtime Kill returned generation {}, status {}, PID {:?}; expected generation {}, running, PID {}",
            killed.generation.0,
            killed.state.status(),
            killed.state.pid(),
            identity.generation,
            started.pid
        ))
        .into());
    }

    let shim_pid = find_exact_shim_pid(config, &id).await?;
    signal_kill(shim_pid)?;
    wait_for_shim_cleanup(config, &channel, &id, shim_pid, &[started.pid]).await?;
    wait_for_runtime_absence(config, identity.container_id).await?;
    ContainersClient::new(channel)
        .get(namespaced(
            GetContainerRequest { id: id.clone() },
            &config.namespace,
        )?)
        .await
        .map_err(|error| {
            rpc_error(
                "read caller-owned metadata after committed runtime Kill and shim SIGKILL",
                error,
            )
        })?;
    delete_container(config, &id).await
}

async fn start_runtime_generation(
    config: &QualificationConfig,
    task_id: &str,
    identity: &RuntimeIdentity,
) -> TestResult<ContainerRecord> {
    let client = runtime_client(config).await?;
    let request = RuntimeStartRequest {
        context: OperationContext::new(containerd_operation_id(
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
                    "commit exact runtime Start before shim death: {error}"
                ))
                .into());
            }
        }
    }
}

async fn exec_runtime_process(
    config: &QualificationConfig,
    task_id: &str,
    exec_id: &str,
    identity: &RuntimeIdentity,
    process: Process,
) -> TestResult<ProcessRecord> {
    let client = runtime_client(config).await?;
    let request = RuntimeExecRequest {
        context: OperationContext::new(containerd_exec_operation_id(
            &config.namespace,
            task_id,
            &identity.incarnation,
            exec_id,
            "exec",
        )?),
        container: ContainerTarget::exact(
            identity.container_id.clone(),
            Generation(identity.generation),
        ),
        process_id: containerd_process_id(&config.namespace, task_id, exec_id)?,
        process,
        io: ProcessIo {
            stdin: IoMode::Null,
            stdout: IoMode::Null,
            stderr: IoMode::Null,
            terminal_size: None,
        },
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.exec(request.clone()).await {
            Ok(process) => return Ok(process),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact Runtime Exec before shim death: {error}"
                ))
                .into());
            }
        }
    }
}

async fn delete_runtime_generation(
    config: &QualificationConfig,
    task_id: &str,
    identity: &RuntimeIdentity,
) -> TestResult<()> {
    let client = runtime_client(config).await?;
    let request = RuntimeDeleteRequest {
        context: OperationContext::new(containerd_operation_id(
            &config.namespace,
            task_id,
            &identity.incarnation,
            "delete",
        )?),
        target: ContainerTarget::exact(
            identity.container_id.clone(),
            Generation(identity.generation),
        ),
        mode: DeleteMode::StoppedOnly,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.delete(request.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact runtime Delete before shim death: {error}"
                ))
                .into());
            }
        }
    }
}

async fn kill_runtime_generation(
    config: &QualificationConfig,
    task_id: &str,
    identity: &RuntimeIdentity,
    signal: i32,
    all: bool,
) -> TestResult<ContainerRecord> {
    let client = runtime_client(config).await?;
    let request = RuntimeKillRequest {
        context: OperationContext::new(containerd_operation_id(
            &config.namespace,
            task_id,
            &identity.incarnation,
            &format!("kill-{signal}-{all}"),
        )?),
        target: ContainerTarget::exact(
            identity.container_id.clone(),
            Generation(identity.generation),
        ),
        signal: Signal::new(signal).map_err(|error| {
            qualification_error(format!("validate committed Kill signal: {error}"))
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
                    "commit exact runtime Kill before shim death: {error}"
                ))
                .into());
            }
        }
    }
}
