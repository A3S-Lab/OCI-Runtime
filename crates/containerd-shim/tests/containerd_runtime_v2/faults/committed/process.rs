use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, Process};
use a3s_oci_sdk::{
    ContainerTarget, ExecRequest as RuntimeExecRequest, Generation, IoMode, OperationContext,
    ProcessIo, ProcessRecord, ProcessTarget, Signal,
    SignalProcessRequest as RuntimeSignalProcessRequest, StateRequest as RuntimeStateRequest,
    WaitProcessRequest as RuntimeWaitProcessRequest,
};
use prost_types::Any;
use tonic::transport::Channel;

use crate::api::{
    ContainersClient, CreateTaskRequest, ExecProcessRequest, GetContainerRequest, StartRequest,
    TasksClient,
};
use crate::support::*;

use super::super::shared::{containerd_exec_operation_id, containerd_process_id, runtime_client};
use super::super::{
    find_exact_shim_pid, signal_kill, wait_for_runtime_absence, wait_for_shim_cleanup,
    SuspendedProcess,
};

struct StartedTask {
    channel: Channel,
    identity: RuntimeIdentity,
    init_pid: u32,
}

pub(crate) async fn qualify_exec_effect_committed_shim_sigkill(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let id = format!("{prefix}-shim-kill-exec-committed");
    let exec_id = "committed-exec";
    let task = create_started_task(config, &id, "exec-committed").await?;
    let process = add_exec(config, &task.channel, &id, exec_id, "exec-committed").await?;

    let process = exec_runtime_process(config, &id, exec_id, &task.identity, process).await?;
    let process_pid = process
        .pid
        .filter(|pid| *pid != 0)
        .ok_or_else(|| qualification_error("committed Runtime Exec returned PID zero"))?;
    if process.target.container.id != task.identity.container_id
        || process.target.container.generation != Some(Generation(task.identity.generation))
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
    wait_for_shim_cleanup(
        config,
        &task.channel,
        &id,
        shim_pid,
        &[task.init_pid, process_pid],
    )
    .await?;
    wait_for_runtime_absence(config, task.identity.container_id).await?;
    require_caller_metadata(
        config,
        task.channel,
        &id,
        "committed Runtime Exec and shim SIGKILL",
    )
    .await?;
    delete_container(config, &id).await
}

pub(crate) async fn qualify_signal_process_effect_committed_shim_sigkill(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let id = format!("{prefix}-shim-kill-signal-process-committed");
    let exec_id = "committed-signal-exec";
    let task = create_started_task(config, &id, "signal-process-committed").await?;
    add_exec(
        config,
        &task.channel,
        &id,
        exec_id,
        "signal-process-committed",
    )
    .await?;
    let exec_pid = start_exec(
        config,
        &task.channel,
        &id,
        exec_id,
        "signal-process-committed",
    )
    .await?;
    if exec_pid == task.init_pid {
        return Err(qualification_error(format!(
            "signal-process-committed exec reused init PID {}",
            task.init_pid
        ))
        .into());
    }

    let shim_pid = find_exact_shim_pid(config, &id).await?;
    let suspended_shim = SuspendedProcess::stop(shim_pid, "signal-process-committed shim")?;
    signal_runtime_process(config, &id, exec_id, &task.identity, libc::SIGKILL).await?;
    let exit = wait_runtime_process(config, &id, exec_id, &task.identity).await?;
    if exit.exit_code.is_some() || exit.signal != Some(libc::SIGKILL) || exit.oom_killed {
        return Err(qualification_error(format!(
            "committed Runtime SignalProcess returned exitCode={:?}, signal={:?}, oomKilled={}; expected signal {}",
            exit.exit_code, exit.signal, exit.oom_killed, libc::SIGKILL
        ))
        .into());
    }

    let init = runtime_state(config, &task.identity).await?;
    if init.generation != Generation(task.identity.generation)
        || *init.state.status() != ContainerState::Running
        || init.state.pid().and_then(|pid| u32::try_from(pid).ok()) != Some(task.init_pid)
    {
        return Err(qualification_error(format!(
            "committed Runtime SignalProcess changed init generation, state, or PID: generation={}, status={}, pid={:?}",
            init.generation.0,
            init.state.status(),
            init.state.pid()
        ))
        .into());
    }

    suspended_shim.kill("signal-process-committed shim")?;
    wait_for_shim_cleanup(
        config,
        &task.channel,
        &id,
        shim_pid,
        &[task.init_pid, exec_pid],
    )
    .await?;
    wait_for_runtime_absence(config, task.identity.container_id).await?;
    require_caller_metadata(
        config,
        task.channel,
        &id,
        "committed Runtime SignalProcess and shim SIGKILL",
    )
    .await?;
    delete_container(config, &id).await
}

async fn create_started_task(
    config: &QualificationConfig,
    id: &str,
    context: &str,
) -> TestResult<StartedTask> {
    create_container(config, id).await?;
    let channel = connect_ready(config).await?;
    let rootfs = task_rootfs(config, &channel, id).await?;
    let created = TasksClient::new(channel.clone())
        .create(namespaced(
            CreateTaskRequest {
                container_id: id.to_string(),
                rootfs,
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error(&format!("create {context} task"), error))?
        .into_inner();
    let started = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: id.to_string(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error(&format!("start {context} task"), error))?
        .into_inner();
    if created.pid == 0 || started.pid != created.pid {
        return Err(qualification_error(format!(
            "{context} task PIDs were create={} and start={}; expected one stable nonzero PID",
            created.pid, started.pid
        ))
        .into());
    }
    let identity = read_runtime_identity(config, id).await?;
    Ok(StartedTask {
        channel,
        identity,
        init_pid: started.pid,
    })
}

async fn add_exec(
    config: &QualificationConfig,
    channel: &Channel,
    task_id: &str,
    exec_id: &str,
    context: &str,
) -> TestResult<Process> {
    let process_value = serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0},
        "args": ["/bin/sh", "-c", "while :; do sleep 1; done"],
        "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    });
    let process: Process = serde_json::from_value(process_value.clone())
        .map_err(|error| qualification_error(format!("decode {context} process: {error}")))?;
    TasksClient::new(channel.clone())
        .exec(namespaced(
            ExecProcessRequest {
                container_id: task_id.to_string(),
                exec_id: exec_id.to_string(),
                spec: Some(Any {
                    type_url: crate::PROCESS_SPEC_TYPE.to_string(),
                    value: serde_json::to_vec(&process_value).map_err(|error| {
                        qualification_error(format!("encode {context} process: {error}"))
                    })?,
                }),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error(&format!("add {context} process"), error))?;
    expect_process(
        &task_process(config, channel, task_id, exec_id).await?,
        STATUS_CREATED,
        Some(0),
        &format!("{context} process before Start"),
    )?;
    Ok(process)
}

async fn start_exec(
    config: &QualificationConfig,
    channel: &Channel,
    task_id: &str,
    exec_id: &str,
    context: &str,
) -> TestResult<u32> {
    let started = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: task_id.to_string(),
                exec_id: exec_id.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error(&format!("start {context} process"), error))?
        .into_inner();
    if started.pid == 0 {
        return Err(
            qualification_error(format!("{context} process Start returned PID zero")).into(),
        );
    }
    expect_process(
        &task_process(config, channel, task_id, exec_id).await?,
        STATUS_RUNNING,
        Some(started.pid),
        &format!("{context} process after Start"),
    )?;
    Ok(started.pid)
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

async fn signal_runtime_process(
    config: &QualificationConfig,
    task_id: &str,
    exec_id: &str,
    identity: &RuntimeIdentity,
    signal: i32,
) -> TestResult<()> {
    let client = runtime_client(config).await?;
    let request = RuntimeSignalProcessRequest {
        context: OperationContext::new(containerd_exec_operation_id(
            &config.namespace,
            task_id,
            &identity.incarnation,
            exec_id,
            &format!("signal-{signal}"),
        )?),
        process: exact_process_target(config, task_id, exec_id, identity)?,
        signal: Signal::new(signal).map_err(|error| {
            qualification_error(format!("validate committed SignalProcess signal: {error}"))
        })?,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.signal_process(request.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact Runtime SignalProcess before shim death: {error}"
                ))
                .into());
            }
        }
    }
}

async fn wait_runtime_process(
    config: &QualificationConfig,
    task_id: &str,
    exec_id: &str,
    identity: &RuntimeIdentity,
) -> TestResult<a3s_oci_sdk::ExitStatus> {
    let client = runtime_client(config).await?;
    let request = RuntimeWaitProcessRequest {
        process: exact_process_target(config, task_id, exec_id, identity)?,
        timeout_ms: Some(2_000),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.wait_process(request.clone()).await {
            Ok(exit) => return Ok(exit),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "observe committed Runtime SignalProcess exit: {error}"
                ))
                .into());
            }
        }
    }
}

async fn runtime_state(
    config: &QualificationConfig,
    identity: &RuntimeIdentity,
) -> TestResult<a3s_oci_sdk::ContainerRecord> {
    runtime_client(config)
        .await?
        .state(RuntimeStateRequest {
            target: ContainerTarget::exact(
                identity.container_id.clone(),
                Generation(identity.generation),
            ),
        })
        .await
        .map_err(|error| {
            qualification_error(format!(
                "read init state after committed Runtime SignalProcess: {error}"
            ))
            .into()
        })
}

fn exact_process_target(
    config: &QualificationConfig,
    task_id: &str,
    exec_id: &str,
    identity: &RuntimeIdentity,
) -> TestResult<ProcessTarget> {
    Ok(ProcessTarget {
        container: ContainerTarget::exact(
            identity.container_id.clone(),
            Generation(identity.generation),
        ),
        process_id: containerd_process_id(&config.namespace, task_id, exec_id)?,
    })
}

async fn require_caller_metadata(
    config: &QualificationConfig,
    channel: Channel,
    id: &str,
    context: &str,
) -> TestResult<()> {
    ContainersClient::new(channel)
        .get(namespaced(
            GetContainerRequest { id: id.to_string() },
            &config.namespace,
        )?)
        .await
        .map_err(|error| {
            rpc_error(
                &format!("read caller-owned metadata after {context}"),
                error,
            )
        })?;
    Ok(())
}
