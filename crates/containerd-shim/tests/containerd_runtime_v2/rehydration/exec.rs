use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{
    ContainerTarget, ExecRequest as RuntimeExecRequest, Generation, IoMode, OperationContext,
    ProcessIo, ProcessRecord, ProcessTarget, ProcessesRequest,
};
use prost_types::Any;

#[path = "exec/evidence.rs"]
mod evidence;

use super::{
    launch_replacement_while_containerd_suspended, lifecycle, load_bootstrap, load_shim_binary,
    stop_replacement, wait_for_pid_exit, wait_for_replacement_exit,
};
use crate::api::{
    CreateTaskRequest, DeleteProcessRequest, DeleteTaskRequest, ExecProcessRequest, KillRequest,
    StartRequest, TasksClient, WaitRequest,
};
use crate::faults;
use crate::support::{
    connect_ready, containerd_main_pid, create_container, delete_container, expect_process,
    namespaced, qualification_error, read_runtime_identity, restart_containerd, rpc_error,
    task_process, task_rootfs, QualificationConfig, RuntimeIdentity, TestResult, STATUS_CREATED,
    STATUS_RUNNING,
};

const EXEC_ID: &str = "committed-exec";
const EXEC_EXIT_STATUS: u32 = 29;

pub(super) async fn qualify_committed_exec_start(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let id = format!("{prefix}-committed-exec-rehydrate");
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
        .map_err(|error| rpc_error("create committed-Exec rehydration task", error))?
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
        .map_err(|error| rpc_error("start committed-Exec rehydration init", error))?
        .into_inner();
    if created.pid == 0 || started.pid != created.pid {
        return Err(qualification_error(format!(
            "committed-Exec init PIDs were create={} and start={}; expected one stable nonzero PID",
            created.pid, started.pid
        ))
        .into());
    }

    let process_value = serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0},
        "args": [
            "/bin/sh",
            "-c",
            format!("trap 'exit {EXEC_EXIT_STATUS}' TERM; while :; do sleep 1; done")
        ],
        "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    });
    let process: Process = serde_json::from_value(process_value.clone()).map_err(|error| {
        qualification_error(format!("decode committed-Exec OCI process: {error}"))
    })?;
    TasksClient::new(channel.clone())
        .exec(namespaced(
            ExecProcessRequest {
                container_id: id.clone(),
                exec_id: EXEC_ID.to_string(),
                spec: Some(Any {
                    type_url: crate::PROCESS_SPEC_TYPE.to_string(),
                    value: serde_json::to_vec(&process_value).map_err(|error| {
                        qualification_error(format!("encode committed-Exec OCI process: {error}"))
                    })?,
                }),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("add committed-Exec process", error))?;
    expect_process(
        &task_process(config, &channel, &id, EXEC_ID).await?,
        STATUS_CREATED,
        Some(0),
        "committed-Exec process after add",
    )?;

    let bundle = config.bundle(&id);
    evidence::require(&bundle, EXEC_ID, "added", None, "after Exec add").await?;
    let identity = read_runtime_identity(config, &id).await?;
    let bootstrap = load_bootstrap(&bundle).await?;
    let binary = load_shim_binary(&bundle).await?;
    let expected_target = exact_exec_target(config, &id, &identity)?;

    let old_shim_pid = faults::find_exact_shim_pid(config, &id).await?;
    let host_pid = faults::find_runtime_host_pid(config).await?;
    let mut suspended_host =
        faults::SuspendedProcess::stop(host_pid, "committed-Exec A3S OCI host service")?;
    let start_address = bootstrap.address.clone();
    let start_id = id.clone();
    let mut start_call =
        tokio::spawn(
            async move { lifecycle::shim_start(&start_address, &start_id, EXEC_ID).await },
        );
    evidence::wait_for_starting(&bundle, EXEC_ID, &mut start_call).await?;

    let suspended_shim =
        faults::SuspendedProcess::stop(old_shim_pid, "committed-Exec original shim")?;
    suspended_host.resume("committed-Exec A3S OCI host service")?;
    let committed = commit_runtime_exec(config, &id, &identity, process).await?;
    validate_runtime_process(&committed, &expected_target)?;
    evidence::require(
        &bundle,
        EXEC_ID,
        "starting",
        None,
        "after Runtime Exec commit and before shim replacement",
    )
    .await?;

    let containerd_pid = containerd_main_pid(config).await?;
    faults::send_signal(containerd_pid, libc::SIGSTOP, "committed-Exec containerd")?;
    let mut replacement = None;
    let relaunch = async {
        suspended_shim.kill("committed-Exec original shim")?;
        wait_for_pid_exit(old_shim_pid, "committed-Exec original shim").await?;
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
    let _ = faults::send_signal(containerd_pid, libc::SIGCONT, "committed-Exec containerd");
    if let Err(error) = relaunch {
        start_call.abort();
        let _ = start_call.await;
        stop_replacement(&mut replacement).await;
        let recovery = restart_containerd(config, "failed-committed-Exec-rehydration").await;
        return match recovery {
            Ok(_) => Err(error),
            Err(recovery_error) => Err(qualification_error(format!(
                "committed Exec replacement failed: {error}; containerd recovery also failed: {recovery_error}"
            ))
            .into()),
        };
    }

    let mut replacement = replacement
        .ok_or_else(|| qualification_error("committed-Exec relaunch omitted its child process"))?;
    let replacement_pid = replacement
        .id()
        .ok_or_else(|| qualification_error("committed-Exec replacement has no PID"))?;
    let channel = restart_containerd(config, "committed-Exec-shim-rehydration").await?;
    lifecycle::require_lost_start_response(start_call, "exec").await?;

    expect_process(
        &task_process(config, &channel, &id, "").await?,
        STATUS_RUNNING,
        Some(started.pid),
        "init after committed Exec replacement",
    )?;
    expect_process(
        &task_process(config, &channel, &id, EXEC_ID).await?,
        STATUS_RUNNING,
        committed.pid,
        "exec after committed Exec replacement",
    )?;
    if read_runtime_identity(config, &id).await? != identity {
        return Err(qualification_error(
            "committed Exec replacement changed the task incarnation or runtime generation",
        )
        .into());
    }
    require_replacement_pid(config, &id, replacement_pid).await?;
    evidence::require(
        &bundle,
        EXEC_ID,
        "started",
        Some(&committed),
        "after committed Exec replacement",
    )
    .await?;

    let replayed = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: id.clone(),
                exec_id: EXEC_ID.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("replay Exec Start through replacement shim", error))?
        .into_inner();
    let committed_pid = committed
        .pid
        .ok_or_else(|| qualification_error("committed Runtime Exec omitted its PID"))?;
    if replayed.pid != committed_pid {
        return Err(qualification_error(format!(
            "replayed Exec Start returned PID {}, expected original PID {committed_pid}",
            replayed.pid
        ))
        .into());
    }
    require_replacement_pid(config, &id, replacement_pid).await?;
    require_single_runtime_exec(config, &identity, &expected_target, &committed).await?;

    TasksClient::new(channel.clone())
        .kill(namespaced(
            KillRequest {
                container_id: id.clone(),
                exec_id: EXEC_ID.to_string(),
                signal: libc::SIGTERM as u32,
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("kill committed-Exec process", error))?;
    let exec_exit = TasksClient::new(channel.clone())
        .wait(namespaced(
            WaitRequest {
                container_id: id.clone(),
                exec_id: EXEC_ID.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("wait committed-Exec process", error))?
        .into_inner();
    if exec_exit.exit_status != EXEC_EXIT_STATUS {
        return Err(qualification_error(format!(
            "committed-Exec process exited {}, expected {EXEC_EXIT_STATUS}",
            exec_exit.exit_status
        ))
        .into());
    }
    let deleted_exec = TasksClient::new(channel.clone())
        .delete_process(namespaced(
            DeleteProcessRequest {
                container_id: id.clone(),
                exec_id: EXEC_ID.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("delete committed-Exec process", error))?
        .into_inner();
    if deleted_exec.exit_status != EXEC_EXIT_STATUS {
        return Err(qualification_error(format!(
            "committed-Exec Delete returned {}, expected {EXEC_EXIT_STATUS}",
            deleted_exec.exit_status
        ))
        .into());
    }
    expect_process(
        &task_process(config, &channel, &id, "").await?,
        STATUS_RUNNING,
        Some(started.pid),
        "init after committed Exec cleanup",
    )?;

    TasksClient::new(channel.clone())
        .kill(namespaced(
            KillRequest {
                container_id: id.clone(),
                signal: libc::SIGTERM as u32,
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("kill committed-Exec init", error))?;
    let init_exit = TasksClient::new(channel.clone())
        .wait(namespaced(
            WaitRequest {
                container_id: id.clone(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("wait committed-Exec init", error))?
        .into_inner();
    if init_exit.exit_status != 42 {
        return Err(qualification_error(format!(
            "committed-Exec init exited {}, expected 42",
            init_exit.exit_status
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
        .map_err(|error| rpc_error("delete committed-Exec task", error))?
        .into_inner();
    if deleted.exit_status != 42 {
        return Err(qualification_error(format!(
            "committed-Exec task Delete returned {}, expected 42",
            deleted.exit_status
        ))
        .into());
    }
    delete_container(config, &id).await?;
    wait_for_replacement_exit(&mut replacement).await
}

async fn commit_runtime_exec(
    config: &QualificationConfig,
    task_id: &str,
    identity: &RuntimeIdentity,
    process: Process,
) -> TestResult<ProcessRecord> {
    let client = faults::runtime_client(config).await?;
    let request = RuntimeExecRequest {
        context: OperationContext::new(faults::containerd_exec_operation_id(
            &config.namespace,
            task_id,
            &identity.incarnation,
            EXEC_ID,
            1,
            "exec",
        )?),
        container: ContainerTarget::exact(
            identity.container_id.clone(),
            Generation(identity.generation),
        ),
        process_id: faults::containerd_process_id(&config.namespace, task_id, EXEC_ID, 1)?,
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
            Ok(record) => return Ok(record),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact Runtime Exec before shim replacement: {error}"
                ))
                .into());
            }
        }
    }
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

fn validate_runtime_process(record: &ProcessRecord, expected: &ProcessTarget) -> TestResult<()> {
    if record.target != *expected || record.pid.is_none_or(|pid| pid == 0) || record.terminal {
        return Err(qualification_error(format!(
            "committed Runtime Exec returned {record:?}; expected target {expected:?}, a nonzero PID, and non-terminal mode"
        ))
        .into());
    }
    Ok(())
}

async fn require_single_runtime_exec(
    config: &QualificationConfig,
    identity: &RuntimeIdentity,
    expected_target: &ProcessTarget,
    expected_record: &ProcessRecord,
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
                "read Runtime process inventory after committed Exec replacement: {error}"
            ))
        })?;
    let exact = inventory
        .iter()
        .filter(|record| record.target == *expected_target)
        .collect::<Vec<_>>();
    if exact.as_slice() != [expected_record] {
        return Err(qualification_error(format!(
            "Runtime inventory contained {} exact committed exec records after replacement: {inventory:?}",
            exact.len()
        ))
        .into());
    }
    Ok(())
}

async fn require_replacement_pid(
    config: &QualificationConfig,
    task_id: &str,
    expected: u32,
) -> TestResult<()> {
    let observed = faults::find_exact_shim_pid(config, task_id).await?;
    if observed != expected {
        return Err(qualification_error(format!(
            "containerd connected committed-Exec shim PID {observed}, expected replacement PID {expected}"
        ))
        .into());
    }
    Ok(())
}
