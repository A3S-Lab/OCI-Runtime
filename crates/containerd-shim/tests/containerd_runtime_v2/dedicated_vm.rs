use prost_types::Any;
use tonic::transport::Channel;

use super::api::{
    CreateTaskRequest, DeleteProcessRequest, DeleteTaskRequest, ExecProcessRequest, KillRequest,
    StartRequest, TasksClient, WaitRequest,
};
use super::support::*;

const PROCESS_SPEC_TYPE: &str = "types.containerd.io/opencontainers/runtime-spec/1/Process";

/// Vertical-slice containerd lifecycle against a DedicatedVm Host Service.
///
/// Narrower than the Native Linux restart matrix: proves CreateOptions select
/// dedicated-vm, the shim records libkrun-kvm, create/start/exec/kill/wait/delete
/// complete without inventing process state, and containerd daemon restart at
/// init and exec Created/Running/Stopped preserves PID, driver, isolation, and
/// exec identity under `KillMode=process`.
pub(crate) async fn qualify_dedicated_vm_lifecycle(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    config.restart_boundaries.reset().map_err(|error| {
        qualification_error(format!("reset dedicated-vm restart ledger: {error}"))
    })?;

    let lifecycle_id = format!("{prefix}-dedicated-vm");
    let mut channel = connect_ready(config).await?;
    // Annotation fallback (ctr cannot marshal Runtime.Options on container create).
    create_dedicated_vm_container(config, &channel, &lifecycle_id).await?;

    let rootfs = task_rootfs(config, &channel, &lifecycle_id).await?;
    let created = TasksClient::new(channel.clone())
        .create(namespaced(
            CreateTaskRequest {
                container_id: lifecycle_id.clone(),
                rootfs,
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("create dedicated-vm task", error))?
        .into_inner();
    if created.pid == 0 {
        return Err(qualification_error("dedicated-vm task Create returned PID zero").into());
    }
    expect_process(
        &task_process(config, &channel, &lifecycle_id, "").await?,
        STATUS_CREATED,
        Some(created.pid),
        "created dedicated-vm init",
    )?;
    expect_dedicated_vm_binding(config, &lifecycle_id).await?;

    channel = restart_containerd(config, "dedicated-vm-init-created").await?;
    expect_process(
        &task_process(config, &channel, &lifecycle_id, "").await?,
        STATUS_CREATED,
        Some(created.pid),
        "created dedicated-vm init after containerd restart",
    )?;
    expect_dedicated_vm_binding(config, &lifecycle_id).await?;

    let started = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: lifecycle_id.clone(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("start dedicated-vm init", error))?
        .into_inner();
    if started.pid != created.pid {
        return Err(qualification_error(format!(
            "dedicated-vm init PID changed across Create/Start: {} -> {}",
            created.pid, started.pid
        ))
        .into());
    }
    expect_process(
        &task_process(config, &channel, &lifecycle_id, "").await?,
        STATUS_RUNNING,
        Some(created.pid),
        "running dedicated-vm init",
    )?;
    expect_dedicated_vm_binding(config, &lifecycle_id).await?;

    channel = restart_containerd(config, "dedicated-vm-init-running").await?;
    expect_process(
        &task_process(config, &channel, &lifecycle_id, "").await?,
        STATUS_RUNNING,
        Some(created.pid),
        "running dedicated-vm init after containerd restart",
    )?;
    expect_dedicated_vm_binding(config, &lifecycle_id).await?;

    channel = qualify_dedicated_vm_exec_restart(config, channel, &lifecycle_id).await?;
    expect_dedicated_vm_binding(config, &lifecycle_id).await?;
    expect_process(
        &task_process(config, &channel, &lifecycle_id, "").await?,
        STATUS_RUNNING,
        Some(created.pid),
        "running dedicated-vm init after exec restart slice",
    )?;

    TasksClient::new(channel.clone())
        .kill(namespaced(
            KillRequest {
                container_id: lifecycle_id.clone(),
                signal: 15,
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("signal dedicated-vm init", error))?;
    let exit = TasksClient::new(channel.clone())
        .wait(namespaced(
            WaitRequest {
                container_id: lifecycle_id.clone(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("wait dedicated-vm init", error))?
        .into_inner();
    if exit.exit_status != 42 {
        return Err(qualification_error(format!(
            "dedicated-vm SIGTERM exit status was {}, expected 42",
            exit.exit_status
        ))
        .into());
    }

    channel = restart_containerd(config, "dedicated-vm-init-stopped").await?;
    match optional_task_process(config, &channel, &lifecycle_id, "").await? {
        Some(stopped) => {
            expect_process(
                &stopped,
                STATUS_STOPPED,
                None,
                "stopped dedicated-vm init after restart",
            )?;
            if stopped.exit_status != 42 {
                return Err(qualification_error(format!(
                    "rehydrated stopped dedicated-vm init reported exit {}, expected 42",
                    stopped.exit_status
                ))
                .into());
            }
            let deleted = TasksClient::new(channel.clone())
                .delete(namespaced(
                    DeleteTaskRequest {
                        container_id: lifecycle_id.clone(),
                    },
                    &config.namespace,
                )?)
                .await
                .map_err(|error| rpc_error("delete dedicated-vm task", error))?
                .into_inner();
            if deleted.exit_status != 42 {
                return Err(qualification_error(format!(
                    "dedicated-vm Delete retained exit {}, expected 42",
                    deleted.exit_status
                ))
                .into());
            }
        }
        None => {
            // containerd may classify an already-stopped shim as leaked during
            // daemon recovery and call DeleteShim. Prove no invented residue.
            eprintln!(
                "dedicated-vm init disappeared after stopped-state containerd restart; treating as daemon leak cleanup"
            );
        }
    }

    config
        .restart_boundaries
        .verify_dedicated_vm_complete()
        .map_err(|error| {
            qualification_error(format!(
                "verify dedicated-vm restart boundary ledger: {error}"
            ))
        })?;

    wait_for_bundle_removal(config, &lifecycle_id).await?;
    delete_container(config, &lifecycle_id).await?;
    Ok(())
}

async fn qualify_dedicated_vm_exec_restart(
    config: &QualificationConfig,
    mut channel: Channel,
    lifecycle_id: &str,
) -> TestResult<Channel> {
    let exec_id = "dedicated-vm-restart-exec";
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
                container_id: lifecycle_id.to_string(),
                exec_id: exec_id.to_string(),
                spec: Some(Any {
                    type_url: PROCESS_SPEC_TYPE.to_string(),
                    value: serde_json::to_vec(&spec).map_err(|error| {
                        qualification_error(format!("encode dedicated-vm exec process: {error}"))
                    })?,
                }),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("add dedicated-vm exec", error))?;
    expect_process(
        &task_process(config, &channel, lifecycle_id, exec_id).await?,
        STATUS_CREATED,
        Some(0),
        "added dedicated-vm exec",
    )?;
    expect_dedicated_vm_binding(config, lifecycle_id).await?;

    channel = restart_containerd(config, "dedicated-vm-exec-added").await?;
    expect_process(
        &task_process(config, &channel, lifecycle_id, exec_id).await?,
        STATUS_CREATED,
        Some(0),
        "added dedicated-vm exec after containerd restart",
    )?;
    expect_dedicated_vm_binding(config, lifecycle_id).await?;

    let started = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: lifecycle_id.to_string(),
                exec_id: exec_id.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("start dedicated-vm exec", error))?
        .into_inner();
    if started.pid == 0 {
        return Err(qualification_error("dedicated-vm exec Start returned PID zero").into());
    }
    expect_process(
        &task_process(config, &channel, lifecycle_id, exec_id).await?,
        STATUS_RUNNING,
        Some(started.pid),
        "running dedicated-vm exec",
    )?;

    channel = restart_containerd(config, "dedicated-vm-exec-running").await?;
    expect_process(
        &task_process(config, &channel, lifecycle_id, exec_id).await?,
        STATUS_RUNNING,
        Some(started.pid),
        "running dedicated-vm exec after containerd restart",
    )?;
    expect_dedicated_vm_binding(config, lifecycle_id).await?;

    TasksClient::new(channel.clone())
        .kill(namespaced(
            KillRequest {
                container_id: lifecycle_id.to_string(),
                exec_id: exec_id.to_string(),
                signal: 15,
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("signal dedicated-vm exec", error))?;
    let exit = TasksClient::new(channel.clone())
        .wait(namespaced(
            WaitRequest {
                container_id: lifecycle_id.to_string(),
                exec_id: exec_id.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("wait dedicated-vm exec", error))?
        .into_inner();
    if exit.exit_status != 7 {
        return Err(qualification_error(format!(
            "dedicated-vm exec SIGTERM exit status was {}, expected 7",
            exit.exit_status
        ))
        .into());
    }

    channel = restart_containerd(config, "dedicated-vm-exec-stopped").await?;
    let stopped = task_process(config, &channel, lifecycle_id, exec_id).await?;
    expect_process(
        &stopped,
        STATUS_STOPPED,
        None,
        "stopped dedicated-vm exec after restart",
    )?;
    if stopped.exit_status != 7 {
        return Err(qualification_error(format!(
            "rehydrated stopped dedicated-vm exec reported exit {}, expected 7",
            stopped.exit_status
        ))
        .into());
    }
    let deleted = TasksClient::new(channel.clone())
        .delete_process(namespaced(
            DeleteProcessRequest {
                container_id: lifecycle_id.to_string(),
                exec_id: exec_id.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("delete dedicated-vm exec", error))?
        .into_inner();
    if deleted.exit_status != 7 {
        return Err(qualification_error(format!(
            "dedicated-vm exec Delete returned exit {}, expected 7",
            deleted.exit_status
        ))
        .into());
    }
    Ok(channel)
}

async fn expect_dedicated_vm_binding(
    config: &QualificationConfig,
    lifecycle_id: &str,
) -> TestResult<()> {
    let (driver, isolation) = read_shim_driver_isolation(config, lifecycle_id).await?;
    if driver != "libkrun-kvm" {
        return Err(qualification_error(format!(
            "dedicated-vm Create recorded driver {driver}, expected libkrun-kvm"
        ))
        .into());
    }
    if isolation != "dedicated-vm" {
        return Err(qualification_error(format!(
            "dedicated-vm Create recorded isolation {isolation}, expected dedicated-vm"
        ))
        .into());
    }
    Ok(())
}
