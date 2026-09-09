use super::api::{
    CreateTaskRequest, DeleteTaskRequest, KillRequest, StartRequest, TasksClient, WaitRequest,
};
use super::support::*;

/// Vertical-slice containerd lifecycle against a DedicatedVm Host Service.
///
/// This is intentionally narrower than the Native Linux restart matrix: it
/// proves CreateOptions select dedicated-vm, the shim records libkrun-kvm, and
/// create/start/kill/wait/delete complete without inventing process state.
pub(crate) async fn qualify_dedicated_vm_lifecycle(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let lifecycle_id = format!("{prefix}-dedicated-vm");
    let channel = connect_ready(config).await?;
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
        return Err(
            qualification_error("dedicated-vm task Create returned PID zero").into(),
        );
    }
    expect_process(
        &task_process(config, &channel, &lifecycle_id, "").await?,
        STATUS_CREATED,
        Some(created.pid),
        "created dedicated-vm init",
    )?;

    let (driver, isolation) = read_shim_driver_isolation(config, &lifecycle_id).await?;
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
    wait_for_bundle_removal(config, &lifecycle_id).await?;
    delete_container(config, &lifecycle_id).await?;
    Ok(())
}
