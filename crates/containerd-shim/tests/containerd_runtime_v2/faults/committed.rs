use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerRecord, ContainerTarget, DeleteMode, DeleteRequest as RuntimeDeleteRequest,
    Generation, LocalIpcEndpoint, OperationContext, OperationId, RuntimeClient,
    StartRequest as RuntimeStartRequest,
};
use sha2::{Digest, Sha256};

use crate::api::{
    ContainersClient, CreateTaskRequest, GetContainerRequest, KillRequest, TasksClient, WaitRequest,
};
use crate::support::*;

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

async fn runtime_client(config: &QualificationConfig) -> TestResult<RuntimeClient> {
    let endpoint =
        LocalIpcEndpoint::unix_socket(config.runtime_endpoint.clone()).map_err(|error| {
            qualification_error(format!(
                "validate A3S OCI runtime endpoint {}: {error}",
                config.runtime_endpoint.display()
            ))
        })?;
    RuntimeClient::connect(&endpoint).await.map_err(|error| {
        qualification_error(format!(
            "connect A3S OCI runtime endpoint {}: {error}",
            config.runtime_endpoint.display()
        ))
        .into()
    })
}

fn containerd_operation_id(
    namespace: &str,
    task_id: &str,
    incarnation: &str,
    action: &str,
) -> TestResult<OperationId> {
    let mut digest = Sha256::new();
    for component in [namespace, task_id, incarnation, action] {
        digest.update((component.len() as u64).to_be_bytes());
        digest.update(component.as_bytes());
    }
    OperationId::new(format!("ctrd-op-{:x}", digest.finalize())).map_err(|error| {
        qualification_error(format!(
            "derive stable containerd {action} operation identity: {error}"
        ))
        .into()
    })
}
