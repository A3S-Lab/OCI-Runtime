use std::path::Path;

use serde::Deserialize;
use tonic::Code;

use super::{
    launch_replacement_while_containerd_suspended, load_bootstrap, load_shim_binary,
    stop_replacement, wait_for_pid_exit, wait_for_replacement_exit,
};
use crate::api::{
    CreateTaskRequest, DeleteTaskRequest, KillRequest, StartRequest, TasksClient, WaitRequest,
};
use crate::faults;
use crate::support::{
    connect_ready, containerd_main_pid, create_container, delete_container, namespaced,
    optional_task_process, qualification_error, read_runtime_identity, restart_containerd,
    rpc_error, task_rootfs, wait_for_bundle_removal, QualificationConfig, RuntimeIdentity,
    TestResult,
};

const TASK_DELETE_RECEIPT_FILE_NAME: &str = "a3s-oci-shim-task-delete-v1.json";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskDeleteReceiptEvidence {
    schema_version: u32,
    namespace: String,
    task_id: String,
    incarnation: Option<String>,
    container_id: String,
    generation: u64,
    bundle: std::path::PathBuf,
    pid: u32,
    exit_status: u32,
    exited_at_unix_nanos: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeleteEvidence {
    pid: u32,
    exit_status: u32,
    exited_at_seconds: i64,
    exited_at_nanos: i32,
}

pub(super) async fn qualify(config: &QualificationConfig, prefix: &str) -> TestResult<()> {
    let id = format!("{prefix}-task-delete-replay");
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
        .map_err(|error| rpc_error("create task-Delete replay task", error))?
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
        .map_err(|error| rpc_error("start task-Delete replay task", error))?
        .into_inner();
    if created.pid == 0 || started.pid != created.pid {
        return Err(qualification_error(format!(
            "task-Delete replay PIDs were create={} and start={}; expected one stable nonzero PID",
            created.pid, started.pid
        ))
        .into());
    }

    let bundle = config.bundle(&id);
    let identity = read_runtime_identity(config, &id).await?;
    let bootstrap = load_bootstrap(&bundle).await?;
    let binary = load_shim_binary(&bundle).await?;
    let old_shim_pid = faults::find_exact_shim_pid(config, &id).await?;

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
        .map_err(|error| rpc_error("stop task-Delete replay task", error))?;
    let exit = TasksClient::new(channel)
        .wait(namespaced(
            WaitRequest {
                container_id: id.clone(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("wait task-Delete replay task", error))?
        .into_inner();
    if exit.exit_status != 42 {
        return Err(qualification_error(format!(
            "task-Delete replay workload exited {}, expected 42",
            exit.exit_status
        ))
        .into());
    }

    // This direct Task call models a containerd request whose response never
    // reaches the daemon. The daemon remains live so the shim can publish its
    // terminal event, but containerd does not own this ttrpc caller.
    let first = shim_delete_task(&bootstrap.address, &id).await?;
    if first.pid != started.pid || first.exit_status != 42 {
        return Err(qualification_error(format!(
            "first task Delete response was {first:?}; expected PID {} and exit 42",
            started.pid
        ))
        .into());
    }
    require_task_delete_receipt(config, &id, &bundle, &identity, first).await?;
    if tokio::fs::try_exists(bundle.join("a3s-oci-shim-v1.json"))
        .await
        .map_err(|error| qualification_error(format!("inspect deleted task metadata: {error}")))?
    {
        return Err(qualification_error(
            "task Delete response became replayable while main shim metadata still existed",
        )
        .into());
    }

    let containerd_pid = containerd_main_pid(config).await?;
    faults::send_signal(
        containerd_pid,
        libc::SIGSTOP,
        "task-Delete replay containerd",
    )?;
    let mut replacement = None;
    let relaunch = async {
        faults::send_signal(
            old_shim_pid,
            libc::SIGKILL,
            "task-Delete replay original shim",
        )?;
        wait_for_pid_exit(old_shim_pid, "task-Delete replay original shim").await?;
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
    let _ = faults::send_signal(
        containerd_pid,
        libc::SIGCONT,
        "task-Delete replay containerd",
    );
    if let Err(error) = relaunch {
        stop_replacement(&mut replacement).await;
        let recovery = restart_containerd(config, "failed-task-Delete-receipt-replay").await;
        return match recovery {
            Ok(_) => Err(error),
            Err(recovery_error) => Err(qualification_error(format!(
                "task Delete receipt replacement failed: {error}; containerd recovery also failed: {recovery_error}"
            ))
            .into()),
        };
    }

    let mut replacement = replacement
        .ok_or_else(|| qualification_error("task-Delete receipt relaunch omitted its child"))?;
    let replacement_pid = replacement
        .id()
        .ok_or_else(|| qualification_error("task-Delete receipt replacement has no PID"))?;
    let replayed = shim_delete_task(&bootstrap.address, &id).await?;
    if replayed != first {
        return Err(qualification_error(format!(
            "replacement task Delete replay was {replayed:?}; expected {first:?}"
        ))
        .into());
    }
    require_task_delete_receipt(config, &id, &bundle, &identity, first).await?;

    let channel = restart_containerd(config, "task-Delete-receipt-replay").await?;
    match TasksClient::new(channel)
        .delete(namespaced(
            DeleteTaskRequest {
                container_id: id.clone(),
            },
            &config.namespace,
        )?)
        .await
    {
        Ok(response) => {
            let response = response.into_inner();
            let replayed = DeleteEvidence {
                pid: response.pid,
                exit_status: response.exit_status,
                exited_at_seconds: response
                    .exited_at
                    .as_ref()
                    .ok_or_else(|| {
                        qualification_error(
                            "containerd task Delete replay omitted its exit timestamp",
                        )
                    })?
                    .seconds,
                exited_at_nanos: response
                    .exited_at
                    .as_ref()
                    .expect("timestamp checked above")
                    .nanos,
            };
            if replayed != first {
                return Err(qualification_error(format!(
                    "containerd task Delete replay was {replayed:?}; expected {first:?}"
                ))
                .into());
            }
        }
        Err(error) if error.code() == Code::NotFound => {
            // containerd 2.2 may classify the metadata-free replacement as a
            // leaked shim and consume the same receipt through DeleteShim.
        }
        Err(error) => {
            return Err(rpc_error("replay task Delete after daemon restart", error).into())
        }
    }
    wait_for_bundle_removal(config, &id).await?;
    if optional_task_process(config, &connect_ready(config).await?, &id, "")
        .await?
        .is_some()
    {
        return Err(
            qualification_error("task Delete receipt replay left containerd task state").into(),
        );
    }
    let observed_replacement = faults::find_exact_shim_pid(config, &id).await;
    if let Ok(observed) = observed_replacement {
        if observed != replacement_pid {
            return Err(qualification_error(format!(
                "task Delete replay changed replacement shim PID {replacement_pid} to {observed}"
            ))
            .into());
        }
    }
    delete_container(config, &id).await?;
    wait_for_replacement_exit(&mut replacement).await
}

async fn require_task_delete_receipt(
    config: &QualificationConfig,
    task_id: &str,
    bundle: &Path,
    identity: &RuntimeIdentity,
    expected: DeleteEvidence,
) -> TestResult<()> {
    let path = bundle.join(TASK_DELETE_RECEIPT_FILE_NAME);
    let bytes = tokio::fs::read(&path).await.map_err(|error| {
        qualification_error(format!(
            "read durable task Delete receipt {}: {error}",
            path.display()
        ))
    })?;
    let receipt: TaskDeleteReceiptEvidence = serde_json::from_slice(&bytes).map_err(|error| {
        qualification_error(format!(
            "decode durable task Delete receipt {}: {error}",
            path.display()
        ))
    })?;
    let seconds = u128::try_from(expected.exited_at_seconds)
        .map_err(|_| qualification_error("task Delete response recorded a negative timestamp"))?;
    let nanos = u128::try_from(expected.exited_at_nanos).map_err(|_| {
        qualification_error("task Delete response recorded negative subsecond nanoseconds")
    })?;
    let exited_at_unix_nanos = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or_else(|| qualification_error("task Delete exit timestamp overflowed u128"))?;
    if receipt.schema_version != 1
        || receipt.namespace != config.namespace
        || receipt.task_id != task_id
        || receipt.incarnation.as_deref() != Some(identity.incarnation.as_str())
        || receipt.container_id != identity.container_id.as_str()
        || receipt.generation != identity.generation
        || receipt.bundle != bundle
        || receipt.pid != expected.pid
        || receipt.exit_status != expected.exit_status
        || receipt.exited_at_unix_nanos != exited_at_unix_nanos
    {
        return Err(qualification_error(format!(
            "task Delete receipt did not retain the exact identity, generation, bundle, and response: {receipt:?}"
        ))
        .into());
    }
    Ok(())
}

async fn shim_delete_task(address: &str, task_id: &str) -> TestResult<DeleteEvidence> {
    let client = containerd_shim_protos::ttrpc::asynchronous::Client::connect(address)
        .await
        .map_err(|error| {
            qualification_error(format!(
                "connect task-Delete receipt shim at {address}: {error}"
            ))
        })?;
    let task = containerd_shim_protos::shim::shim_ttrpc_async::TaskClient::new(client);
    let mut request = containerd_shim_protos::api::DeleteRequest::new();
    request.set_id(task_id.to_string());
    let response = task
        .delete(
            containerd_shim_protos::ttrpc::context::Context::default(),
            &request,
        )
        .await
        .map_err(|error| {
            qualification_error(format!(
                "invoke task Delete through shim {address}: {error}"
            ))
        })?;
    Ok(DeleteEvidence {
        pid: response.pid(),
        exit_status: response.exit_status(),
        exited_at_seconds: response.exited_at().seconds,
        exited_at_nanos: response.exited_at().nanos,
    })
}
