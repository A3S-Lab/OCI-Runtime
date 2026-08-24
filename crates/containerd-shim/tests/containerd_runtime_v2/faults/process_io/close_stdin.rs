use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    CloseStdinRequest, ContainerTarget, Generation, OperationContext, ProcessTarget, StateRequest,
    WaitProcessRequest,
};
use prost_types::Any;

use crate::api::{
    CloseIORequest, ContainersClient, CreateTaskRequest, ExecProcessRequest, GetContainerRequest,
    StartRequest, TasksClient,
};
use crate::support::*;
use crate::terminal;

use super::super::{
    containerd_exec_operation_id, containerd_process_id, find_exact_shim_pid, runtime_client,
    wait_for_runtime_absence, wait_for_shim_cleanup, SuspendedProcess,
};
use super::{MetadataDocument, StdinCloseEvidence};

const EXEC_ID: &str = "committed-close-stdin-exec";
const EXEC_EXIT_STATUS: i32 = 29;

pub(in super::super) async fn qualify_close_stdin_effect_committed_shim_sigkill(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let id = format!("{prefix}-shim-kill-close-stdin-committed");
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
        .map_err(|error| rpc_error("create committed-close task", error))?
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
        .map_err(|error| rpc_error("start committed-close task", error))?
        .into_inner();
    if created.pid == 0 || started.pid != created.pid {
        return Err(qualification_error(format!(
            "committed-close task PIDs were create={} and start={}; expected one stable nonzero PID",
            created.pid, started.pid
        ))
        .into());
    }

    let bundle = config.bundle(&id);
    let stdin_path = bundle.join("committed-close-stdin-exec.stdin");
    terminal::create_fifo(&stdin_path).await?;
    let stdin = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&stdin_path)
        .await
        .map_err(|error| {
            qualification_error(format!("open committed-close FIFO for read/write: {error}"))
        })?;
    let spec = serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0},
        "args": [
            "/bin/sh",
            "-c",
            "if IFS= read -r line; then exit 91; fi; exit 29"
        ],
        "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    });
    TasksClient::new(channel.clone())
        .exec(namespaced(
            ExecProcessRequest {
                container_id: id.clone(),
                exec_id: EXEC_ID.to_string(),
                stdin: stdin_path.to_string_lossy().into_owned(),
                spec: Some(Any {
                    type_url: crate::PROCESS_SPEC_TYPE.to_string(),
                    value: serde_json::to_vec(&spec).map_err(|error| {
                        qualification_error(format!("encode committed-close exec process: {error}"))
                    })?,
                }),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("add committed-close exec", error))?;
    let exec = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: id.clone(),
                exec_id: EXEC_ID.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("start committed-close exec", error))?
        .into_inner();
    if exec.pid == 0 || exec.pid == started.pid {
        return Err(qualification_error(format!(
            "committed-close exec PID {} must be nonzero and distinct from init PID {}",
            exec.pid, started.pid
        ))
        .into());
    }

    let identity = read_runtime_identity(config, &id).await?;
    let host_pid = super::super::find_runtime_host_pid(config).await?;
    let shim_pid = find_exact_shim_pid(config, &id).await?;
    let mut suspended_host =
        SuspendedProcess::stop(host_pid, "committed-close A3S OCI host service")?;
    let mut close_call = spawn_close_io(&channel, config, &id);
    wait_for_closing_stdin(&bundle, &mut close_call).await?;
    let suspended_shim = SuspendedProcess::stop(shim_pid, "committed-close shim")?;
    suspended_host.resume("committed-close A3S OCI host service")?;

    let process = exact_process_target(config, &id, &identity)?;
    commit_runtime_close(config, &id, &identity, &process).await?;
    let exit = wait_runtime_process(config, process).await?;
    if exit.exit_code != Some(EXEC_EXIT_STATUS) || exit.signal.is_some() || exit.oom_killed {
        return Err(qualification_error(format!(
            "committed Runtime CloseStdin produced exitCode={:?}, signal={:?}, oomKilled={}; expected exit {EXEC_EXIT_STATUS}",
            exit.exit_code, exit.signal, exit.oom_killed
        ))
        .into());
    }
    let init = runtime_client(config)
        .await?
        .state(StateRequest {
            target: ContainerTarget::exact(
                identity.container_id.clone(),
                Generation(identity.generation),
            ),
        })
        .await
        .map_err(|error| {
            qualification_error(format!(
                "read init state after committed Runtime CloseStdin: {error}"
            ))
        })?;
    if init.generation != Generation(identity.generation)
        || *init.state.status() != ContainerState::Running
        || init.state.pid().and_then(|pid| u32::try_from(pid).ok()) != Some(started.pid)
    {
        return Err(qualification_error(format!(
            "committed Runtime CloseStdin changed init generation, state, or PID: generation={}, status={}, pid={:?}",
            init.generation.0,
            init.state.status(),
            init.state.pid()
        ))
        .into());
    }

    suspended_shim.kill("committed-close shim")?;
    drop(stdin);
    let lost_close_response = expect_lost_close_response(&mut close_call).await;
    wait_for_shim_cleanup(config, &channel, &id, shim_pid, &[started.pid, exec.pid]).await?;
    wait_for_runtime_absence(config, identity.container_id).await?;
    ContainersClient::new(channel)
        .get(namespaced(
            GetContainerRequest { id: id.clone() },
            &config.namespace,
        )?)
        .await
        .map_err(|error| {
            rpc_error(
                "read caller-owned metadata after committed Runtime CloseStdin and shim SIGKILL",
                error,
            )
        })?;
    lost_close_response?;
    delete_container(config, &id).await
}

fn spawn_close_io(
    channel: &tonic::transport::Channel,
    config: &QualificationConfig,
    id: &str,
) -> tokio::task::JoinHandle<TestResult<()>> {
    let channel = channel.clone();
    let namespace = config.namespace.clone();
    let id = id.to_string();
    tokio::spawn(async move {
        TasksClient::new(channel)
            .close_io(namespaced(
                CloseIORequest {
                    container_id: id.clone(),
                    exec_id: EXEC_ID.to_string(),
                    stdin: true,
                },
                &namespace,
            )?)
            .await
            .map_err(|error| rpc_error("close committed-close exec stdin", error))?;
        Ok(())
    })
}

async fn wait_for_closing_stdin(
    bundle: &Path,
    close_call: &mut tokio::task::JoinHandle<TestResult<()>>,
) -> TestResult<()> {
    let path = bundle.join("a3s-oci-shim-v1.json");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let document: MetadataDocument = serde_json::from_slice(
            &tokio::fs::read(&path)
                .await
                .map_err(|error| qualification_error(format!("read shim metadata: {error}")))?,
        )
        .map_err(|error| qualification_error(format!("decode shim metadata: {error}")))?;
        let exec = document
            .execs
            .iter()
            .find(|exec| exec.exec_id == EXEC_ID)
            .ok_or_else(|| qualification_error(format!("shim metadata omitted exec {EXEC_ID}")))?;
        if document.schema_version == 9
            && document.exec_sequence == 1
            && exec.incarnation == 1
            && exec.stdin_sequence == 0
            && exec.pending_stdin_write.is_none()
            && exec.stdin_close_state == StdinCloseEvidence::Closing
        {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(qualification_error(format!(
                "committed CloseStdin did not retain schema-9 exec incarnation 1 and closing stdin before reaching the suspended Runtime: {exec:?}"
            ))
            .into());
        }
        tokio::select! {
            result = &mut *close_call => {
                return match result {
                    Ok(Ok(())) => Err(qualification_error(
                        "CloseIO returned before its durable close reached the suspended Runtime",
                    ).into()),
                    Ok(Err(error)) => Err(qualification_error(format!(
                        "CloseIO failed before its durable close reached the suspended Runtime: {error}"
                    )).into()),
                    Err(error) => Err(qualification_error(format!(
                        "CloseIO task failed before its durable close reached the suspended Runtime: {error}"
                    )).into()),
                };
            }
            () = tokio::time::sleep(Duration::from_millis(10).min(remaining)) => {}
        }
    }
}

async fn commit_runtime_close(
    config: &QualificationConfig,
    task_id: &str,
    identity: &RuntimeIdentity,
    process: &ProcessTarget,
) -> TestResult<()> {
    let client = runtime_client(config).await?;
    let request = CloseStdinRequest {
        context: OperationContext::new(containerd_exec_operation_id(
            &config.namespace,
            task_id,
            &identity.incarnation,
            EXEC_ID,
            1,
            "close-stdin",
        )?),
        process: process.clone(),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.close_stdin(request.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact Runtime CloseStdin before shim death: {error}"
                ))
                .into());
            }
        }
    }
}

async fn wait_runtime_process(
    config: &QualificationConfig,
    process: ProcessTarget,
) -> TestResult<a3s_oci_sdk::ExitStatus> {
    let client = runtime_client(config).await?;
    let request = WaitProcessRequest {
        process,
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
                    "observe committed Runtime CloseStdin effect: {error}"
                ))
                .into());
            }
        }
    }
}

async fn expect_lost_close_response(
    close_call: &mut tokio::task::JoinHandle<TestResult<()>>,
) -> TestResult<()> {
    match tokio::time::timeout(Duration::from_secs(5), &mut *close_call).await {
        Ok(Ok(Err(_))) => Ok(()),
        Ok(Ok(Ok(()))) => Err(qualification_error(
            "original CloseIO response survived after its frozen shim was killed",
        )
        .into()),
        Ok(Err(error)) => Err(qualification_error(format!(
            "original CloseIO task failed before reporting its lost response: {error}"
        ))
        .into()),
        Err(_) => {
            close_call.abort();
            let _ = close_call.await;
            Err(qualification_error(
                "original CloseIO call did not observe shim death within 5 seconds",
            )
            .into())
        }
    }
}

fn exact_process_target(
    config: &QualificationConfig,
    task_id: &str,
    identity: &RuntimeIdentity,
) -> TestResult<ProcessTarget> {
    Ok(ProcessTarget {
        container: ContainerTarget::exact(
            identity.container_id.clone(),
            Generation(identity.generation),
        ),
        process_id: containerd_process_id(&config.namespace, task_id, EXEC_ID, 1)?,
    })
}
