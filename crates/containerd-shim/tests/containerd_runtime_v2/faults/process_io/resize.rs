use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, Generation, OperationContext, ProcessTarget, ResizeRequest, StateRequest,
    TerminalSize,
};
use prost_types::Any;
use serde::Deserialize;
use tokio::io::AsyncBufReadExt;

use crate::api::{
    ContainersClient, CreateTaskRequest, ExecProcessRequest, GetContainerRequest, StartRequest,
    TasksClient,
};
use crate::support::*;
use crate::terminal;

use super::super::{
    containerd_exec_operation_id, containerd_process_id, find_exact_shim_pid, load_shim_address,
    runtime_client, wait_for_runtime_absence, wait_for_shim_cleanup, SuspendedProcess,
};

const EXEC_ID: &str = "committed-resize-exec";
const COMMITTED_SIZE: TerminalSize = TerminalSize {
    width: 166,
    height: 52,
};

#[derive(Debug, Deserialize)]
struct MetadataDocument {
    schema_version: u64,
    exec_sequence: u64,
    execs: Vec<ExecResizeEvidence>,
}

#[derive(Debug, Deserialize)]
struct ExecResizeEvidence {
    exec_id: String,
    incarnation: u64,
    #[serde(default)]
    resize_sequence: u64,
    pending_resize: Option<PendingResizeEvidence>,
    terminal_size: Option<TerminalSize>,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct PendingResizeEvidence {
    sequence: u64,
    size: TerminalSize,
}

pub(in super::super) async fn qualify_resize_effect_committed_shim_sigkill(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let id = format!("{prefix}-shim-kill-resize-committed");
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
        .map_err(|error| rpc_error("create committed-resize task", error))?
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
        .map_err(|error| rpc_error("start committed-resize task", error))?
        .into_inner();
    if created.pid == 0 || started.pid != created.pid {
        return Err(qualification_error(format!(
            "committed-resize task PIDs were create={} and start={}; expected one stable nonzero PID",
            created.pid, started.pid
        ))
        .into());
    }

    let bundle = config.bundle(&id);
    let stdout_path = bundle.join("committed-resize-exec.stdout");
    terminal::create_fifo(&stdout_path).await?;
    let spec = serde_json::json!({
        "terminal": true,
        "user": {"uid": 0, "gid": 0},
        "args": [
            "/bin/sh",
            "-c",
            "trap '' WINCH; printf 'resize-ready\\n'; while :; do sleep 1; done"
        ],
        "env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM=xterm"
        ],
        "cwd": "/",
        "noNewPrivileges": true
    });
    TasksClient::new(channel.clone())
        .exec(namespaced(
            ExecProcessRequest {
                container_id: id.clone(),
                exec_id: EXEC_ID.to_string(),
                stdout: stdout_path.to_string_lossy().into_owned(),
                terminal: true,
                spec: Some(Any {
                    type_url: crate::PROCESS_SPEC_TYPE.to_string(),
                    value: serde_json::to_vec(&spec).map_err(|error| {
                        qualification_error(format!(
                            "encode committed-resize terminal process: {error}"
                        ))
                    })?,
                }),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("add committed-resize exec", error))?;
    let exec = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: id.clone(),
                exec_id: EXEC_ID.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("start committed-resize exec", error))?
        .into_inner();
    if exec.pid == 0 || exec.pid == started.pid {
        return Err(qualification_error(format!(
            "committed-resize exec PID {} must be nonzero and distinct from init PID {}",
            exec.pid, started.pid
        ))
        .into());
    }
    let mut output =
        tokio::io::BufReader::new(tokio::fs::File::open(&stdout_path).await.map_err(|error| {
            qualification_error(format!("open committed-resize terminal output: {error}"))
        })?)
        .lines();
    terminal::expect_line(&mut output, "resize-ready", "committed-resize exec startup").await?;

    let identity = read_runtime_identity(config, &id).await?;
    let shim_address = load_shim_address(&bundle).await?;
    let host_pid = super::super::find_runtime_host_pid(config).await?;
    let shim_pid = find_exact_shim_pid(config, &id).await?;
    let mut suspended_host =
        SuspendedProcess::stop(host_pid, "committed-resize A3S OCI host service")?;
    let mut resize_call = spawn_resize(&shim_address, &id);
    wait_for_pending_resize(&bundle, &mut resize_call).await?;
    let suspended_shim = SuspendedProcess::stop(shim_pid, "committed-resize shim")?;
    suspended_host.resume("committed-resize A3S OCI host service")?;

    let process = exact_process_target(config, &id, &identity)?;
    commit_runtime_resize(config, &id, &identity, &process).await?;
    wait_for_terminal_size(exec.pid, COMMITTED_SIZE).await?;
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
                "read init state after committed Runtime ResizePty: {error}"
            ))
        })?;
    if init.generation != Generation(identity.generation)
        || *init.state.status() != ContainerState::Running
        || init.state.pid().and_then(|pid| u32::try_from(pid).ok()) != Some(started.pid)
    {
        return Err(qualification_error(format!(
            "committed Runtime ResizePty changed init generation, state, or PID: generation={}, status={}, pid={:?}",
            init.generation.0,
            init.state.status(),
            init.state.pid()
        ))
        .into());
    }

    suspended_shim.kill("committed-resize shim")?;
    drop(output);
    let lost_resize_response = expect_lost_resize_response(&mut resize_call).await;
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
                "read caller-owned metadata after committed Runtime ResizePty and shim SIGKILL",
                error,
            )
        })?;
    lost_resize_response?;
    delete_container(config, &id).await
}

fn spawn_resize(address: &str, id: &str) -> tokio::task::JoinHandle<TestResult<()>> {
    let address = address.to_string();
    let id = id.to_string();
    tokio::spawn(async move {
        let client = containerd_shim_protos::ttrpc::asynchronous::Client::connect(&address)
            .await
            .map_err(|error| {
                qualification_error(format!(
                    "connect committed-resize shim at {address}: {error}"
                ))
            })?;
        let task = containerd_shim_protos::shim::shim_ttrpc_async::TaskClient::new(client);
        let mut request = containerd_shim_protos::api::ResizePtyRequest::new();
        request.set_id(id.clone());
        request.set_exec_id(EXEC_ID.to_string());
        request.set_width(u32::from(COMMITTED_SIZE.width));
        request.set_height(u32::from(COMMITTED_SIZE.height));
        task.resize_pty(
            containerd_shim_protos::ttrpc::context::Context::default(),
            &request,
        )
        .await
        .map_err(|error| -> TestError {
            qualification_error(format!(
                "invoke ResizePty through shim {address} for {id}/{EXEC_ID}: {error}"
            ))
            .into()
        })?;
        Ok(())
    })
}

async fn wait_for_pending_resize(
    bundle: &Path,
    resize_call: &mut tokio::task::JoinHandle<TestResult<()>>,
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
            && exec.resize_sequence == 0
            && exec.pending_resize
                == Some(PendingResizeEvidence {
                    sequence: 1,
                    size: COMMITTED_SIZE,
                })
            && exec.terminal_size.is_none()
        {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(qualification_error(format!(
                "committed ResizePty did not retain schema-9 exec incarnation 1 and pending sequence 1 before reaching the suspended Runtime: {exec:?}"
            ))
            .into());
        }
        tokio::select! {
            result = &mut *resize_call => {
                return match result {
                    Ok(Ok(())) => Err(qualification_error(
                        "ResizePty returned before its durable resize reached the suspended Runtime",
                    ).into()),
                    Ok(Err(error)) => Err(qualification_error(format!(
                        "ResizePty failed before its durable resize reached the suspended Runtime: {error}"
                    )).into()),
                    Err(error) => Err(qualification_error(format!(
                        "ResizePty task failed before its durable resize reached the suspended Runtime: {error}"
                    )).into()),
                };
            }
            () = tokio::time::sleep(Duration::from_millis(10).min(remaining)) => {}
        }
    }
}

async fn commit_runtime_resize(
    config: &QualificationConfig,
    task_id: &str,
    identity: &RuntimeIdentity,
    process: &ProcessTarget,
) -> TestResult<()> {
    let client = runtime_client(config).await?;
    let request = ResizeRequest {
        context: OperationContext::new(containerd_exec_operation_id(
            &config.namespace,
            task_id,
            &identity.incarnation,
            EXEC_ID,
            1,
            "resize-1",
        )?),
        process: process.clone(),
        size: COMMITTED_SIZE,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.resize(request.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact Runtime ResizePty before shim death: {error}"
                ))
                .into());
            }
        }
    }
}

async fn wait_for_terminal_size(pid: u32, expected: TerminalSize) -> TestResult<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match terminal_size(pid) {
            Ok(actual) if actual == expected => return Ok(()),
            Ok(actual) if tokio::time::Instant::now() >= deadline => {
                return Err(qualification_error(format!(
                    "committed ResizePty left exec PID {pid} at {}x{}; expected {}x{}",
                    actual.width, actual.height, expected.width, expected.height
                ))
                .into());
            }
            Err(error) if tokio::time::Instant::now() >= deadline => return Err(error),
            Ok(_) | Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
}

fn terminal_size(pid: u32) -> TestResult<TerminalSize> {
    let path = format!("/proc/{pid}/fd/0");
    let descriptor = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path)
        .map_err(|error| {
            qualification_error(format!(
                "open terminal descriptor {path} for committed resize verification: {error}"
            ))
        })?;
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `size` is valid writable storage and `descriptor` remains open
    // for the duration of the TIOCGWINSZ call.
    if unsafe { libc::ioctl(descriptor.as_raw_fd(), libc::TIOCGWINSZ, &mut size) } < 0 {
        return Err(qualification_error(format!(
            "read terminal dimensions from {path}: {}",
            std::io::Error::last_os_error()
        ))
        .into());
    }
    Ok(TerminalSize {
        width: size.ws_col,
        height: size.ws_row,
    })
}

async fn expect_lost_resize_response(
    resize_call: &mut tokio::task::JoinHandle<TestResult<()>>,
) -> TestResult<()> {
    match tokio::time::timeout(Duration::from_secs(5), &mut *resize_call).await {
        Ok(Ok(Err(_))) => Ok(()),
        Ok(Ok(Ok(()))) => Err(qualification_error(
            "original ResizePty response survived after its frozen shim was killed",
        )
        .into()),
        Ok(Err(error)) => Err(qualification_error(format!(
            "original ResizePty task failed before reporting its lost response: {error}"
        ))
        .into()),
        Err(_) => {
            resize_call.abort();
            let _ = resize_call.await;
            Err(qualification_error(
                "original ResizePty call did not observe shim death within 5 seconds",
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
