use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use prost_types::Any;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader, Lines};
use tokio::process::Child;

use super::api::{
    CreateTaskRequest, DeleteProcessRequest, DeleteTaskRequest, ExecProcessRequest, KillRequest,
    StartRequest, TasksClient, WaitRequest,
};
use super::faults;
use super::support::*;
use super::terminal;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    version: u32,
    address: String,
    protocol: String,
}

pub(crate) async fn qualify_manual_shim_rehydration(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let id = format!("{prefix}-shim-rehydrate");
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
        .map_err(|error| rpc_error("create manual-rehydration task", error))?
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
        .map_err(|error| rpc_error("start manual-rehydration task", error))?
        .into_inner();
    if created.pid == 0 || started.pid != created.pid {
        return Err(qualification_error(format!(
            "manual-rehydration task PIDs were create={} and start={}; expected one stable nonzero PID",
            created.pid, started.pid
        ))
        .into());
    }

    let bundle = config.bundle(&id);
    let (exec_pid, terminal_stdout, mut terminal_output) =
        start_terminal_exec(config, &channel, &id, &bundle).await?;
    let identity = read_runtime_identity(config, &id).await?;
    let bootstrap = load_bootstrap(&bundle).await?;
    let binary = load_shim_binary(&bundle).await?;
    let old_shim_pid = faults::find_exact_shim_pid(config, &id).await?;
    let containerd_pid = containerd_main_pid(config).await?;
    faults::send_signal(containerd_pid, libc::SIGSTOP, "containerd")?;

    let mut replacement = None;
    let relaunch = relaunch_while_containerd_suspended(
        config,
        &id,
        &bundle,
        &binary,
        &bootstrap,
        old_shim_pid,
        containerd_pid,
        &mut replacement,
    )
    .await;
    let _ = faults::send_signal(containerd_pid, libc::SIGCONT, "containerd");
    if let Err(error) = relaunch {
        stop_replacement(&mut replacement).await;
        let recovery = restart_containerd(config, "failed-manual-shim-rehydration").await;
        return match recovery {
            Ok(_) => Err(error),
            Err(recovery_error) => Err(qualification_error(format!(
                "manual shim rehydration failed: {error}; containerd recovery also failed: {recovery_error}"
            ))
            .into()),
        };
    }
    let mut replacement = replacement
        .ok_or_else(|| qualification_error("manual shim relaunch omitted its child process"))?;
    let replacement_pid = replacement
        .id()
        .ok_or_else(|| qualification_error("manual shim replacement has no PID"))?;

    let channel = restart_containerd(config, "manual-shim-rehydration").await?;
    expect_process(
        &task_process(config, &channel, &id, "").await?,
        STATUS_RUNNING,
        Some(started.pid),
        "manually rehydrated shim task",
    )?;
    if read_runtime_identity(config, &id).await? != identity {
        return Err(qualification_error(
            "manual shim rehydration changed the task incarnation or runtime generation",
        )
        .into());
    }
    let observed_shim_pid = faults::find_exact_shim_pid(config, &id).await?;
    if observed_shim_pid != replacement_pid {
        return Err(qualification_error(format!(
            "containerd connected shim PID {observed_shim_pid}, expected replacement PID {replacement_pid}"
        ))
        .into());
    }

    finish_rehydrated_terminal_exec(
        config,
        &channel,
        &id,
        exec_pid,
        &terminal_stdout,
        &mut terminal_output,
    )
    .await?;

    TasksClient::new(channel.clone())
        .kill(namespaced(
            KillRequest {
                container_id: id.clone(),
                signal: 15,
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("signal manually rehydrated task", error))?;
    let exit = TasksClient::new(channel.clone())
        .wait(namespaced(
            WaitRequest {
                container_id: id.clone(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("wait manually rehydrated task", error))?
        .into_inner();
    if exit.exit_status != 42 {
        return Err(qualification_error(format!(
            "manually rehydrated task exited {}, expected 42",
            exit.exit_status
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
        .map_err(|error| rpc_error("delete manually rehydrated task", error))?
        .into_inner();
    if deleted.exit_status != 42 {
        return Err(qualification_error(format!(
            "manually rehydrated task Delete returned {}, expected 42",
            deleted.exit_status
        ))
        .into());
    }
    delete_container(config, &id).await?;
    wait_for_replacement_exit(&mut replacement).await
}

async fn start_terminal_exec(
    config: &QualificationConfig,
    channel: &tonic::transport::Channel,
    id: &str,
    bundle: &Path,
) -> TestResult<(u32, PathBuf, Lines<BufReader<tokio::fs::File>>)> {
    let exec_id = "rehydrated-terminal-exec";
    let stdout = bundle.join("rehydrated-terminal-exec.stdout");
    terminal::create_fifo(&stdout).await?;
    let spec = serde_json::json!({
        "terminal": true,
        "user": {"uid": 0, "gid": 0},
        "args": [
            "/bin/sh",
            "-c",
            "trap 'exit 31' TERM; trap 'stty size' WINCH; printf 'rehydrate-ready\\n'; while :; do sleep 1; done"
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
                container_id: id.to_string(),
                stdout: stdout.to_string_lossy().into_owned(),
                terminal: true,
                spec: Some(Any {
                    type_url: super::PROCESS_SPEC_TYPE.to_string(),
                    value: serde_json::to_vec(&spec).map_err(|error| {
                        qualification_error(format!(
                            "encode manually rehydrated terminal exec: {error}"
                        ))
                    })?,
                }),
                exec_id: exec_id.to_string(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("add terminal exec before shim rehydration", error))?;
    let started = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: id.to_string(),
                exec_id: exec_id.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("start terminal exec before shim rehydration", error))?
        .into_inner();
    if started.pid == 0 {
        return Err(qualification_error(
            "terminal exec before manual shim rehydration returned PID zero",
        )
        .into());
    }
    let mut output = BufReader::new(tokio::fs::File::open(&stdout).await.map_err(|error| {
        qualification_error(format!("open rehydrated terminal stdout FIFO: {error}"))
    })?)
    .lines();
    terminal::expect_line(
        &mut output,
        "rehydrate-ready",
        "terminal exec before manual shim rehydration",
    )
    .await?;
    terminal::resize(config, channel, id, exec_id, 97, 37).await?;
    terminal::expect_line(
        &mut output,
        "37 97",
        "terminal resize before manual shim rehydration",
    )
    .await?;
    Ok((started.pid, stdout, output))
}

async fn finish_rehydrated_terminal_exec(
    config: &QualificationConfig,
    channel: &tonic::transport::Channel,
    id: &str,
    exec_pid: u32,
    stdout: &Path,
    output: &mut Lines<BufReader<tokio::fs::File>>,
) -> TestResult<()> {
    let exec_id = "rehydrated-terminal-exec";
    let restored = task_process(config, channel, id, exec_id).await?;
    expect_process(
        &restored,
        STATUS_RUNNING,
        Some(exec_pid),
        "terminal exec after manual shim rehydration",
    )?;
    if !restored.terminal {
        return Err(qualification_error(
            "terminal exec lost terminal mode during manual shim rehydration",
        )
        .into());
    }
    terminal::resize(config, channel, id, exec_id, 143, 47).await?;
    terminal::expect_line(
        output,
        "47 143",
        "terminal output after manual shim rehydration",
    )
    .await?;
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
        .map_err(|error| rpc_error("signal terminal exec after shim rehydration", error))?;
    let exit = TasksClient::new(channel.clone())
        .wait(namespaced(
            WaitRequest {
                container_id: id.to_string(),
                exec_id: exec_id.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("wait terminal exec after shim rehydration", error))?
        .into_inner();
    if exit.exit_status != 31 {
        return Err(qualification_error(format!(
            "rehydrated terminal exec exited {}, expected 31",
            exit.exit_status
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
        .map_err(|error| rpc_error("delete terminal exec after shim rehydration", error))?
        .into_inner();
    if deleted.exit_status != 31 {
        return Err(qualification_error(format!(
            "rehydrated terminal exec Delete returned {}, expected 31",
            deleted.exit_status
        ))
        .into());
    }
    tokio::fs::remove_file(stdout).await.map_err(|error| {
        qualification_error(format!(
            "remove terminal FIFO after manual shim rehydration: {error}"
        ))
    })?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn relaunch_while_containerd_suspended(
    config: &QualificationConfig,
    id: &str,
    bundle: &Path,
    binary: &Path,
    bootstrap: &Bootstrap,
    old_shim_pid: u32,
    containerd_pid: u32,
    replacement: &mut Option<Child>,
) -> TestResult<()> {
    faults::send_signal(old_shim_pid, libc::SIGKILL, "original shim")?;
    wait_for_pid_exit(old_shim_pid, "original shim").await?;

    let containerd_address = config.socket.to_str().ok_or_else(|| {
        qualification_error("containerd gRPC socket path is not valid UTF-8 for shim arguments")
    })?;
    let mut command = tokio::process::Command::new(binary);
    command
        .current_dir(bundle)
        .env("TTRPC_ADDRESS", &config.ttrpc_address)
        .args([
            "-namespace",
            &config.namespace,
            "-id",
            id,
            "-address",
            containerd_address,
            "-socket",
            &bootstrap.address,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    *replacement =
        Some(command.spawn().map_err(|error| {
            qualification_error(format!("spawn manual shim replacement: {error}"))
        })?);
    let child = replacement
        .as_mut()
        .ok_or_else(|| qualification_error("manual shim replacement disappeared after spawn"))?;
    let replacement_pid = child
        .id()
        .ok_or_else(|| qualification_error("manual shim replacement has no PID after spawn"))?;
    wait_for_shim_socket(child, &bootstrap.address).await?;
    let observed = faults::find_exact_shim_pid(config, id).await?;
    if observed != replacement_pid {
        return Err(qualification_error(format!(
            "manual shim replacement PID was {replacement_pid}, but procfs resolved {observed}"
        ))
        .into());
    }
    faults::send_signal(containerd_pid, libc::SIGKILL, "suspended containerd")
}

async fn load_bootstrap(bundle: &Path) -> TestResult<Bootstrap> {
    let bytes = tokio::fs::read(bundle.join("bootstrap.json"))
        .await
        .map_err(|error| qualification_error(format!("read shim bootstrap metadata: {error}")))?;
    let bootstrap: Bootstrap = serde_json::from_slice(&bytes)
        .map_err(|error| qualification_error(format!("decode shim bootstrap metadata: {error}")))?;
    if bootstrap.version != 2 || bootstrap.protocol != "ttrpc" {
        return Err(qualification_error(format!(
            "shim bootstrap contract was version={} protocol={:?}; expected version 2 ttrpc",
            bootstrap.version, bootstrap.protocol
        ))
        .into());
    }
    let socket = bootstrap
        .address
        .strip_prefix("unix://")
        .ok_or_else(|| qualification_error("shim bootstrap address is not a unix:// URI"))?;
    if !Path::new(socket).is_absolute() {
        return Err(qualification_error("shim bootstrap socket path is not absolute").into());
    }
    Ok(bootstrap)
}

async fn load_shim_binary(bundle: &Path) -> TestResult<PathBuf> {
    let path = tokio::fs::read_to_string(bundle.join("shim-binary-path"))
        .await
        .map_err(|error| qualification_error(format!("read shim binary path: {error}")))?;
    tokio::fs::canonicalize(path.trim())
        .await
        .map_err(|error| qualification_error(format!("resolve shim binary path: {error}")).into())
}

async fn wait_for_shim_socket(child: &mut Child, address: &str) -> TestResult<()> {
    let socket = address
        .strip_prefix("unix://")
        .ok_or_else(|| qualification_error("manual shim socket is not a unix:// URI"))?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| qualification_error(format!("inspect manual shim child: {error}")))?
        {
            let stderr = read_child_stderr(child).await;
            return Err(qualification_error(format!(
                "manual shim replacement exited early with {status}: {stderr}"
            ))
            .into());
        }
        if tokio::net::UnixStream::connect(socket).await.is_ok() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(qualification_error(format!(
                "manual shim replacement did not bind {socket} within 5 seconds"
            ))
            .into());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_pid_exit(pid: u32, context: &str) -> TestResult<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if !tokio::fs::try_exists(format!("/proc/{pid}"))
            .await
            .map_err(|error| qualification_error(format!("inspect {context} PID: {error}")))?
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(qualification_error(format!(
                "{context} PID {pid} did not exit within 5 seconds"
            ))
            .into());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_replacement_exit(child: &mut Child) -> TestResult<()> {
    match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(qualification_error(format!(
            "manual shim replacement exited with {status} after task delete"
        ))
        .into()),
        Ok(Err(error)) => Err(qualification_error(format!(
            "wait for manual shim replacement after task delete: {error}"
        ))
        .into()),
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            Err(qualification_error(
                "manual shim replacement did not exit within 5 seconds after task delete",
            )
            .into())
        }
    }
}

async fn stop_replacement(child: &mut Option<Child>) {
    if let Some(child) = child {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
}

async fn read_child_stderr(child: &mut Child) -> String {
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr).await;
    }
    stderr
}
