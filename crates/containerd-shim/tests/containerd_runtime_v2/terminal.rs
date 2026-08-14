use std::path::Path;
use std::time::Duration;

use prost_types::Any;
use tokio::io::{AsyncBufReadExt, BufReader, Lines};
use tonic::transport::Channel;

use super::api::{
    DeleteProcessRequest, ExecProcessRequest, KillRequest, ResizePtyRequest, StartRequest,
    TasksClient, WaitRequest,
};
use super::support::*;

pub(crate) async fn qualify_terminal_exec_after_restart(
    config: &QualificationConfig,
    channel: &mut Channel,
    id: &str,
) -> TestResult<()> {
    let exec_id = "terminal-restart-exec";
    let stdout = config.bundle(id).join("terminal-restart-exec.stdout");
    create_fifo(&stdout).await?;
    let spec = serde_json::json!({
        "terminal": true,
        "user": {"uid": 0, "gid": 0},
        "args": [
            "/bin/sh",
            "-c",
            "trap 'exit 29' TERM; trap 'stty size' WINCH; printf 'ready\\n'; while :; do sleep 1; done"
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
                        qualification_error(format!("encode terminal exec process: {error}"))
                    })?,
                }),
                exec_id: exec_id.to_string(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("add terminal exec", error))?;
    let started = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: id.to_string(),
                exec_id: exec_id.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("start terminal exec", error))?
        .into_inner();
    if started.pid == 0 {
        return Err(qualification_error("terminal exec Start returned PID zero").into());
    }
    let mut output = BufReader::new(
        tokio::fs::File::open(&stdout)
            .await
            .map_err(|error| qualification_error(format!("open terminal stdout FIFO: {error}")))?,
    )
    .lines();
    expect_line(&mut output, "ready", "terminal exec startup").await?;

    resize(config, channel, id, exec_id, 91, 31).await?;
    expect_line(&mut output, "31 91", "terminal resize before restart").await?;

    *channel = restart_containerd(config, "terminal-exec-running").await?;
    let restored = task_process(config, channel, id, exec_id).await?;
    expect_process(
        &restored,
        STATUS_RUNNING,
        Some(started.pid),
        "terminal exec after containerd restart",
    )?;
    if !restored.terminal {
        return Err(qualification_error(
            "terminal exec lost its terminal flag after containerd restart",
        )
        .into());
    }

    resize(config, channel, id, exec_id, 132, 43).await?;
    expect_line(&mut output, "43 132", "terminal resize after restart").await?;
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
        .map_err(|error| rpc_error("signal terminal exec", error))?;
    let exit = TasksClient::new(channel.clone())
        .wait(namespaced(
            WaitRequest {
                container_id: id.to_string(),
                exec_id: exec_id.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("wait terminal exec", error))?
        .into_inner();
    if exit.exit_status != 29 {
        return Err(qualification_error(format!(
            "terminal exec SIGTERM exit status was {}, expected 29",
            exit.exit_status
        ))
        .into());
    }
    TasksClient::new(channel.clone())
        .delete_process(namespaced(
            DeleteProcessRequest {
                container_id: id.to_string(),
                exec_id: exec_id.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("delete terminal exec", error))?;
    drop(output);
    tokio::fs::remove_file(&stdout).await.map_err(|error| {
        qualification_error(format!(
            "remove terminal stdout FIFO after exec delete: {error}"
        ))
    })?;
    Ok(())
}

pub(crate) async fn create_fifo(path: &Path) -> TestResult<()> {
    let mut command = tokio::process::Command::new("mkfifo");
    command.arg("--mode=600").arg(path);
    let output = tokio::time::timeout(COMMAND_TIMEOUT, command.output())
        .await
        .map_err(|_| qualification_error("create terminal stdout FIFO timed out"))?
        .map_err(|error| qualification_error(format!("run mkfifo: {error}")))?;
    require_success("create terminal stdout FIFO", &output)
}

pub(crate) async fn resize(
    config: &QualificationConfig,
    channel: &Channel,
    id: &str,
    exec_id: &str,
    width: u32,
    height: u32,
) -> TestResult<()> {
    TasksClient::new(channel.clone())
        .resize_pty(namespaced(
            ResizePtyRequest {
                container_id: id.to_string(),
                exec_id: exec_id.to_string(),
                width,
                height,
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("resize terminal exec", error))?;
    Ok(())
}

pub(crate) async fn expect_line(
    lines: &mut Lines<BufReader<tokio::fs::File>>,
    expected: &str,
    context: &str,
) -> TestResult<()> {
    let line = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
        .await
        .map_err(|_| qualification_error(format!("{context} output timed out")))?
        .map_err(|error| qualification_error(format!("read {context} output: {error}")))?
        .ok_or_else(|| qualification_error(format!("{context} output reached early EOF")))?;
    if line.trim() != expected {
        return Err(qualification_error(format!(
            "{context} output was {line:?}, expected {expected:?}"
        ))
        .into());
    }
    Ok(())
}
