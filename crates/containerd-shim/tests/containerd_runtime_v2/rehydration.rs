use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use a3s_oci_sdk::{
    ContainerTarget, Generation, OperationContext, ProcessTarget, WriteStdinRequest,
};
use prost_types::Any;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::Child;

use super::api::{
    CreateTaskRequest, DeleteProcessRequest, DeleteTaskRequest, ExecProcessRequest, KillRequest,
    StartRequest, TasksClient, WaitRequest,
};
use super::faults;
use super::support::*;
use super::terminal;

#[path = "rehydration/close.rs"]
mod close;
#[path = "rehydration/control.rs"]
mod control;
#[path = "rehydration/resize.rs"]
mod resize;
#[path = "rehydration/signal.rs"]
mod signal;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    version: u32,
    address: String,
    protocol: String,
}

struct RehydratedTerminalExec {
    pid: u32,
    stdin_path: PathBuf,
    stdin: Option<tokio::fs::File>,
    stdout_path: PathBuf,
    output: Lines<BufReader<tokio::fs::File>>,
}

#[derive(Debug)]
struct StdinJournalEvidence {
    schema_version: u64,
    completed_sequence: u64,
    pending: Option<PendingStdinEvidence>,
    close_state: String,
    output_cursor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingStdinEvidence {
    sequence: u64,
    data: Vec<u8>,
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
    let mut terminal_exec = start_terminal_exec(config, &channel, &id, &bundle).await?;
    let identity = read_runtime_identity(config, &id).await?;
    let bootstrap = load_bootstrap(&bundle).await?;
    let binary = load_shim_binary(&bundle).await?;
    let old_shim_pid = faults::find_exact_shim_pid(config, &id).await?;
    let pending_data = b"committed-before-rehydrate\n";
    let host_pid = faults::find_runtime_host_pid(config).await?;
    let mut suspended_host = faults::SuspendedProcess::stop(host_pid, "A3S OCI host service")?;
    terminal_exec
        .stdin
        .as_mut()
        .ok_or_else(|| {
            qualification_error("terminal stdin disappeared before pending rehydration write")
        })?
        .write_all(pending_data)
        .await
        .map_err(|error| {
            qualification_error(format!(
                "write pending terminal stdin before shim rehydration: {error}"
            ))
        })?;
    terminal_exec
        .stdin
        .as_mut()
        .ok_or_else(|| {
            qualification_error("terminal stdin disappeared before pending rehydration flush")
        })?
        .flush()
        .await
        .map_err(|error| {
            qualification_error(format!(
                "flush pending terminal stdin before shim rehydration: {error}"
            ))
        })?;
    wait_for_exec_pending_stdin(&bundle, "rehydrated-terminal-exec", 2, 3, pending_data).await?;
    let suspended_shim =
        faults::SuspendedProcess::stop(old_shim_pid, "pending-stdin original shim")?;
    suspended_host.resume("A3S OCI host service")?;
    commit_runtime_exec_stdin(
        config,
        &id,
        "rehydrated-terminal-exec",
        &identity,
        3,
        pending_data,
    )
    .await?;

    let containerd_pid = containerd_main_pid(config).await?;
    faults::send_signal(containerd_pid, libc::SIGSTOP, "containerd")?;

    let mut replacement = None;
    let relaunch = async {
        suspended_shim.kill("pending-stdin original shim")?;
        wait_for_pid_exit(old_shim_pid, "pending-stdin original shim").await?;
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
    let replacement = replacement
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

    finish_rehydrated_terminal_exec(config, &channel, &id, &mut terminal_exec).await?;
    let (_, replacement) = control::qualify(
        config,
        &id,
        &bundle,
        &binary,
        &bootstrap,
        &identity,
        started.pid,
        replacement,
    )
    .await?;
    let (_, replacement) = signal::qualify(
        config,
        &id,
        &bundle,
        &binary,
        &bootstrap,
        &identity,
        &terminal_exec,
        replacement,
    )
    .await?;
    let (_, replacement, stdin_sequence) = resize::qualify(
        config,
        &id,
        &bundle,
        &binary,
        &bootstrap,
        &identity,
        &mut terminal_exec,
        replacement,
    )
    .await?;
    let (channel, mut replacement) = close::qualify(
        config,
        &id,
        &bundle,
        &binary,
        &bootstrap,
        &identity,
        &mut terminal_exec,
        replacement,
        stdin_sequence,
    )
    .await?;
    stop_rehydrated_terminal_exec(config, &channel, &id, &mut terminal_exec).await?;

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
) -> TestResult<RehydratedTerminalExec> {
    let exec_id = "rehydrated-terminal-exec";
    let stdin = bundle.join("rehydrated-terminal-exec.stdin");
    let stdout = bundle.join("rehydrated-terminal-exec.stdout");
    terminal::create_fifo(&stdin).await?;
    terminal::create_fifo(&stdout).await?;
    let mut stdin_writer = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&stdin)
        .await
        .map_err(|error| {
            qualification_error(format!(
                "open rehydrated terminal stdin FIFO for read/write: {error}"
            ))
        })?;
    let spec = serde_json::json!({
        "terminal": true,
        "user": {"uid": 0, "gid": 0},
        "args": [
            "/bin/sh",
            "-c",
            "stty -echo; trap 'exit 31' TERM; trap '' WINCH; printf 'rehydrate-ready\\n'; while IFS= read -r line; do if [ \"$line\" = __a3s_size__ ]; then stty size; else printf 'stdin:%s\\n' \"$line\"; fi; done; printf 'stdin-closed\\n'; while :; do sleep 1; done"
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
                stdin: stdin.to_string_lossy().into_owned(),
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
    stdin_writer
        .write_all(b"before-rehydrate\n")
        .await
        .map_err(|error| {
            qualification_error(format!("write terminal stdin before rehydration: {error}"))
        })?;
    stdin_writer.flush().await.map_err(|error| {
        qualification_error(format!("flush terminal stdin before rehydration: {error}"))
    })?;
    terminal::expect_line(
        &mut output,
        "stdin:before-rehydrate",
        "terminal stdin before manual shim rehydration",
    )
    .await?;
    terminal::resize(config, channel, id, exec_id, 97, 37).await?;
    stdin_writer
        .write_all(b"__a3s_size__\n")
        .await
        .map_err(|error| {
            qualification_error(format!(
                "request terminal size before shim rehydration: {error}"
            ))
        })?;
    stdin_writer.flush().await.map_err(|error| {
        qualification_error(format!(
            "flush terminal size request before shim rehydration: {error}"
        ))
    })?;
    terminal::expect_line(
        &mut output,
        "37 97",
        "terminal resize before manual shim rehydration",
    )
    .await?;
    wait_for_exec_stdin_sequence(bundle, exec_id, 2).await?;
    Ok(RehydratedTerminalExec {
        pid: started.pid,
        stdin_path: stdin,
        stdin: Some(stdin_writer),
        stdout_path: stdout,
        output,
    })
}

async fn finish_rehydrated_terminal_exec(
    config: &QualificationConfig,
    channel: &tonic::transport::Channel,
    id: &str,
    exec: &mut RehydratedTerminalExec,
) -> TestResult<()> {
    let exec_id = "rehydrated-terminal-exec";
    let restored = task_process(config, channel, id, exec_id).await?;
    expect_process(
        &restored,
        STATUS_RUNNING,
        Some(exec.pid),
        "terminal exec after manual shim rehydration",
    )?;
    if !restored.terminal {
        return Err(qualification_error(
            "terminal exec lost terminal mode during manual shim rehydration",
        )
        .into());
    }
    let bundle = exec.stdin_path.parent().ok_or_else(|| {
        qualification_error("rehydrated terminal stdin path has no bundle parent")
    })?;
    let restored_journal = read_exec_stdin_journal(bundle, exec_id).await?;
    if restored_journal.schema_version != 9
        || restored_journal.completed_sequence != 3
        || restored_journal.pending.is_some()
        || restored_journal.close_state != "open"
        || restored_journal.output_cursor == 0
    {
        return Err(qualification_error(format!(
            "terminal stdin journal after manual shim rehydration was {restored_journal:?}; expected schema 9, completed sequence 3, no pending write, open stdin, and a nonzero output cursor"
        ))
        .into());
    }
    terminal::expect_line(
        &mut exec.output,
        "stdin:committed-before-rehydrate",
        "committed terminal stdin replay after manual shim rehydration",
    )
    .await?;
    let stdin = exec.stdin.as_mut().ok_or_else(|| {
        qualification_error("terminal stdin writer disappeared during manual shim rehydration")
    })?;
    stdin
        .write_all(b"after-rehydrate\n")
        .await
        .map_err(|error| {
            qualification_error(format!("write terminal stdin after rehydration: {error}"))
        })?;
    stdin.flush().await.map_err(|error| {
        qualification_error(format!("flush terminal stdin after rehydration: {error}"))
    })?;
    if let Err(error) = terminal::expect_line(
        &mut exec.output,
        "stdin:after-rehydrate",
        "terminal stdin after manual shim rehydration",
    )
    .await
    {
        let journal = read_exec_stdin_journal(bundle, exec_id).await?;
        return Err(qualification_error(format!(
            "terminal stdin after manual shim rehydration failed: {error}; stdin journal was {journal:?}"
        ))
        .into());
    }
    terminal::resize(config, channel, id, exec_id, 143, 47).await?;
    stdin.write_all(b"__a3s_size__\n").await.map_err(|error| {
        qualification_error(format!(
            "request terminal size after shim rehydration: {error}"
        ))
    })?;
    stdin.flush().await.map_err(|error| {
        qualification_error(format!(
            "flush terminal size request after shim rehydration: {error}"
        ))
    })?;
    terminal::expect_line(
        &mut exec.output,
        "47 143",
        "terminal output after manual shim rehydration",
    )
    .await?;
    wait_for_exec_stdin_sequence(bundle, exec_id, 5).await?;
    Ok(())
}

async fn stop_rehydrated_terminal_exec(
    config: &QualificationConfig,
    channel: &tonic::transport::Channel,
    id: &str,
    exec: &mut RehydratedTerminalExec,
) -> TestResult<()> {
    let exec_id = "rehydrated-terminal-exec";
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
    drop(exec.stdin.take());
    tokio::fs::remove_file(&exec.stdin_path)
        .await
        .map_err(|error| {
            qualification_error(format!(
                "remove terminal stdin FIFO after manual shim rehydration: {error}"
            ))
        })?;
    tokio::fs::remove_file(&exec.stdout_path)
        .await
        .map_err(|error| {
            qualification_error(format!(
                "remove terminal FIFO after manual shim rehydration: {error}"
            ))
        })?;
    Ok(())
}

async fn wait_for_exec_stdin_sequence(
    bundle: &Path,
    exec_id: &str,
    expected: u64,
) -> TestResult<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let evidence = read_exec_stdin_journal(bundle, exec_id).await?;
        if evidence.completed_sequence == expected && evidence.pending.is_none() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(qualification_error(format!(
                "terminal stdin journal did not commit sequence {expected}: {evidence:?}"
            ))
            .into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_exec_pending_stdin(
    bundle: &Path,
    exec_id: &str,
    completed_sequence: u64,
    pending_sequence: u64,
    data: &[u8],
) -> TestResult<()> {
    let expected = PendingStdinEvidence {
        sequence: pending_sequence,
        data: data.to_vec(),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let evidence = read_exec_stdin_journal(bundle, exec_id).await?;
        if evidence.completed_sequence == completed_sequence
            && evidence.pending.as_ref() == Some(&expected)
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(qualification_error(format!(
                "terminal stdin journal did not retain pending sequence {pending_sequence}: {evidence:?}"
            ))
            .into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn read_exec_stdin_journal(bundle: &Path, exec_id: &str) -> TestResult<StdinJournalEvidence> {
    let path = bundle.join("a3s-oci-shim-v1.json");
    let document: serde_json::Value = serde_json::from_slice(
        &tokio::fs::read(&path)
            .await
            .map_err(|error| qualification_error(format!("read shim metadata: {error}")))?,
    )
    .map_err(|error| qualification_error(format!("decode shim metadata: {error}")))?;
    let exec = document["execs"]
        .as_array()
        .and_then(|execs| {
            execs
                .iter()
                .find(|exec| exec["exec_id"].as_str() == Some(exec_id))
        })
        .ok_or_else(|| qualification_error(format!("shim metadata omitted exec {exec_id}")))?;
    Ok(StdinJournalEvidence {
        schema_version: document["schema_version"]
            .as_u64()
            .ok_or_else(|| qualification_error("shim metadata omitted schema_version"))?,
        completed_sequence: exec["stdin_sequence"].as_u64().unwrap_or(0),
        pending: serde_json::from_value(
            exec.get("pending_stdin_write")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .map_err(|error| {
            qualification_error(format!(
                "decode shim metadata pending stdin for exec {exec_id}: {error}"
            ))
        })?,
        close_state: exec["stdin_close_state"]
            .as_str()
            .unwrap_or("open")
            .to_string(),
        output_cursor: exec["output_cursor"].as_u64().unwrap_or(0),
    })
}

async fn commit_runtime_exec_stdin(
    config: &QualificationConfig,
    task_id: &str,
    exec_id: &str,
    identity: &RuntimeIdentity,
    sequence: u64,
    data: &[u8],
) -> TestResult<()> {
    let client = faults::runtime_client(config).await?;
    let request = WriteStdinRequest {
        context: OperationContext::new(faults::containerd_exec_operation_id(
            &config.namespace,
            task_id,
            &identity.incarnation,
            exec_id,
            1,
            &format!("write-stdin-{sequence}"),
        )?),
        process: ProcessTarget {
            container: ContainerTarget::exact(
                identity.container_id.clone(),
                Generation(identity.generation),
            ),
            process_id: faults::containerd_process_id(&config.namespace, task_id, exec_id, 1)?,
        },
        data: data.to_vec(),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.write_stdin(request.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact runtime WriteStdin before shim replacement: {error}"
                ))
                .into());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn launch_replacement_while_containerd_suspended(
    config: &QualificationConfig,
    id: &str,
    bundle: &Path,
    binary: &Path,
    bootstrap: &Bootstrap,
    containerd_pid: u32,
    replacement: &mut Option<Child>,
) -> TestResult<()> {
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
