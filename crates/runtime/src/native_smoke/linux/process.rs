use std::future::Future;
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{
    CloseStdinRequest, ContainerTarget, Error, ErrorCode, ExecRequest, ExitStatus, IoMode,
    OperationContext, OperationId, OutputStream, ProcessId, ProcessIo, ProcessTarget,
    ReadOutputRequest, ResizeRequest, RuntimeClient, Signal, SignalProcessRequest, TerminalSize,
    WaitProcessRequest, WriteStdinRequest,
};
use tokio::time::{timeout, Instant};

const CALL_TIMEOUT: Duration = Duration::from_secs(15);
const LIFECYCLE_TIMEOUT_MS: u64 = 15_000;

pub(super) async fn exercise_process_io(
    client: &RuntimeClient,
    target: &ContainerTarget,
    nonce: &str,
) -> Result<(), String> {
    let mut request = exec_request(
        target,
        nonce,
        "io",
        "exec-io",
        "IFS= read -r line; printf 'stdout:%s\\n' \"$line\"; \
         printf 'stderr:%s\\n' \"$line\" >&2",
    )?;
    request.io = ProcessIo {
        stdin: IoMode::Pipe,
        stdout: IoMode::Capture,
        stderr: IoMode::Capture,
        terminal_size: None,
    };
    let process = ProcessTarget {
        container: request.container.clone(),
        process_id: request.process_id.clone(),
    };
    let created = call("exec process I/O probe", client.exec(request)).await?;
    if created.target != process || created.pid.is_none() || created.terminal {
        return Err("native process I/O probe returned an invalid identity".into());
    }

    call(
        "write process I/O probe stdin",
        client.write_stdin(WriteStdinRequest {
            process: process.clone(),
            data: b"a3s-io\n".to_vec(),
        }),
    )
    .await?;
    let close = CloseStdinRequest {
        process: process.clone(),
    };
    call(
        "close process I/O probe stdin",
        client.close_stdin(close.clone()),
    )
    .await?;
    call(
        "repeat process I/O probe stdin close",
        client.close_stdin(close),
    )
    .await?;

    let status = call(
        "wait process I/O probe",
        client.wait_process(WaitProcessRequest {
            process: process.clone(),
            timeout_ms: Some(LIFECYCLE_TIMEOUT_MS),
        }),
    )
    .await?;
    let expected = ExitStatus::exited(0)
        .map_err(|error| format!("failed to construct process I/O exit status: {error}"))?;
    if status != expected {
        return Err(format!(
            "native process I/O probe returned {status:?}, expected {expected:?}"
        ));
    }

    let (stdout, stderr) = collect_output(client, &process).await?;
    if stdout != b"stdout:a3s-io\n" || stderr != b"stderr:a3s-io\n" {
        return Err(format!(
            "native captured output mismatch: stdout={stdout:?}, stderr={stderr:?}"
        ));
    }
    match timeout(
        CALL_TIMEOUT,
        client.write_stdin(WriteStdinRequest {
            process,
            data: b"late".to_vec(),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::FailedPrecondition => Ok(()),
        Ok(Err(error)) => Err(call_error("write after process stdin close", &error)),
        Ok(Ok(())) => Err("native runtime accepted stdin after close".into()),
        Err(_) => Err("write after process stdin close timed out".into()),
    }
}

pub(super) async fn exercise_terminal_io(
    client: &RuntimeClient,
    target: &ContainerTarget,
    nonce: &str,
) -> Result<(), String> {
    let process = terminal_exec_request(
        target,
        nonce,
        "terminal",
        "exec-terminal",
        "/bin/busybox stty size; IFS= read -r line; /bin/busybox stty size; \
         printf 'pty:%s\n' \"$line\"",
        TerminalSize {
            width: 80,
            height: 24,
        },
    )?;
    let process_target = ProcessTarget {
        container: process.container.clone(),
        process_id: process.process_id.clone(),
    };
    let created = call("exec terminal probe", client.exec(process)).await?;
    if created.target != process_target || created.pid.is_none() || !created.terminal {
        return Err("native terminal probe returned an invalid identity".into());
    }

    let (cursor, mut output) =
        read_terminal_until(client, &process_target, 0, Vec::new(), b"24 80").await?;
    call(
        "resize terminal probe",
        client.resize(ResizeRequest {
            process: process_target.clone(),
            size: TerminalSize {
                width: 120,
                height: 40,
            },
        }),
    )
    .await?;
    call(
        "write terminal probe stdin",
        client.write_stdin(WriteStdinRequest {
            process: process_target.clone(),
            data: b"hello\n".to_vec(),
        }),
    )
    .await?;

    let status = call(
        "wait terminal probe",
        client.wait_process(WaitProcessRequest {
            process: process_target.clone(),
            timeout_ms: Some(LIFECYCLE_TIMEOUT_MS),
        }),
    )
    .await?;
    let expected = ExitStatus::exited(0)
        .map_err(|error| format!("failed to construct terminal probe exit status: {error}"))?;
    if status != expected {
        return Err(format!(
            "native terminal probe returned {status:?}, expected {expected:?}"
        ));
    }
    let (final_cursor, remaining) = drain_terminal_output(client, &process_target, cursor).await?;
    output.extend(remaining);
    if final_cursor == 0 {
        return Err("native terminal output cursor did not advance".into());
    }
    let normalized = output
        .into_iter()
        .filter(|byte| *byte != b'\r')
        .collect::<Vec<_>>();
    let text = String::from_utf8(normalized)
        .map_err(|error| format!("native terminal output was not UTF-8: {error}"))?;
    for expected_line in ["24 80\n", "40 120\n", "pty:hello\n"] {
        if !text.contains(expected_line) {
            return Err(format!(
                "native terminal output did not contain {expected_line:?}: {text:?}"
            ));
        }
    }

    let cat = terminal_exec_request(
        target,
        nonce,
        "terminal-eof",
        "exec-terminal-eof",
        "/bin/busybox cat",
        TerminalSize {
            width: 80,
            height: 24,
        },
    )?;
    let cat_target = ProcessTarget {
        container: cat.container.clone(),
        process_id: cat.process_id.clone(),
    };
    let cat_created = call("exec terminal EOF probe", client.exec(cat)).await?;
    if cat_created.target != cat_target || cat_created.pid.is_none() || !cat_created.terminal {
        return Err("native terminal EOF probe returned an invalid identity".into());
    }
    let close = CloseStdinRequest {
        process: cat_target.clone(),
    };
    call(
        "close terminal EOF probe stdin",
        client.close_stdin(close.clone()),
    )
    .await?;
    call(
        "repeat terminal EOF probe stdin close",
        client.close_stdin(close),
    )
    .await?;
    let cat_status = call(
        "wait terminal EOF probe",
        client.wait_process(WaitProcessRequest {
            process: cat_target.clone(),
            timeout_ms: Some(LIFECYCLE_TIMEOUT_MS),
        }),
    )
    .await?;
    if cat_status != expected {
        return Err(format!(
            "native terminal EOF probe returned {cat_status:?}, expected {expected:?}"
        ));
    }
    let (_, cat_output) = drain_terminal_output(client, &cat_target, 0).await?;
    if !cat_output.is_empty() {
        return Err(format!(
            "native terminal EOF probe produced unexpected output: {cat_output:?}"
        ));
    }
    Ok(())
}

async fn read_terminal_until(
    client: &RuntimeClient,
    process: &ProcessTarget,
    mut cursor: u64,
    mut output: Vec<u8>,
    expected: &[u8],
) -> Result<(u64, Vec<u8>), String> {
    let deadline = Instant::now() + CALL_TIMEOUT;
    loop {
        let chunks = call(
            "read terminal probe output",
            client.read_output(ReadOutputRequest {
                process: process.clone(),
                after_sequence: cursor,
                max_bytes: 64,
                wait_timeout_ms: Some(250),
            }),
        )
        .await?;
        for chunk in chunks {
            if chunk.sequence <= cursor || chunk.stream != OutputStream::Stdout {
                return Err("native terminal output violated its merged cursor contract".into());
            }
            cursor = chunk.sequence;
            if chunk.eof {
                return Err("native terminal reached EOF before expected output".into());
            }
            output.extend(chunk.data);
        }
        if output
            .windows(expected.len())
            .any(|window| window == expected)
        {
            return Ok((cursor, output));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for native terminal output {expected:?}"
            ));
        }
    }
}

async fn drain_terminal_output(
    client: &RuntimeClient,
    process: &ProcessTarget,
    mut cursor: u64,
) -> Result<(u64, Vec<u8>), String> {
    let deadline = Instant::now() + CALL_TIMEOUT;
    let mut output = Vec::new();
    loop {
        let chunks = call(
            "drain terminal probe output",
            client.read_output(ReadOutputRequest {
                process: process.clone(),
                after_sequence: cursor,
                max_bytes: 64,
                wait_timeout_ms: Some(250),
            }),
        )
        .await?;
        for chunk in chunks {
            if chunk.sequence <= cursor || chunk.stream != OutputStream::Stdout {
                return Err("native terminal output violated its merged cursor contract".into());
            }
            cursor = chunk.sequence;
            if chunk.eof {
                if !chunk.data.is_empty() {
                    return Err("native terminal EOF carried output data".into());
                }
                return Ok((cursor, output));
            }
            output.extend(chunk.data);
        }
        if Instant::now() >= deadline {
            return Err("timed out draining native terminal output".into());
        }
    }
}

async fn collect_output(
    client: &RuntimeClient,
    process: &ProcessTarget,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let deadline = Instant::now() + CALL_TIMEOUT;
    let mut cursor = 0;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    while !stdout_eof || !stderr_eof {
        let chunks = call(
            "read process I/O probe output",
            client.read_output(ReadOutputRequest {
                process: process.clone(),
                after_sequence: cursor,
                max_bytes: 4,
                wait_timeout_ms: Some(250),
            }),
        )
        .await?;
        for chunk in chunks {
            if chunk.sequence <= cursor {
                return Err("native captured output cursor did not advance".into());
            }
            cursor = chunk.sequence;
            match chunk.stream {
                OutputStream::Stdout => {
                    stdout.extend(chunk.data);
                    stdout_eof |= chunk.eof;
                }
                OutputStream::Stderr => {
                    stderr.extend(chunk.data);
                    stderr_eof |= chunk.eof;
                }
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out draining native captured process output".into());
        }
    }
    Ok((stdout, stderr))
}

pub(super) async fn exercise_before_init_exit(
    client: &RuntimeClient,
    target: &ContainerTarget,
    nonce: &str,
    progress_path: &str,
) -> Result<ProcessTarget, String> {
    let controlled = exec_request(
        target,
        nonce,
        "controlled",
        "exec-controlled",
        "while :; do :; done",
    )?;
    let controlled_target = ProcessTarget {
        container: controlled.container.clone(),
        process_id: controlled.process_id.clone(),
    };
    let created = call("exec controlled process", client.exec(controlled.clone())).await?;
    if created.target != controlled_target || created.pid.is_none() || created.terminal {
        return Err("native executor returned an invalid exec process identity".into());
    }
    if call("replayed exec", client.exec(controlled.clone())).await? != created {
        return Err("native runtime did not exactly replay exec".into());
    }

    let mut duplicate = controlled;
    duplicate.context = operation(nonce, "exec-duplicate")?;
    match timeout(CALL_TIMEOUT, client.exec(duplicate)).await {
        Ok(Err(error)) if error.code == ErrorCode::AlreadyExists => {}
        Ok(Err(error)) => return Err(call_error("duplicate exec process ID", &error)),
        Ok(Ok(_)) => return Err("native executor accepted a duplicate exec process ID".into()),
        Err(_) => return Err("duplicate exec process ID check timed out".into()),
    }

    match timeout(
        CALL_TIMEOUT,
        client.wait_process(WaitProcessRequest {
            process: controlled_target.clone(),
            timeout_ms: Some(50),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::DeadlineExceeded => {}
        Ok(Err(error)) => return Err(call_error("bounded exec wait", &error)),
        Ok(Ok(status)) => {
            return Err(format!(
                "bounded native exec wait returned {status:?} while still running"
            ));
        }
        Err(_) => return Err("bounded native exec wait exceeded its outer timeout".into()),
    }

    let signal = SignalProcessRequest {
        context: operation(nonce, "signal-controlled")?,
        process: controlled_target.clone(),
        signal: Signal::new(libc::SIGKILL)
            .map_err(|error| format!("failed to construct exec signal: {error}"))?,
    };
    call(
        "signal controlled exec process",
        client.signal_process(signal.clone()),
    )
    .await?;
    call(
        "replayed controlled exec signal",
        client.signal_process(signal),
    )
    .await?;
    let wait = WaitProcessRequest {
        process: controlled_target,
        timeout_ms: Some(LIFECYCLE_TIMEOUT_MS),
    };
    let status = call(
        "wait controlled exec process",
        client.wait_process(wait.clone()),
    )
    .await?;
    let expected = ExitStatus::signaled(libc::SIGKILL, false)
        .map_err(|error| format!("failed to construct expected exec status: {error}"))?;
    if status != expected {
        return Err(format!(
            "controlled native exec returned {status:?}, expected {expected:?}"
        ));
    }
    if call("repeated controlled exec wait", client.wait_process(wait)).await? != status {
        return Err("repeated native exec wait returned a different result".into());
    }

    let progress_command = format!(
        "n=0; while :; do n=$((n + 1)); printf '%s\\n' \"$n\" > {progress_path}; \
         /bin/busybox sleep 1; done"
    );
    let cleanup = exec_request(target, nonce, "cleanup", "exec-cleanup", &progress_command)?;
    let cleanup_target = ProcessTarget {
        container: cleanup.container.clone(),
        process_id: cleanup.process_id.clone(),
    };
    call("exec cleanup process", client.exec(cleanup)).await?;
    Ok(cleanup_target)
}

pub(super) async fn verify_after_init_exit(
    client: &RuntimeClient,
    target: &ContainerTarget,
    cleanup_process: ProcessTarget,
    init_status: &ExitStatus,
) -> Result<(), String> {
    let cleanup = call(
        "wait for native exec cleanup after init exit",
        client.wait_process(WaitProcessRequest {
            process: cleanup_process,
            timeout_ms: Some(LIFECYCLE_TIMEOUT_MS),
        }),
    )
    .await?;
    let expected_cleanup = ExitStatus::signaled(libc::SIGKILL, false)
        .map_err(|error| format!("failed to construct expected exec cleanup status: {error}"))?;
    if cleanup != expected_cleanup {
        return Err(format!(
            "init exit cleaned native exec with {cleanup:?}, expected {expected_cleanup:?}"
        ));
    }

    let init = call(
        "wait for reserved native init process",
        client.wait_process(WaitProcessRequest {
            process: ProcessTarget {
                container: target.clone(),
                process_id: ProcessId::init(),
            },
            timeout_ms: Some(LIFECYCLE_TIMEOUT_MS),
        }),
    )
    .await?;
    if &init != init_status {
        return Err("reserved native init wait disagreed with lifecycle wait".into());
    }
    Ok(())
}

fn exec_request(
    target: &ContainerTarget,
    nonce: &str,
    process_suffix: &str,
    operation_suffix: &str,
    command: &str,
) -> Result<ExecRequest, String> {
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", command],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .map_err(|error| format!("failed to construct native exec process: {error}"))?;
    Ok(ExecRequest {
        context: operation(nonce, operation_suffix)?,
        container: target.clone(),
        process_id: ProcessId::new(format!("exec-{nonce}-{process_suffix}"))
            .map_err(|error| format!("failed to construct native exec process ID: {error}"))?,
        process,
        io: ProcessIo {
            stdin: IoMode::Null,
            stdout: IoMode::Null,
            stderr: IoMode::Null,
            terminal_size: None,
        },
    })
}

fn terminal_exec_request(
    target: &ContainerTarget,
    nonce: &str,
    process_suffix: &str,
    operation_suffix: &str,
    command: &str,
    size: TerminalSize,
) -> Result<ExecRequest, String> {
    let mut request = exec_request(target, nonce, process_suffix, operation_suffix, command)?;
    request.process = serde_json::from_value(serde_json::json!({
        "terminal": true,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", command],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .map_err(|error| format!("failed to construct native terminal process: {error}"))?;
    request.io = ProcessIo {
        stdin: IoMode::Terminal,
        stdout: IoMode::Terminal,
        stderr: IoMode::Terminal,
        terminal_size: Some(size),
    };
    Ok(request)
}

fn operation(nonce: &str, suffix: &str) -> Result<OperationContext, String> {
    OperationId::new(format!("native-{nonce}-{suffix}"))
        .map(OperationContext::new)
        .map_err(|error| format!("failed to construct native exec operation ID: {error}"))
}

async fn call<T>(
    operation: &str,
    future: impl Future<Output = a3s_oci_sdk::Result<T>>,
) -> Result<T, String> {
    match timeout(CALL_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(call_error(operation, &error)),
        Err(_) => Err(format!("{operation} timed out")),
    }
}

fn call_error(operation: &str, error: &Error) -> String {
    format!("{operation} failed: {error}")
}
