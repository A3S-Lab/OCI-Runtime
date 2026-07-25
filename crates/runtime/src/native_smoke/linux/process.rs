use std::future::Future;
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{
    ContainerTarget, Error, ErrorCode, ExecRequest, ExitStatus, IoMode, OperationContext,
    OperationId, ProcessId, ProcessIo, ProcessTarget, RuntimeClient, Signal, SignalProcessRequest,
    WaitProcessRequest,
};
use tokio::time::timeout;

const CALL_TIMEOUT: Duration = Duration::from_secs(15);
const LIFECYCLE_TIMEOUT_MS: u64 = 15_000;

pub(super) async fn exercise_before_init_exit(
    client: &RuntimeClient,
    target: &ContainerTarget,
    nonce: &str,
) -> Result<ProcessTarget, String> {
    let controlled = exec_request(target, nonce, "controlled", "exec-controlled")?;
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

    let cleanup = exec_request(target, nonce, "cleanup", "exec-cleanup")?;
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
) -> Result<ExecRequest, String> {
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", "while :; do :; done"],
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
