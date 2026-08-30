use std::future::Future;
use std::path::Path;
use std::time::Duration;

use a3s_oci_agent_protocol::{
    AgentBundle, AgentClient, AgentCloseStdinRequest, AgentContainerOperationRequest,
    AgentCreateRequest, AgentDeleteRequest, AgentExecRequest, AgentKillRequest,
    AgentProcessesRequest, AgentReadOutputRequest, AgentResizeRequest, AgentSignalProcessRequest,
    AgentStartRequest, AgentStateRequest, AgentStatsRequest, AgentUpdateRequest,
    AgentWaitProcessRequest, AgentWaitRequest, AgentWriteStdinRequest, GuestPath,
};
use a3s_oci_core::HostPlatform;
use a3s_oci_sdk::oci_spec::runtime::{ContainerState, ExecCPUAffinity, LinuxResources, Process};
use a3s_oci_sdk::{
    ContainerTarget, DeleteMode, Error, ErrorCode, ExitStatus, IoMode, OciBundle, OperationContext,
    OperationId, OutputStream, ProcessId, ProcessIo, ProcessTarget, Signal, TerminalSize,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{sleep, timeout, Instant};

use super::{path_exists, read_marker, OciVmSmokeReport};
use crate::marker::{exact_marker_state, ExactMarkerState};
use crate::{FaultInjectionEvidence, LifecycleFaultPoint};

const GUEST_CALL_TIMEOUT: Duration = Duration::from_secs(15);
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(15);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const FREEZER_OBSERVATION_DELAY: Duration = Duration::from_millis(1_250);
const LINUX_SIGTERM: i32 = 15;
const LINUX_SIGKILL: i32 = 9;
const MARKER_CONTENTS: &[u8] = b"a3s-oci-create-start-user-time-v1\n";
const PROGRESS_PATH: &str = "/.a3s-oci-create-start-smoke";
pub(crate) const UPDATED_MEMORY_LIMIT: u64 = 512 * 1024 * 1024;

pub(super) trait AgentStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AgentStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(super) async fn exercise<T: AgentStream>(
    client: &AgentClient<T>,
    bundle: &OciBundle,
    guest_bundle: GuestPath,
    target: &ContainerTarget,
    nonce: &str,
    marker: &Path,
    report: &mut OciVmSmokeReport,
) -> Result<(), String> {
    let create = AgentCreateRequest {
        context: operation(nonce, "create")?,
        target: target.clone(),
        bundle: AgentBundle::new(bundle, guest_bundle),
        io: null_io(),
    };
    let created = guest_call("create", client.create(create.clone())).await?;
    report.create_returned_created = created.status() == ContainerState::Created;
    report.created_pid = created.pid();
    if !report.create_returned_created {
        return Err("guest create did not preserve the OCI created barrier".into());
    }

    let observed = guest_call(
        "state after create",
        client.state(AgentStateRequest {
            target: target.clone(),
        }),
    )
    .await?;
    if observed != created {
        return Err("guest state after create did not match the created response".into());
    }
    let replayed = guest_call("replayed create", client.create(create)).await?;
    report.create_replayed = replayed == created;
    if !report.create_replayed {
        return Err("guest did not exactly replay the create result".into());
    }
    report.marker_absent_after_create = !path_exists(marker).await?;
    if !report.marker_absent_after_create {
        return Err("configured process ran before the OCI start request".into());
    }

    let started = guest_call(
        "start",
        client.start(AgentStartRequest {
            context: operation(nonce, "start")?,
            target: target.clone(),
            expected_config_digest: bundle.config_digest().to_string(),
        }),
    )
    .await?;
    report.start_released = started.status() == ContainerState::Running;
    if !report.start_released {
        return Err("guest start did not leave the fixed workload running".into());
    }

    wait_for_running_marker(client, target, marker, report).await?;
    exercise_process_io(client, target, nonce).await?;
    report.process_io_verified = true;
    exercise_terminal_io(client, target, nonce).await?;
    report.terminal_io_verified = true;
    crate::filesystem_smoke::exercise_agent(client, target, nonce).await?;
    report.file_transfer_verified = true;
    report.filesystem_operations_verified = true;
    let cleanup_process = exercise_exec_processes(client, target, nonce).await?;
    exercise_control_plane(client, target, &cleanup_process, nonce, marker, report).await?;
    report.wait_timeout_enforced = wait_times_out_while_running(client, target).await?;
    if !report.wait_timeout_enforced {
        return Err("guest wait returned before the running init process exited".into());
    }

    let kill = AgentKillRequest {
        context: operation(nonce, "kill")?,
        target: target.clone(),
        signal: Signal::new(LINUX_SIGTERM)
            .map_err(|error| format!("invalid smoke signal: {error}"))?,
        all: false,
    };
    let killed = guest_call("kill", client.kill(kill.clone())).await?;
    report.kill_delivered = matches!(
        killed.status(),
        ContainerState::Running | ContainerState::Stopped
    );
    if !report.kill_delivered {
        return Err("guest kill returned an unexpected lifecycle state".into());
    }
    let replayed_kill = guest_call("replayed kill", client.kill(kill)).await?;
    report.kill_replayed = replayed_kill == killed;
    if !report.kill_replayed {
        return Err("guest did not exactly replay the kill result".into());
    }
    let wait = AgentWaitRequest {
        target: target.clone(),
        timeout_ms: Some(
            u64::try_from(LIFECYCLE_TIMEOUT.as_millis())
                .map_err(|_| "guest lifecycle timeout does not fit wait request".to_string())?,
        ),
    };
    let waited = guest_call("wait", client.wait(wait.clone())).await?;
    let expected_exit = ExitStatus::exited(0)
        .map_err(|error| format!("failed to construct expected guest exit status: {error}"))?;
    report.wait_exit_status = Some(waited.clone());
    if waited != expected_exit {
        return Err(format!(
            "guest wait returned {waited:?}, expected {expected_exit:?}"
        ));
    }
    let cleaned_exec = guest_call(
        "wait for exec cleanup after init exit",
        client.wait_process(AgentWaitProcessRequest {
            target: cleanup_process,
            timeout_ms: Some(
                u64::try_from(LIFECYCLE_TIMEOUT.as_millis())
                    .map_err(|_| "exec cleanup timeout does not fit wait request".to_string())?,
            ),
        }),
    )
    .await?;
    let expected_exec_cleanup = ExitStatus::signaled(LINUX_SIGKILL, false)
        .map_err(|error| format!("failed to construct expected exec cleanup status: {error}"))?;
    if cleaned_exec != expected_exec_cleanup {
        return Err(format!(
            "init exit cleaned exec with {cleaned_exec:?}, expected {expected_exec_cleanup:?}"
        ));
    }
    let init_process_wait = guest_call(
        "wait for reserved init process",
        client.wait_process(AgentWaitProcessRequest {
            target: ProcessTarget {
                container: target.clone(),
                process_id: ProcessId::init(),
            },
            timeout_ms: Some(
                u64::try_from(LIFECYCLE_TIMEOUT.as_millis())
                    .map_err(|_| "init process timeout does not fit wait request".to_string())?,
            ),
        }),
    )
    .await?;
    if init_process_wait != waited {
        return Err("reserved init process wait disagreed with lifecycle wait".into());
    }
    report.wait_replayed = guest_call("repeated wait", client.wait(wait)).await? == waited;
    if !report.wait_replayed {
        return Err("guest repeated wait returned a different exit status".into());
    }
    report.stopped_observed = wait_until_stopped(client, target).await?;

    let delete = AgentDeleteRequest {
        context: operation(nonce, "delete")?,
        target: target.clone(),
        mode: DeleteMode::StoppedOnly,
    };
    guest_call("delete", client.delete(delete.clone())).await?;
    report.delete_succeeded = true;
    guest_call("replayed delete", client.delete(delete)).await?;
    report.delete_replayed = true;
    report.state_missing_after_delete = state_is_missing(client, target).await?;
    if !report.state_missing_after_delete {
        return Err("guest state remained visible after delete".into());
    }
    Ok(())
}

async fn exercise_process_io<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
    nonce: &str,
) -> Result<(), String> {
    let mut request = exec_request(
        target,
        nonce,
        "io",
        "exec-io",
        "/bin/busybox awk '$1 == \"Cpus_allowed_list:\" && $2 == \"0\" { ok = 1 } \
           END { exit !ok }' /proc/self/status; \
         IFS= read -r first; IFS= read -r second; \
         printf 'stdout:%s:%s\\n' \"$first\" \"$second\"; \
         printf 'stderr:%s:%s\\n' \"$first\" \"$second\" >&2",
    )?;
    let exec_cpu_affinity: ExecCPUAffinity = serde_json::from_value(serde_json::json!({
        "initial": "0",
        "final": "0"
    }))
    .map_err(|error| format!("failed to construct guest exec CPU affinity: {error}"))?;
    request
        .process
        .set_exec_cpu_affinity(Some(exec_cpu_affinity));
    request.io = ProcessIo {
        stdin: IoMode::Pipe,
        stdout: IoMode::Capture,
        stderr: IoMode::Capture,
        terminal_size: None,
    };
    let process = request.target.clone();
    let created = guest_call("exec process I/O probe", client.exec(request)).await?;
    if created.target() != &process || created.pid() <= 0 || created.terminal() {
        return Err("guest process I/O probe returned an invalid identity".into());
    }

    let first_write = AgentWriteStdinRequest {
        context: Some(operation(nonce, "write-io-first")?),
        process: process.clone(),
        data: b"a3s-io-first\n".to_vec(),
    };
    guest_call(
        "write first process I/O probe stdin",
        client.write_stdin(first_write.clone()),
    )
    .await?;
    guest_call(
        "replay first process I/O probe stdin write",
        client.write_stdin(first_write),
    )
    .await?;
    guest_call(
        "write second process I/O probe stdin",
        client.write_stdin(AgentWriteStdinRequest {
            context: Some(operation(nonce, "write-io-second")?),
            process: process.clone(),
            data: b"a3s-io-second\n".to_vec(),
        }),
    )
    .await?;
    let close = AgentCloseStdinRequest {
        context: Some(operation(nonce, "close-io")?),
        process: process.clone(),
    };
    guest_call(
        "close process I/O probe stdin",
        client.close_stdin(close.clone()),
    )
    .await?;
    guest_call(
        "repeat process I/O probe stdin close",
        client.close_stdin(close),
    )
    .await?;

    let status = guest_call(
        "wait process I/O probe",
        client.wait_process(AgentWaitProcessRequest {
            target: process.clone(),
            timeout_ms: Some(
                u64::try_from(LIFECYCLE_TIMEOUT.as_millis())
                    .map_err(|_| "process I/O timeout does not fit request".to_string())?,
            ),
        }),
    )
    .await?;
    let expected = ExitStatus::exited(0)
        .map_err(|error| format!("failed to construct process I/O exit status: {error}"))?;
    if status != expected {
        return Err(format!(
            "guest process I/O probe returned {status:?}, expected {expected:?}"
        ));
    }

    let (stdout, stderr) = collect_output(client, &process).await?;
    if stdout != b"stdout:a3s-io-first:a3s-io-second\n"
        || stderr != b"stderr:a3s-io-first:a3s-io-second\n"
    {
        return Err(format!(
            "guest captured output mismatch: stdout={stdout:?}, stderr={stderr:?}"
        ));
    }
    match timeout(
        GUEST_CALL_TIMEOUT,
        client.write_stdin(AgentWriteStdinRequest {
            context: Some(operation(nonce, "write-io-late")?),
            process,
            data: b"late".to_vec(),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::FailedPrecondition => Ok(()),
        Ok(Err(error)) => Err(guest_error("write after process stdin close", &error)),
        Ok(Ok(())) => Err("guest accepted stdin after close".into()),
        Err(_) => Err("write after process stdin close timed out".into()),
    }
}

async fn exercise_terminal_io<T: AgentStream>(
    client: &AgentClient<T>,
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
    let process_target = process.target.clone();
    let created = guest_call("exec terminal probe", client.exec(process)).await?;
    if created.target() != &process_target || created.pid() <= 0 || !created.terminal() {
        return Err("guest terminal probe returned an invalid identity".into());
    }

    let (cursor, mut output) =
        read_terminal_until(client, &process_target, 0, Vec::new(), b"24 80").await?;
    guest_call(
        "resize terminal probe",
        client.resize(AgentResizeRequest {
            context: Some(operation(nonce, "resize-terminal")?),
            process: process_target.clone(),
            size: TerminalSize {
                width: 120,
                height: 40,
            },
        }),
    )
    .await?;
    guest_call(
        "write terminal probe stdin",
        client.write_stdin(AgentWriteStdinRequest {
            context: Some(operation(nonce, "write-terminal")?),
            process: process_target.clone(),
            data: b"hello\n".to_vec(),
        }),
    )
    .await?;

    let status = guest_call(
        "wait terminal probe",
        client.wait_process(AgentWaitProcessRequest {
            target: process_target.clone(),
            timeout_ms: Some(
                u64::try_from(LIFECYCLE_TIMEOUT.as_millis())
                    .map_err(|_| "terminal probe timeout does not fit request".to_string())?,
            ),
        }),
    )
    .await?;
    let expected = ExitStatus::exited(0)
        .map_err(|error| format!("failed to construct terminal probe exit status: {error}"))?;
    if status != expected {
        return Err(format!(
            "guest terminal probe returned {status:?}, expected {expected:?}"
        ));
    }
    let (final_cursor, remaining) = drain_terminal_output(client, &process_target, cursor).await?;
    output.extend(remaining);
    if final_cursor == 0 {
        return Err("guest terminal output cursor did not advance".into());
    }
    let normalized = output
        .into_iter()
        .filter(|byte| *byte != b'\r')
        .collect::<Vec<_>>();
    let text = String::from_utf8(normalized)
        .map_err(|error| format!("guest terminal output was not UTF-8: {error}"))?;
    for expected_line in ["24 80\n", "40 120\n", "pty:hello\n"] {
        if !text.contains(expected_line) {
            return Err(format!(
                "guest terminal output did not contain {expected_line:?}: {text:?}"
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
    let cat_target = cat.target.clone();
    let cat_created = guest_call("exec terminal EOF probe", client.exec(cat)).await?;
    if cat_created.target() != &cat_target || cat_created.pid() <= 0 || !cat_created.terminal() {
        return Err("guest terminal EOF probe returned an invalid identity".into());
    }
    let close = AgentCloseStdinRequest {
        context: Some(operation(nonce, "close-terminal-eof")?),
        process: cat_target.clone(),
    };
    guest_call(
        "close terminal EOF probe stdin",
        client.close_stdin(close.clone()),
    )
    .await?;
    guest_call(
        "repeat terminal EOF probe stdin close",
        client.close_stdin(close),
    )
    .await?;
    let cat_status = guest_call(
        "wait terminal EOF probe",
        client.wait_process(AgentWaitProcessRequest {
            target: cat_target.clone(),
            timeout_ms: Some(
                u64::try_from(LIFECYCLE_TIMEOUT.as_millis())
                    .map_err(|_| "terminal EOF timeout does not fit request".to_string())?,
            ),
        }),
    )
    .await?;
    if cat_status != expected {
        return Err(format!(
            "guest terminal EOF probe returned {cat_status:?}, expected {expected:?}"
        ));
    }
    let (_, cat_output) = drain_terminal_output(client, &cat_target, 0).await?;
    if !cat_output.is_empty() {
        return Err(format!(
            "guest terminal EOF probe produced unexpected output: {cat_output:?}"
        ));
    }
    Ok(())
}

async fn read_terminal_until<T: AgentStream>(
    client: &AgentClient<T>,
    process: &ProcessTarget,
    mut cursor: u64,
    mut output: Vec<u8>,
    expected: &[u8],
) -> Result<(u64, Vec<u8>), String> {
    let deadline = Instant::now() + GUEST_CALL_TIMEOUT;
    loop {
        let chunks = guest_call(
            "read terminal probe output",
            client.read_output(AgentReadOutputRequest {
                process: process.clone(),
                after_sequence: cursor,
                max_bytes: 64,
                wait_timeout_ms: Some(250),
            }),
        )
        .await?;
        for chunk in chunks {
            if chunk.sequence <= cursor || chunk.stream != OutputStream::Stdout {
                return Err("guest terminal output violated its merged cursor contract".into());
            }
            cursor = chunk.sequence;
            if chunk.eof {
                return Err("guest terminal reached EOF before expected output".into());
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
                "timed out waiting for guest terminal output {expected:?}"
            ));
        }
    }
}

async fn drain_terminal_output<T: AgentStream>(
    client: &AgentClient<T>,
    process: &ProcessTarget,
    mut cursor: u64,
) -> Result<(u64, Vec<u8>), String> {
    let deadline = Instant::now() + GUEST_CALL_TIMEOUT;
    let mut output = Vec::new();
    loop {
        let chunks = guest_call(
            "drain terminal probe output",
            client.read_output(AgentReadOutputRequest {
                process: process.clone(),
                after_sequence: cursor,
                max_bytes: 64,
                wait_timeout_ms: Some(250),
            }),
        )
        .await?;
        for chunk in chunks {
            if chunk.sequence <= cursor || chunk.stream != OutputStream::Stdout {
                return Err("guest terminal output violated its merged cursor contract".into());
            }
            cursor = chunk.sequence;
            if chunk.eof {
                if !chunk.data.is_empty() {
                    return Err("guest terminal EOF carried output data".into());
                }
                return Ok((cursor, output));
            }
            output.extend(chunk.data);
        }
        if Instant::now() >= deadline {
            return Err("timed out draining guest terminal output".into());
        }
    }
}

async fn collect_output<T: AgentStream>(
    client: &AgentClient<T>,
    process: &ProcessTarget,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let deadline = Instant::now() + GUEST_CALL_TIMEOUT;
    let mut cursor = 0;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    while !stdout_eof || !stderr_eof {
        let chunks = guest_call(
            "read process I/O probe output",
            client.read_output(AgentReadOutputRequest {
                process: process.clone(),
                after_sequence: cursor,
                max_bytes: 4,
                wait_timeout_ms: Some(250),
            }),
        )
        .await?;
        for chunk in chunks {
            if chunk.sequence <= cursor {
                return Err("guest captured output cursor did not advance".into());
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
            return Err("timed out draining guest captured process output".into());
        }
    }
    Ok((stdout, stderr))
}

async fn exercise_control_plane<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
    worker: &ProcessTarget,
    nonce: &str,
    marker: &Path,
    report: &mut OciVmSmokeReport,
) -> Result<(), String> {
    wait_for_marker_change(marker, MARKER_CONTENTS).await?;
    let processes = guest_call(
        "process inventory before pause",
        client.processes(AgentProcessesRequest {
            target: target.clone(),
        }),
    )
    .await?;
    report.processes_verified = process_inventory_is_exact(&processes, target, worker);
    if !report.processes_verified {
        return Err(
            "guest process inventory did not contain exactly the live init and exec".into(),
        );
    }

    let update = AgentUpdateRequest {
        context: operation(nonce, "update")?,
        target: target.clone(),
        resources: resource_profile(report.platform)?,
    };
    let updated = guest_call("update resources", client.update(update.clone())).await?;
    report.resources_updated = updated
        == guest_call("replayed resource update", client.update(update)).await?
        && updated.status() == ContainerState::Running
        && !updated.paused();
    if !report.resources_updated {
        return Err("guest resource update was not exact or idempotent".into());
    }
    let first_stats = guest_call(
        "resource stats",
        client.stats(AgentStatsRequest {
            target: target.clone(),
        }),
    )
    .await?;
    let second_stats = guest_call(
        "repeated resource stats",
        client.stats(AgentStatsRequest {
            target: target.clone(),
        }),
    )
    .await?;
    report.stats_verified = resource_stats_are_exact(&first_stats, &second_stats, target);
    if !report.stats_verified {
        return Err("guest resource stats did not match the updated cgroup".into());
    }

    let pause = AgentContainerOperationRequest {
        context: operation(nonce, "pause")?,
        target: target.clone(),
    };
    let paused = guest_call("pause", client.pause(pause.clone())).await?;
    if !paused.paused()
        || guest_call("replayed pause", client.pause(pause)).await? != paused
        || !guest_call(
            "state while paused",
            client.state(AgentStateRequest {
                target: target.clone(),
            }),
        )
        .await?
        .paused()
    {
        return Err("guest pause did not expose an exact frozen state".into());
    }
    let paused_processes = guest_call(
        "process inventory while paused",
        client.processes(AgentProcessesRequest {
            target: target.clone(),
        }),
    )
    .await?;
    if !process_inventory_is_exact(&paused_processes, target, worker) {
        return Err("guest pause changed the live process inventory".into());
    }

    let frozen_progress = read_marker(marker).await?;
    sleep(FREEZER_OBSERVATION_DELAY).await;
    report.pause_froze_workload = read_marker(marker).await? == frozen_progress;
    if !report.pause_froze_workload {
        return Err("guest workload advanced while its cgroup was frozen".into());
    }

    let resume = AgentContainerOperationRequest {
        context: operation(nonce, "resume")?,
        target: target.clone(),
    };
    let resumed = guest_call("resume", client.resume(resume.clone())).await?;
    if resumed.paused()
        || guest_call("replayed resume", client.resume(resume)).await? != resumed
        || guest_call(
            "state after resume",
            client.state(AgentStateRequest {
                target: target.clone(),
            }),
        )
        .await?
        .paused()
    {
        return Err("guest resume did not expose an exact running state".into());
    }
    wait_for_marker_change(marker, &frozen_progress).await?;
    report.resume_advanced_workload = true;
    Ok(())
}

pub(crate) fn resource_profile(platform: HostPlatform) -> Result<LinuxResources, String> {
    let mut profile = serde_json::json!({
        "memory": {
            "limit": UPDATED_MEMORY_LIMIT,
            "reservation": 64 * 1024 * 1024
        },
        "cpu": {
            "shares": 512,
            "quota": 50000,
            "period": 100000,
            "cpus": "0",
            "mems": "0"
        },
        "pids": {"limit": 64}
    });
    // The fixed KVM and WHPX utility kernels intentionally have no swap
    // controller. Preserve swap-limit coverage on HVF while qualifying the
    // common memory, CPU, cpuset, PID, stats, and freezer surface elsewhere.
    if platform == HostPlatform::Macos {
        profile["memory"]["swap"] = serde_json::json!(1024 * 1024 * 1024_u64);
    }
    serde_json::from_value(profile)
        .map_err(|error| format!("failed to construct guest resource profile: {error}"))
}

pub(crate) fn resource_stats_are_exact(
    first: &a3s_oci_sdk::ContainerStats,
    second: &a3s_oci_sdk::ContainerStats,
    target: &ContainerTarget,
) -> bool {
    resource_stats_snapshot_is_exact(first, target)
        && resource_stats_snapshot_is_exact(second, target)
        && second.timestamp_unix_ns >= first.timestamp_unix_ns
        && second.cpu.usage_ns >= first.cpu.usage_ns
}

pub(crate) fn resource_stats_snapshot_is_exact(
    stats: &a3s_oci_sdk::ContainerStats,
    target: &ContainerTarget,
) -> bool {
    stats.target == *target
        && stats.timestamp_unix_ns > 0
        && stats.cpu.usage_ns > 0
        && stats.memory.limit_bytes == Some(UPDATED_MEMORY_LIMIT)
        && stats.memory.usage_bytes <= UPDATED_MEMORY_LIMIT
        && stats.process_count >= 2
        && stats.metrics.contains_key("memory.events.oom_kill")
        && stats.metrics.contains_key("pids.events.max")
}

pub(crate) fn process_inventory_is_exact(
    processes: &[a3s_oci_sdk::ProcessRecord],
    target: &ContainerTarget,
    worker: &ProcessTarget,
) -> bool {
    processes.len() == 2
        && processes.iter().all(|process| {
            process.target.container == *target
                && process.pid.is_some_and(|pid| pid > 0)
                && !process.terminal
        })
        && processes
            .iter()
            .any(|process| process.target.process_id.is_init())
        && processes.iter().any(|process| process.target == *worker)
}

async fn wait_for_marker_change(marker: &Path, previous: &[u8]) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        let current = read_marker(marker).await?;
        if current != previous {
            return Ok(current);
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for guest workload progress".into());
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn exercise_exec_processes<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
    nonce: &str,
) -> Result<ProcessTarget, String> {
    let controlled = exec_request(
        target,
        nonce,
        "controlled",
        "exec-controlled",
        "while :; do :; done",
    )?;
    let controlled_target = controlled.target.clone();
    let created = guest_call("exec controlled process", client.exec(controlled.clone())).await?;
    if created.target() != &controlled_target || created.pid() <= 0 || created.terminal() {
        return Err("exec returned an invalid controlled-process identity".into());
    }
    let replayed = guest_call("replayed exec", client.exec(controlled.clone())).await?;
    if replayed != created {
        return Err("guest did not exactly replay exec".into());
    }

    let mut duplicate = controlled;
    duplicate.context = operation(nonce, "exec-duplicate")?;
    match timeout(GUEST_CALL_TIMEOUT, client.exec(duplicate)).await {
        Ok(Err(error)) if error.code == ErrorCode::AlreadyExists => {}
        Ok(Err(error)) => return Err(guest_error("duplicate exec process ID", &error)),
        Ok(Ok(_)) => return Err("guest accepted a duplicate exec process ID".into()),
        Err(_) => return Err("duplicate exec process ID check timed out".into()),
    }

    match timeout(
        GUEST_CALL_TIMEOUT,
        client.wait_process(AgentWaitProcessRequest {
            target: controlled_target.clone(),
            timeout_ms: Some(50),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::DeadlineExceeded => {}
        Ok(Err(error)) => return Err(guest_error("bounded exec wait", &error)),
        Ok(Ok(status)) => {
            return Err(format!(
                "bounded exec wait returned {status:?} while the process was running"
            ));
        }
        Err(_) => return Err("bounded exec wait exceeded its outer timeout".into()),
    }

    let signal = AgentSignalProcessRequest {
        context: operation(nonce, "signal-controlled")?,
        target: controlled_target.clone(),
        signal: Signal::new(LINUX_SIGKILL)
            .map_err(|error| format!("invalid exec smoke signal: {error}"))?,
    };
    guest_call(
        "signal controlled exec process",
        client.signal_process(signal.clone()),
    )
    .await?;
    guest_call(
        "replayed controlled exec signal",
        client.signal_process(signal),
    )
    .await?;
    let wait = AgentWaitProcessRequest {
        target: controlled_target,
        timeout_ms: Some(
            u64::try_from(LIFECYCLE_TIMEOUT.as_millis())
                .map_err(|_| "exec wait timeout does not fit request".to_string())?,
        ),
    };
    let status = guest_call(
        "wait controlled exec process",
        client.wait_process(wait.clone()),
    )
    .await?;
    let expected = ExitStatus::signaled(LINUX_SIGKILL, false)
        .map_err(|error| format!("failed to construct expected exec status: {error}"))?;
    if status != expected {
        return Err(format!(
            "controlled exec wait returned {status:?}, expected {expected:?}"
        ));
    }
    if guest_call("repeated controlled exec wait", client.wait_process(wait)).await? != status {
        return Err("repeated exec wait returned a different result".into());
    }

    let progress_command = format!(
        "n=0; while :; do n=$((n + 1)); printf '%s\\n' \"$n\" > {PROGRESS_PATH}; \
         /bin/busybox sleep 1; done"
    );
    let cleanup = exec_request(target, nonce, "cleanup", "exec-cleanup", &progress_command)?;
    let cleanup_target = cleanup.target.clone();
    guest_call("exec cleanup process", client.exec(cleanup)).await?;
    Ok(cleanup_target)
}

fn exec_request(
    target: &ContainerTarget,
    nonce: &str,
    process_suffix: &str,
    operation_suffix: &str,
    command: &str,
) -> Result<AgentExecRequest, String> {
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", command],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .map_err(|error| format!("failed to construct exec smoke process: {error}"))?;
    Ok(AgentExecRequest {
        context: operation(nonce, operation_suffix)?,
        target: ProcessTarget {
            container: target.clone(),
            process_id: ProcessId::new(format!("exec-{nonce}-{process_suffix}"))
                .map_err(|error| format!("failed to construct exec process ID: {error}"))?,
        },
        process,
        io: null_io(),
    })
}

fn terminal_exec_request(
    target: &ContainerTarget,
    nonce: &str,
    process_suffix: &str,
    operation_suffix: &str,
    command: &str,
    size: TerminalSize,
) -> Result<AgentExecRequest, String> {
    let mut request = exec_request(target, nonce, process_suffix, operation_suffix, command)?;
    request.process = serde_json::from_value(serde_json::json!({
        "terminal": true,
        "consoleSize": {"width": size.width, "height": size.height},
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", command],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .map_err(|error| format!("failed to construct terminal smoke process: {error}"))?;
    request.io = ProcessIo {
        stdin: IoMode::Terminal,
        stdout: IoMode::Terminal,
        stderr: IoMode::Terminal,
        terminal_size: None,
    };
    Ok(request)
}

async fn wait_times_out_while_running<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
) -> Result<bool, String> {
    match timeout(
        GUEST_CALL_TIMEOUT,
        client.wait(AgentWaitRequest {
            target: target.clone(),
            timeout_ms: Some(50),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::DeadlineExceeded => Ok(true),
        Ok(Err(error)) => Err(guest_error("bounded wait while running", &error)),
        Ok(Ok(status)) => Err(format!(
            "bounded wait returned {status:?} while the guest workload was running"
        )),
        Err(_) => Err("bounded guest wait exceeded its outer call timeout".into()),
    }
}

pub(super) async fn exercise_until_fault<T: AgentStream>(
    client: &AgentClient<T>,
    bundle: &OciBundle,
    guest_bundle: GuestPath,
    target: &ContainerTarget,
    nonce: &str,
    marker: &Path,
    evidence: &mut FaultInjectionEvidence,
) -> Result<(), String> {
    let created = guest_call(
        "fault create",
        client.create(AgentCreateRequest {
            context: fault_operation(nonce, "create")?,
            target: target.clone(),
            bundle: AgentBundle::new(bundle, guest_bundle),
            io: null_io(),
        }),
    )
    .await?;
    if created.status() != ContainerState::Created {
        return Err("guest fault create did not preserve the OCI created barrier".into());
    }
    evidence.create_completed = true;
    evidence.created_pid = created.pid();
    let observed = guest_call(
        "fault state after create",
        client.state(AgentStateRequest {
            target: target.clone(),
        }),
    )
    .await?;
    if observed != created {
        return Err("guest fault state after create did not match create".into());
    }
    evidence.marker_absent_after_create = !path_exists(marker).await?;
    if !evidence.marker_absent_after_create {
        return Err("guest fault workload ran before OCI start".into());
    }
    if evidence.requested_fault == LifecycleFaultPoint::AfterCreate {
        evidence.injected_fault = Some(LifecycleFaultPoint::AfterCreate);
        return Ok(());
    }

    let started = guest_call(
        "fault start",
        client.start(AgentStartRequest {
            context: fault_operation(nonce, "start")?,
            target: target.clone(),
            expected_config_digest: bundle.config_digest().to_string(),
        }),
    )
    .await?;
    if started.status() != ContainerState::Running {
        return Err("guest fault start did not leave the workload running".into());
    }
    evidence.start_completed = true;
    wait_for_exact_marker(client, target, marker).await?;
    evidence.marker_verified_after_start = true;
    if evidence.requested_fault == LifecycleFaultPoint::AfterStart {
        evidence.injected_fault = Some(LifecycleFaultPoint::AfterStart);
        return Ok(());
    }

    let killed = guest_call(
        "fault kill",
        client.kill(AgentKillRequest {
            context: fault_operation(nonce, "kill")?,
            target: target.clone(),
            signal: Signal::new(LINUX_SIGTERM)
                .map_err(|error| format!("invalid fault cleanup signal: {error}"))?,
            all: false,
        }),
    )
    .await?;
    if !matches!(
        killed.status(),
        ContainerState::Running | ContainerState::Stopped
    ) {
        return Err("guest fault kill returned an unexpected lifecycle state".into());
    }
    evidence.kill_completed = true;
    evidence.injected_fault = Some(LifecycleFaultPoint::AfterKill);
    Ok(())
}

async fn wait_for_running_marker<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
    marker: &Path,
    report: &mut OciVmSmokeReport,
) -> Result<(), String> {
    wait_for_exact_marker(client, target, marker).await?;
    report.running_observed = true;
    report.marker_verified = true;
    Ok(())
}

async fn wait_for_exact_marker<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
    marker: &Path,
) -> Result<(), String> {
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        let state = guest_call(
            "state while waiting for running marker",
            client.state(AgentStateRequest {
                target: target.clone(),
            }),
        )
        .await?;
        match state.status() {
            ContainerState::Running => {}
            status => {
                return Err(format!(
                    "guest reported unexpected state {status} before kill"
                ));
            }
        }
        if path_exists(marker).await? {
            match exact_marker_state(&read_marker(marker).await?, MARKER_CONTENTS) {
                ExactMarkerState::Complete => return Ok(()),
                ExactMarkerState::InProgress => {}
                ExactMarkerState::Mismatch => {
                    return Err("configured process produced unexpected marker contents".into());
                }
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for the running workload marker".into());
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_until_stopped<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
) -> Result<bool, String> {
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        let state = guest_call(
            "state while waiting for stop",
            client.state(AgentStateRequest {
                target: target.clone(),
            }),
        )
        .await?;
        match state.status() {
            ContainerState::Stopped => return Ok(true),
            ContainerState::Running if Instant::now() < deadline => sleep(POLL_INTERVAL).await,
            ContainerState::Running => {
                return Err("timed out waiting for configured process to stop".into());
            }
            status => {
                return Err(format!(
                    "guest reported unexpected state {status} after start"
                ));
            }
        }
    }
}

async fn state_is_missing<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
) -> Result<bool, String> {
    match timeout(
        GUEST_CALL_TIMEOUT,
        client.state(AgentStateRequest {
            target: target.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => Ok(true),
        Ok(Err(error)) => Err(guest_error("state after delete", &error)),
        Ok(Ok(_)) => Ok(false),
        Err(_) => Err("state after delete timed out".into()),
    }
}

pub(super) async fn best_effort_delete<T: AgentStream>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
    nonce: &str,
) {
    let Ok(context) = operation(nonce, "cleanup") else {
        return;
    };
    let _ = timeout(
        CLEANUP_TIMEOUT,
        client.delete(AgentDeleteRequest {
            context,
            target: target.clone(),
            mode: DeleteMode::Force,
        }),
    )
    .await;
}

async fn guest_call<T>(
    operation: &str,
    future: impl Future<Output = a3s_oci_sdk::Result<T>>,
) -> Result<T, String> {
    match timeout(GUEST_CALL_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(guest_error(operation, &error)),
        Err(_) => Err(format!("{operation} timed out")),
    }
}

fn guest_error(operation: &str, error: &Error) -> String {
    format!(
        "{operation} failed with {:?}: {}",
        error.code, error.message
    )
}

fn operation(nonce: &str, name: &str) -> Result<OperationContext, String> {
    let id = OperationId::new(format!("smoke-{nonce}-{name}"))
        .map_err(|error| format!("failed to construct {name} operation ID: {error}"))?;
    Ok(OperationContext::new(id))
}

fn fault_operation(nonce: &str, name: &str) -> Result<OperationContext, String> {
    let id = OperationId::new(format!("fault-smoke-{nonce}-{name}"))
        .map_err(|error| format!("failed to construct fault {name} operation ID: {error}"))?;
    Ok(OperationContext::new(id))
}

fn null_io() -> ProcessIo {
    ProcessIo {
        stdin: IoMode::Null,
        stdout: IoMode::Null,
        stderr: IoMode::Null,
        terminal_size: None,
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_core::HostPlatform;
    use a3s_oci_sdk::{ContainerId, ContainerTarget, Generation, TerminalSize};

    use super::{resource_profile, terminal_exec_request, UPDATED_MEMORY_LIMIT};

    #[test]
    fn fixed_kvm_and_whpx_profiles_omit_only_the_unavailable_swap_controller() {
        let windows = serde_json::to_value(
            resource_profile(HostPlatform::Windows).expect("Windows resource profile"),
        )
        .expect("serialize Windows resource profile");
        assert_eq!(windows["memory"]["limit"], UPDATED_MEMORY_LIMIT);
        assert!(windows["memory"].get("swap").is_none());
        assert_eq!(windows["cpu"]["cpus"], "0");
        assert_eq!(windows["pids"]["limit"], 64);

        let linux = serde_json::to_value(
            resource_profile(HostPlatform::Linux).expect("Linux KVM resource profile"),
        )
        .expect("serialize Linux KVM resource profile");
        assert_eq!(linux["memory"]["limit"], UPDATED_MEMORY_LIMIT);
        assert!(linux["memory"].get("swap").is_none());
        assert_eq!(linux["cpu"]["cpus"], "0");
        assert_eq!(linux["pids"]["limit"], 64);

        let macos = serde_json::to_value(
            resource_profile(HostPlatform::Macos).expect("macOS resource profile"),
        )
        .expect("serialize macOS resource profile");
        assert_eq!(macos["memory"]["swap"], 1024 * 1024 * 1024_u64);
    }

    #[test]
    fn terminal_smoke_sources_initial_dimensions_from_oci() {
        let target = ContainerTarget::exact(
            ContainerId::new("console-size-smoke").expect("container ID"),
            Generation(1),
        );
        let size = TerminalSize {
            width: 120,
            height: 40,
        };
        let request = terminal_exec_request(
            &target,
            "console-size",
            "terminal",
            "terminal",
            "/bin/true",
            size,
        )
        .expect("terminal smoke request");
        assert_eq!(request.io.terminal_size, None);
        assert_eq!(
            request
                .io
                .resolve_for_process(&request.process)
                .expect("resolve terminal smoke dimensions")
                .terminal_size,
            Some(size)
        );
        let configured = request
            .process
            .console_size()
            .expect("OCI console size must be present");
        assert_eq!(configured.width(), u64::from(size.width));
        assert_eq!(configured.height(), u64::from(size.height));
    }
}
