use std::collections::BTreeSet;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, Process};
use a3s_oci_sdk::{
    ContainerId, ContainerTarget, CreateAttachments, CreateRequest, DeleteMode, DeleteRequest,
    Error, ErrorCode, ExecRequest, ExitStatus, IoMode, IsolationRequest, KillRequest, ListRequest,
    OciBundle, OperationContext, OperationId, OutputStream, ProcessId, ProcessIo, ProcessTarget,
    ProcessesRequest, ReadOutputRequest, RuntimeClient, Signal, StartRequest, StateRequest,
    StatsRequest, WaitProcessRequest, WaitRequest,
};
use tokio::sync::Barrier;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, Instant};

use super::super::filesystem::{path_exists, read_marker, MARKER_CONTENTS};
use crate::marker::{exact_marker_state, ExactMarkerState};
use crate::NativeLinuxSoakReport;

const MARKER_POLL_INTERVAL: Duration = Duration::from_millis(25);
const OUTPUT_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(super) struct WaveContext<'a> {
    pub bundles: &'a [OciBundle],
    pub ids: &'a [ContainerId],
    pub markers: &'a [PathBuf],
    pub progress_markers: &'a [PathBuf],
    pub nonce: &'a str,
    pub iteration: u32,
    pub timeout: Duration,
}

pub(super) async fn create_start_and_exercise(
    client: &RuntimeClient,
    wave: &WaveContext<'_>,
    previous_targets: &[Option<ContainerTarget>],
    report: &mut NativeLinuxSoakReport,
) -> Result<Vec<ContainerTarget>, String> {
    let iteration = wave.iteration;
    let timeout_duration = wave.timeout;
    let create_inputs = wave
        .bundles
        .iter()
        .cloned()
        .zip(wave.ids.iter().cloned())
        .enumerate()
        .map(|(slot, (bundle, id))| {
            create_request(wave.nonce, wave.iteration, slot, id, bundle)
                .map(|request| (slot, request))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let client_for_create = client.clone();
    let created = run_concurrently(
        create_inputs,
        "concurrent create wave",
        move |(slot, request)| {
            let client = client_for_create.clone();
            async move {
                let record = soak_call(
                    timeout_duration,
                    format!("create soak container {slot}"),
                    client.create(request),
                )
                .await?;
                Ok((slot, record))
            }
        },
    )
    .await?;
    report.operation_counts.create += created.len() as u64;

    let expected_generation = u64::from(iteration) + 1;
    let mut pids = BTreeSet::new();
    let mut targets = Vec::with_capacity(created.len());
    for (slot, record) in created {
        require(
            *record.state.status() == ContainerState::Created,
            format!("soak container {slot} did not preserve the created barrier"),
        )?;
        if record.generation.0 != expected_generation {
            report.generation_sequence_verified = false;
            return Err(format!(
                "soak container {slot} received generation {}, expected {expected_generation}",
                record.generation.0
            ));
        }
        let pid = record
            .state
            .pid()
            .filter(|pid| *pid > 0)
            .ok_or_else(|| format!("soak container {slot} did not receive a positive PID"))?;
        if !pids.insert(pid) {
            report.unique_live_pids = false;
            return Err(format!("soak wave reused live PID {pid}"));
        }
        targets.push(ContainerTarget::exact(
            wave.ids[slot].clone(),
            record.generation,
        ));
    }
    report.unique_live_pids &= pids.len() == wave.ids.len();
    report.max_live_containers = report
        .max_live_containers
        .max(u32::try_from(pids.len()).unwrap_or(u32::MAX));

    if wave.iteration > 0 {
        let stale_inputs = previous_targets
            .iter()
            .enumerate()
            .map(|(slot, target)| {
                target
                    .clone()
                    .map(|target| (slot, target))
                    .ok_or_else(|| format!("missing prior target for soak slot {slot}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let client_for_stale = client.clone();
        let stale = run_concurrently(
            stale_inputs,
            "stale-generation state wave",
            move |(slot, target)| {
                let client = client_for_stale.clone();
                async move {
                    match timeout(timeout_duration, client.state(StateRequest { target })).await {
                        Ok(Err(error)) if error.code == ErrorCode::Conflict => Ok(slot),
                        Ok(Err(error)) => Err(call_error(
                            &format!("stale-generation state for soak slot {slot}"),
                            &error,
                        )),
                        Ok(Ok(_)) => Err(format!(
                            "stale generation remained usable for soak slot {slot}"
                        )),
                        Err(_) => Err(format!(
                            "stale-generation state timed out for soak slot {slot}"
                        )),
                    }
                }
            },
        )
        .await?;
        report.operation_counts.state += stale.len() as u64;
        report.stale_generation_rejections += stale.len() as u64;
    }

    let start_inputs = targets
        .iter()
        .cloned()
        .enumerate()
        .map(|(slot, target)| {
            operation(wave.nonce, wave.iteration, slot, "start")
                .map(|context| (slot, StartRequest { context, target }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let client_for_start = client.clone();
    let started = run_concurrently(
        start_inputs,
        "concurrent start wave",
        move |(slot, request)| {
            let client = client_for_start.clone();
            async move {
                let record = soak_call(
                    timeout_duration,
                    format!("start soak container {slot}"),
                    client.start(request),
                )
                .await?;
                require(
                    *record.state.status() == ContainerState::Running && !record.is_paused(),
                    format!("soak container {slot} did not enter running"),
                )?;
                Ok(slot)
            }
        },
    )
    .await?;
    report.operation_counts.start += started.len() as u64;

    wait_for_markers(wave.markers, timeout_duration).await?;
    verify_live_list(client, &targets, false, timeout_duration).await?;
    report.operation_counts.list += 1;

    let query_inputs = targets.iter().cloned().enumerate().collect::<Vec<_>>();
    let client_for_query = client.clone();
    let queried = run_concurrently(
        query_inputs,
        "concurrent query wave",
        move |(slot, target)| {
            let client = client_for_query.clone();
            async move {
                let state = soak_call(
                    timeout_duration,
                    format!("state soak container {slot}"),
                    client.state(StateRequest {
                        target: target.clone(),
                    }),
                )
                .await?;
                require(
                    *state.state.status() == ContainerState::Running && !state.is_paused(),
                    format!("soak container {slot} state was not running"),
                )?;
                let processes = soak_call(
                    timeout_duration,
                    format!("processes soak container {slot}"),
                    client.processes(ProcessesRequest {
                        target: target.clone(),
                    }),
                )
                .await?;
                require(
                    processes.iter().any(|process| {
                        process.target.container == target
                            && process.target.process_id.is_init()
                            && process.pid.is_some_and(|pid| pid > 0)
                    }),
                    format!("soak container {slot} omitted its live init process"),
                )?;
                let stats = soak_call(
                    timeout_duration,
                    format!("stats soak container {slot}"),
                    client.stats(StatsRequest {
                        target: target.clone(),
                    }),
                )
                .await?;
                require(
                    stats.target == target
                        && stats.process_count > 0
                        && stats.timestamp_unix_ns > 0,
                    format!("soak container {slot} returned invalid resource stats"),
                )?;
                Ok(slot)
            }
        },
    )
    .await?;
    let queried_count = queried.len() as u64;
    report.operation_counts.state += queried_count;
    report.operation_counts.processes += queried_count;
    report.operation_counts.stats += queried_count;

    let exec_inputs = targets.iter().cloned().enumerate().collect::<Vec<_>>();
    let client_for_exec = client.clone();
    let exec_nonce = wave.nonce.to_string();
    let exec_results = run_concurrently(
        exec_inputs,
        "concurrent exec wave",
        move |(slot, target)| {
            let client = client_for_exec.clone();
            let nonce = exec_nonce.clone();
            async move {
                exercise_exec(&client, target, &nonce, iteration, slot, timeout_duration)
                    .await
                    .map(|read_calls| (slot, read_calls))
            }
        },
    )
    .await?;
    report.operation_counts.exec += exec_results.len() as u64;
    report.operation_counts.wait_process += exec_results.len() as u64;
    report.operation_counts.read_output += exec_results
        .iter()
        .map(|(_, read_calls)| *read_calls)
        .sum::<u64>();

    Ok(targets)
}

pub(super) async fn terminate_and_delete(
    client: &RuntimeClient,
    wave: &WaveContext<'_>,
    targets: &[ContainerTarget],
    report: &mut NativeLinuxSoakReport,
) -> Result<(), String> {
    let timeout_duration = wave.timeout;
    let kill_inputs = targets
        .iter()
        .cloned()
        .enumerate()
        .map(|(slot, target)| {
            operation(wave.nonce, wave.iteration, slot, "kill").and_then(|context| {
                Signal::new(libc::SIGKILL)
                    .map(|signal| {
                        (
                            slot,
                            KillRequest {
                                context,
                                target,
                                signal,
                                all: false,
                            },
                        )
                    })
                    .map_err(|error| format!("failed to construct soak signal: {error}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let client_for_kill = client.clone();
    let killed = run_concurrently(
        kill_inputs,
        "concurrent kill wave",
        move |(slot, request)| {
            let client = client_for_kill.clone();
            async move {
                let record = soak_call(
                    timeout_duration,
                    format!("kill soak container {slot}"),
                    client.kill(request),
                )
                .await?;
                require(
                    matches!(
                        *record.state.status(),
                        ContainerState::Running | ContainerState::Stopped
                    ),
                    format!("soak container {slot} kill returned an invalid state"),
                )?;
                Ok(slot)
            }
        },
    )
    .await?;
    report.operation_counts.kill += killed.len() as u64;

    let wait_inputs = targets.iter().cloned().enumerate().collect::<Vec<_>>();
    let client_for_wait = client.clone();
    let waited = run_concurrently(
        wait_inputs,
        "concurrent init wait wave",
        move |(slot, target)| {
            let client = client_for_wait.clone();
            async move {
                let status = soak_call(
                    timeout_duration,
                    format!("wait soak container {slot}"),
                    client.wait(WaitRequest {
                        target,
                        timeout_ms: Some(duration_millis(timeout_duration)),
                    }),
                )
                .await?;
                let expected = ExitStatus::signaled(libc::SIGKILL, false)
                    .map_err(|error| format!("failed to construct soak exit status: {error}"))?;
                require(
                    status == expected,
                    format!("soak container {slot} returned {status:?}, expected {expected:?}"),
                )?;
                Ok(slot)
            }
        },
    )
    .await?;
    report.operation_counts.wait += waited.len() as u64;

    let delete_inputs = targets
        .iter()
        .cloned()
        .enumerate()
        .map(|(slot, target)| {
            operation(wave.nonce, wave.iteration, slot, "delete").map(|context| {
                (
                    slot,
                    DeleteRequest {
                        context,
                        target,
                        mode: DeleteMode::StoppedOnly,
                    },
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let client_for_delete = client.clone();
    let deleted = run_concurrently(
        delete_inputs,
        "concurrent delete wave",
        move |(slot, request)| {
            let client = client_for_delete.clone();
            async move {
                soak_call(
                    timeout_duration,
                    format!("delete soak container {slot}"),
                    client.delete(request),
                )
                .await?;
                Ok(slot)
            }
        },
    )
    .await?;
    report.operation_counts.delete += deleted.len() as u64;

    let missing_inputs = targets.iter().cloned().enumerate().collect::<Vec<_>>();
    let client_for_missing = client.clone();
    let missing = run_concurrently(
        missing_inputs,
        "deleted-state query wave",
        move |(slot, target)| {
            let client = client_for_missing.clone();
            async move {
                match timeout(timeout_duration, client.state(StateRequest { target })).await {
                    Ok(Err(error)) if error.code == ErrorCode::NotFound => Ok(slot),
                    Ok(Err(error)) => Err(call_error(
                        &format!("deleted state for soak slot {slot}"),
                        &error,
                    )),
                    Ok(Ok(_)) => Err(format!("deleted soak slot {slot} remained visible")),
                    Err(_) => Err(format!("deleted state timed out for soak slot {slot}")),
                }
            }
        },
    )
    .await?;
    report.operation_counts.state += missing.len() as u64;

    let listed = soak_call(
        timeout_duration,
        "list after soak delete wave",
        client.list(ListRequest::default()),
    )
    .await?;
    report.operation_counts.list += 1;
    require(
        listed.is_empty(),
        "runtime list was not empty after soak wave",
    )
}

pub(super) async fn best_effort_delete(
    client: &RuntimeClient,
    ids: &[ContainerId],
    nonce: &str,
    timeout_duration: Duration,
) {
    for (slot, id) in ids.iter().cloned().enumerate() {
        let Ok(context) = operation(nonce, u32::MAX, slot, "cleanup") else {
            continue;
        };
        let _ = timeout(
            timeout_duration,
            client.delete(DeleteRequest {
                context,
                target: ContainerTarget::current(id),
                mode: DeleteMode::Force,
            }),
        )
        .await;
    }
}

pub(super) async fn verify_live_list(
    client: &RuntimeClient,
    targets: &[ContainerTarget],
    paused: bool,
    timeout_duration: Duration,
) -> Result<(), String> {
    let records = soak_call(
        timeout_duration,
        "list live soak containers",
        client.list(ListRequest::default()),
    )
    .await?;
    require(
        records.len() == targets.len(),
        format!(
            "soak list returned {} containers, expected {}",
            records.len(),
            targets.len()
        ),
    )?;
    for target in targets {
        let Some(record) = records.iter().find(|record| {
            record.state.id() == target.id.as_ref() && target.generation == Some(record.generation)
        }) else {
            return Err(format!("soak list omitted container {}", target.id));
        };
        require(
            *record.state.status() == ContainerState::Running && record.is_paused() == paused,
            format!("soak list returned an unexpected state for {}", target.id),
        )?;
    }
    Ok(())
}

async fn wait_for_markers(markers: &[PathBuf], timeout_duration: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout_duration;
    loop {
        let mut complete = true;
        for marker in markers {
            if path_exists(marker).await? {
                match exact_marker_state(&read_marker(marker).await?, MARKER_CONTENTS) {
                    ExactMarkerState::Complete => {}
                    ExactMarkerState::InProgress => complete = false,
                    ExactMarkerState::Mismatch => {
                        return Err(format!(
                            "soak marker contained unexpected data: {}",
                            marker.display()
                        ));
                    }
                }
            } else {
                complete = false;
            }
        }
        if complete {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for all soak workload markers".into());
        }
        sleep(MARKER_POLL_INTERVAL).await;
    }
}

async fn exercise_exec(
    client: &RuntimeClient,
    target: ContainerTarget,
    nonce: &str,
    iteration: u32,
    slot: usize,
    timeout_duration: Duration,
) -> Result<u64, String> {
    let expected = format!("a3s-oci-soak-{iteration}-{slot}\n").into_bytes();
    let command = format!("printf 'a3s-oci-soak-{iteration}-{slot}\\n'");
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", command],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 48, "soft": 48}],
        "noNewPrivileges": true
    }))
    .map_err(|error| format!("failed to construct soak exec process: {error}"))?;
    let process_id = ProcessId::new(format!("soak-{iteration}-{slot}"))
        .map_err(|error| format!("failed to construct soak process ID: {error}"))?;
    let process_target = ProcessTarget {
        container: target.clone(),
        process_id: process_id.clone(),
    };
    let created = soak_call(
        timeout_duration,
        format!("exec soak process {iteration}/{slot}"),
        client.exec(ExecRequest {
            context: operation(nonce, iteration, slot, "exec")?,
            container: target,
            process_id,
            process,
            io: ProcessIo {
                stdin: IoMode::Null,
                stdout: IoMode::Capture,
                stderr: IoMode::Capture,
                terminal_size: None,
            },
        }),
    )
    .await?;
    require(
        created.target == process_target && created.pid.is_some_and(|pid| pid > 0),
        format!("soak exec {iteration}/{slot} returned an invalid identity"),
    )?;
    let status = soak_call(
        timeout_duration,
        format!("wait soak process {iteration}/{slot}"),
        client.wait_process(WaitProcessRequest {
            process: process_target.clone(),
            timeout_ms: Some(duration_millis(timeout_duration)),
        }),
    )
    .await?;
    let expected_status = ExitStatus::exited(0)
        .map_err(|error| format!("failed to construct soak exec exit status: {error}"))?;
    require(
        status == expected_status,
        format!("soak exec {iteration}/{slot} returned {status:?}"),
    )?;
    let (stdout, stderr, read_calls) =
        collect_output(client, process_target, timeout_duration).await?;
    require(
        stdout == expected && stderr.is_empty(),
        format!(
            "soak exec {iteration}/{slot} output mismatch: stdout={stdout:?}, stderr={stderr:?}"
        ),
    )?;
    Ok(read_calls)
}

async fn collect_output(
    client: &RuntimeClient,
    process: ProcessTarget,
    timeout_duration: Duration,
) -> Result<(Vec<u8>, Vec<u8>, u64), String> {
    let deadline = Instant::now() + timeout_duration;
    let mut cursor = 0;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let mut read_calls = 0;
    while !stdout_eof || !stderr_eof {
        let chunks = soak_call(
            timeout_duration,
            "read soak exec output",
            client.read_output(ReadOutputRequest {
                process: process.clone(),
                after_sequence: cursor,
                max_bytes: 4_096,
                wait_timeout_ms: Some(100),
            }),
        )
        .await?;
        read_calls += 1;
        for chunk in chunks {
            require(
                chunk.sequence > cursor,
                "soak output cursor did not advance",
            )?;
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
            return Err("timed out draining soak exec output".into());
        }
        if !stdout_eof || !stderr_eof {
            sleep(OUTPUT_POLL_INTERVAL).await;
        }
    }
    Ok((stdout, stderr, read_calls))
}

fn create_request(
    nonce: &str,
    iteration: u32,
    slot: usize,
    id: ContainerId,
    bundle: OciBundle,
) -> Result<CreateRequest, String> {
    let attachments = CreateAttachments::from_bundle(
        &bundle,
        ProcessIo {
            stdin: IoMode::Null,
            stdout: IoMode::Null,
            stderr: IoMode::Null,
            terminal_size: None,
        },
    )
    .map_err(|error| format!("failed to derive soak create attachments: {error}"))?;
    Ok(CreateRequest {
        context: operation(nonce, iteration, slot, "create")?,
        id,
        bundle,
        isolation: IsolationRequest::SharedHostKernel,
        attachments,
    })
}

pub(super) fn operation(
    nonce: &str,
    iteration: u32,
    slot: usize,
    operation: &str,
) -> Result<OperationContext, String> {
    OperationId::new(format!(
        "native-soak-{nonce}-{iteration}-{slot}-{operation}"
    ))
    .map(OperationContext::new)
    .map_err(|error| format!("failed to construct soak {operation} operation ID: {error}"))
}

pub(super) async fn soak_call<T>(
    timeout_duration: Duration,
    operation: impl AsRef<str>,
    future: impl Future<Output = a3s_oci_sdk::Result<T>>,
) -> Result<T, String> {
    match timeout(timeout_duration, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(call_error(operation.as_ref(), &error)),
        Err(_) => Err(format!("{} timed out", operation.as_ref())),
    }
}

pub(super) async fn run_concurrently<I, T, F, Fut>(
    inputs: Vec<I>,
    description: &str,
    operation: F,
) -> Result<Vec<T>, String>
where
    I: Send + 'static,
    T: Send + 'static,
    F: Fn(I) -> Fut,
    Fut: Future<Output = Result<T, String>> + Send + 'static,
{
    if inputs.is_empty() {
        return Err(format!("{description} had no work"));
    }
    let barrier = Arc::new(Barrier::new(inputs.len() + 1));
    let mut tasks = JoinSet::new();
    for (index, input) in inputs.into_iter().enumerate() {
        let ready = Arc::clone(&barrier);
        let future = operation(input);
        tasks.spawn(async move {
            ready.wait().await;
            (index, future.await)
        });
    }
    barrier.wait().await;

    let mut ordered = (0..tasks.len()).map(|_| None).collect::<Vec<Option<T>>>();
    let mut first_error = None;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((index, Ok(value))) => ordered[index] = Some(value),
            Ok((_, Err(error))) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(format!("{description} task failed to join: {error}"));
                }
            }
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    ordered
        .into_iter()
        .enumerate()
        .map(|(index, value)| value.ok_or_else(|| format!("{description} omitted result {index}")))
        .collect()
}

pub(super) fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn call_error(operation: &str, error: &Error) -> String {
    format!(
        "{operation} failed with {:?}: {}",
        error.code, error.message
    )
}

pub(super) fn require(condition: bool, message: impl Into<String>) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
