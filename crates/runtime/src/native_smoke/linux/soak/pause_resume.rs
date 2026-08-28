use std::path::{Path, PathBuf};
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, Process};
use a3s_oci_sdk::{
    ContainerOperationRequest, ContainerRecord, ContainerTarget, ExecRequest, IoMode, ProcessId,
    ProcessIo, ProcessTarget, RuntimeClient, StateRequest,
};
use tokio::time::{sleep, Instant};

use super::super::filesystem::{path_exists, read_marker};
use super::wave::{operation, require, run_concurrently, soak_call, verify_live_list, WaveContext};
use crate::{NativeLinuxSoakPauseResumeEvidence, NativeLinuxSoakReport};

pub(super) const PROGRESS_MARKER_NAME: &str = ".a3s-oci-native-soak-progress";
pub(super) const PROGRESS_TEMP_MARKER_NAME: &str = ".a3s-oci-native-soak-progress.next";

const PROGRESS_PATH: &str = "/.a3s-oci-native-soak-progress";
const PROGRESS_TEMP_PATH: &str = "/.a3s-oci-native-soak-progress.next";
const PROGRESS_POLL_INTERVAL: Duration = Duration::from_millis(25);
const FREEZE_OBSERVATION_DELAY: Duration = Duration::from_millis(350);

pub(super) struct PausedWave {
    entries: Vec<PausedEntry>,
}

struct PausedEntry {
    slot: usize,
    target: ContainerTarget,
    pause_request: ContainerOperationRequest,
    paused_record: ContainerRecord,
    progress_before_pause: u64,
    progress_at_pause: u64,
}

pub(super) struct ResumedWave {
    entries: Vec<ResumedEntry>,
}

struct ResumedEntry {
    paused: PausedEntry,
    resume_request: ContainerOperationRequest,
    resumed_record: ContainerRecord,
    progress_after_pause_reopen: u64,
    progress_after_resume: u64,
}

pub(super) async fn pause(
    client: &RuntimeClient,
    wave: &WaveContext<'_>,
    targets: &[ContainerTarget],
    report: &mut NativeLinuxSoakReport,
) -> Result<PausedWave, String> {
    require(
        targets.len() == wave.progress_markers.len(),
        "soak progress marker inventory did not match the live target set",
    )?;

    let progress_inputs = targets
        .iter()
        .cloned()
        .zip(wave.progress_markers.iter().cloned())
        .enumerate()
        .map(|(slot, (target, marker))| (slot, target, marker))
        .collect::<Vec<_>>();
    let progress_client = client.clone();
    let progress_nonce = wave.nonce.to_string();
    let iteration = wave.iteration;
    let timeout_duration = wave.timeout;
    let progress = run_concurrently(
        progress_inputs,
        "concurrent progress workload wave",
        move |(slot, target, marker)| {
            let client = progress_client.clone();
            let nonce = progress_nonce.clone();
            async move {
                start_progress_process(
                    &client,
                    target,
                    &nonce,
                    iteration,
                    slot,
                    &marker,
                    timeout_duration,
                )
                .await
                .map(|value| (slot, value))
            }
        },
    )
    .await?;
    report.operation_counts.exec += progress.len() as u64;

    let pause_inputs = targets
        .iter()
        .cloned()
        .zip(wave.progress_markers.iter().cloned())
        .zip(progress)
        .enumerate()
        .map(
            |(slot, ((target, marker), (progress_slot, progress_before_pause)))| {
                require(
                    slot == progress_slot,
                    "concurrent progress results changed soak slot order",
                )?;
                let request = ContainerOperationRequest {
                    context: operation(wave.nonce, wave.iteration, slot, "pause")?,
                    target: target.clone(),
                };
                Ok((slot, target, marker, request, progress_before_pause))
            },
        )
        .collect::<Result<Vec<_>, String>>()?;
    let pause_client = client.clone();
    let paused = run_concurrently(
        pause_inputs,
        "concurrent pause wave",
        move |(slot, target, marker, request, progress_before_pause)| {
            let client = pause_client.clone();
            async move {
                let record = soak_call(
                    timeout_duration,
                    format!("pause soak container {slot}"),
                    client.pause(request.clone()),
                )
                .await?;
                require(
                    *record.state.status() == ContainerState::Running && record.is_paused(),
                    format!("soak container {slot} did not expose a paused state"),
                )?;
                let progress_at_pause = read_progress(&marker).await?;
                require(
                    progress_at_pause >= progress_before_pause,
                    format!("soak progress regressed while pausing container {slot}"),
                )?;
                sleep(FREEZE_OBSERVATION_DELAY).await;
                require(
                    read_progress(&marker).await? == progress_at_pause,
                    format!("soak workload {slot} advanced after Pause committed"),
                )?;
                Ok(PausedEntry {
                    slot,
                    target,
                    pause_request: request,
                    paused_record: record,
                    progress_before_pause,
                    progress_at_pause,
                })
            }
        },
    )
    .await?;
    report.operation_counts.pause += paused.len() as u64;
    Ok(PausedWave { entries: paused })
}

pub(super) async fn replay_pause_and_resume(
    client: &RuntimeClient,
    wave: &WaveContext<'_>,
    paused: PausedWave,
    report: &mut NativeLinuxSoakReport,
) -> Result<ResumedWave, String> {
    let targets = paused
        .entries
        .iter()
        .map(|entry| entry.target.clone())
        .collect::<Vec<_>>();
    verify_live_list(client, &targets, true, wave.timeout).await?;
    report.operation_counts.list += 1;

    let inputs = paused
        .entries
        .into_iter()
        .zip(wave.progress_markers.iter().cloned())
        .collect::<Vec<_>>();
    let replay_client = client.clone();
    let nonce = wave.nonce.to_string();
    let iteration = wave.iteration;
    let timeout_duration = wave.timeout;
    let resumed = run_concurrently(
        inputs,
        "pause replay and resume wave",
        move |(paused, marker)| {
            let client = replay_client.clone();
            let nonce = nonce.clone();
            async move {
                let state = soak_call(
                    timeout_duration,
                    format!("recover paused soak container {}", paused.slot),
                    client.state(StateRequest {
                        target: paused.target.clone(),
                    }),
                )
                .await?;
                require(
                    state == paused.paused_record,
                    format!(
                        "reopened service changed paused state for soak container {}",
                        paused.slot
                    ),
                )?;
                let replay = soak_call(
                    timeout_duration,
                    format!("replay Pause for soak container {}", paused.slot),
                    client.pause(paused.pause_request.clone()),
                )
                .await?;
                require(
                    replay == paused.paused_record,
                    format!(
                        "reopened service did not exactly replay Pause for soak container {}",
                        paused.slot
                    ),
                )?;
                let progress_after_pause_reopen = read_progress(&marker).await?;
                sleep(FREEZE_OBSERVATION_DELAY).await;
                require(
                    progress_after_pause_reopen == paused.progress_at_pause
                        && read_progress(&marker).await? == paused.progress_at_pause,
                    format!(
                        "soak workload {} advanced across paused Host Service reopen",
                        paused.slot
                    ),
                )?;

                let resume_request = ContainerOperationRequest {
                    context: operation(&nonce, iteration, paused.slot, "resume")?,
                    target: paused.target.clone(),
                };
                let resumed_record = soak_call(
                    timeout_duration,
                    format!("resume soak container {}", paused.slot),
                    client.resume(resume_request.clone()),
                )
                .await?;
                require(
                    *resumed_record.state.status() == ContainerState::Running
                        && !resumed_record.is_paused(),
                    format!("soak container {} did not resume", paused.slot),
                )?;
                let progress_after_resume = wait_for_progress_greater(
                    &marker,
                    progress_after_pause_reopen,
                    timeout_duration,
                )
                .await?;
                Ok(ResumedEntry {
                    paused,
                    resume_request,
                    resumed_record,
                    progress_after_pause_reopen,
                    progress_after_resume,
                })
            }
        },
    )
    .await?;
    let count = resumed.len() as u64;
    report.operation_counts.state += count;
    report.operation_counts.pause += count;
    report.operation_counts.resume += count;
    Ok(ResumedWave { entries: resumed })
}

pub(super) async fn replay_resume(
    client: &RuntimeClient,
    wave: &WaveContext<'_>,
    resumed: ResumedWave,
    report: &mut NativeLinuxSoakReport,
) -> Result<Vec<ContainerTarget>, String> {
    let targets = resumed
        .entries
        .iter()
        .map(|entry| entry.paused.target.clone())
        .collect::<Vec<_>>();
    verify_live_list(client, &targets, false, wave.timeout).await?;
    report.operation_counts.list += 1;

    let inputs = resumed
        .entries
        .into_iter()
        .zip(wave.progress_markers.iter().cloned())
        .collect::<Vec<_>>();
    let replay_client = client.clone();
    let timeout_duration = wave.timeout;
    let iteration = wave.iteration;
    let evidence = run_concurrently(inputs, "resume replay wave", move |(resumed, marker)| {
        let client = replay_client.clone();
        async move {
            let state = soak_call(
                timeout_duration,
                format!("recover resumed soak container {}", resumed.paused.slot),
                client.state(StateRequest {
                    target: resumed.paused.target.clone(),
                }),
            )
            .await?;
            require(
                state == resumed.resumed_record,
                format!(
                    "reopened service changed resumed state for soak container {}",
                    resumed.paused.slot
                ),
            )?;
            let replay = soak_call(
                timeout_duration,
                format!("replay Resume for soak container {}", resumed.paused.slot),
                client.resume(resumed.resume_request.clone()),
            )
            .await?;
            require(
                replay == resumed.resumed_record,
                format!(
                    "reopened service did not exactly replay Resume for soak container {}",
                    resumed.paused.slot
                ),
            )?;
            let progress_after_resume_reopen =
                wait_for_progress_greater(&marker, resumed.progress_after_resume, timeout_duration)
                    .await?;
            Ok(NativeLinuxSoakPauseResumeEvidence {
                iteration,
                slot: u32::try_from(resumed.paused.slot).unwrap_or(u32::MAX),
                target: resumed.paused.target,
                pause_operation_id: resumed.paused.pause_request.context.operation_id,
                resume_operation_id: resumed.resume_request.context.operation_id,
                progress_before_pause: resumed.paused.progress_before_pause,
                progress_at_pause: resumed.paused.progress_at_pause,
                progress_after_pause_reopen: resumed.progress_after_pause_reopen,
                progress_after_resume: resumed.progress_after_resume,
                progress_after_resume_reopen,
                pause_response_replayed_after_reopen: true,
                resume_response_replayed_after_reopen: true,
            })
        }
    })
    .await?;
    let count = evidence.len() as u64;
    report.operation_counts.state += count;
    report.operation_counts.resume += count;
    report.pause_resume_evidence.extend(evidence);
    Ok(targets)
}

async fn start_progress_process(
    client: &RuntimeClient,
    target: ContainerTarget,
    nonce: &str,
    iteration: u32,
    slot: usize,
    marker: &Path,
    timeout_duration: Duration,
) -> Result<u64, String> {
    require(
        !path_exists(marker).await?,
        format!(
            "refusing to overwrite a soak progress marker: {}",
            marker.display()
        ),
    )?;
    let command = format!(
        "n=0; while :; do n=$((n + 1)); printf '%s\\n' \"$n\" > {PROGRESS_TEMP_PATH}; \
         /bin/busybox mv {PROGRESS_TEMP_PATH} {PROGRESS_PATH}; /bin/busybox sleep 0.05; done"
    );
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", command],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .map_err(|error| format!("failed to construct soak progress process: {error}"))?;
    let process_id = ProcessId::new(format!("soak-progress-{iteration}-{slot}"))
        .map_err(|error| format!("failed to construct soak progress process ID: {error}"))?;
    let expected_target = ProcessTarget {
        container: target.clone(),
        process_id: process_id.clone(),
    };
    let created = soak_call(
        timeout_duration,
        format!("start soak progress process {iteration}/{slot}"),
        client.exec(ExecRequest {
            context: operation(nonce, iteration, slot, "progress-exec")?,
            container: target,
            process_id,
            process,
            io: ProcessIo {
                stdin: IoMode::Null,
                stdout: IoMode::Null,
                stderr: IoMode::Null,
                terminal_size: None,
            },
        }),
    )
    .await?;
    require(
        created.target == expected_target
            && created.pid.is_some_and(|pid| pid > 0)
            && !created.terminal,
        format!("soak progress process {iteration}/{slot} returned an invalid identity"),
    )?;
    wait_for_progress_greater(marker, 0, timeout_duration).await
}

async fn wait_for_progress_greater(
    marker: &Path,
    minimum: u64,
    timeout_duration: Duration,
) -> Result<u64, String> {
    let deadline = Instant::now() + timeout_duration;
    loop {
        if path_exists(marker).await? {
            let progress = read_progress(marker).await?;
            if progress > minimum {
                return Ok(progress);
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for soak progress beyond {minimum}: {}",
                marker.display()
            ));
        }
        sleep(PROGRESS_POLL_INTERVAL).await;
    }
}

async fn read_progress(marker: &Path) -> Result<u64, String> {
    let bytes = read_marker(marker).await?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| format!("soak progress marker is not UTF-8: {error}"))?;
    let progress = text
        .strip_suffix('\n')
        .ok_or_else(|| "soak progress marker is not newline terminated".to_string())?
        .parse::<u64>()
        .map_err(|error| format!("soak progress marker is not a counter: {error}"))?;
    require(
        progress > 0 && bytes == format!("{progress}\n").as_bytes(),
        "soak progress marker is not a canonical positive counter",
    )?;
    Ok(progress)
}

pub(super) fn progress_artifacts(rootfs: &Path) -> [PathBuf; 2] {
    [
        rootfs.join(PROGRESS_MARKER_NAME),
        rootfs.join(PROGRESS_TEMP_MARKER_NAME),
    ]
}
