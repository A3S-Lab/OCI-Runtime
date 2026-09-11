//! Native Linux Live Host reopen filesystem + retained exec I/O evidence runner.

use std::future::Future;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use a3s_oci_core::CapabilityStatus;
use a3s_oci_sdk::oci_spec::runtime::{ContainerState, Process};
use a3s_oci_sdk::{
    ContainerId, ContainerTarget, CreateAttachments, CreateRequest, DeleteMode, DeleteRequest,
    ExecRequest, FileOp, FileRequest, IoMode, IsolationRequest, KillRequest, OciBundle,
    OperationContext, OperationId, OutputStream, ProcessId, ProcessIo, ProcessTarget,
    ProcessesRequest, ReadOutputRequest, RuntimeClient, Signal, StartRequest, StateRequest,
    WaitRequest, WriteStdinRequest,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use tokio::time::{sleep, timeout, Instant};

use crate::native_hook_recovery_smoke::{
    capture_native_process_identity, NativeLinuxProcessIdentity,
};
use crate::unix_service::validate_unix_socket_path;

use super::host::{self, HostServiceProcess};
use super::report::LinuxNativeLiveRecoverySmokeReport;
use super::LinuxNativeLiveRecoverySmokeConfig;

const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const LIVE_IO_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const SESSION_SUPERVISOR_ENV: &str = "A3S_OCI_NATIVE_SESSION_SUPERVISOR";

struct PreparedRun {
    executable: PathBuf,
    agent: PathBuf,
    bundle: PathBuf,
    service_root: PathBuf,
    evidence_root: PathBuf,
    nonce: String,
}

/// Kill one Live Native Host; prove init survives and replacement reattaches Running.
pub async fn run(config: LinuxNativeLiveRecoverySmokeConfig) -> LinuxNativeLiveRecoverySmokeReport {
    let architecture = std::env::consts::ARCH.to_string();
    let mut report =
        LinuxNativeLiveRecoverySmokeReport::initial(config.work_parent.clone(), architecture);
    report.recovery.session_supervisor_mode_opt_in =
        std::env::var_os(SESSION_SUPERVISOR_ENV).is_some_and(|value| value == "1");
    if !report.recovery.session_supervisor_mode_opt_in {
        let reason = format!(
            "{SESSION_SUPERVISOR_ENV}=1 is required for Native Live Host reopen evidence"
        );
        report.reason = Some(reason.clone());
        report.recovery.reason = Some(reason);
        return report;
    }

    let prepared = match prepare(config).await {
        Ok(prepared) => prepared,
        Err(reason) => {
            report.reason = Some(reason.clone());
            report.recovery.reason = Some(reason);
            return report;
        }
    };
    report.evidence_root = prepared.evidence_root.clone();

    if let Err(reason) = run_live_recovery(&prepared, &mut report).await {
        report.recovery.reason = Some(reason.clone());
        report.reason = Some(reason);
        return report;
    }
    if !report.recovery.is_success() {
        let reason =
            "Native Linux Live recovery evidence failed its completeness audit".to_string();
        report.recovery.reason = Some(reason.clone());
        report.reason = Some(reason);
        return report;
    }
    report.status = CapabilityStatus::Available;
    report.case_count = 1;
    if !report.is_success() {
        report.status = CapabilityStatus::Unavailable;
        report.case_count = 0;
        report.reason = Some("Native Linux Live recovery report failed its final audit".to_string());
    }
    report
}

async fn prepare(config: LinuxNativeLiveRecoverySmokeConfig) -> Result<PreparedRun, String> {
    let work_parent = canonical_plain_directory(&config.work_parent, "work parent").await?;
    let agent = canonical_plain_file(&config.agent, "native agent executable", true)?;
    let bundle = canonical_plain_directory(&config.bundle, "source OCI bundle").await?;
    let _ = OciBundle::load(&bundle)
        .await
        .map_err(|error| format!("failed to validate source OCI bundle: {error}"))?;
    let executable = std::env::current_exe().map_err(|error| {
        format!("failed to resolve current Host Service executable: {error}")
    })?;
    let executable = canonical_plain_file(&executable, "Host Service executable", true)?;
    let nonce = unique_nonce()?;
    let evidence_root = work_parent.join(format!("nlr-{nonce}"));
    let service_root = evidence_root.join("service");
    validate_unix_socket_path(
        &service_root.join("runtime.sock"),
        "Native Linux Live recovery Host endpoint",
    )
    .map_err(|error| error.to_string())?;
    create_private_directory(&evidence_root)?;
    create_private_directory(&service_root)?;
    let _ = config.source_revision;
    Ok(PreparedRun {
        executable,
        agent,
        bundle,
        service_root,
        evidence_root,
        nonce,
    })
}

async fn run_live_recovery(
    prepared: &PreparedRun,
    report: &mut LinuxNativeLiveRecoverySmokeReport,
) -> Result<(), String> {
    let evidence = &mut report.recovery;
    let mut first = HostServiceProcess::spawn(
        &prepared.executable,
        &prepared.service_root,
        &prepared.agent,
        &prepared.evidence_root.join("first.stdout.log"),
        &prepared.evidence_root.join("first.stderr.log"),
    )
    .await?;
    let first_result = run_first_owner(prepared, &first, evidence).await;
    let (init_identity, target) = match first_result {
        Ok(values) => values,
        Err(reason) => {
            first.emergency_stop().await;
            return Err(reason);
        }
    };

    first.sigkill().await?;
    evidence.host_sigkill_delivered = true;
    sleep(Duration::from_millis(200)).await;
    evidence.init_survived_host_sigkill = host::process_still_live(&init_identity)?;
    if !evidence.init_survived_host_sigkill {
        return Err(
            "Live init was reaped after Host SIGKILL (expected survival under session supervisor)"
                .to_string(),
        );
    }

    host::reclaim_dead_owner_socket(first.socket_path())?;

    let mut replacement = HostServiceProcess::spawn(
        &prepared.executable,
        &prepared.service_root,
        &prepared.agent,
        &prepared.evidence_root.join("replacement.stdout.log"),
        &prepared.evidence_root.join("replacement.stderr.log"),
    )
    .await?;
    let replacement_result =
        run_replacement(prepared, &mut replacement, &target, &init_identity, evidence).await;
    if replacement_result.is_err() {
        emergency_cleanup(&mut replacement, &target).await;
        replacement.emergency_stop().await;
    }
    replacement_result
}

async fn run_first_owner(
    prepared: &PreparedRun,
    first: &HostServiceProcess,
    evidence: &mut super::report::LinuxNativeLiveRecoveryEvidence,
) -> Result<(NativeLinuxProcessIdentity, ContainerTarget), String> {
    let _ = first.identity()?;
    let client = first.connect().await?;
    let id = ContainerId::new(format!("nlr-{}", prepared.nonce))
        .map_err(|error| format!("failed to construct Live recovery container ID: {error}"))?;
    let bundle = OciBundle::load(&prepared.bundle)
        .await
        .map_err(|error| format!("failed to load Live recovery bundle: {error}"))?;
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .map_err(|error| format!("failed to derive Live recovery attachments: {error}"))?;
    let create = CreateRequest {
        context: operation(&prepared.nonce, "create")?,
        id: id.clone(),
        bundle,
        isolation: IsolationRequest::SharedHostKernel,
        attachments,
    };
    let created = call("Native Live create", client.create(create)).await?;
    if *created.state.status() != ContainerState::Created {
        return Err("Native Live create did not retain Created state".to_string());
    }
    let target = ContainerTarget::exact(id, created.generation);
    let started = call(
        "Native Live start",
        client.start(StartRequest {
            context: operation(&prepared.nonce, "start")?,
            target: target.clone(),
        }),
    )
    .await?;
    if *started.state.status() != ContainerState::Running {
        return Err("Native Live start did not return Running state".to_string());
    }
    let init_pid = started
        .state
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 1)
        .ok_or_else(|| "Native Live start did not retain a live init PID".to_string())?;
    let init_identity = capture_native_process_identity(init_pid)?;

    prove_retained_exec_io_before_kill(prepared, &client, &target, evidence).await?;
    prove_retained_filesystem_before_kill(prepared, &client, &target, evidence).await?;
    drop(client);
    Ok((init_identity, target))
}

async fn run_replacement(
    prepared: &PreparedRun,
    replacement: &mut HostServiceProcess,
    target: &ContainerTarget,
    init_identity: &NativeLinuxProcessIdentity,
    evidence: &mut super::report::LinuxNativeLiveRecoveryEvidence,
) -> Result<(), String> {
    let _ = replacement.identity()?;
    let client = replacement.connect().await?;
    let recovered = call(
        "replacement Native Live state",
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await?;
    evidence.replacement_state_running = *recovered.state.status() == ContainerState::Running
        && recovered
            .state
            .pid()
            .and_then(|pid| u32::try_from(pid).ok())
            == Some(init_identity.pid)
        && host::process_still_live(init_identity)?;
    if !evidence.replacement_state_running {
        return Err(
            "replacement did not reattach Running with continuous init identity".to_string(),
        );
    }

    let processes = call(
        "replacement Native Live process inventory",
        client.processes(ProcessesRequest {
            target: target.clone(),
        }),
    )
    .await?;
    let retained_exec_present = evidence
        .retained_exec_process_id
        .as_deref()
        .is_some_and(|id| {
            processes
                .iter()
                .any(|process| process.target.process_id.as_str() == id)
        });
    if !retained_exec_present {
        return Err(
            "replacement Live process inventory lost the retained exec process ID".to_string(),
        );
    }

    prove_retained_exec_io_after_reattach(prepared, &client, target, evidence).await?;
    prove_new_exec_io_after_reattach(prepared, &client, target, evidence).await?;
    prove_retained_filesystem_after_reattach(prepared, &client, target, evidence).await?;

    call(
        "replacement Live kill",
        client.kill(KillRequest {
            context: operation(&prepared.nonce, "kill")?,
            target: target.clone(),
            signal: Signal::new(libc::SIGKILL)
                .map_err(|error| format!("failed to construct SIGKILL: {error}"))?,
            all: true,
        }),
    )
    .await?;
    let _ = call(
        "replacement Live wait after kill",
        client.wait(WaitRequest {
            target: target.clone(),
            timeout_ms: Some(20_000),
        }),
    )
    .await?;
    call(
        "replacement Live force delete",
        client.delete(DeleteRequest {
            context: operation(&prepared.nonce, "delete")?,
            target: target.clone(),
            mode: DeleteMode::Force,
        }),
    )
    .await?;
    drop(client);
    if !replacement.terminate().await? {
        return Err("replacement Host Service did not shut down cleanly".to_string());
    }
    Ok(())
}

async fn prove_retained_exec_io_before_kill(
    prepared: &PreparedRun,
    client: &RuntimeClient,
    target: &ContainerTarget,
    evidence: &mut super::report::LinuxNativeLiveRecoveryEvidence,
) -> Result<(), String> {
    let process_id = ProcessId::new(format!("live-io-{}", prepared.nonce))
        .map_err(|error| format!("failed to construct Live retained-exec process ID: {error}"))?;
    let process = retained_echo_process()?;
    let io = ProcessIo {
        stdin: IoMode::Pipe,
        stdout: IoMode::Capture,
        stderr: IoMode::Capture,
        terminal_size: None,
    };
    let process_target = ProcessTarget {
        container: target.clone(),
        process_id: process_id.clone(),
    };
    call(
        "Live retained exec",
        client.exec(ExecRequest {
            context: operation(&prepared.nonce, "exec-io")?,
            container: target.clone(),
            process_id: process_id.clone(),
            process,
            io,
        }),
    )
    .await?;
    evidence.retained_exec_process_id = Some(process_id.as_str().to_string());

    // Wait for the shell readiness marker before the first stdin write.
    wait_for_captured_needle(client, &process_target, b"live-io-ready\n", 0).await?;
    let before = format!("before-{}\n", prepared.nonce);
    call(
        "Live retained write_stdin before Host SIGKILL",
        client.write_stdin(WriteStdinRequest {
            context: operation(&prepared.nonce, "stdin-before")?,
            process: process_target.clone(),
            data: before.into_bytes(),
        }),
    )
    .await?;
    let expected = format!("echo:before-{}\n", prepared.nonce);
    wait_for_captured_needle(client, &process_target, expected.as_bytes(), 0).await?;
    evidence.exec_io_before_kill = true;
    Ok(())
}

async fn prove_retained_exec_io_after_reattach(
    prepared: &PreparedRun,
    client: &RuntimeClient,
    target: &ContainerTarget,
    evidence: &mut super::report::LinuxNativeLiveRecoveryEvidence,
) -> Result<(), String> {
    let process_id = evidence
        .retained_exec_process_id
        .as_deref()
        .ok_or_else(|| "retained exec process ID missing before replacement I/O".to_string())?;
    let process_id = ProcessId::new(process_id.to_string())
        .map_err(|error| format!("invalid retained exec process ID: {error}"))?;
    let process_target = ProcessTarget {
        container: target.clone(),
        process_id,
    };
    let after = format!("after-{}\n", prepared.nonce);
    call(
        "Live retained write_stdin after Host reattach",
        client.write_stdin(WriteStdinRequest {
            context: operation(&prepared.nonce, "stdin-after")?,
            process: process_target.clone(),
            data: after.into_bytes(),
        }),
    )
    .await?;
    evidence.write_stdin_after_reattach = true;
    let expected = format!("echo:after-{}\n", prepared.nonce);
    wait_for_captured_needle(client, &process_target, expected.as_bytes(), 0).await?;
    evidence.read_output_after_reattach = true;
    evidence.retained_exec_io_proven = evidence.exec_io_before_kill
        && evidence.write_stdin_after_reattach
        && evidence.read_output_after_reattach
        && evidence
            .retained_exec_process_id
            .as_deref()
            .is_some_and(|id| !id.is_empty());
    if !evidence.retained_exec_io_proven {
        return Err("Live retained exec I/O evidence failed its completeness audit".to_string());
    }
    Ok(())
}

async fn prove_new_exec_io_after_reattach(
    prepared: &PreparedRun,
    client: &RuntimeClient,
    target: &ContainerTarget,
    evidence: &mut super::report::LinuxNativeLiveRecoveryEvidence,
) -> Result<(), String> {
    let process_id = ProcessId::new(format!("live-new-{}", prepared.nonce))
        .map_err(|error| format!("failed to construct Live new-exec process ID: {error}"))?;
    let process = retained_echo_process()?;
    let io = ProcessIo {
        stdin: IoMode::Pipe,
        stdout: IoMode::Capture,
        stderr: IoMode::Capture,
        terminal_size: None,
    };
    let process_target = ProcessTarget {
        container: target.clone(),
        process_id: process_id.clone(),
    };
    call(
        "Live new exec after Host reattach",
        client.exec(ExecRequest {
            context: operation(&prepared.nonce, "exec-new")?,
            container: target.clone(),
            process_id: process_id.clone(),
            process,
            io,
        }),
    )
    .await?;
    evidence.new_exec_process_id = Some(process_id.as_str().to_string());

    wait_for_captured_needle(client, &process_target, b"live-io-ready\n", 0).await?;
    let payload = format!("new-{}\n", prepared.nonce);
    call(
        "Live new write_stdin after Host reattach",
        client.write_stdin(WriteStdinRequest {
            context: operation(&prepared.nonce, "stdin-new")?,
            process: process_target.clone(),
            data: payload.into_bytes(),
        }),
    )
    .await?;
    let expected = format!("echo:new-{}\n", prepared.nonce);
    wait_for_captured_needle(client, &process_target, expected.as_bytes(), 0).await?;
    evidence.new_exec_io_after_reattach_proven = evidence
        .new_exec_process_id
        .as_deref()
        .is_some_and(|id| !id.is_empty());
    if !evidence.new_exec_io_after_reattach_proven {
        return Err("Live new exec I/O evidence failed its completeness audit".to_string());
    }
    Ok(())
}

async fn prove_retained_filesystem_before_kill(
    prepared: &PreparedRun,
    client: &RuntimeClient,
    target: &ContainerTarget,
    evidence: &mut super::report::LinuxNativeLiveRecoveryEvidence,
) -> Result<(), String> {
    let path = retained_filesystem_path(&prepared.nonce);
    let expected_payload = retained_filesystem_payload(&prepared.nonce);
    let encoded_payload = STANDARD.encode(&expected_payload);
    let uploaded = call(
        "Live retained file upload before Host SIGKILL",
        client.file(FileRequest {
            target: target.clone(),
            op: FileOp::Upload,
            path,
            data: Some(encoded_payload),
            user: None,
            context: Some(operation(&prepared.nonce, "file-upload")?),
        }),
    )
    .await?;
    if uploaded.size != expected_payload.len() as u64 {
        return Err(format!(
            "Live retained file upload size mismatch: got {} expected {}",
            uploaded.size,
            expected_payload.len()
        ));
    }
    evidence.file_upload_before_kill = true;
    Ok(())
}

async fn prove_retained_filesystem_after_reattach(
    prepared: &PreparedRun,
    client: &RuntimeClient,
    target: &ContainerTarget,
    evidence: &mut super::report::LinuxNativeLiveRecoveryEvidence,
) -> Result<(), String> {
    let path = retained_filesystem_path(&prepared.nonce);
    let expected_payload = retained_filesystem_payload(&prepared.nonce);
    let downloaded = call(
        "Live retained file download after Host reattach",
        client.file(FileRequest {
            target: target.clone(),
            op: FileOp::Download,
            path,
            data: None,
            user: None,
            // Downloads are read-only: no mutation context (same as KVM Live).
            context: None,
        }),
    )
    .await?;
    let decoded = downloaded
        .data
        .as_deref()
        .map(|value| STANDARD.decode(value))
        .transpose()
        .map_err(|error| format!("Live retained file download was not base64: {error}"))?
        .ok_or_else(|| "Live retained file download omitted payload data".to_string())?;
    if decoded != expected_payload {
        return Err(
            "Live retained file download did not match the pre-SIGKILL upload payload".to_string(),
        );
    }
    if downloaded.size != expected_payload.len() as u64 {
        return Err(format!(
            "Live retained file download size mismatch: got {} expected {}",
            downloaded.size,
            expected_payload.len()
        ));
    }
    evidence.file_download_after_reattach = true;
    evidence.retained_filesystem_proven = evidence.file_upload_before_kill
        && evidence.file_download_after_reattach
        && evidence.replacement_state_running
        && evidence.init_survived_host_sigkill;
    if !evidence.retained_filesystem_proven {
        return Err(
            "Live retained filesystem evidence failed its completeness audit".to_string(),
        );
    }
    Ok(())
}

async fn emergency_cleanup(replacement: &mut HostServiceProcess, target: &ContainerTarget) {
    let Ok(client) = replacement.connect().await else {
        return;
    };
    let nonce = target.id.as_str();
    if let Ok(signal) = Signal::new(libc::SIGKILL) {
        if let Ok(context) = operation(nonce, "emergency-kill") {
            let _ = call(
                "emergency kill",
                client.kill(KillRequest {
                    context,
                    target: target.clone(),
                    signal,
                    all: true,
                }),
            )
            .await;
        }
    }
    if let Ok(context) = operation(nonce, "emergency-delete") {
        let _ = call(
            "emergency delete",
            client.delete(DeleteRequest {
                context,
                target: target.clone(),
                mode: DeleteMode::Force,
            }),
        )
        .await;
    }
}

fn retained_filesystem_path(nonce: &str) -> String {
    format!("/tmp/.a3s-oci-native-live-fs-{nonce}.bin")
}

fn retained_filesystem_payload(nonce: &str) -> Vec<u8> {
    format!("a3s-oci-native-live-fs-{nonce}\0binary\n").into_bytes()
}

fn retained_echo_process() -> Result<Process, String> {
    // Pipe stdin + Capture stdout. Stay alive after stdin EOF so Host death
    // alone does not exit the shell (parity with KVM Live retained exec).
    let command = "printf 'live-io-ready\\n'; while true; do if IFS= read -r line; then printf 'echo:%s\\n' \"$line\"; else while true; do /bin/busybox sleep 3600 || sleep 3600; done; fi; done";
    serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", command],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .map_err(|error| format!("failed to construct Live retained-exec process: {error}"))
}

async fn wait_for_captured_needle(
    client: &RuntimeClient,
    process: &ProcessTarget,
    needle: &[u8],
    mut after_sequence: u64,
) -> Result<(), String> {
    let deadline = Instant::now() + LIVE_IO_TIMEOUT;
    let mut buffer = Vec::new();
    while Instant::now() < deadline {
        let chunks = call(
            "Live retained read_output",
            client.read_output(ReadOutputRequest {
                process: process.clone(),
                after_sequence,
                max_bytes: 4096,
                wait_timeout_ms: Some(250),
            }),
        )
        .await?;
        for chunk in chunks {
            if chunk.stream != OutputStream::Stdout {
                continue;
            }
            after_sequence = after_sequence.max(chunk.sequence);
            buffer.extend_from_slice(&chunk.data);
        }
        if buffer.windows(needle.len()).any(|window| window == needle) {
            return Ok(());
        }
        sleep(POLL_INTERVAL).await;
    }
    Err(format!(
        "Live retained Capture stdout did not observe {:?} within {:?}",
        String::from_utf8_lossy(needle),
        LIVE_IO_TIMEOUT
    ))
}

fn operation(nonce: &str, suffix: &str) -> Result<OperationContext, String> {
    OperationId::new(format!("nlr-{nonce}-{suffix}"))
        .map(OperationContext::new)
        .map_err(|error| format!("failed to construct Native Live operation ID: {error}"))
}

async fn call<T>(
    label: &str,
    future: impl Future<Output = a3s_oci_sdk::Result<T>>,
) -> Result<T, String> {
    match timeout(CALL_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(format!(
            "{label} failed with {:?}: {}",
            error.code, error.message
        )),
        Err(_) => Err(format!("{label} timed out")),
    }
}

async fn canonical_plain_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{label} is not a plain directory: {}",
            path.display()
        ));
    }
    let canonical = tokio::fs::canonicalize(path)
        .await
        .map_err(|error| format!("failed to resolve {label} {}: {error}", path.display()))?;
    if !path.is_absolute() {
        return Err(format!(
            "{label} must be an absolute path: {}",
            path.display()
        ));
    }
    Ok(canonical)
}

fn canonical_plain_file(path: &Path, label: &str, executable: bool) -> Result<PathBuf, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is not a plain file: {}", path.display()));
    }
    if executable && metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!("{label} is not executable: {}", path.display()));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| format!("failed to resolve {label} {}: {error}", path.display()))?;
    if !path.is_absolute() {
        return Err(format!(
            "{label} must be an absolute path: {}",
            path.display()
        ));
    }
    Ok(canonical)
}

fn create_private_directory(path: &Path) -> Result<(), String> {
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|error| format!("failed to create {}: {error}", path.display()))
}

fn unique_nonce() -> Result<String, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?
        .as_nanos();
    Ok(format!("{}-{nanos}", std::process::id()))
}
