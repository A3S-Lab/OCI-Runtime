use std::path::{Path, PathBuf};
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, Process};
use a3s_oci_sdk::{
    ContainerId, ContainerTarget, CreateRequest, DeleteMode, DeleteRequest, ErrorCode, ExecRequest,
    FileOp, FileRequest, IoMode, IsolationRequest, KillRequest, ListRequest, OutputStream,
    ProcessId, ProcessIo, ProcessTarget, ProcessesRequest, ReadOutputRequest, Signal, StartRequest,
    StateRequest, WaitRequest, WriteStdinRequest,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use tokio::time::{sleep, Instant};

use crate::kvm_live_session_binding::{
    authenticate_live, load_binding, KvmLiveSessionBinding, KVM_LIVE_SESSION_BINDING_FILE,
};
use crate::linux_kvm_recovery_smoke::bundle;
use crate::linux_kvm_recovery_smoke::host::{
    self, HostServiceKind, HostServiceProcess, HostServiceSpawnOptions,
};
use crate::linux_kvm_recovery_smoke::prepare::{
    persist_report, PreparedQualification, QualificationInputs,
};
use crate::linux_kvm_recovery_smoke::qualification::{
    call, operation, verify_qualification_scope, wait_for_marker, wait_for_vm_descendants,
};
use crate::linux_kvm_recovery_smoke::LinuxProcessIdentity;

use super::report::LinuxKvmLiveRecoverySmokeReport;

const LIVE_TIMEOUT: Duration = Duration::from_secs(25);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const SHORT_WAIT_MS: u64 = 500;

/// Exact artifacts and private parent for one Live KVM Host reopen run.
#[derive(Debug, Clone)]
pub struct LinuxKvmLiveRecoverySmokeConfig {
    pub host_service_executable: PathBuf,
    pub shim: PathBuf,
    pub system_image_manifest: PathBuf,
    pub bundle: PathBuf,
    pub work_parent: PathBuf,
    pub source_revision: Option<String>,
}

const DURABLE_SPAWN: HostServiceSpawnOptions = HostServiceSpawnOptions {
    durable_session_owner: true,
};

/// Kill one Live KVM Host Service; prove Guest survives and replacement reattaches Running.
pub async fn run(config: LinuxKvmLiveRecoverySmokeConfig) -> LinuxKvmLiveRecoverySmokeReport {
    let architecture = std::env::consts::ARCH.to_string();
    let mut report =
        LinuxKvmLiveRecoverySmokeReport::initial(config.work_parent.clone(), architecture);
    report.recovery.session_owner_mode_durable = true;
    let prepared = match PreparedQualification::open(
        QualificationInputs {
            host_service_executable: config.host_service_executable,
            shim: config.shim,
            system_image_manifest: config.system_image_manifest,
            bundle: config.bundle,
            work_parent: config.work_parent,
            source_revision: config.source_revision,
        },
        "klr",
        "Linux KVM Live recovery qualification endpoint",
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(reason) => {
            report.reason = Some(reason);
            return report;
        }
    };
    report.evidence_root = prepared.evidence_root.clone();
    report.artifacts = prepared.artifacts.clone();
    if let Err(reason) = persist_report(&report.evidence_root, &report, "KVM Live recovery report") {
        report.reason = Some(reason);
        return report;
    }

    if let Err(reason) = run_live_recovery(&prepared, &mut report.recovery).await {
        report.recovery.reason = Some(reason.clone());
        report.reason = Some(reason);
        let _ = persist_report(&report.evidence_root, &report, "KVM Live recovery report");
        return report;
    }
    if !report.recovery.is_success() {
        let reason = "Linux KVM Live recovery evidence failed its completeness audit".to_string();
        report.recovery.reason = Some(reason.clone());
        report.reason = Some(reason);
        let _ = persist_report(&report.evidence_root, &report, "KVM Live recovery report");
        return report;
    }
    report.status = a3s_oci_core::CapabilityStatus::Available;
    report.case_count = 1;
    if !report.is_success() {
        report.status = a3s_oci_core::CapabilityStatus::Unavailable;
        report.case_count = 0;
        report.reason = Some("Linux KVM Live recovery report failed its final audit".to_string());
    }
    if let Err(reason) = persist_report(&report.evidence_root, &report, "KVM Live recovery report") {
        report.status = a3s_oci_core::CapabilityStatus::Unavailable;
        report.case_count = 0;
        report.reason = Some(reason);
    }
    report
}

async fn run_live_recovery(
    prepared: &PreparedQualification,
    evidence: &mut super::report::LinuxKvmLiveRecoveryEvidence,
) -> Result<(), String> {
    let runtime_root = prepared.service_root.join("runtime");
    let mut first = HostServiceProcess::spawn_with_options(
        HostServiceKind::Recovery,
        &prepared.executable,
        &prepared.service_root,
        &prepared.shim,
        &prepared.manifest,
        &prepared.evidence_root.join("first.stdout.log"),
        &prepared.evidence_root.join("first.stderr.log"),
        DURABLE_SPAWN,
    )
    .await?;
    let first_result = run_first_owner(prepared, &runtime_root, &first, evidence).await;
    let durable_endpoint = match first_result {
        Ok(path) => path,
        Err(reason) => {
            emergency_reap_survivors(evidence).await;
            first.emergency_stop().await;
            return Err(reason);
        }
    };

    let first_socket = host::socket_identity(first.socket_path())?;
    first.sigkill().await?;
    evidence.host_service_sigkill_delivered = true;
    evidence.first_host_service_reaped = true;
    evidence.stale_socket_retained = host::socket_identity(first.socket_path())? == first_socket;
    if !evidence.stale_socket_retained {
        emergency_reap_survivors(evidence).await;
        return Err("SIGKILLed Host Service did not leave its exact stale socket".to_string());
    }

    // Opposite of stopped-only: Guest / session-owner must still be live.
    sleep(Duration::from_millis(200)).await;
    evidence.live_vm_processes_reaped =
        !host::processes_still_live(&evidence.live_vm_processes)?;
    evidence.guest_survived_host_sigkill = host::processes_still_live(&evidence.live_vm_processes)?;
    if evidence.live_vm_processes_reaped || !evidence.guest_survived_host_sigkill {
        return Err(
            "Live session-owner/shim were reaped after Host SIGKILL (expected survival)".to_string(),
        );
    }

    let binding = load_live_binding(&runtime_root, evidence)?;
    authenticate_live(&binding)
        .map_err(|error| format!("Live binding failed authentication after Host SIGKILL: {error}"))?;
    evidence.live_binding_authenticated_after_kill = true;
    retain_binding_identities(evidence, &binding)?;
    if durable_endpoint_dir(&binding) != durable_endpoint {
        return Err(
            "Live binding pipe directory drifted from the retained durable guest endpoint"
                .to_string(),
        );
    }

    let mut replacement = HostServiceProcess::spawn_with_options(
        HostServiceKind::Recovery,
        &prepared.executable,
        &prepared.service_root,
        &prepared.shim,
        &prepared.manifest,
        &prepared.evidence_root.join("replacement.stdout.log"),
        &prepared.evidence_root.join("replacement.stderr.log"),
        DURABLE_SPAWN,
    )
    .await?;
    let replacement_result =
        run_replacement(prepared, &runtime_root, &durable_endpoint, &mut replacement, evidence)
            .await;
    if replacement_result.is_err() {
        emergency_reap_survivors(evidence).await;
        replacement.emergency_stop().await;
    }
    replacement_result
}

async fn run_first_owner(
    prepared: &PreparedQualification,
    runtime_root: &Path,
    first: &HostServiceProcess,
    evidence: &mut super::report::LinuxKvmLiveRecoveryEvidence,
) -> Result<PathBuf, String> {
    let identity = first.identity()?;
    evidence.first_host_service = Some(identity);
    evidence.first_socket_peer = Some(first.socket_peer()?.clone());
    let client = first.connect().await?;
    verify_qualification_scope(
        &client,
        crate::kvm_driver::LINUX_KVM_RECOVERY_QUALIFICATION_SCOPE,
    )
    .await?;
    evidence.qualification_scope_verified = true;
    let id = ContainerId::new(format!("kvm-lr-{}", prepared.nonce))
        .map_err(|error| format!("failed to construct Live recovery container ID: {error}"))?;
    let context = operation("kvm-lr", &prepared.nonce, "create")?;
    let staged = bundle::stage(&prepared.bundle, runtime_root, &id, &context.operation_id).await?;
    let create = CreateRequest {
        context,
        id: id.clone(),
        bundle: staged.bundle,
        isolation: IsolationRequest::DedicatedVm,
        attachments: staged.attachments,
    };
    let created = call("KVM Live recovery create", client.create(create.clone())).await?;
    let replayed = call("KVM Live recovery replayed create", client.create(create)).await?;
    evidence.create_replayed = created == replayed && !staged.directory.exists();
    if !evidence.create_replayed || *created.state.status() != ContainerState::Created {
        return Err("KVM Live recovery Create did not replay the exact created state".to_string());
    }
    let target = ContainerTarget::exact(id, created.generation);
    evidence.target = Some(target.clone());
    evidence.created_config_digest = Some(created.config_digest);
    let started = call(
        "KVM Live recovery start",
        client.start(StartRequest {
            context: operation("kvm-lr", &prepared.nonce, "start")?,
            target: target.clone(),
        }),
    )
    .await?;
    evidence.start_returned_running = *started.state.status() == ContainerState::Running;
    if !evidence.start_returned_running {
        return Err("KVM Live recovery Start did not return running state".to_string());
    }
    evidence.init_pid_before = started
        .state
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0);
    if evidence.init_pid_before.is_none() {
        return Err("KVM Live recovery Start did not retain a live init PID".to_string());
    }
    wait_for_marker(&client, &target).await?;
    evidence.init_marker_verified = true;
    evidence.live_vm_processes = wait_for_vm_descendants(first.pid()?).await?;
    let binding = wait_for_live_binding(runtime_root).await?;
    evidence.live_binding_published = true;
    retain_binding_identities(evidence, &binding)?;
    evidence.durable_guest_endpoint_retained = durable_endpoint_live(&binding)?;
    if !evidence.durable_guest_endpoint_retained {
        return Err(
            "Live durable guest endpoint was not retained under /tmp/<pipe> from the binding"
                .to_string(),
        );
    }
    evidence.durable_pipe_name = Some(binding.pipe_name.clone());
    prove_retained_exec_io_before_kill(prepared, &client, &target, evidence).await?;
    prove_retained_filesystem_before_kill(prepared, &client, &target, evidence).await?;
    let durable_endpoint = durable_endpoint_dir(&binding);
    drop(client);
    Ok(durable_endpoint)
}

async fn run_replacement(
    prepared: &PreparedQualification,
    runtime_root: &Path,
    durable_endpoint: &Path,
    replacement: &mut HostServiceProcess,
    evidence: &mut super::report::LinuxKvmLiveRecoveryEvidence,
) -> Result<(), String> {
    let identity = replacement.identity()?;
    evidence.replacement_host_service = Some(identity);
    evidence.replacement_socket_peer = Some(replacement.socket_peer()?.clone());
    evidence.replacement_socket_new_owner =
        evidence.first_socket_peer != evidence.replacement_socket_peer;
    if !evidence.replacement_socket_new_owner {
        return Err("replacement socket kept the first owner identity".to_string());
    }
    let client = replacement.connect().await?;
    evidence.replacement_connected = true;
    verify_qualification_scope(
        &client,
        crate::kvm_driver::LINUX_KVM_RECOVERY_QUALIFICATION_SCOPE,
    )
    .await?;
    let target = evidence
        .target
        .clone()
        .ok_or_else(|| "Live recovery target disappeared before replacement".to_string())?;
    let recovered = call(
        "replacement KVM Live state",
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await?;
    evidence.replacement_state_running = *recovered.state.status() == ContainerState::Running
        && recovered.generation == target.generation.expect("target is exact")
        && evidence
            .created_config_digest
            .as_deref()
            .is_some_and(|digest| recovered.config_digest == digest)
        && recovered.state.pid().is_some();
    evidence.init_pid_after = recovered
        .state
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0);
    evidence.init_identity_unchanged = evidence.init_pid_before == evidence.init_pid_after
        && evidence.init_pid_before.is_some()
        && host::processes_still_live(&[
            evidence
                .session_owner_identity
                .clone()
                .ok_or_else(|| "session-owner identity missing".to_string())?,
            evidence
                .shim_identity
                .clone()
                .ok_or_else(|| "shim identity missing".to_string())?,
        ])?;
    if !evidence.replacement_state_running || !evidence.init_identity_unchanged {
        return Err(
            "replacement did not reattach Running with continuous init/session-owner identity"
                .to_string(),
        );
    }

    let processes = call(
        "replacement KVM Live process inventory",
        client.processes(ProcessesRequest {
            target: target.clone(),
        }),
    )
    .await?;
    evidence.process_inventory_nonempty = !processes.is_empty();
    if !evidence.process_inventory_nonempty {
        return Err("replacement Live process inventory was empty".to_string());
    }
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

    prove_retained_exec_io_after_reattach(prepared, &client, &target, evidence).await?;
    prove_retained_filesystem_after_reattach(prepared, &client, &target, evidence).await?;

    evidence.no_invented_exit_status =
        assert_no_invented_exit(&client, &target, runtime_root).await?;
    if !evidence.no_invented_exit_status {
        return Err("replacement invented an exit status for a still-running Guest".to_string());
    }

    call(
        "replacement Live kill",
        client.kill(KillRequest {
            context: operation("kvm-lr", &prepared.nonce, "kill")?,
            target: target.clone(),
            signal: Signal::new(libc::SIGKILL)
                .map_err(|error| format!("failed to construct SIGKILL: {error}"))?,
            all: true,
        }),
    )
    .await?;
    let status = call(
        "replacement Live wait after kill",
        client.wait(WaitRequest {
            target: target.clone(),
            timeout_ms: Some(20_000),
        }),
    )
    .await?;
    let _ = status;
    call(
        "replacement Live stopped-only delete",
        client.delete(DeleteRequest {
            context: operation("kvm-lr", &prepared.nonce, "delete")?,
            target: target.clone(),
            mode: DeleteMode::StoppedOnly,
        }),
    )
    .await?;
    evidence.force_cleanup_succeeded = !prepared
        .service_root
        .join("state/containers")
        .join(target.id.as_str())
        .exists()
        && call(
            "replacement list after Live delete",
            client.list(ListRequest::default()),
        )
        .await?
        .is_empty();
    if !evidence.force_cleanup_succeeded {
        return Err("replacement Live delete did not remove durable state".to_string());
    }
    drop(client);
    evidence.replacement_exit_success = replacement.terminate().await?;
    evidence.replacement_socket_removed = !prepared.service_root.join("runtime.sock").exists();
    evidence.durable_guest_endpoint_cleaned =
        wait_for_durable_endpoint_removed(durable_endpoint).await?;
    evidence.service_restart_recovered = evidence.replacement_exit_success
        && evidence.replacement_socket_removed
        && evidence.durable_guest_endpoint_cleaned
        && evidence.replacement_state_running
        && evidence.init_identity_unchanged
        && evidence.no_invented_exit_status;
    if !evidence.service_restart_recovered {
        return Err("replacement Host Service did not shut down cleanly after Live reopen".to_string());
    }
    Ok(())
}

async fn prove_retained_exec_io_before_kill(
    prepared: &PreparedQualification,
    client: &a3s_oci_sdk::RuntimeClient,
    target: &ContainerTarget,
    evidence: &mut super::report::LinuxKvmLiveRecoveryEvidence,
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
            context: operation("kvm-lr", &prepared.nonce, "exec-io")?,
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
            context: operation("kvm-lr", &prepared.nonce, "stdin-before")?,
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
    prepared: &PreparedQualification,
    client: &a3s_oci_sdk::RuntimeClient,
    target: &ContainerTarget,
    evidence: &mut super::report::LinuxKvmLiveRecoveryEvidence,
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
            context: operation("kvm-lr", &prepared.nonce, "stdin-after")?,
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

async fn prove_retained_filesystem_before_kill(
    prepared: &PreparedQualification,
    client: &a3s_oci_sdk::RuntimeClient,
    target: &ContainerTarget,
    evidence: &mut super::report::LinuxKvmLiveRecoveryEvidence,
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
            context: Some(operation("kvm-lr", &prepared.nonce, "file-upload")?),
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
    prepared: &PreparedQualification,
    client: &a3s_oci_sdk::RuntimeClient,
    target: &ContainerTarget,
    evidence: &mut super::report::LinuxKvmLiveRecoveryEvidence,
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
        && evidence.init_identity_unchanged;
    if !evidence.retained_filesystem_proven {
        return Err(
            "Live retained filesystem evidence failed its completeness audit".to_string(),
        );
    }
    Ok(())
}

fn retained_filesystem_path(nonce: &str) -> String {
    format!("/tmp/.a3s-oci-live-fs-{nonce}.bin")
}

fn retained_filesystem_payload(nonce: &str) -> Vec<u8> {
    format!("a3s-oci-live-fs-{nonce}\0binary\n").into_bytes()
}

fn retained_echo_process() -> Result<Process, String> {
    // Pipe stdin + Capture stdout. Guest Pipe stdout is unsupported on KVM;
    // Capture proves byte continuity across Host SIGKILL on the same process ID.
    // Stay alive after stdin EOF so Host death alone does not exit the shell.
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
    client: &a3s_oci_sdk::RuntimeClient,
    process: &ProcessTarget,
    needle: &[u8],
    mut after_sequence: u64,
) -> Result<(), String> {
    let deadline = Instant::now() + LIVE_TIMEOUT;
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
        LIVE_TIMEOUT
    ))
}

async fn assert_no_invented_exit(
    client: &a3s_oci_sdk::RuntimeClient,
    target: &ContainerTarget,
    runtime_root: &Path,
) -> Result<bool, String> {
    let wait = WaitRequest {
        target: target.clone(),
        timeout_ms: Some(SHORT_WAIT_MS),
    };
    match tokio::time::timeout(Duration::from_secs(5), client.wait(wait)).await {
        Ok(Ok(_status)) => {
            // A completed wait while state is Running invents terminal evidence.
            Ok(false)
        }
        Ok(Err(error)) => {
            let acceptable = matches!(
                error.code,
                ErrorCode::DeadlineExceeded | ErrorCode::Unavailable
            ) || error.message.to_ascii_lowercase().contains("timeout")
                || error.message.to_ascii_lowercase().contains("deadline");
            if !acceptable {
                return Err(format!(
                    "short Live wait failed unexpectedly with {:?}: {}",
                    error.code, error.message
                ));
            }
            Ok(!sigkill_recovery_report_present(runtime_root, target)?)
        }
        Err(_) => Ok(!sigkill_recovery_report_present(runtime_root, target)?),
    }
}

fn durable_endpoint_dir(binding: &KvmLiveSessionBinding) -> PathBuf {
    PathBuf::from(crate::agent_socket::PRIVATE_TMP_ROOT).join(&binding.pipe_name)
}

fn durable_endpoint_live(binding: &KvmLiveSessionBinding) -> Result<bool, String> {
    let directory = durable_endpoint_dir(binding);
    let agent = directory.join("agent.sock");
    let host_control = PathBuf::from(&binding.host_control_socket);
    Ok(directory.is_dir()
        && agent.exists()
        && host_control.exists()
        && host_control.parent() == Some(directory.as_path()))
}

/// True when the retained Live pipe directory (and its sockets) are gone.
async fn wait_for_durable_endpoint_removed(endpoint: &Path) -> Result<bool, String> {
    let deadline = Instant::now() + LIVE_TIMEOUT;
    loop {
        let agent = endpoint.join("agent.sock");
        let host_control = endpoint.join(crate::kvm_live_session_binding::KVM_HOST_CONTROL_SOCKET_FILE);
        if !endpoint.exists() && !agent.exists() && !host_control.exists() {
            return Ok(true);
        }
        // Session-owner may unlink sockets before the empty directory is removed.
        if !agent.exists() && !host_control.exists() && endpoint.is_dir() {
            let _ = std::fs::remove_dir(endpoint);
            if !endpoint.exists() {
                return Ok(true);
            }
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(POLL_INTERVAL).await;
    }
}

fn sigkill_recovery_report_present(
    runtime_root: &Path,
    target: &ContainerTarget,
) -> Result<bool, String> {
    let generation = target
        .generation
        .ok_or_else(|| "Live recovery report check requires an exact generation".to_string())?;
    let path = runtime_root
        .join("recovery")
        .join(format!("{}-{}.json", target.id, generation.0));
    match std::fs::symlink_metadata(&path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("failed to inspect recovery report {}: {error}", path.display())),
    }
}

fn retain_binding_identities(
    evidence: &mut super::report::LinuxKvmLiveRecoveryEvidence,
    binding: &KvmLiveSessionBinding,
) -> Result<(), String> {
    let owner = identity_from_binding(
        binding.session_owner.pid,
        binding.session_owner.start_time_ticks,
        "session-owner",
    )?;
    let shim = identity_from_binding(
        binding.shim.pid,
        binding.shim.start_time_ticks,
        "shim",
    )?;
    if let Some(previous) = evidence.session_owner_identity.as_ref() {
        if previous.pid != owner.pid || previous.start_time_ticks != owner.start_time_ticks {
            return Err("Live binding session-owner identity drifted".to_string());
        }
    }
    if let Some(previous) = evidence.shim_identity.as_ref() {
        if previous.pid != shim.pid || previous.start_time_ticks != shim.start_time_ticks {
            return Err("Live binding shim identity drifted".to_string());
        }
    }
    evidence.session_owner_identity = Some(owner);
    evidence.shim_identity = Some(shim);
    Ok(())
}

fn identity_from_binding(
    pid: i32,
    start_time_ticks: u64,
    role: &str,
) -> Result<LinuxProcessIdentity, String> {
    let pid = u32::try_from(pid).map_err(|error| format!("{role} pid is invalid: {error}"))?;
    let inventory_path = PathBuf::from(format!("/proc/{pid}/stat"));
    let encoded = std::fs::read_to_string(&inventory_path)
        .map_err(|error| format!("failed to read {role} identity: {error}"))?;
    let open = encoded
        .find('(')
        .ok_or_else(|| format!("{role} stat has no command start"))?;
    let close = encoded
        .rfind(')')
        .ok_or_else(|| format!("{role} stat has no command end"))?;
    let command = encoded[open + 1..close].to_string();
    let fields = encoded[close + 1..].split_whitespace().collect::<Vec<_>>();
    if fields.len() <= 19 {
        return Err(format!("{role} stat is truncated"));
    }
    let parent_pid = fields[1]
        .parse::<u32>()
        .map_err(|error| format!("invalid {role} parent PID: {error}"))?;
    let process_group_id = fields[2]
        .parse::<u32>()
        .map_err(|error| format!("invalid {role} process group: {error}"))?;
    let observed_start = fields[19]
        .parse::<u64>()
        .map_err(|error| format!("invalid {role} start time: {error}"))?;
    if observed_start != start_time_ticks {
        return Err(format!(
            "{role} start-time drifted from binding ({start_time_ticks} vs {observed_start})"
        ));
    }
    Ok(LinuxProcessIdentity {
        pid,
        parent_pid,
        process_group_id,
        start_time_ticks,
        command,
    })
}

fn load_live_binding(
    runtime_root: &Path,
    evidence: &super::report::LinuxKvmLiveRecoveryEvidence,
) -> Result<KvmLiveSessionBinding, String> {
    let path = find_live_binding_path(runtime_root)?;
    let binding = load_binding(&path)
        .map_err(|error| format!("failed to load Live binding {}: {error}", path.display()))?;
    if let (Some(owner), Some(shim)) = (
        evidence.session_owner_identity.as_ref(),
        evidence.shim_identity.as_ref(),
    ) {
        if owner.pid as i32 != binding.session_owner.pid
            || owner.start_time_ticks != binding.session_owner.start_time_ticks
            || shim.pid as i32 != binding.shim.pid
            || shim.start_time_ticks != binding.shim.start_time_ticks
        {
            return Err("Live binding identities do not match retained session-owner/shim".to_string());
        }
    }
    Ok(binding)
}

async fn wait_for_live_binding(runtime_root: &Path) -> Result<KvmLiveSessionBinding, String> {
    let deadline = Instant::now() + LIVE_TIMEOUT;
    loop {
        if let Ok(path) = find_live_binding_path(runtime_root) {
            match load_binding(&path) {
                Ok(binding) => {
                    authenticate_live(&binding).map_err(|error| {
                        format!("published Live binding failed authentication: {error}")
                    })?;
                    return Ok(binding);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "failed to load published Live binding {}: {error}",
                        path.display()
                    ))
                }
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for published KVM Live session binding".to_string());
        }
        sleep(POLL_INTERVAL).await;
    }
}

fn find_live_binding_path(runtime_root: &Path) -> Result<PathBuf, String> {
    let shares = runtime_root.join("shares");
    let mut found = Vec::new();
    walk_for_binding(&shares, &mut found)?;
    match found.as_slice() {
        [path] => Ok(path.clone()),
        [] => Err(format!(
            "no {} under {}",
            KVM_LIVE_SESSION_BINDING_FILE,
            shares.display()
        )),
        _ => Err(format!(
            "multiple Live bindings under {}: {}",
            shares.display(),
            found.len()
        )),
    }
}

fn walk_for_binding(root: &Path, found: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "failed to enumerate {}: {error}",
                root.display()
            ))
        }
    };
    for entry in entries {
        let entry = entry.map_err(|error| format!("failed to inspect share entry: {error}"))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
        if file_type.is_dir() {
            walk_for_binding(&path, found)?;
        } else if entry.file_name() == KVM_LIVE_SESSION_BINDING_FILE {
            found.push(path);
        }
    }
    Ok(())
}

async fn emergency_reap_survivors(evidence: &super::report::LinuxKvmLiveRecoveryEvidence) {
    for process in &evidence.live_vm_processes {
        let Ok(pid) = libc::pid_t::try_from(process.pid) else {
            continue;
        };
        // SAFETY: best-effort cleanup of retained Live survivors after a failed gate.
        unsafe {
            let _ = libc::kill(pid, libc::SIGKILL);
        }
    }
    if let Some(owner) = evidence.session_owner_identity.as_ref() {
        if let Ok(pid) = libc::pid_t::try_from(owner.pid) {
            unsafe {
                let _ = libc::kill(pid, libc::SIGKILL);
            }
        }
    }
    let _ = host::wait_for_processes_reaped(&evidence.live_vm_processes).await;
}
