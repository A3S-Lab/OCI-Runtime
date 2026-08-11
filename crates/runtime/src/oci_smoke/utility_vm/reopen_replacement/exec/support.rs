use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{
    ContainerTarget, Error, ErrorCode, OciBundle, OperationId, ProcessId, ProcessIo, ProcessRecord,
    ProcessTarget, TerminalSize,
};
use tokio::time::{sleep, Instant};

use super::super::super::{path_exists, read_marker};
use super::super::delete_support::remove_marker_if_present;
use super::super::{
    append_failure, QualificationHvfDriver, FAULT_OPERATION, MARKER_POLL_INTERVAL,
    QUALIFICATION_TIMEOUT,
};
use crate::host_cleanup::MacosHostCleanupTracker;
use crate::marker::{exact_marker_state, ExactMarkerState};
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::OciVmOperationReopenReplacementReport;

const ORIGINAL_INIT_MARKER_WRITE: &str =
    "printf 'a3s-oci-create-start-user-time-v1\\n' > /.a3s-oci-create-start-smoke;";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::oci_smoke::utility_vm::reopen_replacement) enum ExecJournalStatus {
    Prepared,
    Succeeded(ProcessRecord),
}

pub(in crate::oci_smoke::utility_vm::reopen_replacement) fn operation_id(
    value: &str,
) -> std::result::Result<OperationId, String> {
    OperationId::new(value)
        .map_err(|error| format!("failed to construct Exec qualification operation ID: {error}"))
}

pub(in crate::oci_smoke::utility_vm::reopen_replacement) fn nonce_bound_bundle(
    bundle: OciBundle,
    nonce: &str,
) -> std::result::Result<OciBundle, String> {
    if nonce.is_empty()
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("Exec qualification nonce contains unsafe shell characters".to_string());
    }
    let mut config: serde_json::Value = serde_json::from_str(bundle.config_json())
        .map_err(|error| format!("failed to decode Exec qualification bundle: {error}"))?;
    let command = config
        .pointer_mut("/process/args/2")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            "Exec qualification bundle must use the expected /bin/sh -c init command".to_string()
        })?
        .to_string();
    if command.matches(ORIGINAL_INIT_MARKER_WRITE).count() != 1 {
        return Err(
            "Exec qualification bundle does not contain the exact init marker write".to_string(),
        );
    }
    let replacement =
        format!("printf 'a3s-oci-exec-init-{nonce}\\n' > /.a3s-oci-create-start-smoke;");
    config["process"]["args"][2] =
        serde_json::Value::String(command.replacen(ORIGINAL_INIT_MARKER_WRITE, &replacement, 1));
    let encoded = serde_json::to_string_pretty(&config)
        .map_err(|error| format!("failed to encode nonce-bound Exec bundle: {error}"))?;
    OciBundle::from_json(bundle.directory().to_path_buf(), encoded)
        .map_err(|error| format!("failed to validate nonce-bound Exec bundle: {error}"))
}

pub(in crate::oci_smoke::utility_vm::reopen_replacement) fn exec_process(
    nonce: &str,
) -> std::result::Result<(ProcessId, Process, ProcessIo), String> {
    let process_id = ProcessId::new(format!("worker-{nonce}"))
        .map_err(|error| format!("failed to construct Exec process ID: {error}"))?;
    let command = format!(
        "set -eu; printf 'a3s-oci-exec-process-{nonce}\\n' > /{}; while :; do /bin/busybox sleep 1; done",
        super::EXEC_MARKER_NAME
    );
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": true,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", command],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .map_err(|error| format!("failed to construct terminal Exec process: {error}"))?;
    let io = ProcessIo {
        stdin: a3s_oci_sdk::IoMode::Terminal,
        stdout: a3s_oci_sdk::IoMode::Terminal,
        stderr: a3s_oci_sdk::IoMode::Terminal,
        terminal_size: Some(TerminalSize {
            width: 80,
            height: 24,
        }),
    };
    Ok((process_id, process, io))
}

pub(in crate::oci_smoke::utility_vm::reopen_replacement) async fn wait_for_exact_marker(
    marker: &Path,
    expected: &[u8],
    label: &str,
) -> std::result::Result<(), String> {
    let deadline = Instant::now() + QUALIFICATION_TIMEOUT;
    loop {
        if path_exists(marker).await? {
            let contents = read_marker(marker).await?;
            match exact_marker_state(&contents, expected) {
                ExactMarkerState::Complete => return Ok(()),
                ExactMarkerState::InProgress => {}
                ExactMarkerState::Mismatch => {
                    return Err(format!("{label} produced unexpected marker contents"));
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{label} did not produce its marker within {} seconds",
                QUALIFICATION_TIMEOUT.as_secs()
            ));
        }
        sleep(MARKER_POLL_INTERVAL).await;
    }
}

pub(in crate::oci_smoke::utility_vm::reopen_replacement) async fn verify_first_exec_marker(
    marker: &Path,
    expected: &[u8],
    stage: AgentTransportOperationStage,
) -> std::result::Result<(), String> {
    let marker_exists = path_exists(marker).await?;
    if !dispatch_may_have_reached(stage) && marker_exists {
        Err(format!(
            "{} produced an Exec marker before Guest dispatch",
            stage.as_str()
        ))
    } else if marker_exists {
        // Exec success proves that the payload crossed execve, not that the
        // scheduler ran its first userspace instruction before owner-death
        // cleanup. A marker is therefore optional in this first VM, but any
        // observed bytes remain exact nonce-bound evidence.
        wait_for_exact_marker(marker, expected, "first-owner Exec").await
    } else {
        Ok(())
    }
}

pub(in crate::oci_smoke::utility_vm::reopen_replacement) const fn dispatch_may_have_reached(
    stage: AgentTransportOperationStage,
) -> bool {
    matches!(
        stage,
        AgentTransportOperationStage::HostAfterRequestWrite
            | AgentTransportOperationStage::HostBeforeResponseRead
            | AgentTransportOperationStage::HostAfterResponseRead
            | AgentTransportOperationStage::GuestAfterDispatch
            | AgentTransportOperationStage::GuestBeforeResponseWrite
            | AgentTransportOperationStage::GuestAfterResponseWrite
    )
}

pub(in crate::oci_smoke::utility_vm::reopen_replacement) async fn reset_marker(
    marker: &Path,
) -> std::result::Result<(), String> {
    remove_marker_if_present(marker).await?;
    if path_exists(marker).await? {
        return Err(format!(
            "first-owner marker remained before replacement: {}",
            marker.display()
        ));
    }
    Ok(())
}

pub(in crate::oci_smoke::utility_vm::reopen_replacement) fn record_interruption(
    report: &mut OciVmOperationReopenReplacementReport,
    error: Error,
    stage: AgentTransportOperationStage,
) -> std::result::Result<(), String> {
    report.first_operation_error_code = Some(error.code);
    report.first_operation_error_operation = error.operation.clone();
    report.first_operation_error_retryable = error.retryable;
    let expected_operation = if stage.is_guest() {
        error
            .operation
            .as_deref()
            .is_some_and(is_retryable_disconnect_operation)
    } else {
        error.operation.as_deref() == Some(FAULT_OPERATION)
    };
    if error.code == ErrorCode::Unavailable && error.retryable && expected_operation {
        Ok(())
    } else {
        Err(format!(
            "first owner returned an unexpected Exec transport error at {}: {error}",
            stage.as_str()
        ))
    }
}

pub(in crate::oci_smoke::utility_vm::reopen_replacement) async fn shutdown_setup_failure<T>(
    service: crate::HostRuntimeService,
    driver: Arc<QualificationHvfDriver>,
    cleanup: MacosHostCleanupTracker,
    report: &mut OciVmOperationReopenReplacementReport,
    reason: String,
) -> std::result::Result<T, String> {
    drop(service);
    report.first_vm = driver.shutdown().await;
    cleanup.apply(&mut report.first_vm).await;
    Err(reason)
}

pub(in crate::oci_smoke::utility_vm::reopen_replacement) fn record_recovery_evidence(
    report: &mut OciVmOperationReopenReplacementReport,
    driver: &QualificationHvfDriver,
) {
    report.replacement_recovery_calls = driver.recovery_calls();
    report.replacement_rehydrated_created_record = driver.rehydrated_created_record();
    report.replacement_rehydrated_running_record = driver.rehydrated_running_record();
    report.replacement_rehydrated_stopped_record = driver.rehydrated_stopped_record();
    report.replacement_rehydrated_exec_record = driver.rehydrated_exec_record();
    report.replacement_created_pid = driver.rehydrated_running_pid();
    report.replacement_exec_pid = driver
        .rehydrated_exec_pid()
        .and_then(|pid| u32::try_from(pid).ok());
}

pub(in crate::oci_smoke::utility_vm::reopen_replacement) async fn exec_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    target: &ProcessTarget,
) -> std::result::Result<ExecJournalStatus, String> {
    let path = state_root
        .join("operations")
        .join(format!("{}.json", operation_id.as_str()));
    let contents = tokio::fs::read(&path).await.map_err(|error| {
        format!(
            "failed to read durable Exec journal {}: {error}",
            path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_slice(&contents).map_err(|error| {
        format!(
            "failed to decode durable Exec journal {}: {error}",
            path.display()
        )
    })?;
    let expected_generation = serde_json::to_value(target.container.generation)
        .map_err(|error| format!("failed to encode expected Exec generation: {error}"))?;
    let identity_matches = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        == Some("a3s.oci.operation.v1")
        && value.get("operationId").and_then(serde_json::Value::as_str)
            == Some(operation_id.as_str())
        && value.get("kind").and_then(serde_json::Value::as_str) == Some("exec")
        && value.get("containerId").and_then(serde_json::Value::as_str)
            == Some(target.container.id.as_str())
        && value.get("generation") == Some(&expected_generation)
        && value.get("processId").and_then(serde_json::Value::as_str)
            == Some(target.process_id.as_str())
        && value
            .get("requestDigest")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|digest| !digest.is_empty());
    if !identity_matches {
        return Err(format!(
            "durable Exec journal {} did not match the exact operation and process",
            path.display()
        ));
    }
    let outcome = value
        .get("outcome")
        .ok_or_else(|| format!("durable Exec journal {} has no outcome", path.display()))?;
    match outcome.get("status").and_then(serde_json::Value::as_str) {
        Some("prepared") => Ok(ExecJournalStatus::Prepared),
        Some("succeeded-process") => {
            let response: ProcessRecord =
                serde_json::from_value(outcome.get("response").cloned().ok_or_else(|| {
                    format!(
                        "durable Exec journal {} has no process response",
                        path.display()
                    )
                })?)
                .map_err(|error| {
                    format!(
                        "failed to decode durable Exec response {}: {error}",
                        path.display()
                    )
                })?;
            if response.target != *target {
                return Err(format!(
                    "durable Exec response {} changed its process target",
                    path.display()
                ));
            }
            Ok(ExecJournalStatus::Succeeded(response))
        }
        status => Err(format!(
            "durable Exec journal {} had unexpected status {status:?}",
            path.display()
        )),
    }
}

pub(in crate::oci_smoke::utility_vm::reopen_replacement) async fn durable_exec_process(
    state_root: &Path,
    target: &ProcessTarget,
) -> std::result::Result<ProcessRecord, String> {
    let path = state_root
        .join("containers")
        .join(target.container.id.as_str())
        .join("processes")
        .join(format!("{}.json", target.process_id.as_str()));
    let contents = tokio::fs::read(&path).await.map_err(|error| {
        format!(
            "failed to read durable Exec process {}: {error}",
            path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_slice(&contents).map_err(|error| {
        format!(
            "failed to decode durable Exec process {}: {error}",
            path.display()
        )
    })?;
    if value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        != Some("a3s.oci.process-record.v1")
        || value.get("activeOperation").is_some()
        || value.get("exitStatus").is_some()
    {
        return Err(format!(
            "durable Exec process {} retained invalid active or terminal state",
            path.display()
        ));
    }
    let record: ProcessRecord = serde_json::from_value(
        value
            .get("record")
            .cloned()
            .ok_or_else(|| format!("durable Exec process {} has no record", path.display()))?,
    )
    .map_err(|error| {
        format!(
            "failed to decode durable Exec record {}: {error}",
            path.display()
        )
    })?;
    if record.target != *target {
        return Err(format!(
            "durable Exec process {} changed its exact target",
            path.display()
        ));
    }
    Ok(record)
}

pub(in crate::oci_smoke::utility_vm::reopen_replacement) fn identity_or_expected<T: Clone>(
    identity: std::result::Result<T, String>,
    failure: &mut Option<String>,
    expected: T,
) -> T {
    match identity {
        Ok(identity) => identity,
        Err(reason) => {
            append_failure(failure, reason);
            expected
        }
    }
}

pub(in crate::oci_smoke::utility_vm::reopen_replacement) fn exact_process_target(
    exec: &a3s_oci_sdk::ExecRequest,
) -> ProcessTarget {
    ProcessTarget {
        container: exec.container.clone(),
        process_id: exec.process_id.clone(),
    }
}

pub(in crate::oci_smoke::utility_vm::reopen_replacement) fn stale_target(
    container: &ContainerTarget,
) -> std::result::Result<ContainerTarget, String> {
    let generation = container
        .generation
        .ok_or_else(|| "Exec qualification container target is not exact".to_string())?;
    let stale = generation
        .0
        .checked_add(1)
        .ok_or_else(|| "Exec qualification generation cannot be incremented".to_string())?;
    Ok(ContainerTarget::exact(
        container.id.clone(),
        a3s_oci_sdk::Generation(stale),
    ))
}
