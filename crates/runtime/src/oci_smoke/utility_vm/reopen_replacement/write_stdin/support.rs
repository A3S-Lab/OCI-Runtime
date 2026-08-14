use std::path::Path;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{Error, ErrorCode, IoMode, OperationId, ProcessId, ProcessIo, ProcessTarget};

use super::super::exec::support::dispatch_may_have_reached;
use super::super::{append_failure, QualificationHvfDriver, FAULT_OPERATION};
use super::WRITE_MARKER_NAME;
use crate::marker::{exact_marker_state, ExactMarkerState};
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::OciVmOperationReopenReplacementReport;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WriteStdinJournalStatus {
    Prepared,
    SucceededEmpty,
}

pub(super) fn stdin_exec_process(
    nonce: &str,
) -> std::result::Result<(ProcessId, Process, ProcessIo), String> {
    if nonce.is_empty()
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("WriteStdin qualification nonce contains unsafe shell characters".into());
    }
    let process_id = ProcessId::new(format!("stdin-worker-{nonce}"))
        .map_err(|error| format!("failed to construct stdin Exec process ID: {error}"))?;
    let command = format!(
        "set -eu; printf 'a3s-oci-exec-process-{nonce}\\n' > /{}; IFS= read -r input; printf '%s\\n' \"$input\" > /{WRITE_MARKER_NAME}; while :; do /bin/busybox sleep 1; done",
        super::super::exec::EXEC_MARKER_NAME,
    );
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", command],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .map_err(|error| format!("failed to construct stdin Exec process: {error}"))?;
    let io = ProcessIo {
        stdin: IoMode::Pipe,
        stdout: IoMode::Null,
        stderr: IoMode::Null,
        terminal_size: None,
    };
    Ok((process_id, process, io))
}

pub(super) async fn verify_first_write_marker(
    marker: &Path,
    expected: &[u8],
    stage: AgentTransportOperationStage,
) -> std::result::Result<(), String> {
    let marker_exists = super::super::super::path_exists(marker).await?;
    if !dispatch_may_have_reached(stage) {
        return if marker_exists {
            Err(format!(
                "{} produced a WriteStdin marker before Guest dispatch",
                stage.as_str()
            ))
        } else {
            Ok(())
        };
    }
    if marker_exists {
        // A successful write does not guarantee that the shell consumes the
        // bytes before a transport fault terminates the VM. Absence is
        // therefore allowed after dispatch. A file created just before owner
        // termination may retain only an exact prefix; unrelated bytes fail.
        let contents = super::super::super::read_marker(marker).await?;
        match exact_marker_state(&contents, expected) {
            ExactMarkerState::Complete | ExactMarkerState::InProgress => Ok(()),
            ExactMarkerState::Mismatch => {
                Err("first-owner WriteStdin produced unexpected marker contents".to_string())
            }
        }
    } else {
        Ok(())
    }
}

pub(super) fn record_interruption(
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
            "first owner returned an unexpected WriteStdin transport error at {}: {error}",
            stage.as_str()
        ))
    }
}

pub(super) fn record_recovery_evidence(
    report: &mut OciVmOperationReopenReplacementReport,
    driver: &QualificationHvfDriver,
) {
    super::super::exec::support::record_recovery_evidence(report, driver);
    report.replacement_rehydrated_write_stdin = driver.rehydrated_write_stdin();
}

pub(super) async fn write_stdin_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    target: &ProcessTarget,
) -> std::result::Result<WriteStdinJournalStatus, String> {
    let path = state_root
        .join("operations")
        .join(format!("{}.json", operation_id.as_str()));
    let contents = tokio::fs::read(&path).await.map_err(|error| {
        format!(
            "failed to read durable WriteStdin journal {}: {error}",
            path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_slice(&contents).map_err(|error| {
        format!(
            "failed to decode durable WriteStdin journal {}: {error}",
            path.display()
        )
    })?;
    let expected_generation = serde_json::to_value(target.container.generation)
        .map_err(|error| format!("failed to encode expected WriteStdin generation: {error}"))?;
    let identity_matches = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        == Some(crate::state::DURABLE_OPERATION_SCHEMA_VERSION)
        && value.get("operationId").and_then(serde_json::Value::as_str)
            == Some(operation_id.as_str())
        && value.get("kind").and_then(serde_json::Value::as_str) == Some("write-stdin")
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
            "durable WriteStdin journal {} did not match the exact operation and process",
            path.display()
        ));
    }
    let status = value
        .pointer("/outcome/status")
        .and_then(serde_json::Value::as_str);
    match status {
        Some("prepared") => Ok(WriteStdinJournalStatus::Prepared),
        Some("succeeded-empty") => Ok(WriteStdinJournalStatus::SucceededEmpty),
        status => Err(format!(
            "durable WriteStdin journal {} had unexpected status {status:?}",
            path.display()
        )),
    }
}

pub(super) fn identity_or_expected<T: Clone>(
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
