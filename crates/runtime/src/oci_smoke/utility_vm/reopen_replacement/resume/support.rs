use std::path::Path;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::{ContainerRecord, ContainerTarget, Error, ErrorCode, OperationId};

use super::super::{QualificationHvfDriver, FAULT_OPERATION};
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::OciVmOperationReopenReplacementReport;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FreezerJournalStatus {
    Prepared,
    Succeeded(ContainerRecord),
}

pub(super) fn operation_id(value: &str) -> std::result::Result<OperationId, String> {
    OperationId::new(value)
        .map_err(|error| format!("failed to construct Resume qualification operation ID: {error}"))
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
            "first owner returned an unexpected Resume transport error at {}: {error}",
            stage.as_str()
        ))
    }
}

pub(super) fn record_recovery_evidence(
    report: &mut OciVmOperationReopenReplacementReport,
    driver: &QualificationHvfDriver,
) {
    super::super::exec::support::record_recovery_evidence(report, driver);
    report.replacement_rehydrated_paused_record = driver.rehydrated_paused_record();
    report.replacement_rehydrated_resumed_record = driver.rehydrated_resumed_record();
}

pub(super) async fn pause_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    target: &ContainerTarget,
) -> std::result::Result<FreezerJournalStatus, String> {
    freezer_journal_status(state_root, operation_id, target, "pause", "Pause").await
}

pub(super) async fn resume_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    target: &ContainerTarget,
) -> std::result::Result<FreezerJournalStatus, String> {
    freezer_journal_status(state_root, operation_id, target, "resume", "Resume").await
}

async fn freezer_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    target: &ContainerTarget,
    expected_kind: &str,
    label: &str,
) -> std::result::Result<FreezerJournalStatus, String> {
    let path = state_root
        .join("operations")
        .join(format!("{}.json", operation_id.as_str()));
    let contents = tokio::fs::read(&path).await.map_err(|error| {
        format!(
            "failed to read durable {label} journal {}: {error}",
            path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_slice(&contents).map_err(|error| {
        format!(
            "failed to decode durable {label} journal {}: {error}",
            path.display()
        )
    })?;
    let expected_generation = serde_json::to_value(target.generation)
        .map_err(|error| format!("failed to encode expected {label} generation: {error}"))?;
    let identity_matches = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        == Some("a3s.oci.operation.v1")
        && value.get("operationId").and_then(serde_json::Value::as_str)
            == Some(operation_id.as_str())
        && value.get("kind").and_then(serde_json::Value::as_str) == Some(expected_kind)
        && value.get("containerId").and_then(serde_json::Value::as_str) == Some(target.id.as_str())
        && value.get("generation") == Some(&expected_generation)
        && value.get("processId").is_none()
        && value
            .get("requestDigest")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|digest| !digest.is_empty());
    if !identity_matches {
        return Err(format!(
            "durable {label} journal {} did not match the exact operation and generation",
            path.display()
        ));
    }
    let outcome = value
        .get("outcome")
        .ok_or_else(|| format!("durable {label} journal {} has no outcome", path.display()))?;
    match outcome.get("status").and_then(serde_json::Value::as_str) {
        Some("prepared") => Ok(FreezerJournalStatus::Prepared),
        Some("succeeded") => {
            let response: ContainerRecord =
                serde_json::from_value(outcome.get("response").cloned().ok_or_else(|| {
                    format!(
                        "durable {label} journal {} has no container response",
                        path.display()
                    )
                })?)
                .map_err(|error| {
                    format!(
                        "failed to decode durable {label} response {}: {error}",
                        path.display()
                    )
                })?;
            if response.state.id() != target.id.as_str()
                || response.generation != target.generation.unwrap_or(response.generation)
            {
                return Err(format!(
                    "durable {label} response {} changed its exact target",
                    path.display()
                ));
            }
            Ok(FreezerJournalStatus::Succeeded(response))
        }
        status => Err(format!(
            "durable {label} journal {} had unexpected status {status:?}",
            path.display()
        )),
    }
}
