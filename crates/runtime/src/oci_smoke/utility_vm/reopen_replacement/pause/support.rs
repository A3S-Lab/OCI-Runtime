use std::path::Path;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::{ContainerTarget, Error, ErrorCode, OperationId};

use super::super::{QualificationHvfDriver, FAULT_OPERATION};
pub(super) use crate::operation_journal_evidence::ContainerOperationJournalStatus as PauseJournalStatus;
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::OciVmOperationReopenReplacementReport;

pub(super) fn operation_id(value: &str) -> std::result::Result<OperationId, String> {
    OperationId::new(value)
        .map_err(|error| format!("failed to construct Pause qualification operation ID: {error}"))
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
            "first owner returned an unexpected Pause transport error at {}: {error}",
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
}

pub(super) async fn pause_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    target: &ContainerTarget,
) -> std::result::Result<PauseJournalStatus, String> {
    crate::operation_journal_evidence::container_operation_journal_status(
        state_root,
        operation_id,
        "pause",
        target,
    )
    .await
}
