use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::{ContainerTarget, Error, ErrorCode, OperationId};

use super::super::{path_exists, remove_marker};
use super::{QualificationHvfDriver, FAULT_OPERATION};
use crate::host_cleanup::MacosHostCleanupTracker;
use crate::operation_journal_evidence::empty_operation_journal_status;
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::OciVmOperationReopenReplacementReport;

pub(super) use crate::operation_journal_evidence::EmptyOperationJournalStatus as DeleteJournalStatus;

pub(super) async fn shutdown_setup_failure(
    service: crate::HostRuntimeService,
    driver: Arc<QualificationHvfDriver>,
    cleanup: MacosHostCleanupTracker,
    report: &mut OciVmOperationReopenReplacementReport,
    reason: String,
) -> std::result::Result<(), String> {
    drop(service);
    report.first_vm = driver.shutdown().await;
    cleanup.apply(&mut report.first_vm).await;
    Err(reason)
}

pub(super) fn record_recovery_evidence(
    report: &mut OciVmOperationReopenReplacementReport,
    driver: &QualificationHvfDriver,
) {
    report.replacement_recovery_calls = driver.recovery_calls();
    report.replacement_rehydrated_created_record = driver.rehydrated_created_record();
    report.replacement_rehydrated_running_record = driver.rehydrated_running_record();
    report.replacement_rehydrated_stopped_record = driver.rehydrated_stopped_record();
    report.replacement_created_pid = driver.rehydrated_running_pid();
}

pub(super) async fn delete_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    target: &ContainerTarget,
) -> std::result::Result<DeleteJournalStatus, String> {
    empty_operation_journal_status(state_root, operation_id, "delete", target).await
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
            "first owner returned an unexpected Delete transport error at {}: {error}",
            stage.as_str()
        ))
    }
}

pub(super) async fn reset_marker(marker: &Path) -> std::result::Result<(), String> {
    remove_marker_if_present(marker).await?;
    if path_exists(marker).await? {
        return Err(format!(
            "first-owner marker remained before replacement: {}",
            marker.display()
        ));
    }
    Ok(())
}

pub(super) async fn remove_marker_if_present(marker: &Path) -> std::result::Result<(), String> {
    if path_exists(marker).await? {
        remove_marker(marker).await?;
    }
    Ok(())
}

pub(super) fn append_reason(
    report: &mut OciVmOperationReopenReplacementReport,
    reason: impl Into<String>,
) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

pub(super) fn failed(
    mut report: OciVmOperationReopenReplacementReport,
    reason: impl Into<String>,
) -> OciVmOperationReopenReplacementReport {
    append_reason(&mut report, reason);
    report
}
