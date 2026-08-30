use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::{
    ContainerTarget, DeleteMode, DeleteRequest, Error, ErrorCode, KillRequest, OperationId, Signal,
    StartRequest,
};

pub(super) use super::super::super::workload_marker::{
    path_absent, reset_marker, runtime_marker, wait_for_replacement_marker,
};
use crate::operation_journal_evidence::{
    empty_operation_journal_status, EmptyOperationJournalStatus,
};
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::OciVmOperationReopenReplacementReport;

pub(super) type KillIdentity = (OperationId, ContainerTarget, Signal, bool);
pub(super) type DeleteIdentity = (OperationId, ContainerTarget, DeleteMode);

pub(super) struct FirstOwnerOutcome {
    pub(super) target: ContainerTarget,
    pub(super) mount_root: PathBuf,
    pub(super) marker: PathBuf,
    pub(super) create_identity: (OperationId, ContainerTarget),
    pub(super) start_identity: (OperationId, ContainerTarget),
    pub(super) kill_identity: KillIdentity,
    pub(super) delete_identity: DeleteIdentity,
    pub(super) start: StartRequest,
    pub(super) kill: KillRequest,
    pub(super) delete: DeleteRequest,
    pub(super) response_delivered: bool,
}

pub(super) async fn delete_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    target: &ContainerTarget,
) -> Result<EmptyOperationJournalStatus, String> {
    empty_operation_journal_status(state_root, operation_id, "delete", target).await
}

pub(super) fn record_interruption(
    report: &mut OciVmOperationReopenReplacementReport,
    error: Error,
    stage: AgentTransportOperationStage,
) -> Result<(), String> {
    report.first_operation_error_code = Some(error.code);
    report.first_operation_error_operation = error.operation.clone();
    report.first_operation_error_retryable = error.retryable;
    let expected_operation = if stage.is_guest() {
        error
            .operation
            .as_deref()
            .is_some_and(is_retryable_disconnect_operation)
    } else {
        error.operation.as_deref() == Some(super::super::super::QUALIFICATION_FAULT_OPERATION)
    };
    if error.code == ErrorCode::Unavailable && error.retryable && expected_operation {
        Ok(())
    } else {
        Err(format!(
            "first KVM owner returned an unexpected Delete transport error at {}: {error}",
            stage.as_str()
        ))
    }
}

pub(super) fn append_failure(failure: &mut Option<String>, reason: impl Into<String>) {
    let reason = reason.into();
    *failure = Some(match failure.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}
