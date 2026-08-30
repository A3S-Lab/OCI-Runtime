use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::{
    ContainerOperationRequest, ContainerTarget, Error, ErrorCode, OperationId, StartRequest,
};

pub(super) use super::super::super::exec::{stale_target, wait_for_exact_marker};
pub(super) use super::super::super::workload_marker::{path_absent, reset_marker, runtime_marker};
use super::super::super::QUALIFICATION_FAULT_OPERATION;
pub(super) use crate::operation_journal_evidence::ContainerOperationJournalStatus as PauseJournalStatus;
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::OciVmOperationReopenReplacementReport;

pub(super) type ContainerIdentity = (OperationId, ContainerTarget);

pub(super) struct FirstOwnerOutcome {
    pub(super) target: ContainerTarget,
    pub(super) mount_root: PathBuf,
    pub(super) marker: PathBuf,
    pub(super) create_identity: ContainerIdentity,
    pub(super) start_identity: ContainerIdentity,
    pub(super) pause_identity: ContainerIdentity,
    pub(super) start: StartRequest,
    pub(super) pause: ContainerOperationRequest,
    pub(super) response_delivered: bool,
}

pub(super) async fn pause_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    target: &ContainerTarget,
) -> Result<PauseJournalStatus, String> {
    crate::operation_journal_evidence::container_operation_journal_status(
        state_root,
        operation_id,
        "pause",
        target,
    )
    .await
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
        error.operation.as_deref() == Some(QUALIFICATION_FAULT_OPERATION)
    };
    if error.code == ErrorCode::Unavailable && error.retryable && expected_operation {
        Ok(())
    } else {
        Err(format!(
            "first KVM owner returned an unexpected Pause transport error at {}: {error}",
            stage.as_str()
        ))
    }
}

pub(super) fn identity_or_expected<T: Clone>(
    identity: Result<T, String>,
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

pub(super) fn append_failure(failure: &mut Option<String>, reason: impl Into<String>) {
    let reason = reason.into();
    *failure = Some(match failure.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}
