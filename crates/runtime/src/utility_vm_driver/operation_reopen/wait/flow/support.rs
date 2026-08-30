use std::path::PathBuf;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::{
    ContainerTarget, DeleteRequest, Error, ErrorCode, ExitStatus, KillRequest, OperationId, Signal,
    StartRequest, WaitRequest,
};

pub(super) use super::super::super::workload_marker::{
    path_absent, reset_marker, runtime_marker, wait_for_replacement_marker,
};
pub(super) use crate::operation_journal_evidence::init_exit_cache;
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::OciVmOperationReopenReplacementReport;

pub(super) type CreateIdentity = (OperationId, ContainerTarget);
pub(super) type KillIdentity = (OperationId, ContainerTarget, Signal, bool);
pub(super) type WaitIdentity = (ContainerTarget, Option<u64>);

pub(super) struct FirstOwnerOutcome {
    pub(super) target: ContainerTarget,
    pub(super) mount_root: PathBuf,
    pub(super) marker: PathBuf,
    pub(super) create_identity: CreateIdentity,
    pub(super) start_identity: CreateIdentity,
    pub(super) kill_identity: KillIdentity,
    pub(super) wait_identity: WaitIdentity,
    pub(super) start: StartRequest,
    pub(super) kill: KillRequest,
    pub(super) wait: WaitRequest,
    pub(super) delete: DeleteRequest,
    pub(super) expected_exit: ExitStatus,
    pub(super) response_delivered: bool,
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
            "first KVM owner returned an unexpected Wait transport error at {}: {error}",
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
