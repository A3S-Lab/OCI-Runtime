use std::path::PathBuf;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::{
    ContainerTarget, Error, ErrorCode, KillRequest, OperationId, Signal, StartRequest,
};

pub(super) use super::super::super::workload_marker::{
    path_absent, reset_marker, runtime_marker, wait_for_replacement_marker,
};
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::OciVmOperationReopenReplacementReport;

pub(super) type KillIdentity = (OperationId, ContainerTarget, Signal, bool);

pub(super) struct FirstOwnerOutcome {
    pub(super) target: ContainerTarget,
    pub(super) mount_root: PathBuf,
    pub(super) marker: PathBuf,
    pub(super) create_identity: (OperationId, ContainerTarget),
    pub(super) start_identity: (OperationId, ContainerTarget),
    pub(super) kill_identity: KillIdentity,
    pub(super) start: StartRequest,
    pub(super) kill: KillRequest,
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
            "first KVM owner returned an unexpected Kill transport error at {}: {error}",
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
