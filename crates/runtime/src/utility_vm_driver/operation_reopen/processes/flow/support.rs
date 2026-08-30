use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::{
    ContainerTarget, DeleteRequest, Error, ErrorCode, ExecRequest, OperationId, ProcessRecord,
    StartRequest,
};

pub(super) use super::super::super::exec::{
    exact_process_target, stale_target, wait_for_exact_marker, EXEC_MARKER_NAME,
};
pub(super) use super::super::super::workload_marker::{path_absent, reset_marker, runtime_marker};
use super::super::super::QUALIFICATION_FAULT_OPERATION;
pub(super) use crate::operation_journal_evidence::ProcessOperationJournalStatus as ExecJournalStatus;
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::{DriverExecRequest, OciVmOperationReopenReplacementReport};

pub(super) type CreateIdentity = (OperationId, ContainerTarget);

pub(super) struct FirstOwnerOutcome {
    pub(super) target: ContainerTarget,
    pub(super) mount_root: PathBuf,
    pub(super) init_marker: PathBuf,
    pub(super) exec_marker: PathBuf,
    pub(super) create_identity: CreateIdentity,
    pub(super) start_identity: CreateIdentity,
    pub(super) exec_identity: DriverExecRequest,
    pub(super) processes_identity: ContainerTarget,
    pub(super) start: StartRequest,
    pub(super) exec: ExecRequest,
    pub(super) delete: DeleteRequest,
}

pub(super) fn exec_marker(init_marker: &Path) -> Result<PathBuf, String> {
    init_marker
        .parent()
        .map(|rootfs| rootfs.join(EXEC_MARKER_NAME))
        .ok_or_else(|| "KVM Processes init marker has no rootfs parent".to_string())
}

pub(super) async fn exec_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    target: &a3s_oci_sdk::ProcessTarget,
) -> Result<ExecJournalStatus, String> {
    crate::operation_journal_evidence::process_operation_journal_status(
        state_root,
        operation_id,
        "exec",
        target,
    )
    .await
}

pub(super) async fn durable_exec_process(
    state_root: &Path,
    target: &a3s_oci_sdk::ProcessTarget,
) -> Result<ProcessRecord, String> {
    crate::operation_journal_evidence::durable_process(state_root, target).await
}

pub(super) fn inventory_matches(
    inventory: &[ProcessRecord],
    container: &ContainerTarget,
    init_pid: i32,
    exec: &ProcessRecord,
) -> bool {
    let Ok(init_pid) = u32::try_from(init_pid) else {
        return false;
    };
    inventory.len() == 2
        && inventory.iter().all(|process| {
            process.target.container == *container && process.pid.is_some_and(|pid| pid > 0)
        })
        && inventory.iter().any(|process| {
            process.target.process_id.is_init()
                && process.pid == Some(init_pid)
                && !process.terminal
        })
        && inventory.iter().any(|process| process == exec)
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
            "first KVM owner returned an unexpected Processes transport error at {}: {error}",
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
