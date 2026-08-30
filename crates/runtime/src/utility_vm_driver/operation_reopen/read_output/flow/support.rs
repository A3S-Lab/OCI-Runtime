use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::{
    ContainerTarget, DeleteRequest, Error, ErrorCode, ExecRequest, OperationId, ProcessRecord,
    StartRequest,
};

pub(super) use super::super::super::exec::{
    exact_process_target, stale_target, wait_for_exact_marker,
};
pub(super) use super::super::super::workload_marker::{path_absent, reset_marker, runtime_marker};
use super::super::super::QUALIFICATION_FAULT_OPERATION;
pub(super) use crate::operation_journal_evidence::ProcessOperationJournalStatus as ExecJournalStatus;
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::{DriverExecRequest, DriverReadOutputRequest, OciVmOperationReopenReplacementReport};

use super::super::super::driver::QualificationKvmOperationDriver;
use super::super::READ_OUTPUT_MARKER_NAME;

pub(super) type CreateIdentity = (OperationId, ContainerTarget);

pub(super) struct FirstOwnerOutcome {
    pub(super) target: ContainerTarget,
    pub(super) mount_root: PathBuf,
    pub(super) init_marker: PathBuf,
    pub(super) exec_marker: PathBuf,
    pub(super) create_identity: CreateIdentity,
    pub(super) start_identity: CreateIdentity,
    pub(super) exec_identity: DriverExecRequest,
    pub(super) read_output_identity: DriverReadOutputRequest,
    pub(super) start: StartRequest,
    pub(super) exec: ExecRequest,
    pub(super) delete: DeleteRequest,
}

pub(super) fn exec_marker(init_marker: &Path) -> Result<PathBuf, String> {
    init_marker
        .parent()
        .map(|rootfs| rootfs.join(READ_OUTPUT_MARKER_NAME))
        .ok_or_else(|| "KVM ReadOutput init marker has no rootfs parent".to_string())
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
            "first KVM owner returned an unexpected ReadOutput transport error at {}: {error}",
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

pub(super) fn capture_recovery(
    driver: &QualificationKvmOperationDriver,
    report: &mut OciVmOperationReopenReplacementReport,
) {
    report.replacement_recovery_calls = driver.recovery_calls();
    report.replacement_rehydrated_created_record = driver.rehydrated_created_record();
    report.replacement_rehydrated_running_record = driver.rehydrated_running_record();
    report.replacement_rehydrated_stopped_record = driver.rehydrated_stopped_record();
    report.replacement_rehydrated_exec_record = driver.rehydrated_exec_record();
    report.replacement_rehydrated_signal_process = driver.rehydrated_signal_process();
    report.replacement_rehydrated_paused_record = driver.rehydrated_paused_record();
    report.replacement_rehydrated_resumed_record = driver.rehydrated_resumed_record();
    report.replacement_rehydrated_update = driver.rehydrated_update();
    report.replacement_created_pid = driver.rehydrated_running_pid();
    report.replacement_exec_pid = driver
        .rehydrated_exec_pid()
        .and_then(|pid| u32::try_from(pid).ok());
}

pub(super) fn verify_first_dispatches(
    driver: &QualificationKvmOperationDriver,
    report: &OciVmOperationReopenReplacementReport,
    failure: &mut Option<String>,
) {
    for (label, actual) in [
        ("Start", driver.start_calls()),
        ("Exec", driver.exec_calls()),
        ("ReadOutput", report.first_operation_dispatches),
    ] {
        if actual != 1 {
            append_failure(
                failure,
                format!("first KVM driver recorded {actual} {label} dispatches instead of one"),
            );
        }
    }
}

pub(super) async fn setup_failure(
    driver: &QualificationKvmOperationDriver,
    report: &mut OciVmOperationReopenReplacementReport,
    reason: String,
) -> Result<FirstOwnerOutcome, String> {
    report.first_vm = driver.shutdown().await;
    let cleanup = match driver.create_identity() {
        Ok((_, target)) => driver.cleanup(&target).await,
        Err(_) => Ok(()),
    };
    match cleanup {
        Ok(()) => Err(reason),
        Err(cleanup) => Err(format!("{reason}; {cleanup}")),
    }
}

pub(super) async fn active_failure(
    driver: &QualificationKvmOperationDriver,
    target: &ContainerTarget,
    report: &mut OciVmOperationReopenReplacementReport,
    reason: String,
) -> Result<FirstOwnerOutcome, String> {
    report.first_vm = driver.shutdown().await;
    cleanup_failure(driver, target, reason).await
}

pub(super) async fn cleanup_failure(
    driver: &QualificationKvmOperationDriver,
    target: &ContainerTarget,
    reason: String,
) -> Result<FirstOwnerOutcome, String> {
    match driver.cleanup(target).await {
        Ok(()) => Err(reason),
        Err(cleanup) => Err(format!("{reason}; {cleanup}")),
    }
}
