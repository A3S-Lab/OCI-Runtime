use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::{ContainerTarget, Error, ErrorCode, ProcessRecord};

use super::super::{QualificationHvfDriver, FAULT_OPERATION};
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::OciVmOperationReopenReplacementReport;

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

pub(super) fn record_recovery_evidence(
    report: &mut OciVmOperationReopenReplacementReport,
    driver: &QualificationHvfDriver,
) {
    super::super::exec::support::record_recovery_evidence(report, driver);
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
            "first owner returned an unexpected Processes transport error at {}: {error}",
            stage.as_str()
        ))
    }
}
