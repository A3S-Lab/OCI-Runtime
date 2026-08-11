use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::{ContainerTarget, Error, ErrorCode, FilesystemEntryKind, FilesystemResponse};

use super::super::{QualificationHvfDriver, FAULT_OPERATION};
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::OciVmOperationReopenReplacementReport;

pub(super) fn directory_response_matches(
    response: &FilesystemResponse,
    target: &ContainerTarget,
    path: &str,
) -> bool {
    let expected_name = path.rsplit('/').next().unwrap_or(path);
    response.target == *target
        && response.entries.is_empty()
        && response.entry.as_ref().is_some_and(|entry| {
            entry.path == path
                && entry.name == expected_name
                && entry.kind == FilesystemEntryKind::Directory
                && entry.symlink_target.is_none()
        })
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
            "first owner returned an unexpected Filesystem transport error at {}: {error}",
            stage.as_str()
        ))
    }
}

pub(super) fn record_recovery_evidence(
    report: &mut OciVmOperationReopenReplacementReport,
    driver: &QualificationHvfDriver,
) {
    super::super::exec::support::record_recovery_evidence(report, driver);
    report.replacement_rehydrated_filesystem = driver.rehydrated_filesystem();
}
