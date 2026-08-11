use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::{ContainerTarget, Error, ErrorCode, FileResponse, OciBundle};

use super::super::{QualificationHvfDriver, FAULT_OPERATION};
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::OciVmOperationReopenReplacementReport;

pub(in crate::oci_smoke::utility_vm::reopen_replacement) fn session_filesystem_bundle(
    bundle: OciBundle,
) -> std::result::Result<OciBundle, String> {
    let mut config: serde_json::Value = serde_json::from_str(bundle.config_json())
        .map_err(|error| format!("failed to decode File qualification bundle: {error}"))?;
    let mounts = config
        .get_mut("mounts")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| "File qualification bundle must contain a mounts array".to_string())?;
    if mounts
        .iter()
        .any(|mount| mount.get("destination").and_then(serde_json::Value::as_str) == Some("/tmp"))
    {
        return Err("File qualification bundle already mounts /tmp".to_string());
    }
    mounts.push(serde_json::json!({
        "destination": "/tmp",
        "type": "tmpfs",
        "source": "tmpfs",
        "options": ["nosuid", "nodev", "mode=1777"]
    }));
    let encoded = serde_json::to_string_pretty(&config)
        .map_err(|error| format!("failed to encode File qualification bundle: {error}"))?;
    OciBundle::from_json(bundle.directory().to_path_buf(), encoded)
        .map_err(|error| format!("failed to validate File qualification bundle: {error}"))
}

pub(super) fn upload_response_matches(
    response: &FileResponse,
    target: &ContainerTarget,
    payload_size: usize,
) -> bool {
    response.target == *target && response.data.is_none() && response.size == payload_size as u64
}

pub(super) fn download_response_matches(
    response: &FileResponse,
    target: &ContainerTarget,
    encoded_payload: &str,
    payload_size: usize,
) -> bool {
    response.target == *target
        && response.data.as_deref() == Some(encoded_payload)
        && response.size == payload_size as u64
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
            "first owner returned an unexpected File transport error at {}: {error}",
            stage.as_str()
        ))
    }
}

pub(super) fn record_recovery_evidence(
    report: &mut OciVmOperationReopenReplacementReport,
    driver: &QualificationHvfDriver,
) {
    super::super::exec::support::record_recovery_evidence(report, driver);
    report.replacement_rehydrated_file = driver.rehydrated_file();
}
