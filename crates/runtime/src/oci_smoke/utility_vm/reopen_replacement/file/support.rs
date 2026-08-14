use std::path::Path;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::{ContainerTarget, Error, ErrorCode, FileRequest, FileResponse, OciBundle};

use super::super::{QualificationHvfDriver, FAULT_OPERATION};
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::OciVmOperationReopenReplacementReport;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FileMutationJournalStatus {
    Prepared,
    Succeeded(FileResponse),
}

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

pub(super) async fn file_mutation_journal_status(
    state_root: &Path,
    request: &FileRequest,
    target: &ContainerTarget,
) -> std::result::Result<FileMutationJournalStatus, String> {
    let operation_id = &request
        .context
        .as_ref()
        .ok_or_else(|| "File qualification request has no operation context".to_string())?
        .operation_id;
    let path = state_root
        .join("operations")
        .join(format!("{}.json", operation_id.as_str()));
    let contents = tokio::fs::read(&path).await.map_err(|error| {
        format!(
            "failed to read durable File journal {}: {error}",
            path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_slice(&contents).map_err(|error| {
        format!(
            "failed to decode durable File journal {}: {error}",
            path.display()
        )
    })?;
    let expected_generation = serde_json::to_value(target.generation)
        .map_err(|error| format!("failed to encode expected File generation: {error}"))?;
    let retained_request: FileRequest = serde_json::from_value(
        value
            .get("request")
            .and_then(|retained| retained.get("request"))
            .cloned()
            .ok_or_else(|| {
                format!(
                    "durable File journal {} has no retained request",
                    path.display()
                )
            })?,
    )
    .map_err(|error| {
        format!(
            "failed to decode durable File request {}: {error}",
            path.display()
        )
    })?;
    let identity_matches = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        == Some(crate::state::DURABLE_OPERATION_SCHEMA_VERSION)
        && value.get("operationId").and_then(serde_json::Value::as_str)
            == Some(operation_id.as_str())
        && value.get("kind").and_then(serde_json::Value::as_str) == Some("file")
        && value.get("containerId").and_then(serde_json::Value::as_str) == Some(target.id.as_str())
        && value.get("generation") == Some(&expected_generation)
        && value.get("processId").is_none()
        && value
            .get("request")
            .and_then(|retained| retained.get("kind"))
            .and_then(serde_json::Value::as_str)
            == Some("file")
        && retained_request == *request
        && value
            .get("requestDigest")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|digest| !digest.is_empty());
    if !identity_matches {
        return Err(format!(
            "durable File journal {} did not retain the exact request and generation",
            path.display()
        ));
    }
    let outcome = value
        .get("outcome")
        .ok_or_else(|| format!("durable File journal {} has no outcome", path.display()))?;
    match outcome.get("status").and_then(serde_json::Value::as_str) {
        Some("prepared") => Ok(FileMutationJournalStatus::Prepared),
        Some("succeeded-filesystem") => {
            let response_wrapper = outcome.get("response").ok_or_else(|| {
                format!("durable File journal {} has no response", path.display())
            })?;
            if response_wrapper
                .get("kind")
                .and_then(serde_json::Value::as_str)
                != Some("file")
            {
                return Err(format!(
                    "durable File journal {} contains the wrong response kind",
                    path.display()
                ));
            }
            let response: FileResponse = serde_json::from_value(
                response_wrapper.get("response").cloned().ok_or_else(|| {
                    format!(
                        "durable File journal {} has no File response",
                        path.display()
                    )
                })?,
            )
            .map_err(|error| {
                format!(
                    "failed to decode durable File response {}: {error}",
                    path.display()
                )
            })?;
            if response.target != *target {
                return Err(format!(
                    "durable File response {} changed its exact target",
                    path.display()
                ));
            }
            Ok(FileMutationJournalStatus::Succeeded(response))
        }
        status => Err(format!(
            "durable File journal {} had unexpected status {status:?}",
            path.display()
        )),
    }
}
