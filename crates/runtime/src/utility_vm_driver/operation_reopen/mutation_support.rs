use std::path::Path;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::{
    ContainerTarget, Error, ErrorCode, FileRequest, FileResponse, FilesystemEntryKind,
    FilesystemRequest, FilesystemResponse, OciBundle,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use super::QUALIFICATION_FAULT_OPERATION;
use crate::operation_reopen_replacement_report::OciVmOperationReopenReplacementReport;
use crate::transport_cleanup_report::is_retryable_disconnect_operation;

/// The durable outcome of a filesystem mutation journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FileMutationJournalStatus {
    Prepared,
    Succeeded(FileResponse),
}

/// The durable outcome of a directory mutation journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FilesystemMutationJournalStatus {
    Prepared,
    Succeeded(Box<FilesystemResponse>),
}

/// Add an isolated writable `/tmp` mount to a nonce-bound qualification bundle.
pub(super) fn session_filesystem_bundle(
    bundle: OciBundle,
    operation: &str,
) -> Result<OciBundle, String> {
    let mut config: serde_json::Value = serde_json::from_str(bundle.config_json())
        .map_err(|error| format!("failed to decode {operation} qualification bundle: {error}"))?;
    let mounts = config
        .get_mut("mounts")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| format!("{operation} qualification bundle must contain a mounts array"))?;
    if mounts
        .iter()
        .any(|mount| mount.get("destination").and_then(serde_json::Value::as_str) == Some("/tmp"))
    {
        return Err(format!(
            "{operation} qualification bundle already mounts /tmp"
        ));
    }
    mounts.push(serde_json::json!({
        "destination": "/tmp",
        "type": "tmpfs",
        "source": "tmpfs",
        "options": ["nosuid", "nodev", "mode=1777"]
    }));
    let encoded = serde_json::to_string_pretty(&config)
        .map_err(|error| format!("failed to encode {operation} qualification bundle: {error}"))?;
    OciBundle::from_json(bundle.directory().to_path_buf(), encoded)
        .map_err(|error| format!("failed to validate {operation} qualification bundle: {error}"))
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

pub(super) fn empty_filesystem_response(
    response: &FilesystemResponse,
    target: &ContainerTarget,
) -> bool {
    response.target == *target && response.entry.is_none() && response.entries.is_empty()
}

pub(super) fn record_interruption(
    report: &mut OciVmOperationReopenReplacementReport,
    error: Error,
    stage: AgentTransportOperationStage,
    operation: &str,
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
            "first KVM owner returned an unexpected {operation} transport error at {}: {error}",
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

pub(super) async fn file_mutation_journal_status(
    state_root: &Path,
    request: &FileRequest,
    target: &ContainerTarget,
) -> Result<FileMutationJournalStatus, String> {
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

pub(super) async fn filesystem_mutation_journal_status(
    state_root: &Path,
    request: &FilesystemRequest,
    target: &ContainerTarget,
) -> Result<FilesystemMutationJournalStatus, String> {
    let operation_id = &request
        .context
        .as_ref()
        .ok_or_else(|| "Filesystem qualification request has no operation context".to_string())?
        .operation_id;
    let path = state_root
        .join("operations")
        .join(format!("{}.json", operation_id.as_str()));
    let contents = tokio::fs::read(&path).await.map_err(|error| {
        format!(
            "failed to read durable Filesystem journal {}: {error}",
            path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_slice(&contents).map_err(|error| {
        format!(
            "failed to decode durable Filesystem journal {}: {error}",
            path.display()
        )
    })?;
    let expected_generation = serde_json::to_value(target.generation)
        .map_err(|error| format!("failed to encode expected Filesystem generation: {error}"))?;
    let retained_request: FilesystemRequest = serde_json::from_value(
        value
            .get("request")
            .and_then(|retained| retained.get("request"))
            .cloned()
            .ok_or_else(|| {
                format!(
                    "durable Filesystem journal {} has no retained request",
                    path.display()
                )
            })?,
    )
    .map_err(|error| {
        format!(
            "failed to decode durable Filesystem request {}: {error}",
            path.display()
        )
    })?;
    let identity_matches = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        == Some(crate::state::DURABLE_OPERATION_SCHEMA_VERSION)
        && value.get("operationId").and_then(serde_json::Value::as_str)
            == Some(operation_id.as_str())
        && value.get("kind").and_then(serde_json::Value::as_str) == Some("filesystem")
        && value.get("containerId").and_then(serde_json::Value::as_str) == Some(target.id.as_str())
        && value.get("generation") == Some(&expected_generation)
        && value.get("processId").is_none()
        && value
            .get("request")
            .and_then(|retained| retained.get("kind"))
            .and_then(serde_json::Value::as_str)
            == Some("filesystem")
        && retained_request == *request
        && value
            .get("requestDigest")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|digest| !digest.is_empty());
    if !identity_matches {
        return Err(format!(
            "durable Filesystem journal {} did not retain the exact request and generation",
            path.display()
        ));
    }
    let outcome = value.get("outcome").ok_or_else(|| {
        format!(
            "durable Filesystem journal {} has no outcome",
            path.display()
        )
    })?;
    match outcome.get("status").and_then(serde_json::Value::as_str) {
        Some("prepared") => Ok(FilesystemMutationJournalStatus::Prepared),
        Some("succeeded-filesystem") => {
            let response_wrapper = outcome.get("response").ok_or_else(|| {
                format!(
                    "durable Filesystem journal {} has no response",
                    path.display()
                )
            })?;
            if response_wrapper
                .get("kind")
                .and_then(serde_json::Value::as_str)
                != Some("filesystem")
            {
                return Err(format!(
                    "durable Filesystem journal {} contains the wrong response kind",
                    path.display()
                ));
            }
            let response: FilesystemResponse = serde_json::from_value(
                response_wrapper.get("response").cloned().ok_or_else(|| {
                    format!(
                        "durable Filesystem journal {} has no Filesystem response",
                        path.display()
                    )
                })?,
            )
            .map_err(|error| {
                format!(
                    "failed to decode durable Filesystem response {}: {error}",
                    path.display()
                )
            })?;
            if response.target != *target {
                return Err(format!(
                    "durable Filesystem response {} changed its exact target",
                    path.display()
                ));
            }
            Ok(FilesystemMutationJournalStatus::Succeeded(Box::new(
                response,
            )))
        }
        status => Err(format!(
            "durable Filesystem journal {} had unexpected status {status:?}",
            path.display()
        )),
    }
}

/// Keep the import of the base64 engine in this module tied to a compile-time
/// check: all callers use the same canonical encoding for changed uploads.
pub(super) fn changed_upload_data() -> String {
    STANDARD.encode(b"changed-file-payload")
}
