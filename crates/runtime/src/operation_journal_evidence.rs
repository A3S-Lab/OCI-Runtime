use std::path::Path;

use a3s_oci_sdk::{
    ContainerRecord, ContainerTarget, ExitStatus, OperationId, ProcessRecord, ProcessTarget,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ContainerOperationJournalStatus {
    Prepared,
    Succeeded(Box<ContainerRecord>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmptyOperationJournalStatus {
    Prepared,
    SucceededEmpty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProcessOperationJournalStatus {
    Prepared,
    Succeeded(ProcessRecord),
}

pub(crate) async fn init_exit_cache(
    state_root: &Path,
    target: &ContainerTarget,
) -> Result<Option<ExitStatus>, String> {
    let path = state_root
        .join("containers")
        .join(target.id.as_str())
        .join("record.json");
    let contents = tokio::fs::read(&path).await.map_err(|error| {
        format!(
            "failed to read durable Wait container record {}: {error}",
            path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_slice(&contents).map_err(|error| {
        format!(
            "failed to decode durable Wait container record {}: {error}",
            path.display()
        )
    })?;
    let expected_generation = serde_json::to_value(target.generation)
        .map_err(|error| format!("failed to encode expected Wait generation: {error}"))?;
    let identity_matches = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        == Some(crate::state::DURABLE_CONTAINER_SCHEMA_VERSION)
        && value.get("id").and_then(serde_json::Value::as_str) == Some(target.id.as_str())
        && value
            .get("record")
            .and_then(|record| record.get("generation"))
            == Some(&expected_generation);
    if !identity_matches {
        return Err(format!(
            "durable Wait container record {} did not match the exact generation",
            path.display()
        ));
    }
    match value.get("initExitStatus") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(status) => serde_json::from_value(status.clone())
            .map(Some)
            .map_err(|error| {
                format!(
                    "failed to decode durable init exit cache {}: {error}",
                    path.display()
                )
            }),
    }
}

pub(crate) async fn empty_operation_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    kind: &str,
    target: &ContainerTarget,
) -> Result<EmptyOperationJournalStatus, String> {
    let path = state_root
        .join("operations")
        .join(format!("{}.json", operation_id.as_str()));
    let contents = tokio::fs::read(&path).await.map_err(|error| {
        format!(
            "failed to read durable {kind} journal {}: {error}",
            path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_slice(&contents).map_err(|error| {
        format!(
            "failed to decode durable {kind} journal {}: {error}",
            path.display()
        )
    })?;
    let expected_generation = serde_json::to_value(target.generation)
        .map_err(|error| format!("failed to encode expected {kind} generation: {error}"))?;
    let identity_matches = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        == Some(crate::state::DURABLE_OPERATION_SCHEMA_VERSION)
        && value.get("operationId").and_then(serde_json::Value::as_str)
            == Some(operation_id.as_str())
        && value.get("kind").and_then(serde_json::Value::as_str) == Some(kind)
        && value.get("containerId").and_then(serde_json::Value::as_str) == Some(target.id.as_str())
        && value.get("generation") == Some(&expected_generation)
        && value.get("processId").is_none()
        && value
            .get("requestDigest")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|digest| !digest.is_empty());
    if !identity_matches {
        return Err(format!(
            "durable {kind} journal {} did not match the exact operation and generation",
            path.display()
        ));
    }
    match value
        .get("outcome")
        .and_then(|outcome| outcome.get("status"))
        .and_then(serde_json::Value::as_str)
    {
        Some("prepared") => Ok(EmptyOperationJournalStatus::Prepared),
        Some("succeeded-empty") => Ok(EmptyOperationJournalStatus::SucceededEmpty),
        status => Err(format!(
            "durable {kind} journal {} had unexpected status {status:?}",
            path.display()
        )),
    }
}

pub(crate) async fn container_operation_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    kind: &str,
    target: &ContainerTarget,
) -> Result<ContainerOperationJournalStatus, String> {
    let path = state_root
        .join("operations")
        .join(format!("{}.json", operation_id.as_str()));
    let contents = tokio::fs::read(&path).await.map_err(|error| {
        format!(
            "failed to read durable {kind} journal {}: {error}",
            path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_slice(&contents).map_err(|error| {
        format!(
            "failed to decode durable {kind} journal {}: {error}",
            path.display()
        )
    })?;
    let expected_generation = serde_json::to_value(target.generation)
        .map_err(|error| format!("failed to encode expected {kind} generation: {error}"))?;
    let identity_matches = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        == Some(crate::state::DURABLE_OPERATION_SCHEMA_VERSION)
        && value.get("operationId").and_then(serde_json::Value::as_str)
            == Some(operation_id.as_str())
        && value.get("kind").and_then(serde_json::Value::as_str) == Some(kind)
        && value.get("containerId").and_then(serde_json::Value::as_str) == Some(target.id.as_str())
        && value.get("generation") == Some(&expected_generation)
        && value.get("processId").is_none()
        && value
            .get("requestDigest")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|digest| !digest.is_empty());
    if !identity_matches {
        return Err(format!(
            "durable {kind} journal {} did not match the exact operation and generation",
            path.display()
        ));
    }
    let outcome = value
        .get("outcome")
        .ok_or_else(|| format!("durable {kind} journal {} has no outcome", path.display()))?;
    match outcome.get("status").and_then(serde_json::Value::as_str) {
        Some("prepared") => Ok(ContainerOperationJournalStatus::Prepared),
        Some("succeeded") => {
            let response: ContainerRecord =
                serde_json::from_value(outcome.get("response").cloned().ok_or_else(|| {
                    format!(
                        "durable {kind} journal {} has no container response",
                        path.display()
                    )
                })?)
                .map_err(|error| {
                    format!(
                        "failed to decode durable {kind} response {}: {error}",
                        path.display()
                    )
                })?;
            if response.state.id() != target.id.as_str()
                || response.generation != target.generation.unwrap_or(response.generation)
            {
                return Err(format!(
                    "durable {kind} response {} changed its exact target",
                    path.display()
                ));
            }
            Ok(ContainerOperationJournalStatus::Succeeded(Box::new(
                response,
            )))
        }
        status => Err(format!(
            "durable {kind} journal {} had unexpected status {status:?}",
            path.display()
        )),
    }
}

pub(crate) async fn process_operation_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    kind: &str,
    target: &ProcessTarget,
) -> Result<ProcessOperationJournalStatus, String> {
    let path = state_root
        .join("operations")
        .join(format!("{}.json", operation_id.as_str()));
    let contents = tokio::fs::read(&path).await.map_err(|error| {
        format!(
            "failed to read durable {kind} journal {}: {error}",
            path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_slice(&contents).map_err(|error| {
        format!(
            "failed to decode durable {kind} journal {}: {error}",
            path.display()
        )
    })?;
    let expected_generation = serde_json::to_value(target.container.generation)
        .map_err(|error| format!("failed to encode expected {kind} generation: {error}"))?;
    let identity_matches = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        == Some(crate::state::DURABLE_OPERATION_SCHEMA_VERSION)
        && value.get("operationId").and_then(serde_json::Value::as_str)
            == Some(operation_id.as_str())
        && value.get("kind").and_then(serde_json::Value::as_str) == Some(kind)
        && value.get("containerId").and_then(serde_json::Value::as_str)
            == Some(target.container.id.as_str())
        && value.get("generation") == Some(&expected_generation)
        && value.get("processId").and_then(serde_json::Value::as_str)
            == Some(target.process_id.as_str())
        && value
            .get("requestDigest")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|digest| !digest.is_empty());
    if !identity_matches {
        return Err(format!(
            "durable {kind} journal {} did not match the exact operation and process",
            path.display()
        ));
    }
    let outcome = value
        .get("outcome")
        .ok_or_else(|| format!("durable {kind} journal {} has no outcome", path.display()))?;
    match outcome.get("status").and_then(serde_json::Value::as_str) {
        Some("prepared") => Ok(ProcessOperationJournalStatus::Prepared),
        Some("succeeded-process") => {
            let response: ProcessRecord =
                serde_json::from_value(outcome.get("response").cloned().ok_or_else(|| {
                    format!(
                        "durable {kind} journal {} has no process response",
                        path.display()
                    )
                })?)
                .map_err(|error| {
                    format!(
                        "failed to decode durable {kind} response {}: {error}",
                        path.display()
                    )
                })?;
            if response.target != *target {
                return Err(format!(
                    "durable {kind} response {} changed its process target",
                    path.display()
                ));
            }
            Ok(ProcessOperationJournalStatus::Succeeded(response))
        }
        status => Err(format!(
            "durable {kind} journal {} had unexpected status {status:?}",
            path.display()
        )),
    }
}

pub(crate) async fn durable_process(
    state_root: &Path,
    target: &ProcessTarget,
) -> Result<ProcessRecord, String> {
    let path = state_root
        .join("containers")
        .join(target.container.id.as_str())
        .join("processes")
        .join(format!("{}.json", target.process_id.as_str()));
    let contents = tokio::fs::read(&path)
        .await
        .map_err(|error| format!("failed to read durable process {}: {error}", path.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&contents).map_err(|error| {
        format!(
            "failed to decode durable process {}: {error}",
            path.display()
        )
    })?;
    if value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        != Some("a3s.oci.process-record.v1")
        || value.get("activeOperation").is_some()
        || value.get("exitStatus").is_some()
    {
        return Err(format!(
            "durable process {} retained invalid active or terminal state",
            path.display()
        ));
    }
    let record: ProcessRecord = serde_json::from_value(
        value
            .get("record")
            .cloned()
            .ok_or_else(|| format!("durable process {} has no record", path.display()))?,
    )
    .map_err(|error| {
        format!(
            "failed to decode durable process {}: {error}",
            path.display()
        )
    })?;
    if record.target != *target {
        return Err(format!(
            "durable process {} changed its exact target",
            path.display()
        ));
    }
    Ok(record)
}
