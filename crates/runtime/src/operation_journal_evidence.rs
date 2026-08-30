use std::path::Path;

use a3s_oci_sdk::{ContainerRecord, ContainerTarget, OperationId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ContainerOperationJournalStatus {
    Prepared,
    Succeeded(Box<ContainerRecord>),
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
