use std::time::{SystemTime, UNIX_EPOCH};

use a3s_oci_sdk::{ContainerId, ErrorCode, OperationContext, OperationId, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::filesystem::state_error;
use super::model::{StoredOperation, StoredOperationKind};

pub(super) fn request_digest(value: &impl Serialize, operation: &'static str) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        state_error(
            ErrorCode::Internal,
            operation,
            format!("failed to encode operation request: {error}"),
        )
    })?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{digest:x}"))
}

pub(super) fn validate_deadline(context: &OperationContext, operation: &'static str) -> Result<()> {
    let Some(deadline) = context.deadline_unix_ms else {
        return Ok(());
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            state_error(
                ErrorCode::Internal,
                operation,
                format!("system clock is before the Unix epoch: {error}"),
            )
        })?
        .as_millis();
    if now >= u128::from(deadline) {
        return Err(state_error(
            ErrorCode::DeadlineExceeded,
            operation,
            format!("operation deadline {deadline} has expired"),
        ));
    }
    Ok(())
}

pub(super) fn validate_retry(
    stored: &StoredOperation,
    operation_id: &OperationId,
    kind: StoredOperationKind,
    container_id: &ContainerId,
    request_digest: &str,
    operation: &'static str,
) -> Result<()> {
    if stored.kind != kind
        || stored.container_id != *container_id
        || stored.request_digest != request_digest
    {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            operation,
            format!("operation ID {operation_id} was already used for a different request"),
        ));
    }
    Ok(())
}
