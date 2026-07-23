use std::time::{SystemTime, UNIX_EPOCH};

use a3s_oci_sdk::{ContainerId, CreateRequest, ErrorCode, OciBundle, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::filesystem::state_error;
use super::model::{StoredOperation, StoredOperationKind};

#[derive(Serialize)]
struct CreateRequestFingerprint<'a> {
    id: &'a ContainerId,
    bundle: &'a OciBundle,
    isolation: &'a a3s_oci_sdk::IsolationRequest,
    io: &'a a3s_oci_sdk::ProcessIo,
}

pub(super) fn create_request_digest(request: &CreateRequest) -> Result<String> {
    let bytes = serde_json::to_vec(&CreateRequestFingerprint {
        id: &request.id,
        bundle: &request.bundle,
        isolation: &request.isolation,
        io: &request.io,
    })
    .map_err(|error| {
        state_error(
            ErrorCode::Internal,
            "digest-create-request",
            format!("failed to encode create request: {error}"),
        )
    })?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{digest:x}"))
}

pub(super) fn validate_create_retry(
    operation: &StoredOperation,
    request: &CreateRequest,
    request_digest: &str,
) -> Result<()> {
    if operation.kind != StoredOperationKind::Create
        || operation.container_id != request.id
        || operation.request_digest != request_digest
    {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "prepare-create",
            format!(
                "operation ID {} was already used for a different request",
                request.context.operation_id
            ),
        ));
    }
    Ok(())
}

pub(super) fn validate_deadline(request: &CreateRequest) -> Result<()> {
    let Some(deadline) = request.context.deadline_unix_ms else {
        return Ok(());
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            state_error(
                ErrorCode::Internal,
                "validate-operation-deadline",
                format!("system clock is before the Unix epoch: {error}"),
            )
        })?
        .as_millis();
    if now >= u128::from(deadline) {
        return Err(state_error(
            ErrorCode::DeadlineExceeded,
            "prepare-create",
            format!("create operation deadline {deadline} has expired"),
        ));
    }
    Ok(())
}
