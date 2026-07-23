use a3s_oci_sdk::{ContainerId, CreateRequest, OciBundle, Result};
use serde::Serialize;

use super::model::{StoredOperation, StoredOperationKind};
use super::operation::{request_digest, validate_retry};

#[derive(Serialize)]
struct CreateRequestFingerprint<'a> {
    id: &'a ContainerId,
    bundle: &'a OciBundle,
    isolation: &'a a3s_oci_sdk::IsolationRequest,
    io: &'a a3s_oci_sdk::ProcessIo,
}

pub(super) fn create_request_digest(request: &CreateRequest) -> Result<String> {
    request_digest(
        &CreateRequestFingerprint {
            id: &request.id,
            bundle: &request.bundle,
            isolation: &request.isolation,
            io: &request.io,
        },
        "digest-create-request",
    )
}

pub(super) fn validate_create_retry(
    operation: &StoredOperation,
    request: &CreateRequest,
    request_digest: &str,
) -> Result<()> {
    validate_retry(
        operation,
        &request.context.operation_id,
        StoredOperationKind::Create,
        &request.id,
        request_digest,
        "prepare-create",
    )
}
