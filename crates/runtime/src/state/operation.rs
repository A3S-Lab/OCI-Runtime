use std::time::{SystemTime, UNIX_EPOCH};

use a3s_oci_sdk::{
    canonical_json_bytes, ContainerId, ErrorCode, OperationContext, OperationId, Result,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::filesystem::state_error;
use super::model::{
    StoredOperation, StoredOperationKind, OPERATION_SCHEMA_VERSION, OPERATION_SCHEMA_VERSION_V1,
    OPERATION_SCHEMA_VERSION_V2, OPERATION_SCHEMA_VERSION_V3, OPERATION_SCHEMA_VERSION_V4,
    OPERATION_SCHEMA_VERSION_V5,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RequestDigests {
    legacy: String,
    canonical: String,
}

impl RequestDigests {
    pub(super) fn current(&self) -> &str {
        &self.canonical
    }

    #[cfg(test)]
    pub(super) fn legacy(&self) -> &str {
        &self.legacy
    }

    fn for_schema(&self, schema_version: &str) -> Option<&str> {
        match schema_version {
            OPERATION_SCHEMA_VERSION_V1 => Some(&self.legacy),
            OPERATION_SCHEMA_VERSION_V2
            | OPERATION_SCHEMA_VERSION_V3
            | OPERATION_SCHEMA_VERSION_V4
            | OPERATION_SCHEMA_VERSION_V5
            | OPERATION_SCHEMA_VERSION => Some(&self.canonical),
            _ => None,
        }
    }
}

pub(super) fn request_digest(
    value: &impl Serialize,
    operation: &'static str,
) -> Result<RequestDigests> {
    let legacy = serde_json::to_vec(value).map_err(|error| {
        state_error(
            ErrorCode::Internal,
            operation,
            format!("failed to encode legacy operation request fingerprint: {error}"),
        )
    })?;
    let canonical = canonical_json_bytes(value).map_err(|error| {
        state_error(
            ErrorCode::Internal,
            operation,
            format!("failed to encode canonical operation request fingerprint: {error}"),
        )
    })?;
    Ok(RequestDigests {
        legacy: sha256_digest(legacy),
        canonical: sha256_digest(canonical),
    })
}

fn sha256_digest(bytes: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(bytes.as_ref());
    format!("sha256:{digest:x}")
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
    request_digests: &RequestDigests,
    operation: &'static str,
) -> Result<()> {
    let expected_digest = request_digests
        .for_schema(&stored.schema_version)
        .ok_or_else(|| {
            state_error(
                ErrorCode::FailedPrecondition,
                operation,
                format!(
                    "operation ID {operation_id} uses unsupported durable schema {}",
                    stored.schema_version
                ),
            )
        })?;
    if stored.kind != kind
        || stored.container_id != *container_id
        || stored.request_digest != expected_digest
    {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            operation,
            format!("operation ID {operation_id} was already used for a different request"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use a3s_oci_sdk::{ContainerId, Generation, OperationId};
    use serde::Serialize;

    use super::{request_digest, validate_retry};
    use crate::state::model::{
        StoredOperation, StoredOperationKind, StoredOperationStatus, OPERATION_SCHEMA_VERSION,
        OPERATION_SCHEMA_VERSION_V1, OPERATION_SCHEMA_VERSION_V2, OPERATION_SCHEMA_VERSION_V3,
        OPERATION_SCHEMA_VERSION_V4, OPERATION_SCHEMA_VERSION_V5,
    };

    #[derive(Serialize)]
    struct Fingerprint {
        resources: HashMap<String, String>,
    }

    #[test]
    fn durable_request_digest_is_stable_across_unordered_map_reconstruction() {
        let first = Fingerprint {
            resources: HashMap::from([
                ("memory.low".to_string(), "0".to_string()),
                ("memory.high".to_string(), "1".to_string()),
            ]),
        };
        let reopened = Fingerprint {
            resources: HashMap::from([
                ("memory.high".to_string(), "1".to_string()),
                ("memory.low".to_string(), "0".to_string()),
            ]),
        };

        let first = request_digest(&first, "test-fingerprint").expect("first request digest");
        let reopened =
            request_digest(&reopened, "test-fingerprint").expect("reopened request digest");
        assert_eq!(first.current(), reopened.current());
    }

    #[derive(Serialize)]
    struct OrderedFixture {
        zulu: u64,
        alpha: u64,
    }

    #[test]
    fn durable_request_digest_validates_each_persisted_schema_with_its_encoding() {
        let request = OrderedFixture { zulu: 1, alpha: 2 };
        let digests = request_digest(&request, "test-fingerprint").expect("request digests");
        assert_ne!(digests.legacy, digests.canonical);

        let operation_id = OperationId::new("schema-fingerprint").expect("operation ID");
        let container_id = ContainerId::new("schema-container").expect("container ID");
        for (schema_version, request_digest) in [
            (OPERATION_SCHEMA_VERSION_V1, digests.legacy.clone()),
            (OPERATION_SCHEMA_VERSION_V2, digests.canonical.clone()),
            (OPERATION_SCHEMA_VERSION_V3, digests.canonical.clone()),
            (OPERATION_SCHEMA_VERSION_V4, digests.canonical.clone()),
            (OPERATION_SCHEMA_VERSION_V5, digests.canonical.clone()),
            (OPERATION_SCHEMA_VERSION, digests.canonical.clone()),
        ] {
            let stored = StoredOperation {
                schema_version: schema_version.to_string(),
                operation_id: operation_id.clone(),
                kind: StoredOperationKind::Update,
                container_id: container_id.clone(),
                generation: Generation(1),
                process_id: None,
                request: None,
                request_digest,
                outcome: StoredOperationStatus::Prepared,
            };
            validate_retry(
                &stored,
                &operation_id,
                StoredOperationKind::Update,
                &container_id,
                &digests,
                "test-fingerprint",
            )
            .expect("schema-specific request digest");
        }
    }
}
