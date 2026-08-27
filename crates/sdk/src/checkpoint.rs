//! Immutable, capability-gated checkpoint and restore contracts.

use crate::{Error, ErrorCode};

mod artifact;
mod reference;
mod request;
mod response;

pub use artifact::{CheckpointArtifactPath, CheckpointDigest, CheckpointFormat};
pub use reference::{CheckpointCompatibility, CheckpointQuiesce, CheckpointReference};
pub use request::{CheckpointRequest, RestoreRequest};
pub use response::{CheckpointResponse, RestoreResponse};

/// First immutable checkpoint-reference schema.
pub const CHECKPOINT_REFERENCE_SCHEMA_V1: &str = "a3s.oci.checkpoint-reference.v1";
/// Maximum UTF-8 length of one already-authorized local checkpoint artifact path.
pub const MAX_CHECKPOINT_ARTIFACT_PATH_BYTES: usize = 4_096;

const MAX_CHECKPOINT_FORMAT_NAME_BYTES: usize = 128;
const MAX_CHECKPOINT_ARCHITECTURE_BYTES: usize = 64;

fn validate_token(value: &str, label: &str, maximum: usize) -> crate::Result<()> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(checkpoint_error(format!("{label} must not be empty")));
    };
    if value.len() > maximum
        || !first.is_ascii_lowercase() && !first.is_ascii_digit()
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'+' | b'-')
        })
    {
        return Err(checkpoint_error(format!(
            "{label} must be at most {maximum} bytes of canonical lowercase ASCII"
        )));
    }
    Ok(())
}

fn checkpoint_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message).for_operation("validate-checkpoint-contract")
}

#[cfg(test)]
mod tests;
