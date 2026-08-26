use std::collections::BTreeMap;

use a3s_oci_sdk::{ErrorCode, Result};

use super::{
    event_identity_hash, is_transaction_file, parse_event_claim_name, parse_event_record_name,
    validate_event_record, validate_exact_event_target,
};
use crate::state::filesystem::state_error;
use crate::state::model::{StoredEventClaim, StoredEventRecord, EVENT_CLAIM_SCHEMA_VERSION};
use crate::state::DurableStateStore;

impl DurableStateStore {
    /// Validate every committed event claim and record without repairing an
    /// interrupted claim whose sequence record has not been written yet.
    pub(in crate::state) async fn audit_event_journal(&self) -> Result<()> {
        let cursor = self.load_event_cursor().await?;
        let claims_directory = self.event_claims_directory();
        let mut claims = BTreeMap::new();
        for entry in self
            .filesystem
            .read_directory(&claims_directory, "runtime event claims")
            .await?
        {
            let name = entry.into_string().map_err(|name| {
                state_error(
                    ErrorCode::FailedPrecondition,
                    "audit-runtime-events",
                    format!("runtime event claim directory contains a non-UTF-8 entry: {name:?}"),
                )
            })?;
            if is_transaction_file(&name) {
                continue;
            }
            let expected_hash = parse_event_claim_name(&name)?;
            let claim: StoredEventClaim = self
                .filesystem
                .read_json(&claims_directory.join(&name))
                .await?;
            if claim.schema_version != EVENT_CLAIM_SCHEMA_VERSION
                || event_identity_hash(&claim.identity) != expected_hash
                || claim.event.sequence == 0
                || claim.event.sequence > cursor.last_sequence
            {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "audit-runtime-events",
                    format!("invalid durable runtime event claim {name:?}"),
                ));
            }
            validate_exact_event_target(&claim.event)?;
            if claims.insert(claim.event.sequence, claim.event).is_some() {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "audit-runtime-events",
                    "runtime event sequence has more than one durable identity claim",
                ));
            }
        }

        let records_directory = self.event_records_directory();
        for entry in self
            .filesystem
            .read_directory(&records_directory, "runtime event records")
            .await?
        {
            let name = entry.into_string().map_err(|name| {
                state_error(
                    ErrorCode::FailedPrecondition,
                    "audit-runtime-events",
                    format!("runtime event record directory contains a non-UTF-8 entry: {name:?}"),
                )
            })?;
            if is_transaction_file(&name) {
                continue;
            }
            let sequence = parse_event_record_name(&name)?;
            let stored: StoredEventRecord = self
                .filesystem
                .read_json(&records_directory.join(&name))
                .await?;
            validate_event_record(&stored, sequence, cursor.last_sequence)?;
            match claims.get(&sequence) {
                Some(claimed) if claimed == &stored.event => {}
                Some(_) => {
                    return Err(state_error(
                        ErrorCode::FailedPrecondition,
                        "audit-runtime-events",
                        format!(
                            "runtime event sequence {sequence} disagrees with its durable identity claim"
                        ),
                    ));
                }
                None => {
                    return Err(state_error(
                        ErrorCode::FailedPrecondition,
                        "audit-runtime-events",
                        format!("runtime event sequence {sequence} has no durable identity claim"),
                    ));
                }
            }
        }
        Ok(())
    }
}
