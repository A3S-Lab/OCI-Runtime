use std::collections::BTreeMap;
use std::path::PathBuf;

use a3s_oci_agent_protocol::AgentState;
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{ErrorCode, OperationId, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::process::PreparedProcess;
use super::{executor_error, MAX_OPERATION_RECORDS};

#[derive(Debug, Default)]
pub(super) struct ExecutorState {
    pub(super) containers: BTreeMap<ContainerKey, ContainerRecord>,
    pub(super) highest_generations: BTreeMap<String, u64>,
    operations: BTreeMap<OperationId, OperationRecord>,
    pub(super) next_slot: u64,
}

impl ExecutorState {
    pub(super) fn reserve_operation(&self, operation_id: &OperationId) -> Result<()> {
        if self.operations.len() >= MAX_OPERATION_RECORDS {
            Err(executor_error(
                ErrorCode::ResourceExhausted,
                format!(
                    "guest operation journal reached {MAX_OPERATION_RECORDS} entries before \
                     operation {operation_id}"
                ),
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn replay_state(
        &self,
        operation_id: &OperationId,
        request: &RecordedRequest,
    ) -> Option<Result<AgentState>> {
        self.operations.get(operation_id).map(|record| {
            record.validate_request(request)?;
            match &record.outcome {
                RecordedOutcome::State(result) => result.clone(),
                RecordedOutcome::Deleted(_) => Err(reused_operation(operation_id)),
            }
        })
    }

    pub(super) fn replay_delete(
        &self,
        operation_id: &OperationId,
        request: &RecordedRequest,
    ) -> Option<Result<()>> {
        self.operations.get(operation_id).map(|record| {
            record.validate_request(request)?;
            match &record.outcome {
                RecordedOutcome::Deleted(result) => result.clone(),
                RecordedOutcome::State(_) => Err(reused_operation(operation_id)),
            }
        })
    }

    pub(super) fn record(
        &mut self,
        operation_id: OperationId,
        request: RecordedRequest,
        outcome: RecordedOutcome,
    ) {
        self.operations
            .insert(operation_id, OperationRecord { request, outcome });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ContainerKey {
    pub(super) id: String,
    pub(super) generation: u64,
}

impl ContainerKey {
    pub(super) fn from_target(target: &a3s_oci_sdk::ContainerTarget) -> Result<Self> {
        let generation = target.generation.ok_or_else(|| {
            executor_error(
                ErrorCode::InvalidArgument,
                "guest executor requires an exact container generation",
            )
        })?;
        if generation.0 == 0 {
            return Err(executor_error(
                ErrorCode::InvalidArgument,
                "guest executor requires a positive container generation",
            ));
        }
        Ok(Self {
            id: target.id.as_str().to_string(),
            generation: generation.0,
        })
    }
}

#[derive(Debug)]
pub(super) struct ContainerRecord {
    pub(super) target: a3s_oci_sdk::ContainerTarget,
    pub(super) config_digest: String,
    pub(super) status: ContainerState,
    pub(super) process: PreparedProcess,
    pub(super) runtime_directory: PathBuf,
}

impl ContainerRecord {
    pub(super) fn refresh(&mut self) -> Result<()> {
        if self.process.try_wait()?.is_some() {
            self.status = ContainerState::Stopped;
        }
        Ok(())
    }

    pub(super) fn state(&self) -> Result<AgentState> {
        AgentState::new(
            self.target.clone(),
            self.status,
            if self.status == ContainerState::Stopped {
                None
            } else {
                Some(self.process.pid())
            },
            self.config_digest.clone(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MutationKind {
    Create,
    Start,
    Kill,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RecordedRequest {
    kind: MutationKind,
    digest: [u8; 32],
}

impl RecordedRequest {
    pub(super) fn new(kind: MutationKind, request: &impl Serialize) -> Result<Self> {
        let encoded = serde_json::to_vec(request).map_err(|error| {
            executor_error(
                ErrorCode::Internal,
                format!("failed to fingerprint guest operation request: {error}"),
            )
        })?;
        Ok(Self {
            kind,
            digest: Sha256::digest(encoded).into(),
        })
    }
}

#[derive(Debug, Clone)]
struct OperationRecord {
    request: RecordedRequest,
    outcome: RecordedOutcome,
}

impl OperationRecord {
    fn validate_request(&self, request: &RecordedRequest) -> Result<()> {
        if &self.request == request {
            Ok(())
        } else {
            Err(executor_error(
                ErrorCode::Conflict,
                "guest operation ID was reused for a different request",
            ))
        }
    }
}

#[derive(Debug, Clone)]
pub(super) enum RecordedOutcome {
    State(Result<AgentState>),
    Deleted(Result<()>),
}

fn reused_operation(operation_id: &OperationId) -> a3s_oci_sdk::Error {
    executor_error(
        ErrorCode::Conflict,
        format!("guest operation ID {operation_id} was reused across operation kinds"),
    )
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::{ErrorCode, OperationId};
    use serde_json::json;

    use super::{ExecutorState, MutationKind, RecordedOutcome, RecordedRequest};

    #[test]
    fn guest_operation_journal_replays_only_the_exact_request() {
        let operation_id = OperationId::new("guest-create-1").expect("valid operation ID");
        let request = RecordedRequest::new(MutationKind::Delete, &json!({"target": "one"}))
            .expect("fingerprint request");
        let mut state = ExecutorState::default();
        state.record(
            operation_id.clone(),
            request.clone(),
            RecordedOutcome::Deleted(Ok(())),
        );

        assert_eq!(state.replay_delete(&operation_id, &request), Some(Ok(())));
        let changed = RecordedRequest::new(MutationKind::Delete, &json!({"target": "two"}))
            .expect("fingerprint changed request");
        let error = state
            .replay_delete(&operation_id, &changed)
            .expect("operation exists")
            .expect_err("changed request must fail");
        assert_eq!(error.code, ErrorCode::Conflict);
    }
}
