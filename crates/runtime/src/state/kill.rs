use a3s_oci_core::{LifecycleEvent, LifecycleState};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerRecord, ContainerTarget, ErrorCode, KillRequest, OciSchemaValidator, OperationId,
    Result, ValidateRequest,
};
use serde::Serialize;

use super::filesystem::{atomic_write_json, state_error};
use super::model::{
    StoredOperation, StoredOperationKind, StoredOperationStatus, OPERATION_SCHEMA_VERSION,
};
use super::oci_state::{container_state, rebuild_state};
use super::operation::{request_digest, validate_deadline, validate_retry};
use super::{
    claim_active_operation, ensure_active_operation, generation_conflict, DurableStateStore,
    RecordOperationPreparation,
};

#[derive(Serialize)]
struct KillFingerprint<'a> {
    target: &'a ContainerTarget,
    signal: a3s_oci_sdk::Signal,
    all: bool,
}

impl DurableStateStore {
    pub(crate) async fn prepare_kill(
        &self,
        request: &KillRequest,
    ) -> Result<RecordOperationPreparation> {
        request.validate()?;
        let digest = request_digest(
            &KillFingerprint {
                target: &request.target,
                signal: request.signal,
                all: request.all,
            },
            "digest-kill-request",
        )?;
        let _guard = self.gate.lock().await;

        if let Some(mut operation) = self
            .load_operation_if_present(&request.context.operation_id)
            .await?
        {
            validate_retry(
                &operation,
                &request.context.operation_id,
                StoredOperationKind::Kill,
                &request.target.id,
                &digest,
                "prepare-kill",
            )?;
            return match &operation.outcome {
                StoredOperationStatus::Prepared => {
                    let mut stored = self
                        .load_stored_exact(&operation.container_id, operation.generation)
                        .await?;
                    if *stored.record.state.status() == ContainerState::Stopped {
                        ensure_active_operation(
                            &stored,
                            &request.context.operation_id,
                            "prepare-kill",
                        )?;
                        if stored.active_operation.is_some() {
                            stored.active_operation = None;
                            atomic_write_json(
                                &self
                                    .container_directory(&operation.container_id)
                                    .join(super::CONTAINER_RECORD_FILE),
                                &stored,
                            )
                            .await?;
                        }
                        operation.outcome = StoredOperationStatus::Succeeded {
                            response: stored.record.clone(),
                        };
                        atomic_write_json(
                            &self.operation_path(&request.context.operation_id),
                            &operation,
                        )
                        .await?;
                        return Ok(RecordOperationPreparation::Replayed(stored.record));
                    }
                    claim_active_operation(
                        self,
                        &mut stored,
                        &request.context.operation_id,
                        "prepare-kill",
                    )
                    .await?;
                    Ok(RecordOperationPreparation::Resume(stored.record))
                }
                StoredOperationStatus::Succeeded { response } => {
                    Ok(RecordOperationPreparation::Replayed(response.clone()))
                }
                StoredOperationStatus::Failed { error } => Err(error.clone()),
                StoredOperationStatus::SucceededEmpty => Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "prepare-kill",
                    format!(
                        "kill operation {} has an invalid empty outcome",
                        request.context.operation_id
                    ),
                )),
            };
        }

        validate_deadline(&request.context, "prepare-kill")?;
        let mut stored = self.load_stored_container(&request.target.id).await?;
        if let Some(expected) = request.target.generation {
            if stored.record.generation != expected {
                return Err(generation_conflict(
                    &request.target.id,
                    expected,
                    stored.record.generation,
                    "prepare-kill",
                ));
            }
        }
        if !matches!(
            *stored.record.state.status(),
            ContainerState::Created | ContainerState::Running
        ) {
            return Err(invalid_state(
                &request.target,
                *stored.record.state.status(),
                "prepare-kill",
            ));
        }

        let operation = StoredOperation {
            schema_version: OPERATION_SCHEMA_VERSION.to_string(),
            operation_id: request.context.operation_id.clone(),
            kind: StoredOperationKind::Kill,
            container_id: request.target.id.clone(),
            generation: stored.record.generation,
            request_digest: digest,
            outcome: StoredOperationStatus::Prepared,
        };
        atomic_write_json(
            &self.operation_path(&request.context.operation_id),
            &operation,
        )
        .await?;
        claim_active_operation(
            self,
            &mut stored,
            &request.context.operation_id,
            "prepare-kill",
        )
        .await?;
        Ok(RecordOperationPreparation::Prepared(stored.record))
    }

    pub(crate) async fn complete_kill(
        &self,
        operation_id: &OperationId,
        status: ContainerState,
        pid: Option<i32>,
    ) -> Result<ContainerRecord> {
        validate_observed_state(status, pid, "complete-kill")?;
        let _guard = self.gate.lock().await;
        let mut operation = self.load_operation(operation_id).await?;
        if operation.kind != StoredOperationKind::Kill {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "complete-kill",
                format!("operation {operation_id} is not an OCI kill"),
            ));
        }
        match &operation.outcome {
            StoredOperationStatus::Prepared => {}
            StoredOperationStatus::Succeeded { response } => return Ok(response.clone()),
            StoredOperationStatus::Failed { error } => return Err(error.clone()),
            StoredOperationStatus::SucceededEmpty => {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "complete-kill",
                    format!("kill operation {operation_id} has an invalid empty outcome"),
                ));
            }
        }

        let mut stored = self.load_stored_container(&operation.container_id).await?;
        if stored.record.generation != operation.generation {
            return Err(generation_conflict(
                &operation.container_id,
                operation.generation,
                stored.record.generation,
                "complete-kill",
            ));
        }
        let current = *stored.record.state.status();
        match (current, status) {
            (ContainerState::Created, ContainerState::Created)
            | (ContainerState::Running, ContainerState::Running) => {
                if *stored.record.state.pid() != pid {
                    return Err(pid_conflict(&stored.record, pid, "complete-kill"));
                }
            }
            (ContainerState::Created | ContainerState::Running, ContainerState::Stopped) => {
                let lifecycle = lifecycle_state(current)
                    .transition(LifecycleEvent::ProcessExited)
                    .map_err(|error| {
                        state_error(
                            ErrorCode::FailedPrecondition,
                            "complete-kill",
                            error.to_string(),
                        )
                    })?;
                stored.record.state =
                    rebuild_state(&stored.record.state, container_state(lifecycle), None)?;
                OciSchemaValidator::new()?.validate_state(&stored.record.state)?;
            }
            (ContainerState::Stopped, ContainerState::Stopped) => {}
            (_, observed) => {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "complete-kill",
                    format!(
                        "container {} cannot reconcile {current} to {observed}",
                        operation.container_id
                    ),
                ));
            }
        }

        ensure_active_operation(&stored, operation_id, "complete-kill")?;
        stored.active_operation = None;
        atomic_write_json(
            &self
                .container_directory(&operation.container_id)
                .join(super::CONTAINER_RECORD_FILE),
            &stored,
        )
        .await?;
        let response = stored.record.clone();
        operation.outcome = StoredOperationStatus::Succeeded {
            response: response.clone(),
        };
        atomic_write_json(&self.operation_path(operation_id), &operation).await?;
        Ok(response)
    }
}

fn validate_observed_state(
    status: ContainerState,
    pid: Option<i32>,
    operation: &'static str,
) -> Result<()> {
    match (status, pid) {
        (ContainerState::Created | ContainerState::Running, Some(pid)) if pid > 0 => Ok(()),
        (ContainerState::Stopped, None) => Ok(()),
        _ => Err(state_error(
            ErrorCode::InvalidArgument,
            operation,
            format!("driver returned invalid OCI state {status} with PID {pid:?}"),
        )),
    }
}

const fn lifecycle_state(status: ContainerState) -> LifecycleState {
    match status {
        ContainerState::Creating => LifecycleState::Creating,
        ContainerState::Created => LifecycleState::Created,
        ContainerState::Running => LifecycleState::Running,
        ContainerState::Stopped => LifecycleState::Stopped,
    }
}

fn invalid_state(
    target: &ContainerTarget,
    status: ContainerState,
    operation: &'static str,
) -> a3s_oci_sdk::Error {
    state_error(
        ErrorCode::FailedPrecondition,
        operation,
        format!(
            "container {} generation {:?} cannot be signaled while {status}",
            target.id, target.generation
        ),
    )
}

fn pid_conflict(
    record: &ContainerRecord,
    observed: Option<i32>,
    operation: &'static str,
) -> a3s_oci_sdk::Error {
    state_error(
        ErrorCode::Conflict,
        operation,
        format!(
            "container {} PID mismatch: durable {:?}, driver {observed:?}",
            record.state.id(),
            record.state.pid()
        ),
    )
}
