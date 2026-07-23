use a3s_oci_core::{LifecycleEvent, LifecycleState};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, ErrorCode, OciSchemaValidator, OciSemanticPhase, OperationId, Result,
    StartRequest, ValidateRequest,
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
struct StartFingerprint<'a> {
    target: &'a ContainerTarget,
}

impl DurableStateStore {
    pub(crate) async fn prepare_start(
        &self,
        request: &StartRequest,
    ) -> Result<RecordOperationPreparation> {
        request.validate()?;
        let digest = request_digest(
            &StartFingerprint {
                target: &request.target,
            },
            "digest-start-request",
        )?;
        let _guard = self.gate.lock().await;

        if let Some(mut operation) = self
            .load_operation_if_present(&request.context.operation_id)
            .await?
        {
            validate_retry(
                &operation,
                &request.context.operation_id,
                StoredOperationKind::Start,
                &request.target.id,
                &digest,
                "prepare-start",
            )?;
            return match &operation.outcome {
                StoredOperationStatus::Prepared => {
                    let mut stored = self
                        .load_stored_exact(&operation.container_id, operation.generation)
                        .await?;
                    match *stored.record.state.status() {
                        ContainerState::Created => {
                            claim_active_operation(
                                self,
                                &mut stored,
                                &request.context.operation_id,
                                "prepare-start",
                            )
                            .await?;
                            Ok(RecordOperationPreparation::Resume(stored.record))
                        }
                        ContainerState::Running | ContainerState::Stopped => {
                            ensure_active_operation(
                                &stored,
                                &request.context.operation_id,
                                "prepare-start",
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
                            Ok(RecordOperationPreparation::Replayed(stored.record))
                        }
                        status => Err(invalid_state(&request.target, status, "resume-start")),
                    }
                }
                StoredOperationStatus::Succeeded { response } => {
                    Ok(RecordOperationPreparation::Replayed(response.clone()))
                }
                StoredOperationStatus::Failed { error } => Err(error.clone()),
                StoredOperationStatus::SucceededEmpty => Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "prepare-start",
                    format!(
                        "start operation {} has an invalid empty outcome",
                        request.context.operation_id
                    ),
                )),
            };
        }

        validate_deadline(&request.context, "prepare-start")?;
        let mut stored = self.load_stored_container(&request.target.id).await?;
        if let Some(expected) = request.target.generation {
            if stored.record.generation != expected {
                return Err(generation_conflict(
                    &request.target.id,
                    expected,
                    stored.record.generation,
                    "prepare-start",
                ));
            }
        }
        if *stored.record.state.status() != ContainerState::Created {
            return Err(invalid_state(
                &request.target,
                *stored.record.state.status(),
                "prepare-start",
            ));
        }
        self.load_bundle(&stored)
            .await?
            .validate_for_phase(OciSemanticPhase::Start)?;

        let operation = StoredOperation {
            schema_version: OPERATION_SCHEMA_VERSION.to_string(),
            operation_id: request.context.operation_id.clone(),
            kind: StoredOperationKind::Start,
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
            "prepare-start",
        )
        .await?;
        Ok(RecordOperationPreparation::Prepared(stored.record))
    }

    pub(crate) async fn complete_start(
        &self,
        operation_id: &OperationId,
        status: ContainerState,
        pid: Option<i32>,
    ) -> Result<a3s_oci_sdk::ContainerRecord> {
        match (status, pid) {
            (ContainerState::Running, Some(pid)) if pid > 0 => {}
            (ContainerState::Stopped, None) => {}
            _ => {
                return Err(state_error(
                    ErrorCode::InvalidArgument,
                    "complete-start",
                    format!("driver returned invalid start state {status} with PID {pid:?}"),
                ));
            }
        }
        let _guard = self.gate.lock().await;
        let mut operation = self.load_operation(operation_id).await?;
        if operation.kind != StoredOperationKind::Start {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "complete-start",
                format!("operation {operation_id} is not an OCI start"),
            ));
        }
        match &operation.outcome {
            StoredOperationStatus::Prepared => {}
            StoredOperationStatus::Succeeded { response } => return Ok(response.clone()),
            StoredOperationStatus::Failed { error } => return Err(error.clone()),
            StoredOperationStatus::SucceededEmpty => {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "complete-start",
                    format!("start operation {operation_id} has an invalid empty outcome"),
                ));
            }
        }

        let mut stored = self.load_stored_container(&operation.container_id).await?;
        if stored.record.generation != operation.generation {
            return Err(generation_conflict(
                &operation.container_id,
                operation.generation,
                stored.record.generation,
                "complete-start",
            ));
        }
        match *stored.record.state.status() {
            ContainerState::Created => {
                let prepared_pid = *stored.record.state.pid();
                if status == ContainerState::Running && prepared_pid != pid {
                    return Err(pid_conflict(&operation.container_id, prepared_pid, pid));
                }
                let running = LifecycleState::Created
                    .transition(LifecycleEvent::StartCompleted)
                    .map_err(|error| {
                        state_error(
                            ErrorCode::FailedPrecondition,
                            "complete-start",
                            error.to_string(),
                        )
                    })?;
                let lifecycle = if status == ContainerState::Stopped {
                    running
                        .transition(LifecycleEvent::ProcessExited)
                        .map_err(|error| {
                            state_error(
                                ErrorCode::FailedPrecondition,
                                "complete-start",
                                error.to_string(),
                            )
                        })?
                } else {
                    running
                };
                stored.record.state = rebuild_state(
                    &stored.record.state,
                    container_state(lifecycle),
                    if status == ContainerState::Running {
                        prepared_pid
                    } else {
                        None
                    },
                )?;
                OciSchemaValidator::new()?.validate_state(&stored.record.state)?;
            }
            ContainerState::Running if status == ContainerState::Running => {
                if *stored.record.state.pid() != pid {
                    return Err(pid_conflict(
                        &operation.container_id,
                        *stored.record.state.pid(),
                        pid,
                    ));
                }
            }
            ContainerState::Running if status == ContainerState::Stopped => {
                let stopped = LifecycleState::Running
                    .transition(LifecycleEvent::ProcessExited)
                    .map_err(|error| {
                        state_error(
                            ErrorCode::FailedPrecondition,
                            "complete-start",
                            error.to_string(),
                        )
                    })?;
                stored.record.state =
                    rebuild_state(&stored.record.state, container_state(stopped), None)?;
                OciSchemaValidator::new()?.validate_state(&stored.record.state)?;
            }
            ContainerState::Stopped if status == ContainerState::Stopped => {}
            status => {
                return Err(invalid_state(
                    &ContainerTarget::exact(operation.container_id.clone(), operation.generation),
                    status,
                    "complete-start",
                ));
            }
        }

        ensure_active_operation(&stored, operation_id, "complete-start")?;
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

fn pid_conflict(
    container_id: &a3s_oci_sdk::ContainerId,
    durable: Option<i32>,
    observed: Option<i32>,
) -> a3s_oci_sdk::Error {
    state_error(
        ErrorCode::Conflict,
        "complete-start",
        format!("container {container_id} PID mismatch: durable {durable:?}, driver {observed:?}"),
    )
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
            "container {} generation {:?} cannot start while {status}",
            target.id, target.generation
        ),
    )
}
