use std::collections::BTreeMap;

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, LinuxResources};
use a3s_oci_sdk::{
    ContainerRecord, ContainerTarget, ErrorCode, OperationId, Result, RuntimeEventKind,
    UpdateRequest, ValidateRequest,
};
use serde::Serialize;

use crate::fault::DurableMutation;

use super::filesystem::state_error;
use super::model::{
    StoredOperation, StoredOperationKind, StoredOperationStatus, OPERATION_SCHEMA_VERSION,
};
use super::oci_state::{is_paused, rebuild_paused_state, rebuild_state};
use super::operation::{request_digest, validate_deadline, validate_retry};
use super::{
    claim_active_operation, ensure_active_operation, generation_conflict, DurableStateStore,
    RecordOperationPreparation,
};

#[derive(Serialize)]
struct UpdateFingerprint<'a> {
    target: &'a ContainerTarget,
    resources: &'a LinuxResources,
}

impl DurableStateStore {
    pub(crate) async fn prepare_update(
        &self,
        request: &UpdateRequest,
    ) -> Result<RecordOperationPreparation> {
        request.validate()?;
        let digest = request_digest(
            &UpdateFingerprint {
                target: &request.target,
                resources: &request.resources,
            },
            "update",
        )?;
        let _guard = self.gate.lock().await;

        if let Some(operation) = self
            .load_operation_if_present(&request.context.operation_id)
            .await?
        {
            validate_retry(
                &operation,
                &request.context.operation_id,
                StoredOperationKind::Update,
                &request.target.id,
                &digest,
                "update",
            )?;
            return match operation.outcome.clone() {
                StoredOperationStatus::Prepared => {
                    let mut stored = self
                        .load_stored_exact(&operation.container_id, operation.generation)
                        .await?;
                    claim_active_operation(
                        self,
                        &mut stored,
                        &request.context.operation_id,
                        DurableMutation::ClaimUpdateOperation,
                        "update",
                    )
                    .await?;
                    Ok(RecordOperationPreparation::Resume(stored.record))
                }
                StoredOperationStatus::Succeeded { response } => {
                    self.reconcile_succeeded_update(operation, response).await
                }
                StoredOperationStatus::Failed { error } => Err(error),
                StoredOperationStatus::SucceededProcess { .. }
                | StoredOperationStatus::SucceededFilesystem { .. }
                | StoredOperationStatus::SucceededEmpty => Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "update",
                    format!(
                        "update operation {} has an invalid outcome",
                        request.context.operation_id
                    ),
                )),
            };
        }

        validate_deadline(&request.context, "update")?;
        let mut stored = self.load_stored_container(&request.target.id).await?;
        if let Some(expected) = request.target.generation {
            if stored.record.generation != expected {
                return Err(generation_conflict(
                    &request.target.id,
                    expected,
                    stored.record.generation,
                    "update",
                ));
            }
        }
        if !matches!(
            *stored.record.state.status(),
            ContainerState::Created | ContainerState::Running
        ) {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "update",
                format!(
                    "container {} generation {} cannot update resources while {}",
                    stored.id,
                    stored.record.generation.0,
                    stored.record.state.status()
                ),
            ));
        }

        let operation = StoredOperation {
            schema_version: OPERATION_SCHEMA_VERSION.to_string(),
            operation_id: request.context.operation_id.clone(),
            kind: StoredOperationKind::Update,
            container_id: request.target.id.clone(),
            generation: stored.record.generation,
            process_id: None,
            request: None,
            request_digest: digest.current().to_string(),
            outcome: StoredOperationStatus::Prepared,
        };
        self.write_json(
            DurableMutation::PrepareUpdateOperation,
            &self.operation_path(&request.context.operation_id),
            &operation,
        )
        .await?;
        claim_active_operation(
            self,
            &mut stored,
            &request.context.operation_id,
            DurableMutation::ClaimUpdateOperation,
            "update",
        )
        .await?;
        Ok(RecordOperationPreparation::Prepared(stored.record))
    }

    async fn reconcile_succeeded_update(
        &self,
        mut operation: StoredOperation,
        response: ContainerRecord,
    ) -> Result<RecordOperationPreparation> {
        let stored = match self.load_stored_container(&operation.container_id).await {
            Ok(stored) => stored,
            Err(error) if error.code == ErrorCode::NotFound => {
                return Ok(RecordOperationPreparation::Replayed(response));
            }
            Err(error) => return Err(error),
        };
        if stored.record.generation != operation.generation || stored.record == response {
            return Ok(RecordOperationPreparation::Replayed(response));
        }
        let durable_status = *stored.record.state.status();
        let response_status = *response.state.status();
        if !matches!(
            durable_status,
            ContainerState::Created | ContainerState::Running
        ) || !matches!(
            response_status,
            ContainerState::Created | ContainerState::Running
        ) || stored.record.state.pid() == response.state.pid()
        {
            return Ok(RecordOperationPreparation::Replayed(response));
        }

        let mut rebound_state =
            rebuild_state(&response.state, response_status, *stored.record.state.pid())?;
        if is_paused(&response.state) {
            rebound_state = rebuild_paused_state(&rebound_state, true)?;
        }
        let rebound_response = ContainerRecord {
            state: rebound_state,
            ..response
        };
        let mut expected_state = rebuild_state(
            &rebound_response.state,
            durable_status,
            *stored.record.state.pid(),
        )?;
        if is_paused(&stored.record.state) {
            expected_state = rebuild_paused_state(&expected_state, true)?;
        }
        let expected_durable = ContainerRecord {
            state: expected_state,
            ..rebound_response.clone()
        };
        if expected_durable != stored.record {
            return Err(state_error(
                ErrorCode::Conflict,
                "update",
                format!(
                    "completed update operation {} changed beyond its recovered process identity",
                    operation.operation_id
                ),
            ));
        }

        operation.outcome = StoredOperationStatus::Succeeded {
            response: rebound_response.clone(),
        };
        self.write_json(
            DurableMutation::CompleteUpdateOperation,
            &self.operation_path(&operation.operation_id),
            &operation,
        )
        .await?;
        Ok(RecordOperationPreparation::Replayed(rebound_response))
    }

    pub(crate) async fn complete_update(
        &self,
        operation_id: &OperationId,
        status: ContainerState,
        pid: Option<i32>,
        paused: bool,
    ) -> Result<ContainerRecord> {
        if !matches!(status, ContainerState::Created | ContainerState::Running)
            || pid.is_none_or(|pid| pid <= 0)
            || (status == ContainerState::Created && paused)
        {
            return Err(state_error(
                ErrorCode::InvalidArgument,
                "update",
                format!(
                    "driver returned invalid update state {status} with PID {pid:?} and paused={paused}"
                ),
            ));
        }

        let _guard = self.gate.lock().await;
        let mut operation = self.load_operation(operation_id).await?;
        if operation.kind != StoredOperationKind::Update {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "update",
                format!("operation {operation_id} is not an OCI update"),
            ));
        }
        match &operation.outcome {
            StoredOperationStatus::Prepared => {}
            StoredOperationStatus::Succeeded { response } => return Ok(response.clone()),
            StoredOperationStatus::Failed { error } => return Err(error.clone()),
            StoredOperationStatus::SucceededProcess { .. }
            | StoredOperationStatus::SucceededFilesystem { .. }
            | StoredOperationStatus::SucceededEmpty => {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "update",
                    format!("update operation {operation_id} has an invalid outcome"),
                ));
            }
        }

        let mut stored = self.load_stored_container(&operation.container_id).await?;
        if stored.record.generation != operation.generation {
            return Err(generation_conflict(
                &operation.container_id,
                operation.generation,
                stored.record.generation,
                "update",
            ));
        }
        if *stored.record.state.status() != status
            || *stored.record.state.pid() != pid
            || is_paused(&stored.record.state) != paused
        {
            return Err(state_error(
                ErrorCode::Conflict,
                "update",
                format!(
                    "container {} durable state does not match the driver update response",
                    operation.container_id
                ),
            ));
        }

        ensure_active_operation(&stored, operation_id, "update")?;
        stored.active_operation = None;
        self.write_json(
            DurableMutation::CompleteUpdateContainer,
            &self
                .container_directory(&operation.container_id)
                .join(super::CONTAINER_RECORD_FILE),
            &stored,
        )
        .await?;
        let response = stored.record.clone();
        self.append_operation_event(
            operation_id,
            "resources-updated",
            &ContainerTarget::exact(operation.container_id.clone(), operation.generation),
            None,
            RuntimeEventKind::ResourcesUpdated,
            BTreeMap::from([(
                "operation-id".to_string(),
                operation_id.as_str().to_string(),
            )]),
        )
        .await?;
        operation.outcome = StoredOperationStatus::Succeeded {
            response: response.clone(),
        };
        self.write_json(
            DurableMutation::CompleteUpdateOperation,
            &self.operation_path(operation_id),
            &operation,
        )
        .await?;
        Ok(response)
    }
}
