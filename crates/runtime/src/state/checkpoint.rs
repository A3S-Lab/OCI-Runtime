use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    CheckpointArtifactPath, CheckpointDigest, CheckpointQuiesce, CheckpointRequest,
    CheckpointResponse, ContainerRecord, ErrorCode, OperationId, Result, ValidateRequest,
};
use serde::Serialize;

use crate::fault::DurableMutation;

use super::filesystem::state_error;
use super::model::{
    StoredOperation, StoredOperationKind, StoredOperationRequest, StoredOperationStatus,
    OPERATION_SCHEMA_VERSION,
};
use super::operation::{request_digest, validate_deadline, validate_retry, RequestDigests};
use super::{
    claim_active_operation, ensure_active_operation, generation_conflict,
    CheckpointOperationPreparation, DurableStateStore,
};

#[derive(Serialize)]
struct CheckpointFingerprint<'a> {
    target: &'a a3s_oci_sdk::ContainerTarget,
    artifact_path: &'a CheckpointArtifactPath,
    quiesce: CheckpointQuiesce,
}

impl DurableStateStore {
    pub(crate) async fn prepare_checkpoint(
        &self,
        request: &CheckpointRequest,
    ) -> Result<CheckpointOperationPreparation> {
        request.validate()?;
        let digest = checkpoint_request_digest(request)?;
        let operation_id = &request.context().operation_id;
        let _guard = self.gate.lock().await;

        if let Some(operation) = self.load_operation_if_present(operation_id).await? {
            validate_retry(
                &operation,
                operation_id,
                StoredOperationKind::Checkpoint,
                &request.target().id,
                &digest,
                "checkpoint",
            )?;
            if operation.request.as_ref()
                != Some(&StoredOperationRequest::Checkpoint(request.clone()))
            {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "checkpoint",
                    format!(
                        "operation ID {operation_id} was already used for a different checkpoint request"
                    ),
                ));
            }
            return match operation.outcome {
                StoredOperationStatus::Prepared => {
                    let mut stored = self
                        .load_stored_exact(&operation.container_id, operation.generation)
                        .await?;
                    ensure_checkpoint_source(&stored.record)?;
                    self.ensure_no_active_process_operations(&stored, "checkpoint")
                        .await?;
                    claim_active_operation(
                        self,
                        &mut stored,
                        operation_id,
                        DurableMutation::ClaimCheckpointOperation,
                        "checkpoint",
                    )
                    .await?;
                    Ok(CheckpointOperationPreparation::Resume(stored.record))
                }
                StoredOperationStatus::SucceededCheckpoint { response } => {
                    Ok(CheckpointOperationPreparation::Replayed(response))
                }
                StoredOperationStatus::Failed { error } => Err(error),
                StoredOperationStatus::Succeeded { .. }
                | StoredOperationStatus::SucceededProcess { .. }
                | StoredOperationStatus::SucceededFilesystem { .. }
                | StoredOperationStatus::SucceededEmpty => Err(invalid_outcome(operation_id)),
            };
        }

        validate_deadline(request.context(), "checkpoint")?;
        let mut stored = self.load_stored_container(&request.target().id).await?;
        let expected_generation = request.target().generation.ok_or_else(|| {
            state_error(
                ErrorCode::InvalidArgument,
                "checkpoint",
                "checkpoint request does not contain an exact generation",
            )
        })?;
        if stored.record.generation != expected_generation {
            return Err(generation_conflict(
                &request.target().id,
                expected_generation,
                stored.record.generation,
                "checkpoint",
            ));
        }
        ensure_checkpoint_source(&stored.record)?;
        self.ensure_no_active_process_operations(&stored, "checkpoint")
            .await?;

        let operation = StoredOperation {
            schema_version: OPERATION_SCHEMA_VERSION.to_string(),
            operation_id: operation_id.clone(),
            kind: StoredOperationKind::Checkpoint,
            container_id: stored.id.clone(),
            generation: stored.record.generation,
            process_id: None,
            request: Some(StoredOperationRequest::Checkpoint(request.clone())),
            request_digest: digest.current().to_string(),
            outcome: StoredOperationStatus::Prepared,
        };
        self.write_json(
            DurableMutation::PrepareCheckpointOperation,
            &self.operation_path(operation_id),
            &operation,
        )
        .await?;
        claim_active_operation(
            self,
            &mut stored,
            operation_id,
            DurableMutation::ClaimCheckpointOperation,
            "checkpoint",
        )
        .await?;
        Ok(CheckpointOperationPreparation::Prepared(stored.record))
    }

    pub(crate) async fn complete_checkpoint(
        &self,
        operation_id: &OperationId,
        response: CheckpointResponse,
    ) -> Result<CheckpointResponse> {
        let _guard = self.gate.lock().await;
        let mut operation = self.load_operation(operation_id).await?;
        if operation.kind != StoredOperationKind::Checkpoint {
            return Err(invalid_outcome(operation_id));
        }
        match &operation.outcome {
            StoredOperationStatus::Prepared => {}
            StoredOperationStatus::SucceededCheckpoint { response } => {
                return Ok(response.as_ref().clone());
            }
            StoredOperationStatus::Failed { error } => return Err(error.clone()),
            StoredOperationStatus::Succeeded { .. }
            | StoredOperationStatus::SucceededProcess { .. }
            | StoredOperationStatus::SucceededFilesystem { .. }
            | StoredOperationStatus::SucceededEmpty => return Err(invalid_outcome(operation_id)),
        }
        let Some(StoredOperationRequest::Checkpoint(request)) = operation.request.as_ref() else {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "checkpoint",
                format!("checkpoint operation {operation_id} has no retained request"),
            ));
        };
        response.validate_for_request(request)?;

        let mut stored = self
            .load_stored_exact(&operation.container_id, operation.generation)
            .await?;
        ensure_checkpoint_source(&stored.record)?;
        if response.source() != &stored.record {
            return Err(state_error(
                ErrorCode::Conflict,
                "checkpoint",
                format!(
                    "checkpoint operation {operation_id} returned a source record that differs from durable state"
                ),
            ));
        }
        ensure_active_operation(&stored, operation_id, "checkpoint")?;
        stored.active_operation = None;
        self.write_json(
            DurableMutation::CompleteCheckpointContainer,
            &self
                .container_directory(&operation.container_id)
                .join(super::CONTAINER_RECORD_FILE),
            &stored,
        )
        .await?;

        operation.outcome = StoredOperationStatus::SucceededCheckpoint {
            response: Box::new(response.clone()),
        };
        self.write_json(
            DurableMutation::CompleteCheckpointOperation,
            &self.operation_path(operation_id),
            &operation,
        )
        .await?;
        Ok(response)
    }
}

pub(super) fn checkpoint_request_digest(request: &CheckpointRequest) -> Result<RequestDigests> {
    request_digest(
        &CheckpointFingerprint {
            target: request.target(),
            artifact_path: request.artifact_path(),
            quiesce: request.quiesce(),
        },
        "checkpoint",
    )
}

fn ensure_checkpoint_source(record: &ContainerRecord) -> Result<()> {
    if *record.state.status() != ContainerState::Running || !record.is_paused() {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "checkpoint",
            format!(
                "container {} generation {} must be running and paused before checkpoint",
                record.state.id(),
                record.generation.0
            ),
        ));
    }
    CheckpointDigest::new(record.config_digest.clone()).map_err(|error| {
        state_error(
            ErrorCode::FailedPrecondition,
            "checkpoint",
            format!(
                "checkpoint source has an invalid configuration digest: {}",
                error.message
            ),
        )
    })?;
    let attachments = record.attachments_digest.as_ref().ok_or_else(|| {
        state_error(
            ErrorCode::FailedPrecondition,
            "checkpoint",
            "checkpoint source has no attachment-manifest digest",
        )
    })?;
    CheckpointDigest::new(attachments.clone()).map_err(|error| {
        state_error(
            ErrorCode::FailedPrecondition,
            "checkpoint",
            format!(
                "checkpoint source has an invalid attachment digest: {}",
                error.message
            ),
        )
    })?;
    Ok(())
}

fn invalid_outcome(operation_id: &OperationId) -> a3s_oci_sdk::Error {
    state_error(
        ErrorCode::FailedPrecondition,
        "checkpoint",
        format!("checkpoint operation {operation_id} has an invalid durable outcome"),
    )
}
