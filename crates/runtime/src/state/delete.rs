use std::collections::BTreeMap;
use std::path::PathBuf;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, DeleteMode, DeleteRequest, ErrorCode, OperationId, Result, RuntimeEventKind,
    ValidateRequest,
};
use serde::Serialize;

use crate::fault::DurableMutation;

use super::filesystem::{path_exists, state_error};
use super::model::{
    StoredOperation, StoredOperationKind, StoredOperationStatus, OPERATION_SCHEMA_VERSION,
};
use super::operation::{request_digest, validate_deadline, validate_retry};
use super::{
    claim_active_operation, ensure_active_operation, generation_conflict, DeletePreparation,
    DurableStateStore,
};

#[derive(Serialize)]
struct DeleteFingerprint<'a> {
    target: &'a ContainerTarget,
    mode: DeleteMode,
}

impl DurableStateStore {
    pub(crate) async fn prepare_delete(
        &self,
        request: &DeleteRequest,
    ) -> Result<DeletePreparation> {
        request.validate()?;
        let digest = request_digest(
            &DeleteFingerprint {
                target: &request.target,
                mode: request.mode,
            },
            "digest-delete-request",
        )?;
        let _guard = self.gate.lock().await;

        if let Some(mut operation) = self
            .load_operation_if_present(&request.context.operation_id)
            .await?
        {
            validate_retry(
                &operation,
                &request.context.operation_id,
                StoredOperationKind::Delete,
                &request.target.id,
                &digest,
                "prepare-delete",
            )?;
            return match &operation.outcome {
                StoredOperationStatus::Prepared => {
                    let source = self.container_directory(&operation.container_id);
                    let tombstone = self.delete_tombstone(&operation.operation_id);
                    match (path_exists(&source).await?, path_exists(&tombstone).await?) {
                        (true, false) => {
                            let mut stored = self
                                .load_stored_exact(&operation.container_id, operation.generation)
                                .await?;
                            claim_active_operation(
                                self,
                                &mut stored,
                                &request.context.operation_id,
                                DurableMutation::ClaimDeleteOperation,
                                "prepare-delete",
                            )
                            .await?;
                            Ok(DeletePreparation::Resume(stored.record))
                        }
                        (false, true) => {
                            self.append_delete_event(&operation).await?;
                            operation.outcome = StoredOperationStatus::SucceededEmpty;
                            self.write_json(
                                DurableMutation::ReconcileDeleteOperation,
                                &self.operation_path(&request.context.operation_id),
                                &operation,
                            )
                            .await?;
                            Ok(DeletePreparation::Replayed)
                        }
                        (true, true) => {
                            let live = self.load_stored_container(&operation.container_id).await?;
                            if live.record.generation == operation.generation {
                                Err(state_error(
                                    ErrorCode::Conflict,
                                    "prepare-delete",
                                    format!(
                                        "delete operation {} has both a live record and tombstone",
                                        request.context.operation_id
                                    ),
                                ))
                            } else {
                                self.append_delete_event(&operation).await?;
                                operation.outcome = StoredOperationStatus::SucceededEmpty;
                                self.write_json(
                                    DurableMutation::ReconcileDeleteOperation,
                                    &self.operation_path(&request.context.operation_id),
                                    &operation,
                                )
                                .await?;
                                Ok(DeletePreparation::Replayed)
                            }
                        }
                        (false, false) => Err(state_error(
                            ErrorCode::Unavailable,
                            "prepare-delete",
                            format!(
                                "delete operation {} has neither a live record nor tombstone",
                                request.context.operation_id
                            ),
                        )
                        .retryable(true)),
                    }
                }
                StoredOperationStatus::SucceededEmpty => Ok(DeletePreparation::Replayed),
                StoredOperationStatus::Failed { error } => Err(error.clone()),
                StoredOperationStatus::Succeeded { .. }
                | StoredOperationStatus::SucceededProcess { .. } => Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "prepare-delete",
                    format!(
                        "delete operation {} has an invalid state response",
                        request.context.operation_id
                    ),
                )),
            };
        }

        validate_deadline(&request.context, "prepare-delete")?;
        let mut stored = self.load_stored_container(&request.target.id).await?;
        if let Some(expected) = request.target.generation {
            if stored.record.generation != expected {
                return Err(generation_conflict(
                    &request.target.id,
                    expected,
                    stored.record.generation,
                    "prepare-delete",
                ));
            }
        }
        let status = *stored.record.state.status();
        match request.mode {
            DeleteMode::StoppedOnly if status != ContainerState::Stopped => {
                return Err(invalid_state(&request.target, status));
            }
            DeleteMode::Force if status == ContainerState::Creating => {
                return Err(state_error(
                    ErrorCode::Conflict,
                    "prepare-delete",
                    format!(
                        "container {} create operation is still in progress",
                        request.target.id
                    ),
                ));
            }
            DeleteMode::StoppedOnly | DeleteMode::Force => {}
        }
        self.ensure_no_active_process_operations(&stored, "prepare-delete")
            .await?;

        let operation = StoredOperation {
            schema_version: OPERATION_SCHEMA_VERSION.to_string(),
            operation_id: request.context.operation_id.clone(),
            kind: StoredOperationKind::Delete,
            container_id: request.target.id.clone(),
            generation: stored.record.generation,
            process_id: None,
            request_digest: digest,
            outcome: StoredOperationStatus::Prepared,
        };
        self.write_json(
            DurableMutation::PrepareDeleteOperation,
            &self.operation_path(&request.context.operation_id),
            &operation,
        )
        .await?;
        claim_active_operation(
            self,
            &mut stored,
            &request.context.operation_id,
            DurableMutation::ClaimDeleteOperation,
            "prepare-delete",
        )
        .await?;
        Ok(DeletePreparation::Prepared(stored.record))
    }

    pub(crate) async fn complete_delete(&self, operation_id: &OperationId) -> Result<()> {
        let _guard = self.gate.lock().await;
        let mut operation = self.load_operation(operation_id).await?;
        if operation.kind != StoredOperationKind::Delete {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "complete-delete",
                format!("operation {operation_id} is not an OCI delete"),
            ));
        }
        match &operation.outcome {
            StoredOperationStatus::Prepared => {}
            StoredOperationStatus::SucceededEmpty => return Ok(()),
            StoredOperationStatus::Failed { error } => return Err(error.clone()),
            StoredOperationStatus::Succeeded { .. }
            | StoredOperationStatus::SucceededProcess { .. } => {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "complete-delete",
                    format!("delete operation {operation_id} has an invalid state response"),
                ));
            }
        }

        let source = self.container_directory(&operation.container_id);
        let tombstone = self.delete_tombstone(operation_id);
        match (path_exists(&source).await?, path_exists(&tombstone).await?) {
            (true, false) => {
                let stored = self
                    .load_stored_exact(&operation.container_id, operation.generation)
                    .await?;
                ensure_active_operation(&stored, operation_id, "complete-delete")?;
                self.move_directory(DurableMutation::MoveDeleteTombstone, &source, &tombstone)
                    .await?;
            }
            (false, true) => {}
            (true, true) => {
                let live = self.load_stored_container(&operation.container_id).await?;
                if live.record.generation == operation.generation {
                    return Err(state_error(
                        ErrorCode::Conflict,
                        "complete-delete",
                        format!(
                            "delete operation {operation_id} has both a live record and tombstone"
                        ),
                    ));
                }
            }
            (false, false) => {
                return Err(state_error(
                    ErrorCode::Unavailable,
                    "complete-delete",
                    format!(
                        "delete operation {operation_id} has neither a live record nor tombstone"
                    ),
                )
                .retryable(true));
            }
        }

        self.append_delete_event(&operation).await?;
        operation.outcome = StoredOperationStatus::SucceededEmpty;
        self.write_json(
            DurableMutation::CompleteDeleteOperation,
            &self.operation_path(operation_id),
            &operation,
        )
        .await
    }

    fn delete_tombstone(&self, operation_id: &OperationId) -> PathBuf {
        self.root
            .join("quarantine")
            .join(format!("{}.deleted", operation_id.as_str()))
    }

    async fn append_delete_event(&self, operation: &StoredOperation) -> Result<()> {
        let target = ContainerTarget::exact(operation.container_id.clone(), operation.generation);
        self.append_container_event(
            "stopped",
            &target,
            RuntimeEventKind::ContainerStopped,
            BTreeMap::new(),
        )
        .await?;
        self.append_container_event(
            "deleted",
            &target,
            RuntimeEventKind::ContainerDeleted,
            BTreeMap::new(),
        )
        .await
        .map(|_| ())
    }
}

fn invalid_state(target: &ContainerTarget, status: ContainerState) -> a3s_oci_sdk::Error {
    state_error(
        ErrorCode::FailedPrecondition,
        "prepare-delete",
        format!(
            "container {} generation {:?} cannot be deleted without force while {status}",
            target.id, target.generation
        ),
    )
}
