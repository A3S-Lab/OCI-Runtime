use a3s_oci_sdk::{Error, ErrorCode, OperationId, Result};

use super::filesystem::{atomic_move_directory, atomic_write_json, path_exists, state_error};
use super::model::{StoredOperationKind, StoredOperationStatus};
use super::{ensure_active_operation, DurableStateStore, CONTAINER_RECORD_FILE};

impl DurableStateStore {
    /// Persist a terminal driver failure so the same operation replays the
    /// exact error and no later mutation remains blocked by an abandoned claim.
    pub(crate) async fn fail_operation(
        &self,
        operation_id: &OperationId,
        error: &Error,
    ) -> Result<()> {
        if error.retryable {
            return Ok(());
        }

        let _guard = self.gate.lock().await;
        let mut operation = self.load_operation(operation_id).await?;
        match &operation.outcome {
            StoredOperationStatus::Prepared => {}
            StoredOperationStatus::Failed { error: durable } if durable == error => {
                if operation.kind == StoredOperationKind::Create {
                    self.reconcile_failed_create(&operation).await?;
                }
                return Ok(());
            }
            StoredOperationStatus::Failed { .. } => {
                return Err(state_error(
                    ErrorCode::Conflict,
                    "fail-operation",
                    format!("operation {operation_id} already has a different failure"),
                ));
            }
            StoredOperationStatus::Succeeded { .. } | StoredOperationStatus::SucceededEmpty => {
                return Err(state_error(
                    ErrorCode::Conflict,
                    "fail-operation",
                    format!("operation {operation_id} already succeeded"),
                ));
            }
        }

        if operation.kind == StoredOperationKind::Create {
            // Journal first. If the host dies before the directory move, the
            // next retry can still recover the exact error and finish cleanup.
            operation.outcome = StoredOperationStatus::Failed {
                error: error.clone(),
            };
            atomic_write_json(&self.operation_path(operation_id), &operation).await?;
            self.reconcile_failed_create(&operation).await?;
            return Ok(());
        }

        let mut stored = self
            .load_stored_exact(&operation.container_id, operation.generation)
            .await?;
        ensure_active_operation(&stored, operation_id, "fail-operation")?;
        stored.active_operation = None;
        atomic_write_json(
            &self
                .container_directory(&operation.container_id)
                .join(CONTAINER_RECORD_FILE),
            &stored,
        )
        .await?;
        operation.outcome = StoredOperationStatus::Failed {
            error: error.clone(),
        };
        atomic_write_json(&self.operation_path(operation_id), &operation).await
    }

    pub(super) async fn reconcile_failed_create(
        &self,
        operation: &super::model::StoredOperation,
    ) -> Result<()> {
        if operation.kind != StoredOperationKind::Create {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "reconcile-failed-create",
                format!("operation {} is not an OCI create", operation.operation_id),
            ));
        }
        if !matches!(operation.outcome, StoredOperationStatus::Failed { .. }) {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "reconcile-failed-create",
                format!("operation {} has not failed", operation.operation_id),
            ));
        }

        let source = self.container_directory(&operation.container_id);
        let tombstone = self.failed_create_tombstone(&operation.operation_id);
        match (path_exists(&source).await?, path_exists(&tombstone).await?) {
            (true, false) => {
                let stored = self
                    .load_stored_exact(&operation.container_id, operation.generation)
                    .await?;
                ensure_active_operation(
                    &stored,
                    &operation.operation_id,
                    "reconcile-failed-create",
                )?;
                atomic_move_directory(&source, &tombstone).await
            }
            (true, true) => {
                let live = self.load_stored_container(&operation.container_id).await?;
                if live.record.generation == operation.generation {
                    Err(state_error(
                        ErrorCode::Conflict,
                        "reconcile-failed-create",
                        format!(
                            "failed create operation {} has both live state and a tombstone",
                            operation.operation_id
                        ),
                    ))
                } else {
                    // The failed generation is already quarantined and the
                    // container ID has legitimately been reused.
                    Ok(())
                }
            }
            (false, true) | (false, false) => Ok(()),
        }
    }
}
