use a3s_oci_core::{LifecycleEvent, LifecycleState};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{ContainerRecord, ContainerTarget, ErrorCode, OciSchemaValidator, Result};

use super::filesystem::{atomic_write_json, state_error};
use super::model::{StoredOperation, StoredOperationKind, StoredOperationStatus};
use super::oci_state::{container_state, rebuild_state};
use super::{generation_conflict, DurableStateStore};

impl DurableStateStore {
    pub(crate) async fn observe_state(
        &self,
        target: &ContainerTarget,
        status: ContainerState,
        pid: Option<i32>,
    ) -> Result<ContainerRecord> {
        validate_observation(status, pid)?;
        let _guard = self.gate.lock().await;
        let mut stored = self.load_stored_container(&target.id).await?;
        if let Some(expected) = target.generation {
            if stored.record.generation != expected {
                return Err(generation_conflict(
                    &target.id,
                    expected,
                    stored.record.generation,
                    "observe-state",
                ));
            }
        }

        let current = *stored.record.state.status();
        let mut active = if let Some(operation_id) = stored.active_operation.as_ref() {
            let operation = self.load_operation(operation_id).await?;
            validate_active_operation(&stored, &operation)?;
            Some(operation)
        } else {
            None
        };
        let completes_active = active
            .as_ref()
            .is_some_and(|operation| observation_completes(operation.kind, status));
        let mut state_changed = false;
        match (current, status) {
            (ContainerState::Created, ContainerState::Created)
            | (ContainerState::Running, ContainerState::Running) => {
                if *stored.record.state.pid() != pid {
                    return Err(state_error(
                        ErrorCode::Conflict,
                        "observe-state",
                        format!(
                            "container {} PID mismatch: durable {:?}, driver {pid:?}",
                            target.id,
                            stored.record.state.pid()
                        ),
                    ));
                }
            }
            (ContainerState::Created, ContainerState::Running)
                if active
                    .as_ref()
                    .is_some_and(|operation| operation.kind == StoredOperationKind::Start) =>
            {
                let running = LifecycleState::Created
                    .transition(LifecycleEvent::StartCompleted)
                    .map_err(|error| {
                        state_error(
                            ErrorCode::FailedPrecondition,
                            "observe-state",
                            error.to_string(),
                        )
                    })?;
                stored.record.state =
                    rebuild_state(&stored.record.state, container_state(running), pid)?;
                OciSchemaValidator::new()?.validate_state(&stored.record.state)?;
                state_changed = true;
            }
            (ContainerState::Created | ContainerState::Running, ContainerState::Stopped) => {
                let lifecycle = lifecycle_state(current)
                    .transition(LifecycleEvent::ProcessExited)
                    .map_err(|error| {
                        state_error(
                            ErrorCode::FailedPrecondition,
                            "observe-state",
                            error.to_string(),
                        )
                    })?;
                stored.record.state =
                    rebuild_state(&stored.record.state, container_state(lifecycle), None)?;
                OciSchemaValidator::new()?.validate_state(&stored.record.state)?;
                state_changed = true;
            }
            (ContainerState::Stopped, ContainerState::Stopped) => {}
            (_, observed) => {
                return Err(state_error(
                    ErrorCode::Conflict,
                    "observe-state",
                    format!(
                        "container {} cannot reconcile durable {current} with driver {observed}",
                        target.id
                    ),
                ));
            }
        }

        if completes_active {
            stored.active_operation = None;
            state_changed = true;
        }
        if state_changed {
            atomic_write_json(
                &self
                    .container_directory(&target.id)
                    .join(super::CONTAINER_RECORD_FILE),
                &stored,
            )
            .await?;
        }
        if completes_active {
            let mut operation = active.take().ok_or_else(|| {
                state_error(
                    ErrorCode::Internal,
                    "observe-state",
                    "active operation disappeared during state reconciliation",
                )
            })?;
            operation.outcome = StoredOperationStatus::Succeeded {
                response: stored.record.clone(),
            };
            atomic_write_json(&self.operation_path(&operation.operation_id), &operation).await?;
        }
        Ok(stored.record)
    }
}

fn validate_active_operation(
    stored: &super::model::StoredContainer,
    operation: &StoredOperation,
) -> Result<()> {
    if operation.container_id != stored.id
        || operation.generation != stored.record.generation
        || !matches!(operation.outcome, StoredOperationStatus::Prepared)
    {
        return Err(state_error(
            ErrorCode::Conflict,
            "observe-state",
            format!(
                "container {} active operation {} does not match its durable record",
                stored.id, operation.operation_id
            ),
        ));
    }
    Ok(())
}

const fn observation_completes(kind: StoredOperationKind, status: ContainerState) -> bool {
    match kind {
        StoredOperationKind::Start => {
            matches!(status, ContainerState::Running | ContainerState::Stopped)
        }
        StoredOperationKind::Kill => matches!(status, ContainerState::Stopped),
        StoredOperationKind::Create | StoredOperationKind::Delete => false,
    }
}

fn validate_observation(status: ContainerState, pid: Option<i32>) -> Result<()> {
    match (status, pid) {
        (ContainerState::Created | ContainerState::Running, Some(pid)) if pid > 0 => Ok(()),
        (ContainerState::Stopped, None) => Ok(()),
        _ => Err(state_error(
            ErrorCode::InvalidArgument,
            "observe-state",
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
