use a3s_oci_sdk::oci_spec::runtime::{ContainerState, LinuxResources};
use a3s_oci_sdk::ContainerRecord;
use containerd_shim::TtrpcResult;

use super::*;
pub(super) use crate::metadata::update_request_digest;

#[derive(Debug, Clone)]
pub(super) struct PreparedControl {
    pub(super) task: TaskState,
    pub(super) operation: PendingControlOperation,
}

impl Service {
    pub(super) async fn prepare_control(
        &self,
        task_id: &str,
        control_gate: &Arc<Mutex<()>>,
        kind: ControlOperationKind,
        request_digest: Option<String>,
        resources: Option<LinuxResources>,
    ) -> TtrpcResult<Option<PreparedControl>> {
        let _guard = self.metadata_gate.lock().await;
        let mut state = self.state.lock().await;
        let task = state
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| ttrpc_not_found(format!("unknown task {task_id}")))?;
        if !Arc::ptr_eq(&task.control_gate, control_gate) {
            return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                ttrpc::Code::ABORTED,
                format!("task {task_id} was replaced while waiting for its control lock"),
            )));
        }
        if task.restore_state == RestoreState::PendingStart {
            return Err(runtime_error(
                RuntimeError::new(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "containerd {kind:?} requires the restored task to pass its Start barrier"
                    ),
                )
                .for_operation("containerd-restore-start-barrier"),
            ));
        }

        if let Some(pending) = task.pending_control.clone() {
            if pending.kind() != kind || pending.request_digest() != request_digest.as_deref() {
                return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                    ttrpc::Code::ABORTED,
                    format!(
                        "task {task_id} has pending {:?} control sequence {}; retry that request before {:?}",
                        pending.kind(),
                        pending.sequence(),
                        kind,
                    ),
                )));
            }
            let operation = match resources {
                Some(resources) => pending
                    .with_update_resources(resources)
                    .map_err(runtime_error)?,
                None => pending.clone(),
            };
            if operation == pending {
                return Ok(Some(PreparedControl {
                    task: task.clone(),
                    operation,
                }));
            }

            task.pending_control = Some(operation.clone());
            let snapshot = task.clone();
            drop(state);
            if let Err(error) = metadata_from_task(&snapshot).store() {
                let mut state = self.state.lock().await;
                if let Some(task) = state.tasks.get_mut(task_id) {
                    if task.pending_control.as_ref() == Some(&operation) {
                        task.pending_control = Some(pending);
                    }
                }
                return Err(runtime_error(error));
            }
            return Ok(Some(PreparedControl {
                task: snapshot,
                operation,
            }));
        }

        if control_already_applied(task, kind, request_digest.as_deref()) {
            return Ok(None);
        }

        let sequence = task.control_sequence.checked_add(1).ok_or_else(|| {
            runtime_error(
                RuntimeError::new(
                    ErrorCode::ResourceExhausted,
                    format!("task {task_id} exhausted its durable control sequence"),
                )
                .for_operation("containerd-control-prepare"),
            )
        })?;
        let operation = PendingControlOperation::new(sequence, kind, request_digest, resources)
            .map_err(runtime_error)?;
        task.pending_control = Some(operation.clone());
        let snapshot = task.clone();
        drop(state);
        if let Err(error) = metadata_from_task(&snapshot).store() {
            let mut state = self.state.lock().await;
            if let Some(task) = state.tasks.get_mut(task_id) {
                if task.pending_control.as_ref() == Some(&operation) {
                    task.pending_control = None;
                }
            }
            return Err(runtime_error(error));
        }
        Ok(Some(PreparedControl {
            task: snapshot,
            operation,
        }))
    }

    pub(super) async fn complete_control(
        &self,
        task_id: &str,
        operation: &PendingControlOperation,
        record: ContainerRecord,
    ) -> TtrpcResult<()> {
        validate_control_response(operation.kind(), &record)?;
        let _guard = self.metadata_gate.lock().await;
        let mut state = self.state.lock().await;
        let task = state
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| ttrpc_not_found(format!("unknown task {task_id}")))?;
        if task.pending_control.as_ref() != Some(operation) {
            return Err(ttrpc_error(format!(
                "task {task_id} control sequence {} changed before completion",
                operation.sequence()
            )));
        }
        validate_control_target(task, operation.kind(), &record)?;
        let previous_record = task.record.clone();
        let previous_sequence = task.control_sequence;
        let previous_update_digest = task.last_update_digest.clone();
        task.record = record;
        task.control_sequence = operation.sequence();
        task.pending_control = None;
        if operation.kind() == ControlOperationKind::Update {
            task.last_update_digest = operation.request_digest().map(str::to_string);
        }
        let snapshot = task.clone();
        drop(state);
        if let Err(error) = metadata_from_task(&snapshot).store() {
            let mut state = self.state.lock().await;
            if let Some(task) = state.tasks.get_mut(task_id) {
                if task.control_sequence == operation.sequence() && task.pending_control.is_none() {
                    task.record = previous_record;
                    task.control_sequence = previous_sequence;
                    task.pending_control = Some(operation.clone());
                    task.last_update_digest = previous_update_digest;
                }
            }
            return Err(runtime_error(error));
        }
        Ok(())
    }

    pub(super) async fn finish_control_error(
        &self,
        task_id: &str,
        operation: &PendingControlOperation,
        error: &RuntimeError,
    ) -> TtrpcResult<()> {
        if error.retryable {
            return Ok(());
        }
        let _guard = self.metadata_gate.lock().await;
        let mut state = self.state.lock().await;
        let task = state
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| ttrpc_not_found(format!("unknown task {task_id}")))?;
        if task.pending_control.as_ref() != Some(operation) {
            return Err(ttrpc_error(format!(
                "task {task_id} control sequence {} changed after failure",
                operation.sequence()
            )));
        }
        let previous_sequence = task.control_sequence;
        task.control_sequence = operation.sequence();
        task.pending_control = None;
        let snapshot = task.clone();
        drop(state);
        if let Err(store_error) = metadata_from_task(&snapshot).store() {
            let mut state = self.state.lock().await;
            if let Some(task) = state.tasks.get_mut(task_id) {
                if task.control_sequence == operation.sequence() && task.pending_control.is_none() {
                    task.control_sequence = previous_sequence;
                    task.pending_control = Some(operation.clone());
                }
            }
            return Err(runtime_error(store_error));
        }
        Ok(())
    }
}

pub(super) async fn replay_pending(
    adapter: &RuntimeAdapter,
    task: &mut TaskState,
) -> Result<(), RuntimeError> {
    let Some(operation) = task.pending_control.clone() else {
        return Ok(());
    };
    if operation.kind() == ControlOperationKind::Update && operation.resources().is_none() {
        return Ok(());
    }

    let record = match dispatch(adapter, task, &operation).await {
        Ok(record) => Some(record),
        Err(error) if error.retryable => return Err(error),
        Err(error) => {
            log::warn!(
                "settling terminal failure while replaying containerd {:?} control sequence {}: {error}",
                operation.kind(),
                operation.sequence()
            );
            None
        }
    };
    complete_replayed(task, &operation, record)?;
    metadata_from_task(task).store()
}

async fn dispatch(
    adapter: &RuntimeAdapter,
    task: &TaskState,
    operation: &PendingControlOperation,
) -> Result<ContainerRecord, RuntimeError> {
    match operation.kind() {
        ControlOperationKind::Pause => {
            adapter
                .pause(&task.identity, task.record.generation, operation.sequence())
                .await
        }
        ControlOperationKind::Resume => {
            adapter
                .resume(&task.identity, task.record.generation, operation.sequence())
                .await
        }
        ControlOperationKind::Update => {
            let resources = operation.resources().cloned().ok_or_else(|| {
                control_error(format!(
                    "pending Update control sequence {} omitted its Linux resources",
                    operation.sequence()
                ))
            })?;
            adapter
                .update(
                    &task.identity,
                    task.record.generation,
                    operation.sequence(),
                    resources,
                )
                .await
        }
    }
}

fn complete_replayed(
    task: &mut TaskState,
    operation: &PendingControlOperation,
    record: Option<ContainerRecord>,
) -> Result<(), RuntimeError> {
    if task.pending_control.as_ref() != Some(operation)
        || task.control_sequence.checked_add(1) != Some(operation.sequence())
    {
        return Err(control_error(format!(
            "cannot commit replayed {:?} control sequence {} from completed sequence {}",
            operation.kind(),
            operation.sequence(),
            task.control_sequence
        )));
    }
    if let Some(record) = record {
        validate_control_response_runtime(operation.kind(), &record)?;
        validate_control_target_runtime(task, operation.kind(), &record)?;
        task.record = record;
        if operation.kind() == ControlOperationKind::Update {
            task.last_update_digest = operation.request_digest().map(str::to_string);
        }
    }
    task.control_sequence = operation.sequence();
    task.pending_control = None;
    Ok(())
}

fn control_already_applied(
    task: &TaskState,
    kind: ControlOperationKind,
    request_digest: Option<&str>,
) -> bool {
    match kind {
        ControlOperationKind::Pause => task.record.is_paused(),
        ControlOperationKind::Resume => !task.record.is_paused(),
        ControlOperationKind::Update => task.last_update_digest.as_deref() == request_digest,
    }
}

fn validate_control_response(
    kind: ControlOperationKind,
    record: &ContainerRecord,
) -> TtrpcResult<()> {
    validate_control_response_runtime(kind, record).map_err(runtime_error)
}

fn validate_control_response_runtime(
    kind: ControlOperationKind,
    record: &ContainerRecord,
) -> Result<(), RuntimeError> {
    if record.state.status() != &ContainerState::Running {
        return Err(RuntimeError::new(
            ErrorCode::FailedPrecondition,
            format!(
                "containerd {kind:?} returned runtime status {} instead of running",
                record.state.status()
            ),
        )
        .for_operation("containerd-control-complete"));
    }
    match kind {
        ControlOperationKind::Pause if !record.is_paused() => Err(RuntimeError::new(
            ErrorCode::FailedPrecondition,
            "containerd Pause returned an unpaused runtime record",
        )
        .for_operation("containerd-control-complete")),
        ControlOperationKind::Resume if record.is_paused() => Err(RuntimeError::new(
            ErrorCode::FailedPrecondition,
            "containerd Resume returned a paused runtime record",
        )
        .for_operation("containerd-control-complete")),
        ControlOperationKind::Pause
        | ControlOperationKind::Resume
        | ControlOperationKind::Update => Ok(()),
    }
}

fn validate_control_target(
    task: &TaskState,
    kind: ControlOperationKind,
    record: &ContainerRecord,
) -> TtrpcResult<()> {
    validate_control_target_runtime(task, kind, record).map_err(runtime_error)
}

fn validate_control_target_runtime(
    task: &TaskState,
    kind: ControlOperationKind,
    record: &ContainerRecord,
) -> Result<(), RuntimeError> {
    if record.state.id() != task.identity.container_id.as_str()
        || record.generation != task.record.generation
        || record.driver != task.record.driver
        || record.isolation != task.record.isolation
        || (kind == ControlOperationKind::Update && record.is_paused() != task.record.is_paused())
    {
        return Err(
            RuntimeError::new(
                ErrorCode::Conflict,
                format!(
                    "containerd {kind:?} response changed the task identity, generation, driver, isolation, or freezer state"
                ),
            )
            .for_operation("containerd-control-complete"),
        );
    }
    Ok(())
}

fn control_error(message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(ErrorCode::FailedPrecondition, message)
        .for_operation("containerd-control-replay")
}
