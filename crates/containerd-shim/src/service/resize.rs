use super::*;

#[derive(Debug, Clone)]
pub(super) struct PreparedResize {
    pub(super) task: TaskState,
    pub(super) operation: PendingResize,
}

impl Service {
    pub(super) async fn prepare_resize(
        &self,
        task_id: &str,
        exec_id: Option<&str>,
        resize_gate: &Arc<Mutex<()>>,
        size: TerminalSize,
    ) -> TtrpcResult<Option<PreparedResize>> {
        let _guard = self.metadata_gate.lock().await;
        let mut state = self.state.lock().await;
        let task = state
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| ttrpc_not_found(format!("unknown task {task_id}")))?;
        let (current_gate, terminal, completed, pending, terminal_size) =
            resize_state_mut(task, exec_id)?;
        if !Arc::ptr_eq(current_gate, resize_gate) {
            return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                ttrpc::Code::ABORTED,
                resize_context_message(
                    task_id,
                    exec_id,
                    "was replaced while waiting for its resize lock",
                ),
            )));
        }
        if !*terminal {
            return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                ttrpc::Code::FAILED_PRECONDITION,
                resize_context_message(task_id, exec_id, "is not a terminal process"),
            )));
        }

        if let Some(operation) = pending.clone() {
            return Ok(Some(PreparedResize {
                task: task.clone(),
                operation,
            }));
        }
        if *terminal_size == Some(size) {
            return Ok(None);
        }

        let sequence = completed.checked_add(1).ok_or_else(|| {
            runtime_error(
                RuntimeError::new(
                    ErrorCode::ResourceExhausted,
                    resize_context_message(
                        task_id,
                        exec_id,
                        "exhausted its durable resize sequence",
                    ),
                )
                .for_operation("containerd-resize-prepare"),
            )
        })?;
        let operation = PendingResize::new(sequence, size).map_err(runtime_error)?;
        *pending = Some(operation.clone());
        let snapshot = task.clone();
        drop(state);
        if let Err(error) = metadata_from_task(&snapshot).store() {
            let mut state = self.state.lock().await;
            if let Some(task) = state.tasks.get_mut(task_id) {
                if let Ok((current_gate, _, _, pending, _)) = resize_state_mut(task, exec_id) {
                    if Arc::ptr_eq(current_gate, resize_gate)
                        && pending.as_ref() == Some(&operation)
                    {
                        *pending = None;
                    }
                }
            }
            return Err(runtime_error(error));
        }
        Ok(Some(PreparedResize {
            task: snapshot,
            operation,
        }))
    }

    pub(super) async fn complete_resize(
        &self,
        task_id: &str,
        exec_id: Option<&str>,
        resize_gate: &Arc<Mutex<()>>,
        operation: &PendingResize,
        applied: bool,
    ) -> TtrpcResult<()> {
        let _guard = self.metadata_gate.lock().await;
        let mut state = self.state.lock().await;
        let task = state
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| ttrpc_not_found(format!("unknown task {task_id}")))?;
        let (current_gate, _, completed, pending, terminal_size) = resize_state_mut(task, exec_id)?;
        if !Arc::ptr_eq(current_gate, resize_gate) {
            return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                ttrpc::Code::ABORTED,
                resize_context_message(task_id, exec_id, "was replaced before resize completion"),
            )));
        }
        if pending.as_ref() != Some(operation) {
            return Err(ttrpc_error(resize_context_message(
                task_id,
                exec_id,
                format!(
                    "resize sequence {} changed before completion",
                    operation.sequence()
                ),
            )));
        }
        if completed.checked_add(1) != Some(operation.sequence()) {
            return Err(ttrpc_error(resize_context_message(
                task_id,
                exec_id,
                format!(
                    "resize sequence {} does not follow completed sequence {}",
                    operation.sequence(),
                    *completed
                ),
            )));
        }

        let previous_sequence = *completed;
        let previous_pending = pending.take();
        let previous_size = *terminal_size;
        *completed = operation.sequence();
        if applied {
            *terminal_size = Some(operation.size());
        }
        let snapshot = task.clone();
        drop(state);
        if let Err(error) = metadata_from_task(&snapshot).store() {
            let mut state = self.state.lock().await;
            if let Some(task) = state.tasks.get_mut(task_id) {
                if let Ok((current_gate, _, completed, pending, terminal_size)) =
                    resize_state_mut(task, exec_id)
                {
                    if Arc::ptr_eq(current_gate, resize_gate)
                        && *completed == operation.sequence()
                        && pending.is_none()
                    {
                        *completed = previous_sequence;
                        *pending = previous_pending;
                        *terminal_size = previous_size;
                    }
                }
            }
            return Err(runtime_error(error));
        }
        Ok(())
    }

    pub(super) async fn finish_resize_error(
        &self,
        task_id: &str,
        exec_id: Option<&str>,
        resize_gate: &Arc<Mutex<()>>,
        operation: &PendingResize,
        error: &RuntimeError,
    ) -> TtrpcResult<()> {
        if error.retryable {
            return Ok(());
        }
        self.complete_resize(task_id, exec_id, resize_gate, operation, false)
            .await
    }
}

pub(super) async fn dispatch(
    adapter: &RuntimeAdapter,
    task: &TaskState,
    exec_id: Option<&str>,
    operation: &PendingResize,
) -> Result<(), RuntimeError> {
    let target = adapter.process_target(&task.identity, task.record.generation, exec_id)?;
    let result = adapter
        .resize(
            &task.identity,
            task.record.generation,
            exec_id,
            operation.sequence(),
            operation.size(),
        )
        .await;
    let Err(error) = result else {
        return Ok(());
    };
    let exited = match adapter
        .processes(&task.identity, task.record.generation)
        .await
    {
        Ok(processes) => crate::io::late_process_io_can_be_ignored(&error, &processes, &target),
        Err(inventory_error) if inventory_error.code == ErrorCode::NotFound => true,
        Err(inventory_error) => {
            log::warn!(
                "could not confirm process exit after late containerd resize: {inventory_error}"
            );
            false
        }
    };
    if exited {
        Ok(())
    } else {
        Err(error)
    }
}

pub(super) async fn replay_pending(
    adapter: &RuntimeAdapter,
    task: &mut TaskState,
) -> Result<(), RuntimeError> {
    replay_one(adapter, task, None).await?;
    let exec_ids = task.execs.keys().cloned().collect::<Vec<_>>();
    for exec_id in exec_ids {
        replay_one(adapter, task, Some(&exec_id)).await?;
    }
    Ok(())
}

async fn replay_one(
    adapter: &RuntimeAdapter,
    task: &mut TaskState,
    exec_id: Option<&str>,
) -> Result<(), RuntimeError> {
    let pending = resize_state(task, exec_id)?.3.clone();
    let Some(operation) = pending else {
        return Ok(());
    };
    let known_exit = if let Some(exec_id) = exec_id {
        task.execs
            .get(exec_id)
            .is_some_and(|exec| exec.exit.is_some())
    } else {
        task.exit.is_some()
    };
    let result = if known_exit {
        Ok(())
    } else {
        dispatch(adapter, task, exec_id, &operation).await
    };
    let applied = match result {
        Ok(()) => true,
        Err(error) if error.retryable => return Err(error),
        Err(error) => {
            log::warn!(
                "settling terminal failure while replaying {}: {error}",
                resize_context_message(
                    &task.identity.task_id,
                    exec_id,
                    format!("resize sequence {}", operation.sequence()),
                )
            );
            false
        }
    };
    complete_replayed(task, exec_id, &operation, applied)?;
    metadata_from_task(task).store()
}

fn complete_replayed(
    task: &mut TaskState,
    exec_id: Option<&str>,
    operation: &PendingResize,
    applied: bool,
) -> Result<(), RuntimeError> {
    let task_id = task.identity.task_id.clone();
    let (_, _, completed, pending, terminal_size) = resize_state_mut_runtime(task, exec_id)?;
    if pending.as_ref() != Some(operation) || completed.checked_add(1) != Some(operation.sequence())
    {
        return Err(resize_error(resize_context_message(
            &task_id,
            exec_id,
            format!(
                "cannot commit replayed resize sequence {} from completed sequence {}",
                operation.sequence(),
                *completed
            ),
        )));
    }
    *completed = operation.sequence();
    *pending = None;
    if applied {
        *terminal_size = Some(operation.size());
    }
    Ok(())
}

type ResizeState<'a> = (
    &'a Arc<Mutex<()>>,
    &'a bool,
    &'a u64,
    &'a Option<PendingResize>,
    &'a Option<TerminalSize>,
);

type ResizeStateMut<'a> = (
    &'a Arc<Mutex<()>>,
    &'a mut bool,
    &'a mut u64,
    &'a mut Option<PendingResize>,
    &'a mut Option<TerminalSize>,
);

fn resize_state<'a>(
    task: &'a TaskState,
    exec_id: Option<&str>,
) -> Result<ResizeState<'a>, RuntimeError> {
    if let Some(exec_id) = exec_id {
        let exec = task.execs.get(exec_id).ok_or_else(|| {
            resize_error(format!(
                "containerd exec {exec_id} disappeared before resize journal access"
            ))
        })?;
        Ok((
            &exec.resize_gate,
            &exec.terminal,
            &exec.resize_sequence,
            &exec.pending_resize,
            &exec.terminal_size,
        ))
    } else {
        Ok((
            &task.resize_gate,
            &task.terminal,
            &task.resize_sequence,
            &task.pending_resize,
            &task.terminal_size,
        ))
    }
}

fn resize_state_mut<'a>(
    task: &'a mut TaskState,
    exec_id: Option<&str>,
) -> TtrpcResult<ResizeStateMut<'a>> {
    resize_state_mut_runtime(task, exec_id).map_err(runtime_error)
}

fn resize_state_mut_runtime<'a>(
    task: &'a mut TaskState,
    exec_id: Option<&str>,
) -> Result<ResizeStateMut<'a>, RuntimeError> {
    if let Some(exec_id) = exec_id {
        let exec = task.execs.get_mut(exec_id).ok_or_else(|| {
            resize_error(format!(
                "containerd exec {exec_id} disappeared before resize journal update"
            ))
        })?;
        Ok((
            &exec.resize_gate,
            &mut exec.terminal,
            &mut exec.resize_sequence,
            &mut exec.pending_resize,
            &mut exec.terminal_size,
        ))
    } else {
        Ok((
            &task.resize_gate,
            &mut task.terminal,
            &mut task.resize_sequence,
            &mut task.pending_resize,
            &mut task.terminal_size,
        ))
    }
}

fn resize_context_message(
    task_id: &str,
    exec_id: Option<&str>,
    message: impl AsRef<str>,
) -> String {
    if let Some(exec_id) = exec_id {
        format!("containerd exec {task_id}/{exec_id} {}", message.as_ref())
    } else {
        format!("containerd task {task_id} {}", message.as_ref())
    }
}

fn resize_error(message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(ErrorCode::FailedPrecondition, message)
        .for_operation("containerd-resize-journal")
}
