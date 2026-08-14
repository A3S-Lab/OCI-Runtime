use super::*;

#[derive(Debug, Clone)]
pub(super) struct PreparedSignal {
    pub(super) task: TaskState,
    pub(super) operation: PendingSignal,
}

impl Service {
    pub(super) async fn prepare_signal(
        &self,
        task_id: &str,
        exec_id: Option<&str>,
        signal_gate: &Arc<Mutex<()>>,
        signal: i32,
        all: bool,
    ) -> TtrpcResult<PreparedSignal> {
        let _guard = self.metadata_gate.lock().await;
        let mut state = self.state.lock().await;
        let task = state
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| ttrpc_not_found(format!("unknown task {task_id}")))?;
        let (current_gate, completed, pending) = signal_state_mut(task, exec_id)?;
        if !Arc::ptr_eq(current_gate, signal_gate) {
            return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                ttrpc::Code::ABORTED,
                signal_context_message(
                    task_id,
                    exec_id,
                    "was replaced while waiting for its signal lock",
                ),
            )));
        }

        if let Some(operation) = pending.clone() {
            return Ok(PreparedSignal {
                task: task.clone(),
                operation,
            });
        }

        let sequence = completed.checked_add(1).ok_or_else(|| {
            runtime_error(
                RuntimeError::new(
                    ErrorCode::ResourceExhausted,
                    signal_context_message(
                        task_id,
                        exec_id,
                        "exhausted its durable signal sequence",
                    ),
                )
                .for_operation("containerd-signal-prepare"),
            )
        })?;
        let operation = PendingSignal::new(sequence, signal, all).map_err(runtime_error)?;
        *pending = Some(operation.clone());
        let snapshot = task.clone();
        drop(state);
        if let Err(error) = metadata_from_task(&snapshot).store() {
            let mut state = self.state.lock().await;
            if let Some(task) = state.tasks.get_mut(task_id) {
                if let Ok((current_gate, _, pending)) = signal_state_mut(task, exec_id) {
                    if Arc::ptr_eq(current_gate, signal_gate)
                        && pending.as_ref() == Some(&operation)
                    {
                        *pending = None;
                    }
                }
            }
            return Err(runtime_error(error));
        }
        Ok(PreparedSignal {
            task: snapshot,
            operation,
        })
    }

    pub(super) async fn complete_signal(
        &self,
        task_id: &str,
        exec_id: Option<&str>,
        signal_gate: &Arc<Mutex<()>>,
        operation: &PendingSignal,
        record: Option<ContainerRecord>,
    ) -> TtrpcResult<()> {
        let _guard = self.metadata_gate.lock().await;
        let mut state = self.state.lock().await;
        let task = state
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| ttrpc_not_found(format!("unknown task {task_id}")))?;
        validate_signal_response(task, exec_id, record.as_ref())?;
        let (current_gate, completed, pending) = signal_state_mut(task, exec_id)?;
        if !Arc::ptr_eq(current_gate, signal_gate) {
            return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                ttrpc::Code::ABORTED,
                signal_context_message(task_id, exec_id, "was replaced before signal completion"),
            )));
        }
        if pending.as_ref() != Some(operation) {
            return Err(ttrpc_error(signal_context_message(
                task_id,
                exec_id,
                format!(
                    "signal sequence {} changed before completion",
                    operation.sequence()
                ),
            )));
        }
        if completed.checked_add(1) != Some(operation.sequence()) {
            return Err(ttrpc_error(signal_context_message(
                task_id,
                exec_id,
                format!(
                    "signal sequence {} does not follow completed sequence {}",
                    operation.sequence(),
                    *completed
                ),
            )));
        }

        let previous_sequence = *completed;
        let previous_pending = pending.take();
        *completed = operation.sequence();
        let previous_record = record.as_ref().map(|_| task.record.clone());
        if let Some(record) = record {
            task.record = record;
        }
        let snapshot = task.clone();
        drop(state);
        if let Err(error) = metadata_from_task(&snapshot).store() {
            let mut state = self.state.lock().await;
            if let Some(task) = state.tasks.get_mut(task_id) {
                if let Ok((current_gate, completed, pending)) = signal_state_mut(task, exec_id) {
                    if Arc::ptr_eq(current_gate, signal_gate)
                        && *completed == operation.sequence()
                        && pending.is_none()
                    {
                        *completed = previous_sequence;
                        *pending = previous_pending;
                        if let Some(previous_record) = previous_record {
                            task.record = previous_record;
                        }
                    }
                }
            }
            return Err(runtime_error(error));
        }
        Ok(())
    }

    pub(super) async fn finish_signal_error(
        &self,
        task_id: &str,
        exec_id: Option<&str>,
        signal_gate: &Arc<Mutex<()>>,
        operation: &PendingSignal,
        error: &RuntimeError,
    ) -> TtrpcResult<()> {
        if error.retryable {
            return Ok(());
        }
        self.complete_signal(task_id, exec_id, signal_gate, operation, None)
            .await
    }
}

pub(super) async fn dispatch(
    adapter: &RuntimeAdapter,
    task: &TaskState,
    exec_id: Option<&str>,
    operation: &PendingSignal,
) -> Result<Option<ContainerRecord>, RuntimeError> {
    if let Some(exec_id) = exec_id {
        adapter
            .signal_process_with_sequence(
                &task.identity,
                task.record.generation,
                exec_id,
                operation.sequence(),
                operation.signal().get(),
            )
            .await?;
        Ok(None)
    } else {
        adapter
            .kill_with_sequence(
                &task.identity,
                task.record.generation,
                operation.sequence(),
                operation.signal().get(),
                operation.all(),
            )
            .await
            .map(Some)
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
    let pending = signal_state(task, exec_id)?.2.clone();
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
        Ok(None)
    } else {
        dispatch(adapter, task, exec_id, &operation).await
    };
    let record = match result {
        Ok(record) => record,
        Err(error) if error.retryable => return Err(error),
        Err(error) => {
            log::warn!(
                "settling terminal failure while replaying {}: {error}",
                signal_context_message(
                    &task.identity.task_id,
                    exec_id,
                    format!("signal sequence {}", operation.sequence()),
                )
            );
            None
        }
    };
    complete_replayed(task, exec_id, &operation, record)?;
    metadata_from_task(task).store()
}

fn complete_replayed(
    task: &mut TaskState,
    exec_id: Option<&str>,
    operation: &PendingSignal,
    record: Option<ContainerRecord>,
) -> Result<(), RuntimeError> {
    validate_signal_response_runtime(task, exec_id, record.as_ref())?;
    let task_id = task.identity.task_id.clone();
    let (_, completed, pending) = signal_state_mut_runtime(task, exec_id)?;
    if pending.as_ref() != Some(operation) || completed.checked_add(1) != Some(operation.sequence())
    {
        return Err(signal_error(signal_context_message(
            &task_id,
            exec_id,
            format!(
                "cannot commit replayed signal sequence {} from completed sequence {}",
                operation.sequence(),
                *completed
            ),
        )));
    }
    *completed = operation.sequence();
    *pending = None;
    if let Some(record) = record {
        task.record = record;
    }
    Ok(())
}

type SignalState<'a> = (&'a Arc<Mutex<()>>, &'a u64, &'a Option<PendingSignal>);

type SignalStateMut<'a> = (
    &'a Arc<Mutex<()>>,
    &'a mut u64,
    &'a mut Option<PendingSignal>,
);

fn signal_state<'a>(
    task: &'a TaskState,
    exec_id: Option<&str>,
) -> Result<SignalState<'a>, RuntimeError> {
    if let Some(exec_id) = exec_id {
        let exec = task.execs.get(exec_id).ok_or_else(|| {
            signal_error(format!(
                "containerd exec {exec_id} disappeared before signal journal access"
            ))
        })?;
        Ok((
            &exec.signal_gate,
            &exec.signal_sequence,
            &exec.pending_signal,
        ))
    } else {
        Ok((
            &task.signal_gate,
            &task.signal_sequence,
            &task.pending_signal,
        ))
    }
}

fn signal_state_mut<'a>(
    task: &'a mut TaskState,
    exec_id: Option<&str>,
) -> TtrpcResult<SignalStateMut<'a>> {
    signal_state_mut_runtime(task, exec_id).map_err(runtime_error)
}

fn signal_state_mut_runtime<'a>(
    task: &'a mut TaskState,
    exec_id: Option<&str>,
) -> Result<SignalStateMut<'a>, RuntimeError> {
    if let Some(exec_id) = exec_id {
        let exec = task.execs.get_mut(exec_id).ok_or_else(|| {
            signal_error(format!(
                "containerd exec {exec_id} disappeared before signal journal update"
            ))
        })?;
        Ok((
            &exec.signal_gate,
            &mut exec.signal_sequence,
            &mut exec.pending_signal,
        ))
    } else {
        Ok((
            &task.signal_gate,
            &mut task.signal_sequence,
            &mut task.pending_signal,
        ))
    }
}

fn validate_signal_response(
    task: &TaskState,
    exec_id: Option<&str>,
    record: Option<&ContainerRecord>,
) -> TtrpcResult<()> {
    validate_signal_response_runtime(task, exec_id, record).map_err(runtime_error)
}

fn validate_signal_response_runtime(
    task: &TaskState,
    exec_id: Option<&str>,
    record: Option<&ContainerRecord>,
) -> Result<(), RuntimeError> {
    if exec_id.is_some() && record.is_some() {
        return Err(signal_error(
            "containerd exec signal unexpectedly returned a container record",
        ));
    }
    let Some(record) = record else {
        return Ok(());
    };
    if record.state.id() != task.identity.container_id.as_str()
        || record.generation != task.record.generation
        || record.driver != task.record.driver
        || record.isolation != task.record.isolation
    {
        return Err(RuntimeError::new(
            ErrorCode::Conflict,
            "containerd Kill response changed the task identity, generation, driver, or isolation",
        )
        .for_operation("containerd-signal-complete"));
    }
    Ok(())
}

fn signal_context_message(
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

fn signal_error(message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(ErrorCode::FailedPrecondition, message)
        .for_operation("containerd-signal-journal")
}
