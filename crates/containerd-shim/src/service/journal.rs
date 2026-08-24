use super::*;

struct DurableOutputCursor {
    state: Weak<Mutex<ServiceState>>,
    metadata_gate: Weak<Mutex<()>>,
    task_id: String,
    exec_id: Option<String>,
}

struct DurableStdinJournal {
    state: Weak<Mutex<ServiceState>>,
    metadata_gate: Weak<Mutex<()>>,
    task_id: String,
    exec_id: Option<String>,
}

#[async_trait]
impl io::OutputCursorCommitter for DurableOutputCursor {
    async fn commit(&self, cursor: u64) -> Result<(), RuntimeError> {
        let state = self.state.upgrade().ok_or_else(|| {
            RuntimeError::new(
                ErrorCode::Unavailable,
                "containerd shim state closed before output cursor commit",
            )
            .for_operation("containerd-output-cursor")
            .retryable(true)
        })?;
        let metadata_gate = self.metadata_gate.upgrade().ok_or_else(|| {
            RuntimeError::new(
                ErrorCode::Unavailable,
                "containerd shim metadata gate closed before output cursor commit",
            )
            .for_operation("containerd-output-cursor")
            .retryable(true)
        })?;
        let _guard = metadata_gate.lock().await;
        let (task_snapshot, previous) = {
            let mut state = state.lock().await;
            let task = state.tasks.get_mut(&self.task_id).ok_or_else(|| {
                RuntimeError::new(
                    ErrorCode::NotFound,
                    format!(
                        "containerd task {} disappeared before output cursor commit",
                        self.task_id
                    ),
                )
                .for_operation("containerd-output-cursor")
            })?;
            let current = if let Some(exec_id) = &self.exec_id {
                &mut task
                    .execs
                    .get_mut(exec_id)
                    .ok_or_else(|| {
                        RuntimeError::new(
                            ErrorCode::NotFound,
                            format!(
                                "containerd exec {exec_id} disappeared before output cursor commit"
                            ),
                        )
                        .for_operation("containerd-output-cursor")
                    })?
                    .output_cursor
            } else {
                &mut task.output_cursor
            };
            if cursor <= *current {
                return Ok(());
            }
            let previous = *current;
            *current = cursor;
            (task.clone(), previous)
        };
        if let Err(error) = metadata_from_task(&task_snapshot).store() {
            let mut state = state.lock().await;
            if let Some(task) = state.tasks.get_mut(&self.task_id) {
                let current = if let Some(exec_id) = &self.exec_id {
                    task.execs
                        .get_mut(exec_id)
                        .map(|exec| &mut exec.output_cursor)
                } else {
                    Some(&mut task.output_cursor)
                };
                if let Some(current) = current {
                    if *current == cursor {
                        *current = previous;
                    }
                }
            }
            return Err(error);
        }
        Ok(())
    }
}

#[async_trait]
impl io::StdinJournal for DurableStdinJournal {
    async fn prepare(&self, sequence: u64, data: Vec<u8>) -> Result<(), RuntimeError> {
        let pending = PendingStdinWrite::new(sequence, data)?;
        let state = self.state.upgrade().ok_or_else(|| {
            stdin_journal_error(
                ErrorCode::Unavailable,
                "containerd shim state closed before stdin prepare",
                true,
            )
        })?;
        let metadata_gate = self.metadata_gate.upgrade().ok_or_else(|| {
            stdin_journal_error(
                ErrorCode::Unavailable,
                "containerd shim metadata gate closed before stdin prepare",
                true,
            )
        })?;
        let _guard = metadata_gate.lock().await;
        let task_snapshot = {
            let mut state = state.lock().await;
            let task = state.tasks.get_mut(&self.task_id).ok_or_else(|| {
                stdin_journal_error(
                    ErrorCode::NotFound,
                    format!(
                        "containerd task {} disappeared before stdin prepare",
                        self.task_id
                    ),
                    false,
                )
            })?;
            let (completed, current, close_state) = stdin_state_mut(task, self.exec_id.as_deref())?;
            if *close_state != StdinCloseState::Open {
                return Err(stdin_journal_error(
                    ErrorCode::FailedPrecondition,
                    "containerd stdin cannot prepare a write after close has started",
                    false,
                ));
            }
            if let Some(current) = current.as_ref() {
                if current == &pending {
                    return Ok(());
                }
                return Err(stdin_journal_error(
                    ErrorCode::Conflict,
                    format!(
                        "containerd stdin sequence {} is already pending with different data",
                        current.sequence()
                    ),
                    false,
                ));
            }
            if completed.checked_add(1) != Some(sequence) {
                return Err(stdin_journal_error(
                    ErrorCode::Conflict,
                    format!(
                        "containerd stdin sequence {sequence} does not follow completed sequence {}",
                        *completed
                    ),
                    false,
                ));
            }
            *current = Some(pending.clone());
            task.clone()
        };
        if let Err(error) = metadata_from_task(&task_snapshot).store() {
            let mut state = state.lock().await;
            if let Some(task) = state.tasks.get_mut(&self.task_id) {
                if let Ok((_, current, _)) = stdin_state_mut(task, self.exec_id.as_deref()) {
                    if current.as_ref() == Some(&pending) {
                        *current = None;
                    }
                }
            }
            return Err(error);
        }
        Ok(())
    }

    async fn commit(&self, sequence: u64) -> Result<(), RuntimeError> {
        let state = self.state.upgrade().ok_or_else(|| {
            stdin_journal_error(
                ErrorCode::Unavailable,
                "containerd shim state closed before stdin commit",
                true,
            )
        })?;
        let metadata_gate = self.metadata_gate.upgrade().ok_or_else(|| {
            stdin_journal_error(
                ErrorCode::Unavailable,
                "containerd shim metadata gate closed before stdin commit",
                true,
            )
        })?;
        let _guard = metadata_gate.lock().await;
        let (task_snapshot, previous_sequence, previous_pending) = {
            let mut state = state.lock().await;
            let task = state.tasks.get_mut(&self.task_id).ok_or_else(|| {
                stdin_journal_error(
                    ErrorCode::NotFound,
                    format!(
                        "containerd task {} disappeared before stdin commit",
                        self.task_id
                    ),
                    false,
                )
            })?;
            let (completed, current, _) = stdin_state_mut(task, self.exec_id.as_deref())?;
            if *completed == sequence && current.is_none() {
                return Ok(());
            }
            let pending = current.as_ref().ok_or_else(|| {
                stdin_journal_error(
                    ErrorCode::Conflict,
                    format!("containerd stdin sequence {sequence} was not prepared"),
                    false,
                )
            })?;
            if pending.sequence() != sequence || completed.checked_add(1) != Some(sequence) {
                return Err(stdin_journal_error(
                    ErrorCode::Conflict,
                    format!(
                        "containerd stdin commit sequence {sequence} does not match completed sequence {} and pending sequence {}",
                        *completed,
                        pending.sequence()
                    ),
                    false,
                ));
            }
            let previous_sequence = *completed;
            let previous_pending = current.take();
            *completed = sequence;
            (task.clone(), previous_sequence, previous_pending)
        };
        if let Err(error) = metadata_from_task(&task_snapshot).store() {
            let mut state = state.lock().await;
            if let Some(task) = state.tasks.get_mut(&self.task_id) {
                if let Ok((completed, current, _)) = stdin_state_mut(task, self.exec_id.as_deref())
                {
                    if *completed == sequence && current.is_none() {
                        *completed = previous_sequence;
                        *current = previous_pending;
                    }
                }
            }
            return Err(error);
        }
        Ok(())
    }

    async fn prepare_close(&self) -> Result<(), RuntimeError> {
        let state = self.state.upgrade().ok_or_else(|| {
            stdin_journal_error(
                ErrorCode::Unavailable,
                "containerd shim state closed before stdin close prepare",
                true,
            )
        })?;
        let metadata_gate = self.metadata_gate.upgrade().ok_or_else(|| {
            stdin_journal_error(
                ErrorCode::Unavailable,
                "containerd shim metadata gate closed before stdin close prepare",
                true,
            )
        })?;
        let _guard = metadata_gate.lock().await;
        let task_snapshot = {
            let mut state = state.lock().await;
            let task = state.tasks.get_mut(&self.task_id).ok_or_else(|| {
                stdin_journal_error(
                    ErrorCode::NotFound,
                    format!(
                        "containerd task {} disappeared before stdin close prepare",
                        self.task_id
                    ),
                    false,
                )
            })?;
            let (_, pending, close_state) = stdin_state_mut(task, self.exec_id.as_deref())?;
            if *close_state != StdinCloseState::Open {
                return Ok(());
            }
            if pending.is_some() {
                return Err(stdin_journal_error(
                    ErrorCode::Conflict,
                    "containerd stdin cannot close while a write remains pending",
                    false,
                ));
            }
            *close_state = StdinCloseState::Closing;
            task.clone()
        };
        if let Err(error) = metadata_from_task(&task_snapshot).store() {
            let mut state = state.lock().await;
            if let Some(task) = state.tasks.get_mut(&self.task_id) {
                if let Ok((_, _, close_state)) = stdin_state_mut(task, self.exec_id.as_deref()) {
                    if *close_state == StdinCloseState::Closing {
                        *close_state = StdinCloseState::Open;
                    }
                }
            }
            return Err(error);
        }
        Ok(())
    }

    async fn commit_close(&self) -> Result<(), RuntimeError> {
        let state = self.state.upgrade().ok_or_else(|| {
            stdin_journal_error(
                ErrorCode::Unavailable,
                "containerd shim state closed before stdin close commit",
                true,
            )
        })?;
        let metadata_gate = self.metadata_gate.upgrade().ok_or_else(|| {
            stdin_journal_error(
                ErrorCode::Unavailable,
                "containerd shim metadata gate closed before stdin close commit",
                true,
            )
        })?;
        let _guard = metadata_gate.lock().await;
        let task_snapshot = {
            let mut state = state.lock().await;
            let task = state.tasks.get_mut(&self.task_id).ok_or_else(|| {
                stdin_journal_error(
                    ErrorCode::NotFound,
                    format!(
                        "containerd task {} disappeared before stdin close commit",
                        self.task_id
                    ),
                    false,
                )
            })?;
            let (_, pending, close_state) = stdin_state_mut(task, self.exec_id.as_deref())?;
            if *close_state == StdinCloseState::Closed {
                return Ok(());
            }
            if *close_state != StdinCloseState::Closing || pending.is_some() {
                return Err(stdin_journal_error(
                    ErrorCode::Conflict,
                    "containerd stdin close was not prepared from a fully committed write stream",
                    false,
                ));
            }
            *close_state = StdinCloseState::Closed;
            task.clone()
        };
        if let Err(error) = metadata_from_task(&task_snapshot).store() {
            let mut state = state.lock().await;
            if let Some(task) = state.tasks.get_mut(&self.task_id) {
                if let Ok((_, _, close_state)) = stdin_state_mut(task, self.exec_id.as_deref()) {
                    if *close_state == StdinCloseState::Closed {
                        *close_state = StdinCloseState::Closing;
                    }
                }
            }
            return Err(error);
        }
        Ok(())
    }
}

fn stdin_state_mut<'a>(
    task: &'a mut TaskState,
    exec_id: Option<&str>,
) -> Result<
    (
        &'a mut u64,
        &'a mut Option<PendingStdinWrite>,
        &'a mut StdinCloseState,
    ),
    RuntimeError,
> {
    if let Some(exec_id) = exec_id {
        let exec = task.execs.get_mut(exec_id).ok_or_else(|| {
            stdin_journal_error(
                ErrorCode::NotFound,
                format!("containerd exec {exec_id} disappeared before stdin journal update"),
                false,
            )
        })?;
        Ok((
            &mut exec.stdin_sequence,
            &mut exec.pending_stdin_write,
            &mut exec.stdin_close_state,
        ))
    } else {
        Ok((
            &mut task.stdin_sequence,
            &mut task.pending_stdin_write,
            &mut task.stdin_close_state,
        ))
    }
}

fn stdin_journal_error(
    code: ErrorCode,
    message: impl Into<String>,
    retryable: bool,
) -> RuntimeError {
    RuntimeError::new(code, message)
        .for_operation("containerd-stdin-journal")
        .retryable(retryable)
}

impl Service {
    pub(super) fn output_cursor_committer(
        &self,
        task_id: &str,
        exec_id: Option<&str>,
    ) -> Arc<dyn io::OutputCursorCommitter> {
        Arc::new(DurableOutputCursor {
            state: Arc::downgrade(&self.state),
            metadata_gate: Arc::downgrade(&self.metadata_gate),
            task_id: task_id.to_string(),
            exec_id: exec_id.map(str::to_string),
        })
    }

    pub(super) fn stdin_journal(
        &self,
        task_id: &str,
        exec_id: Option<&str>,
    ) -> Arc<dyn io::StdinJournal> {
        Arc::new(DurableStdinJournal {
            state: Arc::downgrade(&self.state),
            metadata_gate: Arc::downgrade(&self.metadata_gate),
            task_id: task_id.to_string(),
            exec_id: exec_id.map(str::to_string),
        })
    }
}
