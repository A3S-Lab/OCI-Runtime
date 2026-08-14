use a3s_oci_agent_protocol::{
    AgentCloseStdinRequest, AgentReadOutputRequest, AgentResizeRequest, AgentWriteStdinRequest,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{Error, ErrorCode, OperationId, OutputChunk, ProcessTarget, Result};
use tokio::sync::watch;

use super::io::ProcessIoHandle;
use super::state::{
    ContainerKey, ExecutorState, MutationKind, RecordedOutcome, RecordedRequest,
    UnitOperationPreparation,
};
use super::{executor_error, validate_deadline, LinuxExecutor};

impl LinuxExecutor {
    pub(super) async fn read_output_new(
        &self,
        request: &AgentReadOutputRequest,
    ) -> Result<Vec<OutputChunk>> {
        let io = {
            let mut state = self.state.lock().await;
            process_io_handle(&mut state, &request.process, Access::Read)?
        };
        io.read_output(
            request.after_sequence,
            request.max_bytes,
            request.wait_timeout_ms,
        )
        .await
    }

    pub(super) async fn write_stdin_new(&self, request: &AgentWriteStdinRequest) -> Result<()> {
        let task = {
            let mut state = self.state.lock().await;
            process_io_handle(&mut state, &request.process, Access::Write)?
                .spawn_write_stdin(request.data.clone())?
        };
        task.await.map_err(stdin_operation_task_error)?
    }

    pub(super) async fn write_stdin_recorded(&self, request: AgentWriteStdinRequest) -> Result<()> {
        let Some(context) = request.context.as_ref() else {
            return self.write_stdin_new(&request).await;
        };
        let operation = RecordedRequest::new(MutationKind::WriteStdin, &request)?;
        let operation_id = context.operation_id.clone();
        let (io, completion) = {
            let mut state = self.state.lock().await;
            match state.prepare_unit_operation(&operation_id, &operation)? {
                UnitOperationPreparation::Completed(result) => return result,
                UnitOperationPreparation::Pending(completion) => (None, completion),
                UnitOperationPreparation::Claimed(completion) => {
                    let task = validate_deadline(context)
                        .and_then(|()| {
                            process_io_handle(&mut state, &request.process, Access::Write)
                        })
                        .and_then(|io| io.spawn_write_stdin(request.data.clone()));
                    (Some(task), completion)
                }
            }
        };
        if let Some(task) = io {
            let state = self.state.clone();
            tokio::spawn(async move {
                let result = match task {
                    Ok(task) => match task.await {
                        Ok(result) => result,
                        Err(error) => Err(stdin_operation_task_error(error)),
                    },
                    Err(error) => Err(error),
                };
                complete_unit_operation(state, operation_id, operation, result).await;
            });
        }
        wait_for_unit_operation(completion).await
    }

    pub(super) async fn close_stdin_new(&self, request: &AgentCloseStdinRequest) -> Result<()> {
        let task = {
            let mut state = self.state.lock().await;
            process_io_handle(&mut state, &request.process, Access::Close)?.spawn_close_stdin()?
        };
        task.await.map_err(stdin_operation_task_error)?
    }

    pub(super) async fn close_stdin_recorded(&self, request: AgentCloseStdinRequest) -> Result<()> {
        let Some(context) = request.context.as_ref() else {
            return self.close_stdin_new(&request).await;
        };
        let operation = RecordedRequest::new(MutationKind::CloseStdin, &request)?;
        let operation_id = context.operation_id.clone();
        let (io, completion) = {
            let mut state = self.state.lock().await;
            match state.prepare_unit_operation(&operation_id, &operation)? {
                UnitOperationPreparation::Completed(result) => return result,
                UnitOperationPreparation::Pending(completion) => (None, completion),
                UnitOperationPreparation::Claimed(completion) => {
                    let task = validate_deadline(context)
                        .and_then(|()| {
                            process_io_handle(&mut state, &request.process, Access::Close)
                        })
                        .and_then(|io| io.spawn_close_stdin());
                    (Some(task), completion)
                }
            }
        };
        if let Some(task) = io {
            let state = self.state.clone();
            tokio::spawn(async move {
                let result = match task {
                    Ok(task) => match task.await {
                        Ok(result) => result,
                        Err(error) => Err(stdin_operation_task_error(error)),
                    },
                    Err(error) => Err(error),
                };
                complete_unit_operation(state, operation_id, operation, result).await;
            });
        }
        wait_for_unit_operation(completion).await
    }

    pub(super) async fn resize_new(&self, request: &AgentResizeRequest) -> Result<()> {
        let io = {
            let mut state = self.state.lock().await;
            process_io_handle(&mut state, &request.process, Access::Resize)?
        };
        io.resize(request.size)
    }

    pub(super) async fn resize_recorded(&self, request: AgentResizeRequest) -> Result<()> {
        let Some(context) = request.context.as_ref() else {
            return self.resize_new(&request).await;
        };
        let operation = RecordedRequest::new(MutationKind::Resize, &request)?;
        let operation_id = context.operation_id.clone();
        let mut state = self.state.lock().await;
        if let Some(result) = state.replay_unit(&operation_id, &operation) {
            return result;
        }
        state.reserve_operation(&operation_id)?;
        let result = validate_deadline(context)
            .and_then(|()| process_io_handle(&mut state, &request.process, Access::Resize))
            .and_then(|io| io.resize(request.size));
        state.record(
            operation_id,
            operation,
            RecordedOutcome::Unit(result.clone()),
        );
        result
    }
}

async fn complete_unit_operation(
    state: std::sync::Arc<tokio::sync::Mutex<ExecutorState>>,
    operation_id: OperationId,
    operation: RecordedRequest,
    result: Result<()>,
) {
    let mut state = state.lock().await;
    if let Err(error) = state.complete_unit_operation(operation_id, operation, result) {
        // The claim and request were validated before the detached I/O began;
        // reaching this branch means the executor journal itself is corrupt.
        // Dropping the sender wakes every waiter, which then reports a bounded
        // internal error instead of hanging indefinitely.
        debug_assert!(false, "failed to complete guest unit operation: {error}");
    }
}

fn stdin_operation_task_error(error: tokio::task::JoinError) -> Error {
    executor_error(
        ErrorCode::Internal,
        format!("process stdin operation task failed: {error}"),
    )
}

async fn wait_for_unit_operation(
    mut completion: watch::Receiver<Option<Result<()>>>,
) -> Result<()> {
    loop {
        if let Some(result) = completion.borrow_and_update().clone() {
            return result;
        }
        if completion.changed().await.is_err() {
            return Err(executor_error(
                ErrorCode::Internal,
                "guest unit operation owner disappeared before publishing its result",
            ));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Write,
    Close,
    Resize,
}

fn process_io_handle(
    state: &mut ExecutorState,
    target: &ProcessTarget,
    access: Access,
) -> Result<ProcessIoHandle> {
    let key = ContainerKey::from_target(&target.container)?;
    let record = state.containers.get_mut(&key).ok_or_else(|| {
        executor_error(
            ErrorCode::NotFound,
            format!(
                "container {} generation {} does not exist",
                key.id, key.generation
            ),
        )
    })?;
    record.refresh()?;

    if target.process_id.is_init() {
        if access == Access::Write && !configured_process_accepts_stdin(record.status) {
            return Err(executor_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "configured process stdin cannot be written while container is {}",
                    record.status
                ),
            ));
        }
        if access == Access::Resize && record.status == ContainerState::Stopped {
            return Err(executor_error(
                ErrorCode::FailedPrecondition,
                "configured process has already exited",
            ));
        }
        return Ok(record.process.io_handle());
    }

    let process = record
        .processes
        .get_mut(&target.process_id)
        .ok_or_else(|| {
            executor_error(
                ErrorCode::NotFound,
                format!(
                    "process {} does not exist in container {} generation {}",
                    target.process_id, key.id, key.generation
                ),
            )
        })?;
    if access == Access::Write && process.try_wait()?.is_some() {
        return Err(executor_error(
            ErrorCode::FailedPrecondition,
            format!("process {} has already exited", target.process_id),
        ));
    }
    if access == Access::Resize && process.try_wait()?.is_some() {
        return Err(executor_error(
            ErrorCode::FailedPrecondition,
            format!("process {} has already exited", target.process_id),
        ));
    }
    Ok(process.io_handle())
}

fn configured_process_accepts_stdin(status: ContainerState) -> bool {
    matches!(status, ContainerState::Created | ContainerState::Running)
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::oci_spec::runtime::ContainerState;

    use super::configured_process_accepts_stdin;

    #[test]
    fn configured_process_accepts_containerd_input_before_and_after_start() {
        assert!(configured_process_accepts_stdin(ContainerState::Created));
        assert!(configured_process_accepts_stdin(ContainerState::Running));
        assert!(!configured_process_accepts_stdin(ContainerState::Creating));
        assert!(!configured_process_accepts_stdin(ContainerState::Stopped));
    }
}
