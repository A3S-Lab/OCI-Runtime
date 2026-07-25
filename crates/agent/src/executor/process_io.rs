use a3s_oci_agent_protocol::{
    AgentCloseStdinRequest, AgentReadOutputRequest, AgentWriteStdinRequest,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{ErrorCode, OutputChunk, ProcessTarget, Result};

use super::io::ProcessIoHandle;
use super::state::{ContainerKey, ExecutorState};
use super::{executor_error, LinuxExecutor};

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
        let io = {
            let mut state = self.state.lock().await;
            process_io_handle(&mut state, &request.process, Access::Write)?
        };
        io.write_stdin(&request.data).await
    }

    pub(super) async fn close_stdin_new(&self, request: &AgentCloseStdinRequest) -> Result<()> {
        let io = {
            let mut state = self.state.lock().await;
            process_io_handle(&mut state, &request.process, Access::Close)?
        };
        io.close_stdin().await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Write,
    Close,
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
        if access == Access::Write && record.status != ContainerState::Running {
            return Err(executor_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "configured process stdin cannot be written while container is {}",
                    record.status
                ),
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
    Ok(process.io_handle())
}
