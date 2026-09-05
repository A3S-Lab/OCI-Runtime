use std::time::Duration;

use a3s_oci_agent_protocol::{
    AgentExecRequest, AgentProcess, AgentSignalProcessRequest, AgentWaitProcessRequest,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{ErrorCode, ExitStatus, Result};
use tokio::time::{sleep, Instant};

use super::exec_process::ExecProcess;
use super::pidfd::SignalOutcome;
use super::plan::ProcessPlan;
use super::state::{ContainerKey, ExecutorState, MutationKind, RecordedOutcome, RecordedRequest};
use super::{
    create_private_directory, executor_error, remove_process_directory, validate_deadline,
    write_private_snapshot, LinuxExecutor, WAIT_POLL_INTERVAL,
};

impl LinuxExecutor {
    pub(super) async fn exec_recorded(&self, request: AgentExecRequest) -> Result<AgentProcess> {
        let operation = RecordedRequest::new(MutationKind::Exec, &request)?;
        let operation_id = request.context.operation_id.clone();
        let mut state = self.state.lock().await;
        if let Some(result) = state.replay_process(&operation_id, &operation) {
            return result;
        }
        state.reserve_operation(&operation_id)?;
        let result = self.exec_new(&mut state, &request).await;
        state.record(
            operation_id,
            operation,
            RecordedOutcome::Process(result.clone()),
        );
        result
    }

    async fn exec_new(
        &self,
        state: &mut ExecutorState,
        request: &AgentExecRequest,
    ) -> Result<AgentProcess> {
        validate_deadline(&request.context)?;
        if request.target.process_id.is_init() {
            return Err(executor_error(
                ErrorCode::InvalidArgument,
                "exec process ID `init` is reserved for the configured process",
            ));
        }
        let key = ContainerKey::from_target(&request.target.container)?;
        {
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
            if record.status != ContainerState::Running {
                return Err(executor_error(
                    ErrorCode::FailedPrecondition,
                    "container exec requires a running configured process",
                ));
            }
            if record.paused {
                return Err(executor_error(
                    ErrorCode::FailedPrecondition,
                    "container exec is unavailable while the container is paused",
                ));
            }
            if record.processes.contains_key(&request.target.process_id) {
                return Err(executor_error(
                    ErrorCode::AlreadyExists,
                    format!(
                        "process {} already exists in container {} generation {}",
                        request.target.process_id, key.id, key.generation
                    ),
                ));
            }
        }

        let process_io = request.io.resolve_for_process(&request.process)?;
        let mut plan = ProcessPlan::from_exec_process(&request.process, &process_io)?;
        let seccomp = state
            .containers
            .get(&key)
            .ok_or_else(|| missing_locked_container(&key))?
            .process
            .seccomp();
        plan.attach_seccomp(seccomp);
        let container_capabilities = state
            .containers
            .get(&key)
            .ok_or_else(|| missing_locked_container(&key))?
            .process
            .capabilities();
        plan.capabilities
            .validate_exec_ceiling(container_capabilities)?;
        state
            .containers
            .get(&key)
            .ok_or_else(|| missing_locked_container(&key))?
            .process
            .execution_context()
            .validate_process_ids(plan.uid, plan.gid, &plan.additional_gids)?;
        let slot = state.next_slot.checked_add(1).ok_or_else(|| {
            executor_error(
                ErrorCode::ResourceExhausted,
                "guest process slot space is exhausted",
            )
        })?;
        state.next_slot = slot;
        let container_directory = state
            .containers
            .get(&key)
            .ok_or_else(|| missing_locked_container(&key))?
            .runtime_directory
            .clone();
        let process_directory = container_directory.join(format!("p-{slot:016x}"));
        create_private_directory(&process_directory).await?;
        let snapshot = process_directory.join("process.json");
        let encoded = serde_json::to_string(&plan).map_err(|error| {
            executor_error(
                ErrorCode::Internal,
                format!("failed to encode exec process plan: {error}"),
            )
        })?;
        if let Err(error) = write_private_snapshot(&snapshot, &encoded).await {
            let _ = remove_process_directory(&container_directory, &process_directory).await;
            return Err(error);
        }

        let process = {
            let record = state
                .containers
                .get_mut(&key)
                .ok_or_else(|| missing_locked_container(&key))?;
            match ExecProcess::spawn(
                &snapshot,
                self.init_executable.command_path(),
                &record.process,
                request.process.terminal().unwrap_or(false),
                &process_io,
            )
            .await
            {
                Ok(process) => process,
                Err(error) => {
                    let _ =
                        remove_process_directory(&container_directory, &process_directory).await;
                    return Err(error);
                }
            }
        };
        let response =
            match AgentProcess::new(request.target.clone(), process.pid(), process.terminal()) {
                Ok(response) => response,
                Err(error) => {
                    let mut process = process;
                    let _ = process.force_stop().await;
                    let _ =
                        remove_process_directory(&container_directory, &process_directory).await;
                    return Err(error);
                }
            };
        state
            .containers
            .get_mut(&key)
            .ok_or_else(|| missing_locked_container(&key))?
            .processes
            .insert(request.target.process_id.clone(), process);
        Ok(response)
    }

    pub(super) async fn signal_process_recorded(
        &self,
        request: AgentSignalProcessRequest,
    ) -> Result<()> {
        let operation = RecordedRequest::new(MutationKind::SignalProcess, &request)?;
        let operation_id = request.context.operation_id.clone();
        let mut state = self.state.lock().await;
        if let Some(result) = state.replay_unit(&operation_id, &operation) {
            return result;
        }
        state.reserve_operation(&operation_id)?;
        let result = Self::signal_process_new(&mut state, &request);
        state.record(
            operation_id,
            operation,
            RecordedOutcome::Unit(result.clone()),
        );
        result
    }

    fn signal_process_new(
        state: &mut ExecutorState,
        request: &AgentSignalProcessRequest,
    ) -> Result<()> {
        validate_deadline(&request.context)?;
        let key = ContainerKey::from_target(&request.target.container)?;
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
        if request.target.process_id.is_init() {
            if record.status == ContainerState::Stopped {
                return Err(executor_error(
                    ErrorCode::FailedPrecondition,
                    "cannot signal a stopped configured process",
                ));
            }
            if matches!(
                record.process.signal(request.signal.get())?,
                SignalOutcome::Exited
            ) {
                record.status = ContainerState::Stopped;
                return Err(executor_error(
                    ErrorCode::FailedPrecondition,
                    "configured process exited before signal delivery",
                ));
            }
            return Ok(());
        }

        let process = record
            .processes
            .get_mut(&request.target.process_id)
            .ok_or_else(|| {
                executor_error(
                    ErrorCode::NotFound,
                    format!(
                        "process {} does not exist in container {} generation {}",
                        request.target.process_id, key.id, key.generation
                    ),
                )
            })?;
        if process.try_wait()?.is_some() {
            return Err(executor_error(
                ErrorCode::FailedPrecondition,
                format!("process {} has already exited", request.target.process_id),
            ));
        }
        if matches!(process.signal(request.signal.get())?, SignalOutcome::Exited) {
            process.try_wait()?;
            return Err(executor_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "process {} exited before signal delivery",
                    request.target.process_id
                ),
            ));
        }
        Ok(())
    }

    pub(super) async fn wait_process_new(
        &self,
        request: &AgentWaitProcessRequest,
    ) -> Result<ExitStatus> {
        let key = ContainerKey::from_target(&request.target.container)?;
        let timeout = request.timeout_ms.map(Duration::from_millis);
        let started = Instant::now();
        loop {
            let status = {
                let mut state = self.state.lock().await;
                let record = state.containers.get_mut(&key).ok_or_else(|| {
                    executor_error(
                        ErrorCode::NotFound,
                        format!(
                            "container {} generation {} does not exist",
                            key.id, key.generation
                        ),
                    )
                })?;
                if request.target.process_id.is_init() {
                    let status = record.poll_wait()?;
                    if status.is_some() {
                        for process in record.processes.values_mut() {
                            process.force_stop().await?;
                        }
                    }
                    status
                } else {
                    record.refresh()?;
                    record
                        .processes
                        .get_mut(&request.target.process_id)
                        .ok_or_else(|| {
                            executor_error(
                                ErrorCode::NotFound,
                                format!(
                                    "process {} does not exist in container {} generation {}",
                                    request.target.process_id, key.id, key.generation
                                ),
                            )
                        })?
                        .try_wait()?
                }
            };
            if let Some(status) = status {
                return Ok(status);
            }
            let delay = wait_delay(
                timeout,
                started,
                request.timeout_ms,
                request.target.process_id.as_ref(),
                &key,
            )?;
            sleep(delay).await;
        }
    }
}

fn missing_locked_container(key: &ContainerKey) -> a3s_oci_sdk::Error {
    executor_error(
        ErrorCode::Internal,
        format!(
            "container {} generation {} disappeared while executor state remained locked",
            key.id, key.generation
        ),
    )
}

fn wait_delay(
    timeout: Option<Duration>,
    started: Instant,
    timeout_ms: Option<u64>,
    process_id: &str,
    key: &ContainerKey,
) -> Result<Duration> {
    match timeout {
        Some(limit) => {
            let elapsed = started.elapsed();
            if elapsed >= limit {
                return Err(executor_error(
                    ErrorCode::DeadlineExceeded,
                    format!(
                        "timed out after {} ms waiting for process {} in container {} generation {}",
                        timeout_ms.unwrap_or_default(),
                        process_id,
                        key.id,
                        key.generation
                    ),
                )
                .retryable(true));
            }
            Ok(WAIT_POLL_INTERVAL.min(limit - elapsed))
        }
        None => Ok(WAIT_POLL_INTERVAL),
    }
}
