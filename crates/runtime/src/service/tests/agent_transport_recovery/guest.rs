use std::sync::Mutex;

use a3s_oci_agent_protocol::{
    AgentCapabilities, AgentContainerOperationRequest, AgentCreateRequest, AgentDeleteRequest,
    AgentExecRequest, AgentKillRequest, AgentOperation, AgentProcess, AgentSignalProcessRequest,
    AgentStartRequest, AgentState, AgentStateRequest, AgentWaitProcessRequest, AgentWaitRequest,
    GuestAgentService,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{async_trait, DeleteMode, Error, ErrorCode, ExitStatus, Result};

use super::guest_journal::{already_exists, changed_request, OperationJournal};

mod metrics;

#[derive(Debug, Default)]
struct LifecycleJournal {
    create: OperationJournal<AgentCreateRequest, AgentState>,
    state_requests: usize,
    start: OperationJournal<AgentStartRequest, AgentState>,
    kill: OperationJournal<AgentKillRequest, AgentState>,
    delete: OperationJournal<AgentDeleteRequest, ()>,
    wait_requests: usize,
    exec: OperationJournal<AgentExecRequest, AgentProcess>,
    signal_process: OperationJournal<AgentSignalProcessRequest, ()>,
    wait_process_requests: usize,
    pause: OperationJournal<AgentContainerOperationRequest, AgentState>,
    init_exit_status: Option<ExitStatus>,
    exec_exit_status: Option<ExitStatus>,
    current: Option<AgentState>,
}

#[derive(Debug)]
pub(super) struct JournaledLifecycleGuest {
    capabilities: AgentCapabilities,
    journal: Mutex<LifecycleJournal>,
}

impl JournaledLifecycleGuest {
    pub(super) fn new() -> Self {
        Self {
            capabilities: AgentCapabilities::new(
                "host-service-reopen-test",
                std::env::consts::ARCH,
                vec![
                    AgentOperation::Create,
                    AgentOperation::State,
                    AgentOperation::Start,
                    AgentOperation::Kill,
                    AgentOperation::Delete,
                    AgentOperation::Wait,
                    AgentOperation::Exec,
                    AgentOperation::SignalProcess,
                    AgentOperation::WaitProcess,
                    AgentOperation::Pause,
                ],
            )
            .expect("test guest capabilities"),
            journal: Mutex::new(LifecycleJournal::default()),
        }
    }
}

#[async_trait]
impl GuestAgentService for JournaledLifecycleGuest {
    fn capabilities(&self) -> AgentCapabilities {
        self.capabilities.clone()
    }

    async fn create(&self, request: AgentCreateRequest) -> Result<AgentState> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.create.requests += 1;
        if let Some((recorded, response)) = journal.create.entry.as_ref() {
            if recorded.context.operation_id == request.context.operation_id {
                if recorded != &request {
                    return Err(changed_request("create"));
                }
                return Ok(response.clone());
            }
            return Err(already_exists("create"));
        }

        let response = AgentState::new(
            request.target.clone(),
            ContainerState::Created,
            Some(6_101),
            request.bundle.config_digest(),
        )?;
        journal.create.effects += 1;
        journal.create.entry = Some((request, response.clone()));
        journal.init_exit_status = None;
        journal.current = Some(response.clone());
        Ok(response)
    }

    async fn state(&self, request: AgentStateRequest) -> Result<AgentState> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.state_requests += 1;
        let response = journal.current.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-state")
        })?;
        if response.target() != &request.target {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-state"));
        }
        Ok(response.clone())
    }

    async fn start(&self, request: AgentStartRequest) -> Result<AgentState> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.start.requests += 1;
        if let Some((recorded, response)) = journal.start.entry.as_ref() {
            if recorded.context.operation_id == request.context.operation_id {
                if recorded != &request {
                    return Err(changed_request("start"));
                }
                return Ok(response.clone());
            }
            return Err(already_exists("start"));
        }

        let current = journal.current.clone().ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-start")
        })?;
        if current.target() != &request.target {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-start"));
        }
        if current.config_digest() != request.expected_config_digest {
            return Err(Error::new(
                ErrorCode::Conflict,
                "start configuration digest does not match the guest create snapshot",
            )
            .for_operation("agent-start"));
        }
        if current.status() != ContainerState::Created {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "guest start requires created state, found {}",
                    current.status()
                ),
            )
            .for_operation("agent-start"));
        }

        let response = AgentState::new(
            request.target.clone(),
            ContainerState::Running,
            current.pid(),
            current.config_digest(),
        )?;
        journal.start.effects += 1;
        journal.start.entry = Some((request, response.clone()));
        journal.current = Some(response.clone());
        Ok(response)
    }

    async fn kill(&self, request: AgentKillRequest) -> Result<AgentState> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.kill.requests += 1;
        if let Some((recorded, response)) = journal.kill.entry.as_ref() {
            if recorded.context.operation_id == request.context.operation_id {
                if recorded != &request {
                    return Err(changed_request("kill"));
                }
                return Ok(response.clone());
            }
            return Err(already_exists("kill"));
        }

        let current = journal.current.clone().ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-kill")
        })?;
        if current.target() != &request.target {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-kill"));
        }
        if !matches!(
            current.status(),
            ContainerState::Created | ContainerState::Running
        ) {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "guest kill requires created or running state, found {}",
                    current.status()
                ),
            )
            .for_operation("agent-kill"));
        }

        let response = AgentState::new(
            request.target.clone(),
            ContainerState::Stopped,
            None,
            current.config_digest(),
        )?;
        let exit_status = ExitStatus::signaled(request.signal.get(), false)?;
        journal.kill.effects += 1;
        journal.kill.entry = Some((request, response.clone()));
        journal.init_exit_status = Some(exit_status);
        journal.current = Some(response.clone());
        Ok(response)
    }

    async fn delete(&self, request: AgentDeleteRequest) -> Result<()> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.delete.requests += 1;
        if let Some((recorded, ())) = journal.delete.entry.as_ref() {
            if recorded.context.operation_id == request.context.operation_id {
                if recorded != &request {
                    return Err(changed_request("delete"));
                }
                return Ok(());
            }
            return Err(already_exists("delete"));
        }

        let current = journal.current.clone().ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-delete")
        })?;
        if current.target() != &request.target {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-delete"));
        }
        if request.mode == DeleteMode::StoppedOnly && current.status() != ContainerState::Stopped {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "guest stopped-only delete requires stopped state, found {}",
                    current.status()
                ),
            )
            .for_operation("agent-delete"));
        }

        journal.delete.effects += 1;
        journal.delete.entry = Some((request, ()));
        journal.init_exit_status = None;
        journal.current = None;
        Ok(())
    }

    async fn wait(&self, request: AgentWaitRequest) -> Result<ExitStatus> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.wait_requests += 1;
        let current = journal.current.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-wait")
        })?;
        if current.target() != &request.target {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-wait"));
        }
        if current.status() != ContainerState::Stopped {
            return Err(Error::new(
                ErrorCode::DeadlineExceeded,
                "guest init process is still running",
            )
            .for_operation("agent-wait")
            .retryable(true));
        }
        journal.init_exit_status.clone().ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                "guest stopped state has no init exit status",
            )
            .for_operation("agent-wait")
        })
    }

    async fn exec(&self, request: AgentExecRequest) -> Result<AgentProcess> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.exec.requests += 1;
        if let Some((recorded, response)) = journal.exec.entry.as_ref() {
            if recorded.context.operation_id == request.context.operation_id {
                if recorded != &request {
                    return Err(changed_request("exec"));
                }
                return Ok(response.clone());
            }
            return Err(already_exists("exec"));
        }

        let current = journal.current.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-exec")
        })?;
        if current.target() != &request.target.container {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-exec"));
        }
        if current.status() != ContainerState::Running {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "guest exec requires running state, found {}",
                    current.status()
                ),
            )
            .for_operation("agent-exec"));
        }

        let terminal = request.process.terminal().unwrap_or(false);
        let response = AgentProcess::new(request.target.clone(), 6_202, terminal)?;
        journal.exec.effects += 1;
        journal.exec.entry = Some((request, response.clone()));
        journal.exec_exit_status = None;
        Ok(response)
    }

    async fn signal_process(&self, request: AgentSignalProcessRequest) -> Result<()> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.signal_process.requests += 1;
        if let Some((recorded, ())) = journal.signal_process.entry.as_ref() {
            if recorded.context.operation_id == request.context.operation_id {
                if recorded != &request {
                    return Err(changed_request("signal-process"));
                }
                return Ok(());
            }
            return Err(already_exists("signal-process"));
        }

        let process = journal
            .exec
            .entry
            .as_ref()
            .map(|(_, process)| process)
            .ok_or_else(|| {
                Error::new(ErrorCode::NotFound, "guest exec process is unavailable")
                    .for_operation("agent-signal-process")
            })?;
        if process.target() != &request.target {
            return Err(
                Error::new(ErrorCode::NotFound, "guest exec process is unavailable")
                    .for_operation("agent-signal-process"),
            );
        }

        let exit_status = ExitStatus::signaled(request.signal.get(), false)?;
        journal.signal_process.effects += 1;
        journal.signal_process.entry = Some((request, ()));
        journal.exec_exit_status = Some(exit_status);
        Ok(())
    }

    async fn wait_process(&self, request: AgentWaitProcessRequest) -> Result<ExitStatus> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.wait_process_requests += 1;
        let process = journal
            .exec
            .entry
            .as_ref()
            .map(|(_, process)| process)
            .ok_or_else(|| {
                Error::new(ErrorCode::NotFound, "guest exec process is unavailable")
                    .for_operation("agent-wait-process")
            })?;
        if process.target() != &request.target {
            return Err(
                Error::new(ErrorCode::NotFound, "guest exec process is unavailable")
                    .for_operation("agent-wait-process"),
            );
        }
        journal.exec_exit_status.clone().ok_or_else(|| {
            Error::new(
                ErrorCode::DeadlineExceeded,
                "guest exec process is still running",
            )
            .for_operation("agent-wait-process")
            .retryable(true)
        })
    }

    async fn pause(&self, request: AgentContainerOperationRequest) -> Result<AgentState> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.pause.requests += 1;
        if let Some((recorded, response)) = journal.pause.entry.as_ref() {
            if recorded.context.operation_id == request.context.operation_id {
                if recorded != &request {
                    return Err(changed_request("pause"));
                }
                return Ok(response.clone());
            }
            return Err(already_exists("pause"));
        }

        let current = journal.current.clone().ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-pause")
        })?;
        if current.target() != &request.target {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-pause"));
        }
        if current.status() != ContainerState::Running || current.paused() {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "guest pause requires an unfrozen running container",
            )
            .for_operation("agent-pause"));
        }

        let response = AgentState::new_with_pause(
            request.target.clone(),
            ContainerState::Running,
            current.pid(),
            current.config_digest(),
            true,
        )?;
        journal.pause.effects += 1;
        journal.pause.entry = Some((request, response.clone()));
        journal.current = Some(response.clone());
        Ok(response)
    }
}
