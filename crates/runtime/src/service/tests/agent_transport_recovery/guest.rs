use std::sync::Mutex;

use a3s_oci_agent_protocol::{
    AgentCapabilities, AgentCreateRequest, AgentDeleteRequest, AgentKillRequest, AgentStartRequest,
    AgentState, AgentStateRequest, GuestAgentService,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{async_trait, Error, ErrorCode, Result};

#[derive(Debug)]
struct OperationJournal<Request, Response> {
    entry: Option<(Request, Response)>,
    requests: usize,
    effects: usize,
}

impl<Request, Response> Default for OperationJournal<Request, Response> {
    fn default() -> Self {
        Self {
            entry: None,
            requests: 0,
            effects: 0,
        }
    }
}

#[derive(Debug, Default)]
struct LifecycleJournal {
    create: OperationJournal<AgentCreateRequest, AgentState>,
    start: OperationJournal<AgentStartRequest, AgentState>,
    kill: OperationJournal<AgentKillRequest, AgentState>,
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
            capabilities: AgentCapabilities::core(
                "host-service-reopen-test",
                std::env::consts::ARCH,
            )
            .expect("test guest capabilities"),
            journal: Mutex::new(LifecycleJournal::default()),
        }
    }

    pub(super) fn create_request_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .create
            .requests
    }

    pub(super) fn create_effect_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .create
            .effects
    }

    pub(super) fn start_request_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .start
            .requests
    }

    pub(super) fn start_effect_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .start
            .effects
    }

    pub(super) fn kill_request_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .kill
            .requests
    }

    pub(super) fn kill_effect_count(&self) -> usize {
        self.journal
            .lock()
            .expect("guest journal lock")
            .kill
            .effects
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
        journal.current = Some(response.clone());
        Ok(response)
    }

    async fn state(&self, request: AgentStateRequest) -> Result<AgentState> {
        let journal = self.journal.lock().expect("guest journal lock");
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
        journal.kill.effects += 1;
        journal.kill.entry = Some((request, response.clone()));
        journal.current = Some(response.clone());
        Ok(response)
    }

    async fn delete(&self, _request: AgentDeleteRequest) -> Result<()> {
        Err(Error::unsupported("agent-delete"))
    }
}

fn changed_request(operation: &'static str) -> Error {
    Error::new(
        ErrorCode::Conflict,
        format!("{operation} operation ID was reused with a different guest request"),
    )
    .for_operation(format!("agent-{operation}"))
}

fn already_exists(operation: &'static str) -> Error {
    Error::new(
        ErrorCode::AlreadyExists,
        format!("the exact guest container generation already has a {operation} journal"),
    )
    .for_operation(format!("agent-{operation}"))
}
