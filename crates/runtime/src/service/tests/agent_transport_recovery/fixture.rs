use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use a3s_oci_agent_protocol::{
    AgentBundle, AgentCapabilities, AgentClient, AgentCreateRequest, AgentDeleteRequest,
    AgentKillRequest, AgentStartRequest, AgentState, AgentStateRequest,
    AgentTransportFaultInjector, AgentTransportFaultPoint, GuestAgentService, GuestPath,
    SessionToken,
};
use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, IsolationClass,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    async_trait, ContainerRecord, ContainerTarget, Error, ErrorCode, OciBundle, OperationContext,
    ProcessIo, Result,
};
use tokio::io::DuplexStream;

use crate::{
    DriverCreateRequest, DriverDeleteRequest, DriverKillRequest, DriverRecovery,
    DriverStartRequest, DriverState, RuntimeDriver,
};

#[derive(Debug, Default)]
struct CreateJournal {
    entry: Option<(AgentCreateRequest, AgentState)>,
    requests: usize,
    effects: usize,
}

#[derive(Debug)]
pub(super) struct JournaledCreateGuest {
    capabilities: AgentCapabilities,
    journal: Mutex<CreateJournal>,
}

impl JournaledCreateGuest {
    pub(super) fn new() -> Self {
        Self {
            capabilities: AgentCapabilities::core(
                "host-service-reopen-test",
                std::env::consts::ARCH,
            )
            .expect("test guest capabilities"),
            journal: Mutex::new(CreateJournal::default()),
        }
    }

    pub(super) fn request_count(&self) -> usize {
        self.journal.lock().expect("guest journal lock").requests
    }

    pub(super) fn effect_count(&self) -> usize {
        self.journal.lock().expect("guest journal lock").effects
    }
}

#[async_trait]
impl GuestAgentService for JournaledCreateGuest {
    fn capabilities(&self) -> AgentCapabilities {
        self.capabilities.clone()
    }

    async fn create(&self, request: AgentCreateRequest) -> Result<AgentState> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.requests += 1;
        if let Some((recorded, response)) = journal.entry.as_ref() {
            if recorded.context.operation_id == request.context.operation_id {
                if recorded != &request {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "create operation ID was reused with a different guest request",
                    )
                    .for_operation("agent-create"));
                }
                return Ok(response.clone());
            }
            return Err(Error::new(
                ErrorCode::AlreadyExists,
                "the exact guest container generation already exists",
            )
            .for_operation("agent-create"));
        }

        let response = AgentState::new(
            request.target.clone(),
            ContainerState::Created,
            Some(6_101),
            request.bundle.config_digest(),
        )?;
        journal.effects += 1;
        journal.entry = Some((request, response.clone()));
        Ok(response)
    }

    async fn state(&self, request: AgentStateRequest) -> Result<AgentState> {
        let journal = self.journal.lock().expect("guest journal lock");
        let (_, response) = journal.entry.as_ref().ok_or_else(|| {
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

    async fn start(&self, _request: AgentStartRequest) -> Result<AgentState> {
        Err(Error::unsupported("agent-start"))
    }

    async fn kill(&self, _request: AgentKillRequest) -> Result<AgentState> {
        Err(Error::unsupported("agent-kill"))
    }

    async fn delete(&self, _request: AgentDeleteRequest) -> Result<()> {
        Err(Error::unsupported("agent-delete"))
    }
}

#[derive(Debug)]
pub(super) struct FailOnceTransportFault {
    target: AgentTransportFaultPoint,
    crossings: AtomicUsize,
}

impl FailOnceTransportFault {
    pub(super) fn new(target: AgentTransportFaultPoint) -> Self {
        Self {
            target,
            crossings: AtomicUsize::new(0),
        }
    }

    pub(super) fn crossing_count(&self) -> usize {
        self.crossings.load(Ordering::SeqCst)
    }
}

impl AgentTransportFaultInjector for FailOnceTransportFault {
    fn check(&self, point: AgentTransportFaultPoint) -> Result<()> {
        if point == self.target && self.crossings.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(Error::new(
                ErrorCode::Unavailable,
                format!("injected agent transport fault at {point}"),
            )
            .for_operation("agent-transport-fault")
            .retryable(true));
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(super) struct DriverMetrics {
    create_dispatches: AtomicUsize,
    recoveries: AtomicUsize,
}

impl DriverMetrics {
    pub(super) fn create_dispatches(&self) -> usize {
        self.create_dispatches.load(Ordering::SeqCst)
    }

    pub(super) fn recoveries(&self) -> usize {
        self.recoveries.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
pub(super) struct AgentCreateDriver {
    client: AgentClient<DuplexStream>,
    metrics: Arc<DriverMetrics>,
}

impl AgentCreateDriver {
    pub(super) fn new(client: AgentClient<DuplexStream>, metrics: Arc<DriverMetrics>) -> Self {
        Self { client, metrics }
    }
}

#[async_trait]
impl RuntimeDriver for AgentCreateDriver {
    fn capability(&self) -> DriverCapability {
        DriverCapability {
            driver: DriverKind::LibkrunWhpx,
            status: CapabilityStatus::Available,
            readiness: DriverReadiness::Experimental,
            isolation_classes: vec![IsolationClass::DedicatedVm],
            reason: None,
            evidence: BTreeMap::from([(
                "test-driver".to_string(),
                "authenticated-in-memory-agent".to_string(),
            )]),
        }
    }

    async fn recover(&self, _record: &ContainerRecord) -> Result<DriverRecovery> {
        self.metrics.recoveries.fetch_add(1, Ordering::SeqCst);
        Ok(DriverRecovery::none())
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        self.metrics
            .create_dispatches
            .fetch_add(1, Ordering::SeqCst);
        let expected_target = request.target.clone();
        let expected_digest = request.bundle.config_digest().to_string();
        let state = self
            .client
            .create(agent_create_request(
                request.context,
                request.target,
                &request.bundle,
                request.io,
            )?)
            .await?;
        map_agent_state(&expected_target, Some(&expected_digest), state)
    }

    async fn state(&self, target: ContainerTarget) -> Result<DriverState> {
        let state = self
            .client
            .state(AgentStateRequest {
                target: target.clone(),
            })
            .await?;
        map_agent_state(&target, None, state)
    }

    async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        let expected_target = request.target.clone();
        let expected_digest = request.bundle.config_digest().to_string();
        let state = self
            .client
            .start(AgentStartRequest {
                context: request.context,
                target: request.target,
                expected_config_digest: expected_digest.clone(),
            })
            .await?;
        map_agent_state(&expected_target, Some(&expected_digest), state)
    }

    async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        let expected_target = request.target.clone();
        let state = self
            .client
            .kill(AgentKillRequest {
                context: request.context,
                target: request.target,
                signal: request.signal,
                all: request.all,
            })
            .await?;
        map_agent_state(&expected_target, None, state)
    }

    async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        self.client
            .delete(AgentDeleteRequest {
                context: request.context,
                target: request.target,
                mode: request.mode,
            })
            .await
    }
}

pub(super) fn agent_create_request(
    context: OperationContext,
    target: ContainerTarget,
    bundle: &OciBundle,
    io: ProcessIo,
) -> Result<AgentCreateRequest> {
    Ok(AgentCreateRequest {
        context,
        target,
        bundle: AgentBundle::new(bundle, GuestPath::new("/run/a3s/reopen-test-bundle")?),
        io,
    })
}

fn map_agent_state(
    expected_target: &ContainerTarget,
    expected_digest: Option<&str>,
    state: AgentState,
) -> Result<DriverState> {
    if state.target() != expected_target {
        return Err(Error::new(
            ErrorCode::Conflict,
            "guest returned a different container generation",
        )
        .for_operation("map-agent-state"));
    }
    if expected_digest.is_some_and(|digest| state.config_digest() != digest) {
        return Err(Error::new(
            ErrorCode::Conflict,
            "guest returned a different configuration digest",
        )
        .for_operation("map-agent-state"));
    }
    let mapped = match state.status() {
        ContainerState::Created => DriverState::created(required_pid(&state)?)?,
        ContainerState::Running => DriverState::running(required_pid(&state)?)?,
        ContainerState::Stopped => DriverState::stopped(),
        status => {
            return Err(Error::new(
                ErrorCode::Internal,
                format!("guest returned invalid lifecycle state {status}"),
            )
            .for_operation("map-agent-state"));
        }
    };
    mapped.with_paused(state.paused())
}

fn required_pid(state: &AgentState) -> Result<i32> {
    state.pid().ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            format!("guest returned {} without an init PID", state.status()),
        )
        .for_operation("map-agent-state")
    })
}

pub(super) fn session_token() -> SessionToken {
    SessionToken::from_bytes([0x6d; 32]).expect("test session token")
}
