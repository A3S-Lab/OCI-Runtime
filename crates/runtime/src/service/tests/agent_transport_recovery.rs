use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use a3s_oci_agent_protocol::{
    serve_agent_connection, serve_agent_connection_with_fault_injector, AgentBundle,
    AgentCapabilities, AgentClient, AgentCreateRequest, AgentDeleteRequest, AgentKillRequest,
    AgentOperation, AgentStartRequest, AgentState, AgentStateRequest, AgentTransportFaultInjector,
    AgentTransportFaultPoint, AgentTransportOperationStage, GuestAgentService, GuestPath,
    SessionToken, AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, IsolationClass,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    async_trait, ContainerRecord, ContainerTarget, CreateAttachments, Error, ErrorCode, IoMode,
    ListRequest, OciBundle, OciRuntimeService, OperationContext, ProcessIo, Result,
};
use tokio::io::DuplexStream;

use super::create_request;
use crate::{
    DriverCreateRequest, DriverDeleteRequest, DriverKillRequest, DriverRecovery,
    DriverStartRequest, DriverState, HostRuntimeService, RuntimeDriver,
};

#[derive(Debug, Default)]
struct CreateJournal {
    entry: Option<(AgentCreateRequest, AgentState)>,
    requests: usize,
    effects: usize,
}

#[derive(Debug)]
struct JournaledCreateGuest {
    capabilities: AgentCapabilities,
    journal: Mutex<CreateJournal>,
}

impl JournaledCreateGuest {
    fn new() -> Self {
        Self {
            capabilities: AgentCapabilities::core(
                "host-service-reopen-test",
                std::env::consts::ARCH,
            )
            .expect("test guest capabilities"),
            journal: Mutex::new(CreateJournal::default()),
        }
    }

    fn request_count(&self) -> usize {
        self.journal.lock().expect("guest journal lock").requests
    }

    fn effect_count(&self) -> usize {
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
struct FailOnceTransportFault {
    target: AgentTransportFaultPoint,
    fired: AtomicBool,
}

impl FailOnceTransportFault {
    fn new(target: AgentTransportFaultPoint) -> Self {
        Self {
            target,
            fired: AtomicBool::new(false),
        }
    }

    fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
}

impl AgentTransportFaultInjector for FailOnceTransportFault {
    fn check(&self, point: AgentTransportFaultPoint) -> Result<()> {
        if point == self.target && !self.fired.swap(true, Ordering::SeqCst) {
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

#[derive(Debug)]
struct AgentCreateDriver {
    client: AgentClient<DuplexStream>,
    create_dispatches: Arc<AtomicUsize>,
    recoveries: Arc<AtomicUsize>,
}

impl AgentCreateDriver {
    fn new(
        client: AgentClient<DuplexStream>,
        create_dispatches: Arc<AtomicUsize>,
        recoveries: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            client,
            create_dispatches,
            recoveries,
        }
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
        self.recoveries.fetch_add(1, Ordering::SeqCst);
        Ok(DriverRecovery::none())
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        self.create_dispatches.fetch_add(1, Ordering::SeqCst);
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

fn agent_create_request(
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

fn session_token() -> SessionToken {
    SessionToken::from_bytes([0x6d; 32]).expect("test session token")
}

#[tokio::test]
async fn create_response_loss_resumes_after_host_service_reopen_with_one_guest_effect() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let request = create_request(&bundle_directory, "agent-reopen-create");
    let guest = Arc::new(JournaledCreateGuest::new());
    let create_dispatches = Arc::new(AtomicUsize::new(0));
    let recoveries = Arc::new(AtomicUsize::new(0));
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::Create,
        stage: AgentTransportOperationStage::GuestBeforeResponseWrite,
    };
    let faults = Arc::new(FailOnceTransportFault::new(fault_point));

    let (first_host_stream, first_guest_stream) = tokio::io::duplex(1024 * 1024);
    let first_guest_service: Arc<dyn GuestAgentService> = guest.clone();
    let first_faults: Arc<dyn AgentTransportFaultInjector> = faults.clone();
    let first_server = tokio::spawn(serve_agent_connection_with_fault_injector(
        first_guest_stream,
        session_token(),
        first_guest_service,
        first_faults,
    ));
    let first_client = AgentClient::connect(first_host_stream, session_token())
        .await
        .expect("connect first authenticated agent session");
    let first_driver = Arc::new(AgentCreateDriver::new(
        first_client,
        Arc::clone(&create_dispatches),
        Arc::clone(&recoveries),
    ));
    let first_service = HostRuntimeService::open(
        &state_root,
        Arc::clone(&first_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("open first host runtime service");

    let first_error = first_service
        .create(request.clone())
        .await
        .expect_err("lost create response must remain visible to the caller");
    assert_eq!(first_error.code, ErrorCode::Unavailable);
    assert!(first_error.retryable);
    assert!(faults.fired());
    assert_eq!(guest.effect_count(), 1);
    assert_eq!(guest.request_count(), 1);
    assert_eq!(create_dispatches.load(Ordering::SeqCst), 1);

    let active = first_service
        .list(ListRequest::default())
        .await
        .expect("list resumable create");
    assert_eq!(active.len(), 1);
    assert_eq!(*active[0].state.status(), ContainerState::Creating);
    let generation = active[0].generation;
    drop(first_service);
    drop(first_driver);

    let server_error = first_server
        .await
        .expect("first agent server task")
        .expect_err("injected response loss must end the first connection");
    assert_eq!(
        server_error.operation.as_deref(),
        Some("agent-transport-fault")
    );

    let (second_host_stream, second_guest_stream) = tokio::io::duplex(1024 * 1024);
    let second_guest_service: Arc<dyn GuestAgentService> = guest.clone();
    let second_server = tokio::spawn(serve_agent_connection(
        second_guest_stream,
        session_token(),
        second_guest_service,
    ));
    let second_client = AgentClient::connect(second_host_stream, session_token())
        .await
        .expect("connect replacement authenticated agent session");
    let second_driver = Arc::new(AgentCreateDriver::new(
        second_client.clone(),
        Arc::clone(&create_dispatches),
        Arc::clone(&recoveries),
    ));
    let reopened = HostRuntimeService::open(
        &state_root,
        Arc::clone(&second_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("reopen host runtime service");
    assert_eq!(recoveries.load(Ordering::SeqCst), 1);

    let created = reopened
        .create(request.clone())
        .await
        .expect("resume create through replacement agent session");
    assert_eq!(created.generation, generation);
    assert_eq!(*created.state.status(), ContainerState::Created);
    assert_eq!(*created.state.pid(), Some(6_101));
    assert_eq!(create_dispatches.load(Ordering::SeqCst), 2);
    assert_eq!(guest.request_count(), 2);
    assert_eq!(guest.effect_count(), 1, "replay must not repeat create");

    let target = ContainerTarget::exact(request.id.clone(), generation);
    let mut changed_guest_request = agent_create_request(
        request.context.clone(),
        target,
        &request.bundle,
        request.attachments.process_io().clone(),
    )
    .expect("changed guest request");
    changed_guest_request.io.stdout = IoMode::Null;
    let guest_conflict = second_client
        .create(changed_guest_request)
        .await
        .expect_err("changed guest request must fail closed");
    assert_eq!(guest_conflict.code, ErrorCode::Conflict);
    assert_eq!(guest.request_count(), 3);
    assert_eq!(guest.effect_count(), 1);

    let mut changed_host_request = request;
    let mut changed_io = changed_host_request.attachments.process_io().clone();
    changed_io.stdout = IoMode::Null;
    changed_host_request.attachments =
        CreateAttachments::from_bundle(&changed_host_request.bundle, changed_io)
            .expect("changed host attachment contract");
    let host_conflict = reopened
        .create(changed_host_request)
        .await
        .expect_err("changed durable create retry must fail closed");
    assert_eq!(host_conflict.code, ErrorCode::FailedPrecondition);
    assert_eq!(create_dispatches.load(Ordering::SeqCst), 2);
    assert_eq!(guest.effect_count(), 1);

    drop(reopened);
    drop(second_driver);
    second_client
        .close()
        .await
        .expect("close replacement agent session");
    second_server
        .await
        .expect("replacement agent server task")
        .expect("replacement agent server observed clean close");
}
