use super::*;
use crate::{
    serve_agent_connection_with_fault_injector, AgentTransportFaultInjector,
    AgentTransportFaultPoint, AgentTransportOperationStage, AgentTransportShutdownStage,
};

#[derive(Debug)]
struct ReplayCreateAgent {
    capabilities: AgentCapabilities,
    state: Mutex<ReplayCreateState>,
}

#[derive(Debug, Default)]
struct ReplayCreateState {
    request: Option<AgentCreateRequest>,
    response: Option<AgentState>,
    effects: usize,
}

impl ReplayCreateAgent {
    fn new() -> Self {
        Self {
            capabilities: AgentCapabilities::new(
                "response-replay-test",
                std::env::consts::ARCH,
                vec![crate::AgentOperation::Create, crate::AgentOperation::State],
            )
            .expect("replay test capabilities"),
            state: Mutex::new(ReplayCreateState::default()),
        }
    }

    fn effects(&self) -> usize {
        self.state.lock().expect("replay state lock").effects
    }
}

#[async_trait]
impl GuestAgentService for ReplayCreateAgent {
    fn capabilities(&self) -> AgentCapabilities {
        self.capabilities.clone()
    }

    async fn create(&self, request: AgentCreateRequest) -> Result<AgentState> {
        let mut state = self.state.lock().expect("replay state lock");
        if let (Some(recorded), Some(response)) = (&state.request, &state.response) {
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
                "the exact container generation already exists",
            )
            .for_operation("agent-create"));
        }

        let response = AgentState::new(
            request.target.clone(),
            ContainerState::Created,
            Some(101),
            request.bundle.config_digest(),
        )?;
        state.effects += 1;
        state.request = Some(request);
        state.response = Some(response.clone());
        Ok(response)
    }

    async fn state(&self, request: AgentStateRequest) -> Result<AgentState> {
        let state = self.state.lock().expect("replay state lock");
        let response = state.response.as_ref().ok_or_else(|| {
            Error::new(ErrorCode::NotFound, "container generation is unavailable")
                .for_operation("agent-state")
        })?;
        if response.target() != &request.target {
            return Err(
                Error::new(ErrorCode::NotFound, "container generation is unavailable")
                    .for_operation("agent-state"),
            );
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
struct FailOnceTransportInjector {
    target: AgentTransportFaultPoint,
    fired: AtomicBool,
    events: Mutex<Vec<AgentTransportFaultPoint>>,
}

impl FailOnceTransportInjector {
    fn new(target: AgentTransportFaultPoint) -> Self {
        Self {
            target,
            fired: AtomicBool::new(false),
            events: Mutex::new(Vec::new()),
        }
    }

    fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }

    fn events(&self) -> Vec<AgentTransportFaultPoint> {
        self.events.lock().expect("fault event lock").clone()
    }
}

impl AgentTransportFaultInjector for FailOnceTransportInjector {
    fn check(&self, point: AgentTransportFaultPoint) -> Result<()> {
        self.events.lock().expect("fault event lock").push(point);
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

#[test]
fn transport_fault_registries_cover_every_current_operation_and_stage() {
    assert_eq!(crate::AgentOperation::ALL.len(), 20);
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    assert_eq!(AgentTransportShutdownStage::ALL.len(), 2);
    for operation in crate::AgentOperation::ALL {
        assert!(
            (crate::AGENT_PROTOCOL_VERSION_MIN..=crate::AGENT_PROTOCOL_VERSION_MAX)
                .contains(&operation.minimum_protocol_version()),
            "{operation:?} has no current protocol version"
        );
    }
}

#[tokio::test]
async fn host_fault_injector_reports_versioned_operation_and_shutdown_stages() {
    let protocol_version = crate::AGENT_PROTOCOL_VERSION_MAX;
    let faults = Arc::new(FailOnceTransportInjector::new(
        AgentTransportFaultPoint::Operation {
            protocol_version,
            operation: crate::AgentOperation::Create,
            stage: AgentTransportOperationStage::GuestBeforeDispatch,
        },
    ));
    let service: Arc<dyn GuestAgentService> = Arc::new(ReplayCreateAgent::new());
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let server = tokio::spawn(serve_agent_connection(guest, token(37), service));
    let client_faults: Arc<dyn AgentTransportFaultInjector> = faults.clone();
    let client = AgentClient::connect_with_fault_injector(host, token(37), client_faults)
        .await
        .expect("connect host fault-stage session");

    client
        .create(create_request_for("host-stages", 1, "host-stages-create"))
        .await
        .expect("create across observed host stages");
    client
        .close()
        .await
        .expect("close across observed host stages");
    server
        .await
        .expect("host fault-stage server task")
        .expect("host fault-stage server observed clean close");

    assert!(!faults.fired());
    assert_eq!(
        faults.events(),
        vec![
            AgentTransportFaultPoint::Operation {
                protocol_version,
                operation: crate::AgentOperation::Create,
                stage: AgentTransportOperationStage::HostBeforeRequestWrite,
            },
            AgentTransportFaultPoint::Operation {
                protocol_version,
                operation: crate::AgentOperation::Create,
                stage: AgentTransportOperationStage::HostAfterRequestWrite,
            },
            AgentTransportFaultPoint::Operation {
                protocol_version,
                operation: crate::AgentOperation::Create,
                stage: AgentTransportOperationStage::HostBeforeResponseRead,
            },
            AgentTransportFaultPoint::Operation {
                protocol_version,
                operation: crate::AgentOperation::Create,
                stage: AgentTransportOperationStage::HostAfterResponseRead,
            },
            AgentTransportFaultPoint::Shutdown {
                protocol_version,
                stage: AgentTransportShutdownStage::HostBeforeShutdown,
            },
            AgentTransportFaultPoint::Shutdown {
                protocol_version,
                stage: AgentTransportShutdownStage::HostAfterShutdown,
            },
        ]
    );
}

#[tokio::test]
async fn every_host_operation_fault_poisons_and_releases_the_connection() {
    let protocol_version = crate::AGENT_PROTOCOL_VERSION_MAX;
    let stages = [
        AgentTransportOperationStage::HostBeforeRequestWrite,
        AgentTransportOperationStage::HostAfterRequestWrite,
        AgentTransportOperationStage::HostBeforeResponseRead,
        AgentTransportOperationStage::HostAfterResponseRead,
    ];

    for (index, target_stage) in stages.into_iter().enumerate() {
        let fault_point = AgentTransportFaultPoint::Operation {
            protocol_version,
            operation: crate::AgentOperation::Create,
            stage: target_stage,
        };
        let faults = Arc::new(FailOnceTransportInjector::new(fault_point));
        let service: Arc<dyn GuestAgentService> = Arc::new(ReplayCreateAgent::new());
        let (host, guest) = tokio::io::duplex(1024 * 1024);
        let dropped = Arc::new(AtomicBool::new(false));
        let host = DropObservedStream::new(host, Arc::clone(&dropped));
        let server = tokio::spawn(serve_agent_connection(
            guest,
            token(40 + index as u8),
            service,
        ));
        let client_faults: Arc<dyn AgentTransportFaultInjector> = faults.clone();
        let client =
            AgentClient::connect_with_fault_injector(host, token(40 + index as u8), client_faults)
                .await
                .expect("connect host operation-fault session");
        let clone = client.clone();

        let error = client
            .create(create_request_for(
                &format!("host-fault-{index}"),
                1,
                &format!("host-fault-create-{index}"),
            ))
            .await
            .expect_err("host operation fault must fail the request");
        assert_eq!(error.operation.as_deref(), Some("agent-transport-fault"));
        assert!(error.retryable);
        assert!(faults.fired());
        assert!(
            dropped.load(Ordering::SeqCst),
            "{target_stage:?} must release the shared transport"
        );
        assert_eq!(
            faults.events(),
            stages[..=index]
                .iter()
                .copied()
                .map(|stage| AgentTransportFaultPoint::Operation {
                    protocol_version,
                    operation: crate::AgentOperation::Create,
                    stage,
                })
                .collect::<Vec<_>>()
        );

        let error = clone
            .create(create_request_for(
                &format!("host-fault-clone-{index}"),
                1,
                &format!("host-fault-clone-create-{index}"),
            ))
            .await
            .expect_err("a host fault must poison every client clone");
        assert_eq!(error.code, ErrorCode::Unavailable);
        clone
            .close()
            .await
            .expect("close poisoned host-fault client");
        drop(client);
        let _server_result = server.await.expect("host operation-fault server task");
    }
}

#[tokio::test]
async fn every_host_shutdown_fault_releases_the_connection() {
    let protocol_version = crate::AGENT_PROTOCOL_VERSION_MAX;
    let stages = AgentTransportShutdownStage::ALL;

    for (index, target_stage) in stages.into_iter().enumerate() {
        let fault_point = AgentTransportFaultPoint::Shutdown {
            protocol_version,
            stage: target_stage,
        };
        let faults = Arc::new(FailOnceTransportInjector::new(fault_point));
        let service: Arc<dyn GuestAgentService> = Arc::new(ReplayCreateAgent::new());
        let (host, guest) = tokio::io::duplex(1024 * 1024);
        let dropped = Arc::new(AtomicBool::new(false));
        let host = DropObservedStream::new(host, Arc::clone(&dropped));
        let server = tokio::spawn(serve_agent_connection(
            guest,
            token(50 + index as u8),
            service,
        ));
        let client_faults: Arc<dyn AgentTransportFaultInjector> = faults.clone();
        let client =
            AgentClient::connect_with_fault_injector(host, token(50 + index as u8), client_faults)
                .await
                .expect("connect host shutdown-fault session");
        let clone = client.clone();

        let error = client
            .close()
            .await
            .expect_err("host shutdown fault must fail the first close");
        assert_eq!(error.operation.as_deref(), Some("agent-transport-fault"));
        assert!(error.retryable);
        assert!(faults.fired());
        assert!(
            dropped.load(Ordering::SeqCst),
            "{target_stage:?} must release the shared transport"
        );
        assert_eq!(
            faults.events(),
            stages[..=index]
                .iter()
                .copied()
                .map(|stage| AgentTransportFaultPoint::Shutdown {
                    protocol_version,
                    stage,
                })
                .collect::<Vec<_>>()
        );

        clone
            .close()
            .await
            .expect("repeat close after a shutdown fault is idempotent");
        let request_error = clone
            .create(create_request_for(
                &format!("shutdown-fault-{index}"),
                1,
                &format!("shutdown-fault-create-{index}"),
            ))
            .await
            .expect_err("shutdown fault must close every retained client clone");
        assert_eq!(request_error.code, ErrorCode::Unavailable);
        server
            .await
            .expect("host shutdown-fault server task")
            .expect("host shutdown fault released the server transport");
    }
}

#[tokio::test]
async fn validation_failure_only_crosses_guest_response_write_stages() {
    let protocol_version = crate::AGENT_PROTOCOL_VERSION_MAX;
    let faults = Arc::new(FailOnceTransportInjector::new(
        AgentTransportFaultPoint::Operation {
            protocol_version,
            operation: crate::AgentOperation::Create,
            stage: AgentTransportOperationStage::HostBeforeRequestWrite,
        },
    ));
    let service = Arc::new(ReplayCreateAgent::new());
    let server_service: Arc<dyn GuestAgentService> = service.clone();
    let server_faults: Arc<dyn AgentTransportFaultInjector> = faults.clone();
    let (mut host, guest) = tokio::io::duplex(1024 * 1024);
    let expected_token = token(38);
    let server = tokio::spawn(serve_agent_connection_with_fault_injector(
        guest,
        expected_token.clone(),
        server_service,
        server_faults,
    ));

    write_frame(
        &mut host,
        &HostHello {
            protocols: ProtocolRange::CURRENT,
            token: expected_token,
        },
    )
    .await
    .expect("write validation-stage hello");
    let hello: HelloOutcome = read_frame(&mut host)
        .await
        .expect("read validation-stage hello")
        .expect("server returned validation-stage hello");
    let HelloOutcome::Accepted { hello } = hello else {
        panic!("validation-stage negotiation was rejected");
    };
    assert_eq!(hello.selected_version(), protocol_version);

    write_frame(
        &mut host,
        &RequestEnvelope {
            version: protocol_version,
            request_id: 0,
            request: AgentRequest::Create(create_request_for(
                "validation-stages",
                1,
                "validation-stages-create",
            )),
        },
    )
    .await
    .expect("write invalid request envelope");
    let response: ResponseEnvelope = read_frame(&mut host)
        .await
        .expect("read invalid request response")
        .expect("server returned invalid request response");
    let ResponseOutcome::Failed { error } = response.outcome else {
        panic!("invalid request envelope unexpectedly succeeded");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(service.effects(), 0);
    assert_eq!(
        faults.events(),
        vec![
            AgentTransportFaultPoint::Operation {
                protocol_version,
                operation: crate::AgentOperation::Create,
                stage: AgentTransportOperationStage::GuestBeforeResponseWrite,
            },
            AgentTransportFaultPoint::Operation {
                protocol_version,
                operation: crate::AgentOperation::Create,
                stage: AgentTransportOperationStage::GuestAfterResponseWrite,
            },
        ]
    );
    assert!(!faults.fired());
    server
        .await
        .expect("validation-stage server task")
        .expect_err("request ID zero must end the server connection");
}

#[tokio::test]
async fn response_loss_after_guest_dispatch_replays_one_exact_create_effect() {
    let protocol_version = crate::AGENT_PROTOCOL_VERSION_MAX;
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version,
        operation: crate::AgentOperation::Create,
        stage: AgentTransportOperationStage::GuestBeforeResponseWrite,
    };
    let faults = Arc::new(FailOnceTransportInjector::new(fault_point));
    let service = Arc::new(ReplayCreateAgent::new());
    let request = create_request_for("response-loss", 7, "response-loss-create");
    let target = request.target.clone();

    let (first_host, first_guest) = tokio::io::duplex(1024 * 1024);
    let first_service: Arc<dyn GuestAgentService> = service.clone();
    let first_faults: Arc<dyn AgentTransportFaultInjector> = faults.clone();
    let first_server = tokio::spawn(serve_agent_connection_with_fault_injector(
        first_guest,
        token(36),
        first_service,
        first_faults,
    ));
    let first_client = AgentClient::connect(first_host, token(36))
        .await
        .expect("connect response-loss session");
    let error = first_client
        .create(request.clone())
        .await
        .expect_err("injected response loss must hide the completed create response");
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert!(error.retryable);
    assert_eq!(service.effects(), 1);
    let server_error = first_server
        .await
        .expect("response-loss server task")
        .expect_err("guest response fault must end the first connection");
    assert_eq!(
        server_error.operation.as_deref(),
        Some("agent-transport-fault")
    );
    assert!(faults.fired());
    assert_eq!(
        faults.events(),
        vec![
            AgentTransportFaultPoint::Operation {
                protocol_version,
                operation: crate::AgentOperation::Create,
                stage: AgentTransportOperationStage::GuestAfterRequestRead,
            },
            AgentTransportFaultPoint::Operation {
                protocol_version,
                operation: crate::AgentOperation::Create,
                stage: AgentTransportOperationStage::GuestBeforeDispatch,
            },
            AgentTransportFaultPoint::Operation {
                protocol_version,
                operation: crate::AgentOperation::Create,
                stage: AgentTransportOperationStage::GuestAfterDispatch,
            },
            fault_point,
        ]
    );

    let (second_host, second_guest) = tokio::io::duplex(1024 * 1024);
    let second_service: Arc<dyn GuestAgentService> = service.clone();
    let second_server = tokio::spawn(serve_agent_connection(
        second_guest,
        token(36),
        second_service,
    ));
    let second_client = AgentClient::connect(second_host, token(36))
        .await
        .expect("reconnect authenticated replay session");
    let replayed = second_client
        .create(request.clone())
        .await
        .expect("replay exact create request");
    assert_eq!(replayed.target(), &target);
    assert_eq!(replayed.status(), ContainerState::Created);
    assert_eq!(service.effects(), 1, "replay must not repeat create");

    let mut changed = request;
    changed.io.stdout = IoMode::Null;
    let error = second_client
        .create(changed)
        .await
        .expect_err("changed replay must fail closed");
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(
        second_client
            .state(AgentStateRequest { target })
            .await
            .expect("business failure must leave replay connection usable"),
        replayed
    );
    second_client.close().await.expect("close replay session");
    second_server
        .await
        .expect("replay server task")
        .expect("replay server observed clean close");
}
