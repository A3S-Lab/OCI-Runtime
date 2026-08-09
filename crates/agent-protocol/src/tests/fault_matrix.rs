use super::*;
use crate::{
    serve_agent_connection_with_fault_injector, AgentTransportFaultInjector,
    AgentTransportFaultPoint, AgentTransportOperationStage,
};

#[derive(Debug, Default)]
struct ArmedTransportFaultInjector {
    target: Mutex<Option<AgentTransportFaultPoint>>,
    fired: AtomicBool,
    events: Mutex<Vec<AgentTransportFaultPoint>>,
}

impl ArmedTransportFaultInjector {
    fn arm(&self, target: AgentTransportFaultPoint) {
        *self.target.lock().expect("matrix fault target lock") = Some(target);
        self.fired.store(false, Ordering::SeqCst);
        self.events.lock().expect("matrix fault event lock").clear();
    }

    fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }

    fn events(&self) -> Vec<AgentTransportFaultPoint> {
        self.events.lock().expect("matrix fault event lock").clone()
    }
}

impl AgentTransportFaultInjector for ArmedTransportFaultInjector {
    fn check(&self, point: AgentTransportFaultPoint) -> Result<()> {
        self.events
            .lock()
            .expect("matrix fault event lock")
            .push(point);
        if self
            .target
            .lock()
            .expect("matrix fault target lock")
            .is_some_and(|target| target == point)
            && !self.fired.swap(true, Ordering::SeqCst)
        {
            return Err(Error::new(
                ErrorCode::Unavailable,
                format!("injected exhaustive agent transport fault at {point}"),
            )
            .for_operation("agent-transport-fault")
            .retryable(true));
        }
        Ok(())
    }
}

#[tokio::test]
async fn every_current_operation_crosses_every_versioned_transport_fault_stage() {
    let registry = crate::AgentOperation::ALL
        .into_iter()
        .flat_map(|operation| {
            AgentTransportOperationStage::ALL
                .into_iter()
                .map(move |stage| (operation, stage))
        })
        .collect::<Vec<_>>();
    assert_eq!(registry.len(), 20 * 9);
    assert_eq!(
        registry.iter().copied().collect::<HashSet<_>>().len(),
        registry.len(),
        "the exhaustive transport registry must not omit a pair behind a duplicate"
    );

    for (index, (operation, stage)) in registry.into_iter().enumerate() {
        exercise_operation_stage(index, operation, stage).await;
    }
}

async fn exercise_operation_stage(
    index: usize,
    operation: crate::AgentOperation,
    stage: AgentTransportOperationStage,
) {
    let protocol_version = crate::AGENT_PROTOCOL_VERSION_MAX;
    let point = AgentTransportFaultPoint::Operation {
        protocol_version,
        operation,
        stage,
    };
    let faults = Arc::new(ArmedTransportFaultInjector::default());
    let client_faults: Arc<dyn AgentTransportFaultInjector> = faults.clone();
    let server_faults: Arc<dyn AgentTransportFaultInjector> = faults.clone();
    let service: Arc<dyn GuestAgentService> = Arc::new(TestAgent::default());
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let token_byte = u8::try_from(index % 254 + 1).expect("nonzero matrix token byte");
    let session_token = token(token_byte);
    let server = tokio::spawn(serve_agent_connection_with_fault_injector(
        guest,
        session_token.clone(),
        service,
        server_faults,
    ));
    let client = AgentClient::connect_with_fault_injector(host, session_token, client_faults)
        .await
        .unwrap_or_else(|error| panic!("connect matrix session for {point}: {error}"));
    let request = prepare_request(&client, operation, index).await;
    assert_eq!(request.operation(), operation);

    faults.arm(point);
    let result = client.call_for_test(request).await;
    if stage == AgentTransportOperationStage::GuestAfterResponseWrite {
        result.unwrap_or_else(|error| panic!("response written before {point}: {error}"));
    } else {
        let error = match result {
            Ok(response) => panic!("{point} unexpectedly returned {response:?}"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::Unavailable, "{point}");
        assert!(error.retryable, "{point}");
    }

    let server_result = server
        .await
        .unwrap_or_else(|error| panic!("matrix server task for {point}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest fault must end the server connection");
        assert_eq!(error.operation.as_deref(), Some("agent-transport-fault"));
    }

    assert!(faults.fired(), "fault point was not reached: {point}");
    let events = faults.events();
    assert!(
        events.iter().all(|event| matches!(
            event,
            AgentTransportFaultPoint::Operation {
                protocol_version: event_version,
                operation: event_operation,
                ..
            } if *event_version == protocol_version && *event_operation == operation
        )),
        "setup or another operation leaked into the armed matrix case: {point}; events={events:?}"
    );
    assert_eq!(
        events.iter().filter(|event| **event == point).count(),
        1,
        "fault point must be crossed exactly once: {point}; events={events:?}"
    );
    let unique = events.iter().copied().collect::<HashSet<_>>();
    assert_eq!(
        unique.len(),
        events.len(),
        "operation transitions must not repeat before disconnect: {point}; events={events:?}"
    );

    let target = request_target(operation, index);
    let follow_up = client
        .call_for_test(AgentRequest::State(AgentStateRequest { target }))
        .await
        .expect_err("faulted matrix connection must reject the next request");
    assert_eq!(follow_up.code, ErrorCode::Unavailable, "{point}");
    client
        .close()
        .await
        .unwrap_or_else(|error| panic!("close matrix session after {point}: {error}"));
}

const fn is_guest_stage(stage: AgentTransportOperationStage) -> bool {
    matches!(
        stage,
        AgentTransportOperationStage::GuestAfterRequestRead
            | AgentTransportOperationStage::GuestBeforeDispatch
            | AgentTransportOperationStage::GuestAfterDispatch
            | AgentTransportOperationStage::GuestBeforeResponseWrite
            | AgentTransportOperationStage::GuestAfterResponseWrite
    )
}

async fn prepare_request<T>(
    client: &AgentClient<T>,
    operation: crate::AgentOperation,
    index: usize,
) -> AgentRequest
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    let case = format!("matrix-{}-{index}", operation.as_str());
    let create = create_request_for(&case, 1, &format!("{case}-create"));
    let target = create.target.clone();
    let digest = create.bundle.config_digest().to_string();
    if operation == crate::AgentOperation::Create {
        return AgentRequest::Create(create);
    }

    client
        .create(create)
        .await
        .unwrap_or_else(|error| panic!("prepare create for {operation}: {error}"));

    if requires_running_container(operation) {
        client
            .start(AgentStartRequest {
                context: OperationContext::new(operation_id(&format!("{case}-start"))),
                target: target.clone(),
                expected_config_digest: digest.clone(),
            })
            .await
            .unwrap_or_else(|error| panic!("prepare start for {operation}: {error}"));
    }

    if operation == crate::AgentOperation::Wait {
        client
            .kill(AgentKillRequest {
                context: OperationContext::new(operation_id(&format!("{case}-setup-kill"))),
                target: target.clone(),
                signal: Signal::new(15).expect("matrix setup signal"),
                all: false,
            })
            .await
            .expect("prepare stopped matrix container");
    }

    let process = if matches!(
        operation,
        crate::AgentOperation::SignalProcess | crate::AgentOperation::WaitProcess
    ) {
        let request = exec_request(
            target.clone(),
            &format!("{case}-worker"),
            &format!("{case}-setup-exec"),
        );
        let process = request.target.clone();
        client
            .exec(request)
            .await
            .unwrap_or_else(|error| panic!("prepare exec for {operation}: {error}"));
        Some(process)
    } else {
        None
    };

    if operation == crate::AgentOperation::WaitProcess {
        client
            .signal_process(AgentSignalProcessRequest {
                context: OperationContext::new(operation_id(&format!("{case}-setup-signal"))),
                target: process.clone().expect("matrix process target"),
                signal: Signal::new(15).expect("matrix process signal"),
            })
            .await
            .expect("prepare stopped matrix process");
    }

    if operation == crate::AgentOperation::Resume {
        client
            .pause(AgentContainerOperationRequest {
                context: OperationContext::new(operation_id(&format!("{case}-setup-pause"))),
                target: target.clone(),
            })
            .await
            .expect("prepare paused matrix container");
    }

    request_for_operation(operation, case, target, digest, process)
}

const fn requires_running_container(operation: crate::AgentOperation) -> bool {
    matches!(
        operation,
        crate::AgentOperation::Kill
            | crate::AgentOperation::Wait
            | crate::AgentOperation::Exec
            | crate::AgentOperation::SignalProcess
            | crate::AgentOperation::WaitProcess
            | crate::AgentOperation::Pause
            | crate::AgentOperation::Resume
            | crate::AgentOperation::Processes
            | crate::AgentOperation::Update
            | crate::AgentOperation::Stats
            | crate::AgentOperation::ReadOutput
            | crate::AgentOperation::WriteStdin
            | crate::AgentOperation::CloseStdin
            | crate::AgentOperation::Resize
    )
}

fn request_for_operation(
    operation: crate::AgentOperation,
    case: String,
    target: ContainerTarget,
    digest: String,
    process: Option<ProcessTarget>,
) -> AgentRequest {
    let context = || OperationContext::new(operation_id(&format!("{case}-target")));
    let init = || ProcessTarget {
        container: target.clone(),
        process_id: ProcessId::init(),
    };
    match operation {
        crate::AgentOperation::Create => unreachable!("create request returned before setup"),
        crate::AgentOperation::State => AgentRequest::State(AgentStateRequest { target }),
        crate::AgentOperation::Start => AgentRequest::Start(AgentStartRequest {
            context: context(),
            target,
            expected_config_digest: digest,
        }),
        crate::AgentOperation::Kill => AgentRequest::Kill(AgentKillRequest {
            context: context(),
            target,
            signal: Signal::new(15).expect("matrix signal"),
            all: false,
        }),
        crate::AgentOperation::Delete => AgentRequest::Delete(AgentDeleteRequest {
            context: context(),
            target,
            mode: DeleteMode::Force,
        }),
        crate::AgentOperation::Wait => AgentRequest::Wait(AgentWaitRequest {
            target,
            timeout_ms: Some(1),
        }),
        crate::AgentOperation::Exec => AgentRequest::Exec(Box::new(exec_request(
            target,
            &format!("{case}-target-worker"),
            &format!("{case}-target"),
        ))),
        crate::AgentOperation::SignalProcess => {
            AgentRequest::SignalProcess(AgentSignalProcessRequest {
                context: context(),
                target: process.expect("matrix signal process"),
                signal: Signal::new(15).expect("matrix process signal"),
            })
        }
        crate::AgentOperation::WaitProcess => AgentRequest::WaitProcess(AgentWaitProcessRequest {
            target: process.expect("matrix wait process"),
            timeout_ms: Some(1),
        }),
        crate::AgentOperation::Pause => AgentRequest::Pause(AgentContainerOperationRequest {
            context: context(),
            target,
        }),
        crate::AgentOperation::Resume => AgentRequest::Resume(AgentContainerOperationRequest {
            context: context(),
            target,
        }),
        crate::AgentOperation::Processes => {
            AgentRequest::Processes(AgentProcessesRequest { target })
        }
        crate::AgentOperation::Update => {
            let resources = serde_json::from_value(serde_json::json!({
                "memory": {"limit": 4096}
            }))
            .expect("matrix resource update");
            AgentRequest::Update(Box::new(AgentUpdateRequest {
                context: context(),
                target,
                resources,
            }))
        }
        crate::AgentOperation::Stats => AgentRequest::Stats(AgentStatsRequest { target }),
        crate::AgentOperation::ReadOutput => AgentRequest::ReadOutput(AgentReadOutputRequest {
            process: init(),
            after_sequence: 0,
            max_bytes: 8,
            wait_timeout_ms: None,
        }),
        crate::AgentOperation::WriteStdin => AgentRequest::WriteStdin(AgentWriteStdinRequest {
            context: Some(context()),
            process: init(),
            data: b"matrix".to_vec(),
        }),
        crate::AgentOperation::CloseStdin => AgentRequest::CloseStdin(AgentCloseStdinRequest {
            context: Some(context()),
            process: init(),
        }),
        crate::AgentOperation::Resize => AgentRequest::Resize(AgentResizeRequest {
            context: Some(context()),
            process: init(),
            size: TerminalSize {
                width: 120,
                height: 40,
            },
        }),
        crate::AgentOperation::File => AgentRequest::File(FileRequest {
            target,
            op: FileOp::Download,
            path: "/matrix.txt".to_string(),
            data: None,
            user: None,
            context: None,
        }),
        crate::AgentOperation::Filesystem => AgentRequest::Filesystem(FilesystemRequest {
            target,
            op: FilesystemOp::ListDir,
            path: "/".to_string(),
            destination: None,
            depth: 1,
            user: None,
            context: None,
        }),
    }
}

fn request_target(operation: crate::AgentOperation, index: usize) -> ContainerTarget {
    ContainerTarget::exact(
        container_id(&format!("matrix-{}-{index}", operation.as_str())),
        Generation(1),
    )
}
