use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    serve_agent_connection, serve_agent_connection_with_fault_injector, AgentClient,
    AgentTransportFaultInjector, AgentTransportFaultPoint, AgentTransportOperationStage,
    GuestAgentService, SessionToken,
};
use a3s_oci_sdk::{Error, ErrorCode, Result};
use tokio::io::DuplexStream;
use tokio::task::JoinHandle;

use super::guest::JournaledLifecycleGuest;

type AgentServer = JoinHandle<Result<()>>;

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

pub(super) async fn connect_faulted(
    stage: AgentTransportOperationStage,
    guest: Arc<JournaledLifecycleGuest>,
    faults: Arc<FailOnceTransportFault>,
) -> (AgentClient<DuplexStream>, AgentServer) {
    let (host_stream, guest_stream) = tokio::io::duplex(1024 * 1024);
    let guest_service: Arc<dyn GuestAgentService> = guest;
    if is_host_stage(stage) {
        let server = tokio::spawn(serve_agent_connection(
            guest_stream,
            session_token(),
            guest_service,
        ));
        let client_faults: Arc<dyn AgentTransportFaultInjector> = faults;
        let client =
            AgentClient::connect_with_fault_injector(host_stream, session_token(), client_faults)
                .await
                .unwrap_or_else(|error| panic!("connect faulted host stage {stage:?}: {error}"));
        (client, server)
    } else {
        let server_faults: Arc<dyn AgentTransportFaultInjector> = faults;
        let server = tokio::spawn(serve_agent_connection_with_fault_injector(
            guest_stream,
            session_token(),
            guest_service,
            server_faults,
        ));
        let client = AgentClient::connect(host_stream, session_token())
            .await
            .unwrap_or_else(|error| panic!("connect faulted guest stage {stage:?}: {error}"));
        (client, server)
    }
}

pub(super) async fn connect_normal(
    guest: Arc<JournaledLifecycleGuest>,
) -> (AgentClient<DuplexStream>, AgentServer) {
    let (host_stream, guest_stream) = tokio::io::duplex(1024 * 1024);
    let guest_service: Arc<dyn GuestAgentService> = guest;
    let server = tokio::spawn(serve_agent_connection(
        guest_stream,
        session_token(),
        guest_service,
    ));
    let client = AgentClient::connect(host_stream, session_token())
        .await
        .expect("connect replacement authenticated agent session");
    (client, server)
}

pub(super) const fn is_guest_stage(stage: AgentTransportOperationStage) -> bool {
    !is_host_stage(stage)
}

pub(super) const fn guest_dispatch_reached(stage: AgentTransportOperationStage) -> bool {
    matches!(
        stage,
        AgentTransportOperationStage::HostAfterRequestWrite
            | AgentTransportOperationStage::HostBeforeResponseRead
            | AgentTransportOperationStage::HostAfterResponseRead
            | AgentTransportOperationStage::GuestAfterDispatch
            | AgentTransportOperationStage::GuestBeforeResponseWrite
            | AgentTransportOperationStage::GuestAfterResponseWrite
    )
}

pub(super) const fn response_reached_host(stage: AgentTransportOperationStage) -> bool {
    matches!(stage, AgentTransportOperationStage::GuestAfterResponseWrite)
}

const fn is_host_stage(stage: AgentTransportOperationStage) -> bool {
    matches!(
        stage,
        AgentTransportOperationStage::HostBeforeRequestWrite
            | AgentTransportOperationStage::HostAfterRequestWrite
            | AgentTransportOperationStage::HostBeforeResponseRead
            | AgentTransportOperationStage::HostAfterResponseRead
    )
}

fn session_token() -> SessionToken {
    SessionToken::from_bytes([0x6d; 32]).expect("test session token")
}
