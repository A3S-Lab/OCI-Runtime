use std::sync::Arc;

use a3s_oci_agent_protocol::{
    serve_agent_connection, serve_agent_connection_with_fault_injector, AgentClient,
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultPoint,
    AgentTransportOperationStage, GuestAgentService,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, CreateAttachments, ErrorCode, IoMode, ListRequest, OciRuntimeService,
};
use tokio::io::DuplexStream;
use tokio::task::JoinHandle;

use super::create_request;
use crate::{HostRuntimeService, RuntimeDriver};

mod fixture;

use fixture::{
    agent_create_request, session_token, AgentCreateDriver, DriverMetrics, FailOnceTransportFault,
    JournaledCreateGuest,
};

type AgentServer = JoinHandle<a3s_oci_sdk::Result<()>>;

#[tokio::test]
async fn every_create_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_create_reopen(index, stage).await;
    }
}

async fn exercise_create_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let request = create_request(&bundle_directory, &format!("agent-reopen-create-{index}"));
    let guest = Arc::new(JournaledCreateGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::Create,
        stage,
    };
    let faults = Arc::new(FailOnceTransportFault::new(fault_point));

    let (first_client, first_server) =
        connect_faulted(stage, Arc::clone(&guest), Arc::clone(&faults)).await;
    let first_driver = Arc::new(AgentCreateDriver::new(first_client, Arc::clone(&metrics)));
    let first_service = HostRuntimeService::open(
        &state_root,
        Arc::clone(&first_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    .unwrap_or_else(|error| panic!("open first host runtime for {stage:?}: {error}"));

    let first_result = first_service.create(request.clone()).await;
    if response_reached_host(stage) {
        let created = first_result
            .unwrap_or_else(|error| panic!("written response must complete {stage:?}: {error}"));
        assert_eq!(
            *created.state.status(),
            ContainerState::Created,
            "{stage:?}"
        );
    } else {
        let error = first_result.expect_err("fault must remain visible before response delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.create_dispatches(), 1, "{stage:?}");

    let active = first_service
        .list(ListRequest::default())
        .await
        .unwrap_or_else(|error| panic!("list first durable record for {stage:?}: {error}"));
    assert_eq!(active.len(), 1, "{stage:?}");
    let expected_first_status = if response_reached_host(stage) {
        ContainerState::Created
    } else {
        ContainerState::Creating
    };
    assert_eq!(
        *active[0].state.status(),
        expected_first_status,
        "{stage:?}"
    );
    let generation = active[0].generation;
    drop(first_service);
    drop(first_driver);

    let server_result = first_server
        .await
        .unwrap_or_else(|error| panic!("first agent server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest fault must end the first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(guest.request_count(), first_guest_dispatches, "{stage:?}");
    assert_eq!(guest.effect_count(), first_guest_dispatches, "{stage:?}");

    let (second_client, second_server) = connect_normal(Arc::clone(&guest)).await;
    let second_driver = Arc::new(AgentCreateDriver::new(
        second_client.clone(),
        Arc::clone(&metrics),
    ));
    let reopened = HostRuntimeService::open(
        &state_root,
        Arc::clone(&second_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    .unwrap_or_else(|error| panic!("reopen host runtime for {stage:?}: {error}"));
    assert_eq!(metrics.recoveries(), 1, "{stage:?}");

    let created = reopened
        .create(request.clone())
        .await
        .unwrap_or_else(|error| panic!("resume create after {stage:?}: {error}"));
    assert_eq!(created.generation, generation, "{stage:?}");
    assert_eq!(
        *created.state.status(),
        ContainerState::Created,
        "{stage:?}"
    );
    assert_eq!(*created.state.pid(), Some(6_101), "{stage:?}");

    let expected_driver_dispatches = if response_reached_host(stage) { 1 } else { 2 };
    let expected_guest_requests = if response_reached_host(stage) {
        1
    } else {
        first_guest_dispatches + 1
    };
    assert_eq!(
        metrics.create_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(guest.request_count(), expected_guest_requests, "{stage:?}");
    assert_eq!(
        guest.effect_count(),
        1,
        "reopen after {stage:?} must produce exactly one create effect"
    );

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_changed_replays_fail_closed(
            &second_client,
            &reopened,
            &request,
            generation,
            guest.as_ref(),
            metrics.as_ref(),
        )
        .await;
    }

    drop(reopened);
    drop(second_driver);
    second_client
        .close()
        .await
        .unwrap_or_else(|error| panic!("close replacement session for {stage:?}: {error}"));
    second_server
        .await
        .unwrap_or_else(|error| panic!("replacement server task for {stage:?}: {error}"))
        .unwrap_or_else(|error| panic!("replacement server close for {stage:?}: {error}"));
}

async fn connect_faulted(
    stage: AgentTransportOperationStage,
    guest: Arc<JournaledCreateGuest>,
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

async fn connect_normal(
    guest: Arc<JournaledCreateGuest>,
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

async fn verify_changed_replays_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &a3s_oci_sdk::CreateRequest,
    generation: a3s_oci_sdk::Generation,
    guest: &JournaledCreateGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.request_count();
    let driver_dispatches = metrics.create_dispatches();
    let target = ContainerTarget::exact(request.id.clone(), generation);
    let mut changed_guest_request = agent_create_request(
        request.context.clone(),
        target,
        &request.bundle,
        request.attachments.process_io().clone(),
    )
    .expect("changed guest request");
    changed_guest_request.io.stdout = IoMode::Null;
    let guest_conflict = client
        .create(changed_guest_request)
        .await
        .expect_err("changed guest request must fail closed");
    assert_eq!(guest_conflict.code, ErrorCode::Conflict);
    assert_eq!(guest.request_count(), request_count + 1);
    assert_eq!(guest.effect_count(), 1);

    let mut changed_host_request = request.clone();
    let mut changed_io = changed_host_request.attachments.process_io().clone();
    changed_io.stdout = IoMode::Null;
    changed_host_request.attachments =
        CreateAttachments::from_bundle(&changed_host_request.bundle, changed_io)
            .expect("changed host attachment contract");
    let host_conflict = service
        .create(changed_host_request)
        .await
        .expect_err("changed durable create retry must fail closed");
    assert_eq!(host_conflict.code, ErrorCode::FailedPrecondition);
    assert_eq!(metrics.create_dispatches(), driver_dispatches);
    assert_eq!(guest.request_count(), request_count + 1);
    assert_eq!(guest.effect_count(), 1);
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

const fn is_guest_stage(stage: AgentTransportOperationStage) -> bool {
    !is_host_stage(stage)
}

const fn guest_dispatch_reached(stage: AgentTransportOperationStage) -> bool {
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

const fn response_reached_host(stage: AgentTransportOperationStage) -> bool {
    matches!(stage, AgentTransportOperationStage::GuestAfterResponseWrite)
}
