use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentClient, AgentOperation, AgentStartRequest, AgentTransportFaultPoint,
    AgentTransportOperationStage,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, ErrorCode, ListRequest, OciRuntimeService, OperationContext, StartRequest,
};
use tokio::io::DuplexStream;

use super::driver::{AgentLifecycleDriver, DriverMetrics};
use super::guest::JournaledLifecycleGuest;
use super::transport::{
    connect_faulted, connect_normal, guest_dispatch_reached, is_guest_stage, response_reached_host,
    FailOnceTransportFault,
};
use crate::service::tests::{create_request, operation_id};
use crate::{HostRuntimeService, RuntimeDriver};

#[tokio::test]
async fn every_start_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_start_reopen(index, stage).await;
    }
}

async fn exercise_start_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let create = create_request(
        &bundle_directory,
        &format!("agent-reopen-start-create-{index}"),
    );
    let guest = Arc::new(JournaledLifecycleGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::Start,
        stage,
    };
    let faults = Arc::new(FailOnceTransportFault::new(fault_point));

    let (first_client, first_server) =
        connect_faulted(stage, Arc::clone(&guest), Arc::clone(&faults)).await;
    let first_driver = Arc::new(AgentLifecycleDriver::new(
        first_client,
        Arc::clone(&metrics),
    ));
    let first_service = HostRuntimeService::open(
        &state_root,
        Arc::clone(&first_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    .unwrap_or_else(|error| panic!("open first start runtime for {stage:?}: {error}"));
    let created = first_service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare start matrix for {stage:?}: {error}"));
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    let start = StartRequest {
        context: OperationContext::new(operation_id(&format!("agent-reopen-start-{index}"))),
        target: target.clone(),
    };
    assert_eq!(guest.create_effect_count(), 1, "{stage:?}");
    assert_eq!(metrics.create_dispatches(), 1, "{stage:?}");

    let first_result = first_service.start(start.clone()).await;
    if response_reached_host(stage) {
        let running = first_result
            .unwrap_or_else(|error| panic!("written start response for {stage:?}: {error}"));
        assert_eq!(
            *running.state.status(),
            ContainerState::Running,
            "{stage:?}"
        );
    } else {
        let error = first_result.expect_err("start fault must remain visible before delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.start_dispatches(), 1, "{stage:?}");

    let active = first_service
        .list(ListRequest::default())
        .await
        .unwrap_or_else(|error| panic!("list first start record for {stage:?}: {error}"));
    assert_eq!(active.len(), 1, "{stage:?}");
    let expected_first_status = if response_reached_host(stage) {
        ContainerState::Running
    } else {
        ContainerState::Created
    };
    assert_eq!(
        *active[0].state.status(),
        expected_first_status,
        "{stage:?}"
    );
    drop(first_service);
    drop(first_driver);

    let server_result = first_server
        .await
        .unwrap_or_else(|error| panic!("first start server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest start fault must end the first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(
        guest.start_request_count(),
        first_guest_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.start_effect_count(),
        first_guest_dispatches,
        "{stage:?}"
    );

    let (second_client, second_server) = connect_normal(Arc::clone(&guest)).await;
    let second_driver = Arc::new(AgentLifecycleDriver::new(
        second_client.clone(),
        Arc::clone(&metrics),
    ));
    let reopened = HostRuntimeService::open(
        &state_root,
        Arc::clone(&second_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    .unwrap_or_else(|error| panic!("reopen start runtime for {stage:?}: {error}"));
    assert_eq!(metrics.recoveries(), 1, "{stage:?}");

    let running = reopened
        .start(start.clone())
        .await
        .unwrap_or_else(|error| panic!("resume start after {stage:?}: {error}"));
    assert_eq!(running.generation, created.generation, "{stage:?}");
    assert_eq!(
        *running.state.status(),
        ContainerState::Running,
        "{stage:?}"
    );
    assert_eq!(*running.state.pid(), Some(6_101), "{stage:?}");

    let expected_driver_dispatches = if response_reached_host(stage) { 1 } else { 2 };
    let expected_guest_requests = if response_reached_host(stage) {
        1
    } else {
        first_guest_dispatches + 1
    };
    assert_eq!(
        metrics.start_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.start_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );
    assert_eq!(
        guest.start_effect_count(),
        1,
        "reopen after {stage:?} must produce exactly one start effect"
    );

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_changed_start_replays_fail_closed(
            &second_client,
            &reopened,
            &start,
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
        .unwrap_or_else(|error| panic!("close replacement start session for {stage:?}: {error}"));
    second_server
        .await
        .unwrap_or_else(|error| panic!("replacement start server task for {stage:?}: {error}"))
        .unwrap_or_else(|error| panic!("replacement start server close for {stage:?}: {error}"));
}

async fn verify_changed_start_replays_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &StartRequest,
    guest: &JournaledLifecycleGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.start_request_count();
    let driver_dispatches = metrics.start_dispatches();
    let changed_guest = AgentStartRequest {
        context: request.context.clone(),
        target: request.target.clone(),
        expected_config_digest: format!("sha256:{}", "0".repeat(64)),
    };
    let guest_conflict = client
        .start(changed_guest)
        .await
        .expect_err("changed guest start must fail closed");
    assert_eq!(guest_conflict.code, ErrorCode::Conflict);
    assert_eq!(guest.start_request_count(), request_count + 1);
    assert_eq!(guest.start_effect_count(), 1);

    let mut changed_host = request.clone();
    changed_host.target = ContainerTarget::current(request.target.id.clone());
    let host_conflict = service
        .start(changed_host)
        .await
        .expect_err("changed durable start retry must fail closed");
    assert_eq!(host_conflict.code, ErrorCode::FailedPrecondition);
    assert_eq!(metrics.start_dispatches(), driver_dispatches);
    assert_eq!(guest.start_request_count(), request_count + 1);
    assert_eq!(guest.start_effect_count(), 1);
}
