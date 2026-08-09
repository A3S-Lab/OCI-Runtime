use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentClient, AgentOperation, AgentStateRequest, AgentTransportFaultPoint,
    AgentTransportOperationStage,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, ErrorCode, Generation, ListRequest, OciRuntimeService, StateRequest,
};
use tokio::io::DuplexStream;

use super::driver::{AgentLifecycleDriver, DriverMetrics};
use super::guest::JournaledLifecycleGuest;
use super::transport::{
    connect_faulted, connect_normal, guest_dispatch_reached, is_guest_stage, response_reached_host,
    FailOnceTransportFault,
};
use crate::service::tests::create_request;
use crate::{HostRuntimeService, RuntimeDriver};

#[tokio::test]
async fn every_state_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_state_reopen(index, stage).await;
    }
}

async fn exercise_state_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let create = create_request(
        &bundle_directory,
        &format!("agent-reopen-state-create-{index}"),
    );
    let guest = Arc::new(JournaledLifecycleGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::State,
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
    .unwrap_or_else(|error| panic!("open first state runtime for {stage:?}: {error}"));
    let created = first_service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare state matrix for {stage:?}: {error}"));
    let state = StateRequest {
        target: ContainerTarget::current(create.id.clone()),
    };
    assert_eq!(guest.create_effect_count(), 1, "{stage:?}");
    assert_eq!(metrics.create_dispatches(), 1, "{stage:?}");

    let first_result = first_service.state(state.clone()).await;
    if response_reached_host(stage) {
        let observed = first_result
            .unwrap_or_else(|error| panic!("written state response for {stage:?}: {error}"));
        assert_created(&observed, created.generation, stage);
    } else {
        let error = first_result.expect_err("state fault must remain visible before delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.state_dispatches(), 1, "{stage:?}");

    let durable = first_service
        .list(ListRequest::default())
        .await
        .unwrap_or_else(|error| panic!("list first state record for {stage:?}: {error}"));
    assert_eq!(durable.len(), 1, "{stage:?}");
    assert_created(&durable[0], created.generation, stage);
    assert_eq!(metrics.state_dispatches(), 1, "{stage:?}");
    drop(first_service);
    drop(first_driver);

    let server_result = first_server
        .await
        .unwrap_or_else(|error| panic!("first state server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest state fault must end the first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(
        guest.state_request_count(),
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
    .unwrap_or_else(|error| panic!("reopen state runtime for {stage:?}: {error}"));
    assert_eq!(metrics.recoveries(), 1, "{stage:?}");

    let observed = reopened
        .state(state.clone())
        .await
        .unwrap_or_else(|error| panic!("repeat state after {stage:?}: {error}"));
    assert_created(&observed, created.generation, stage);
    assert_eq!(metrics.state_dispatches(), 2, "{stage:?}");
    assert_eq!(
        guest.state_request_count(),
        first_guest_dispatches + 1,
        "{stage:?}"
    );

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_stale_state_targets_fail_closed(
            &second_client,
            &reopened,
            &state,
            created.generation,
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
        .unwrap_or_else(|error| panic!("close replacement state session for {stage:?}: {error}"));
    second_server
        .await
        .unwrap_or_else(|error| panic!("replacement state server task for {stage:?}: {error}"))
        .unwrap_or_else(|error| panic!("replacement state server close for {stage:?}: {error}"));
}

fn assert_created(
    record: &a3s_oci_sdk::ContainerRecord,
    generation: Generation,
    stage: AgentTransportOperationStage,
) {
    assert_eq!(record.generation, generation, "{stage:?}");
    assert_eq!(*record.state.status(), ContainerState::Created, "{stage:?}");
    assert_eq!(*record.state.pid(), Some(6_101), "{stage:?}");
}

async fn verify_stale_state_targets_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &StateRequest,
    generation: Generation,
    guest: &JournaledLifecycleGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.state_request_count();
    let driver_dispatches = metrics.state_dispatches();
    let stale_target =
        ContainerTarget::exact(request.target.id.clone(), Generation(generation.0 + 1));
    let guest_error = client
        .state(AgentStateRequest {
            target: stale_target.clone(),
        })
        .await
        .expect_err("stale guest state target must fail closed");
    assert_eq!(guest_error.code, ErrorCode::NotFound);
    assert_eq!(guest.state_request_count(), request_count + 1);

    let host_error = service
        .state(StateRequest {
            target: stale_target,
        })
        .await
        .expect_err("stale durable state target must fail closed");
    assert_eq!(host_error.code, ErrorCode::Conflict);
    assert_eq!(metrics.state_dispatches(), driver_dispatches);
    assert_eq!(guest.state_request_count(), request_count + 1);
}
