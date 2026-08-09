use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentClient, AgentContainerOperationRequest, AgentOperation, AgentTransportFaultPoint,
    AgentTransportOperationStage,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerOperationRequest, ContainerTarget, ErrorCode, Generation, ListRequest,
    OciRuntimeService, OperationContext, StartRequest,
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
async fn every_pause_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_pause_reopen(index, stage).await;
    }
}

async fn exercise_pause_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let create = create_request(
        &bundle_directory,
        &format!("agent-reopen-pause-create-{index}"),
    );
    let guest = Arc::new(JournaledLifecycleGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::Pause,
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
    .unwrap_or_else(|error| panic!("open first pause runtime for {stage:?}: {error}"));
    let created = first_service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare pause create for {stage:?}: {error}"));
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    first_service
        .start(StartRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-pause-start-{index}"
            ))),
            target,
        })
        .await
        .unwrap_or_else(|error| panic!("prepare pause start for {stage:?}: {error}"));
    let pause = ContainerOperationRequest {
        context: OperationContext::new(operation_id(&format!("agent-reopen-pause-{index}"))),
        target: ContainerTarget::current(create.id.clone()),
    };
    assert_eq!(guest.start_effect_count(), 1, "{stage:?}");

    let first_result = first_service.pause(pause.clone()).await;
    if response_reached_host(stage) {
        let paused = first_result
            .unwrap_or_else(|error| panic!("written pause response for {stage:?}: {error}"));
        assert_running(&paused, created.generation, true, stage);
    } else {
        let error = first_result.expect_err("pause fault must remain visible before delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.pause_dispatches(), 1, "{stage:?}");

    let active = first_service
        .list(ListRequest::default())
        .await
        .unwrap_or_else(|error| panic!("list first pause record for {stage:?}: {error}"));
    assert_eq!(active.len(), 1, "{stage:?}");
    assert_running(
        &active[0],
        created.generation,
        response_reached_host(stage),
        stage,
    );
    drop(first_service);
    drop(first_driver);

    let server_result = first_server
        .await
        .unwrap_or_else(|error| panic!("first pause server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest pause fault must end first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(
        guest.pause_request_count(),
        first_guest_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.pause_effect_count(),
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
    .unwrap_or_else(|error| panic!("reopen pause runtime for {stage:?}: {error}"));
    assert_eq!(metrics.recoveries(), 1, "{stage:?}");

    let paused = reopened
        .pause(pause.clone())
        .await
        .unwrap_or_else(|error| panic!("resume pause after {stage:?}: {error}"));
    assert_running(&paused, created.generation, true, stage);
    let expected_driver_dispatches = if response_reached_host(stage) { 1 } else { 2 };
    let expected_guest_requests = if response_reached_host(stage) {
        1
    } else {
        first_guest_dispatches + 1
    };
    assert_eq!(
        metrics.pause_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.pause_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );
    assert_eq!(
        guest.pause_effect_count(),
        1,
        "reopen after {stage:?} must produce exactly one pause effect"
    );

    let replayed = reopened
        .pause(pause.clone())
        .await
        .unwrap_or_else(|error| panic!("replay cached pause after {stage:?}: {error}"));
    assert_running(&replayed, created.generation, true, stage);
    assert_eq!(
        metrics.pause_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.pause_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );
    assert_eq!(guest.pause_effect_count(), 1, "{stage:?}");

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_changed_pause_replays_fail_closed(
            &second_client,
            &reopened,
            &pause,
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
        .unwrap_or_else(|error| panic!("close replacement pause session for {stage:?}: {error}"));
    second_server
        .await
        .unwrap_or_else(|error| panic!("replacement pause server task for {stage:?}: {error}"))
        .unwrap_or_else(|error| panic!("replacement pause server close for {stage:?}: {error}"));
}

fn assert_running(
    record: &a3s_oci_sdk::ContainerRecord,
    generation: Generation,
    paused: bool,
    stage: AgentTransportOperationStage,
) {
    assert_eq!(record.generation, generation, "{stage:?}");
    assert_eq!(*record.state.status(), ContainerState::Running, "{stage:?}");
    assert_eq!(*record.state.pid(), Some(6_101), "{stage:?}");
    assert_eq!(record.is_paused(), paused, "{stage:?}");
}

async fn verify_changed_pause_replays_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &ContainerOperationRequest,
    generation: Generation,
    guest: &JournaledLifecycleGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.pause_request_count();
    let driver_dispatches = metrics.pause_dispatches();
    let changed_target =
        ContainerTarget::exact(request.target.id.clone(), Generation(generation.0 + 1));
    let guest_conflict = client
        .pause(AgentContainerOperationRequest {
            context: request.context.clone(),
            target: changed_target.clone(),
        })
        .await
        .expect_err("changed guest pause must fail closed");
    assert_eq!(guest_conflict.code, ErrorCode::Conflict);
    assert_eq!(guest.pause_request_count(), request_count + 1);
    assert_eq!(guest.pause_effect_count(), 1);

    let host_conflict = service
        .pause(ContainerOperationRequest {
            context: request.context.clone(),
            target: changed_target,
        })
        .await
        .expect_err("changed durable pause retry must fail closed");
    assert_eq!(host_conflict.code, ErrorCode::FailedPrecondition);
    assert_eq!(metrics.pause_dispatches(), driver_dispatches);
    assert_eq!(guest.pause_request_count(), request_count + 1);
    assert_eq!(guest.pause_effect_count(), 1);
}
