use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentClient, AgentOperation, AgentTransportFaultPoint, AgentTransportOperationStage,
    AgentUpdateRequest,
};
use a3s_oci_sdk::oci_spec::runtime::{ContainerState, LinuxResources};
use a3s_oci_sdk::{
    ContainerTarget, ErrorCode, Generation, ListRequest, OciRuntimeService, OperationContext,
    StartRequest, UpdateRequest,
};
use tokio::io::DuplexStream;

use super::driver::{AgentLifecycleDriver, DriverMetrics};
use super::guest::JournaledLifecycleGuest;
use super::transport::{
    connect_faulted, connect_normal, guest_dispatch_reached, is_guest_stage, response_reached_host,
    FailOnceTransportFault,
};
use crate::service::tests::{create_request, operation_id, update_request};
use crate::{HostRuntimeService, RuntimeDriver};

#[tokio::test]
async fn every_update_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_update_reopen(index, stage).await;
    }
}

async fn exercise_update_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let create = create_request(
        &bundle_directory,
        &format!("agent-reopen-update-create-{index}"),
    );
    let guest = Arc::new(JournaledLifecycleGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::Update,
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
    .unwrap_or_else(|error| panic!("open first update runtime for {stage:?}: {error}"));
    let created = first_service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare update create for {stage:?}: {error}"));
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    first_service
        .start(StartRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-update-start-{index}"
            ))),
            target,
        })
        .await
        .unwrap_or_else(|error| panic!("prepare update start for {stage:?}: {error}"));
    let update = update_request(
        ContainerTarget::current(create.id.clone()),
        &format!("agent-reopen-update-{index}"),
    );

    let first_result = first_service.update(update.clone()).await;
    if response_reached_host(stage) {
        let updated = first_result
            .unwrap_or_else(|error| panic!("written update response for {stage:?}: {error}"));
        assert_running(&updated, created.generation, stage);
    } else {
        let error = first_result.expect_err("update fault must remain visible before delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.update_dispatches(), 1, "{stage:?}");

    let active = first_service
        .list(ListRequest::default())
        .await
        .unwrap_or_else(|error| panic!("list first update record for {stage:?}: {error}"));
    assert_eq!(active.len(), 1, "{stage:?}");
    assert_running(&active[0], created.generation, stage);
    drop(first_service);
    drop(first_driver);

    let server_result = first_server
        .await
        .unwrap_or_else(|error| panic!("first update server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest update fault must end first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(
        guest.update_request_count(),
        first_guest_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.update_effect_count(),
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
    .unwrap_or_else(|error| panic!("reopen update runtime for {stage:?}: {error}"));
    assert_eq!(metrics.recoveries(), 1, "{stage:?}");

    let updated = reopened
        .update(update.clone())
        .await
        .unwrap_or_else(|error| panic!("resume update after {stage:?}: {error}"));
    assert_running(&updated, created.generation, stage);
    let expected_driver_dispatches = if response_reached_host(stage) { 1 } else { 2 };
    let expected_guest_requests = if response_reached_host(stage) {
        1
    } else {
        first_guest_dispatches + 1
    };
    assert_eq!(
        metrics.update_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.update_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );
    assert_eq!(guest.update_effect_count(), 1, "{stage:?}");

    let replayed = reopened
        .update(update.clone())
        .await
        .unwrap_or_else(|error| panic!("replay cached update after {stage:?}: {error}"));
    assert_running(&replayed, created.generation, stage);
    assert_eq!(
        metrics.update_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.update_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );
    assert_eq!(guest.update_effect_count(), 1, "{stage:?}");

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_changed_update_replays_fail_closed(
            &second_client,
            &reopened,
            &update,
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
        .unwrap_or_else(|error| panic!("close replacement update session for {stage:?}: {error}"));
    second_server
        .await
        .unwrap_or_else(|error| panic!("replacement update server task for {stage:?}: {error}"))
        .unwrap_or_else(|error| panic!("replacement update server close for {stage:?}: {error}"));
}

fn assert_running(
    record: &a3s_oci_sdk::ContainerRecord,
    generation: Generation,
    stage: AgentTransportOperationStage,
) {
    assert_eq!(record.generation, generation, "{stage:?}");
    assert_eq!(*record.state.status(), ContainerState::Running, "{stage:?}");
    assert_eq!(*record.state.pid(), Some(6_101), "{stage:?}");
    assert!(!record.is_paused(), "{stage:?}");
}

async fn verify_changed_update_replays_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &UpdateRequest,
    generation: Generation,
    guest: &JournaledLifecycleGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.update_request_count();
    let driver_dispatches = metrics.update_dispatches();
    let changed_resources: LinuxResources = serde_json::from_value(serde_json::json!({
        "memory": {"limit": 8192},
        "cpu": {"shares": 1024},
        "pids": {"limit": 16}
    }))
    .expect("valid changed resource update");
    let guest_conflict = client
        .update(AgentUpdateRequest {
            context: request.context.clone(),
            target: ContainerTarget::exact(request.target.id.clone(), generation),
            resources: changed_resources.clone(),
        })
        .await
        .expect_err("changed guest update must fail closed");
    assert_eq!(guest_conflict.code, ErrorCode::Conflict);
    assert_eq!(guest.update_request_count(), request_count + 1);
    assert_eq!(guest.update_effect_count(), 1);

    let host_conflict = service
        .update(UpdateRequest {
            context: request.context.clone(),
            target: request.target.clone(),
            resources: changed_resources,
        })
        .await
        .expect_err("changed durable update retry must fail closed");
    assert_eq!(host_conflict.code, ErrorCode::FailedPrecondition);
    assert_eq!(metrics.update_dispatches(), driver_dispatches);
    assert_eq!(guest.update_request_count(), request_count + 1);
    assert_eq!(guest.update_effect_count(), 1);
}
