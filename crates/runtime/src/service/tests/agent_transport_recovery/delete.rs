use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentClient, AgentDeleteRequest, AgentOperation, AgentTransportFaultPoint,
    AgentTransportOperationStage,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, DeleteMode, DeleteRequest, ErrorCode, KillRequest, ListRequest,
    OciRuntimeService, OperationContext, Signal, StartRequest,
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
async fn every_delete_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_delete_reopen(index, stage).await;
    }
}

async fn exercise_delete_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let create = create_request(
        &bundle_directory,
        &format!("agent-reopen-delete-create-{index}"),
    );
    let guest = Arc::new(JournaledLifecycleGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::Delete,
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
    .unwrap_or_else(|error| panic!("open first delete runtime for {stage:?}: {error}"));
    let created = first_service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare delete create for {stage:?}: {error}"));
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    let running = first_service
        .start(StartRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-delete-start-{index}"
            ))),
            target: target.clone(),
        })
        .await
        .unwrap_or_else(|error| panic!("prepare delete start for {stage:?}: {error}"));
    assert_eq!(
        *running.state.status(),
        ContainerState::Running,
        "{stage:?}"
    );
    let stopped = first_service
        .kill(KillRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-delete-kill-{index}"
            ))),
            target: target.clone(),
            signal: Signal::new(9).expect("kill signal"),
            all: true,
        })
        .await
        .unwrap_or_else(|error| panic!("prepare delete kill for {stage:?}: {error}"));
    assert_eq!(
        *stopped.state.status(),
        ContainerState::Stopped,
        "{stage:?}"
    );
    let delete = DeleteRequest {
        context: OperationContext::new(operation_id(&format!("agent-reopen-delete-{index}"))),
        target: target.clone(),
        mode: DeleteMode::StoppedOnly,
    };
    assert_eq!(guest.create_effect_count(), 1, "{stage:?}");
    assert_eq!(guest.start_effect_count(), 1, "{stage:?}");
    assert_eq!(guest.kill_effect_count(), 1, "{stage:?}");
    assert_eq!(metrics.create_dispatches(), 1, "{stage:?}");
    assert_eq!(metrics.start_dispatches(), 1, "{stage:?}");
    assert_eq!(metrics.kill_dispatches(), 1, "{stage:?}");

    let first_result = first_service.delete(delete.clone()).await;
    if response_reached_host(stage) {
        first_result
            .unwrap_or_else(|error| panic!("written delete response for {stage:?}: {error}"));
    } else {
        let error = first_result.expect_err("delete fault must remain visible before delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.delete_dispatches(), 1, "{stage:?}");

    let active = first_service
        .list(ListRequest::default())
        .await
        .unwrap_or_else(|error| panic!("list first delete record for {stage:?}: {error}"));
    if response_reached_host(stage) {
        assert!(active.is_empty(), "{stage:?}");
    } else {
        assert_eq!(active.len(), 1, "{stage:?}");
        assert_eq!(
            *active[0].state.status(),
            ContainerState::Stopped,
            "{stage:?}"
        );
        assert_eq!(active[0].generation, created.generation, "{stage:?}");
    }
    drop(first_service);
    drop(first_driver);

    let server_result = first_server
        .await
        .unwrap_or_else(|error| panic!("first delete server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest delete fault must end the first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(
        guest.delete_request_count(),
        first_guest_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.delete_effect_count(),
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
    .unwrap_or_else(|error| panic!("reopen delete runtime for {stage:?}: {error}"));
    let expected_recoveries = usize::from(!response_reached_host(stage));
    assert_eq!(metrics.recoveries(), expected_recoveries, "{stage:?}");

    reopened
        .delete(delete.clone())
        .await
        .unwrap_or_else(|error| panic!("resume delete after {stage:?}: {error}"));
    let remaining = reopened
        .list(ListRequest::default())
        .await
        .unwrap_or_else(|error| panic!("list after resumed delete for {stage:?}: {error}"));
    assert!(remaining.is_empty(), "{stage:?}");

    let expected_driver_dispatches = if response_reached_host(stage) { 1 } else { 2 };
    let expected_guest_requests = if response_reached_host(stage) {
        1
    } else {
        first_guest_dispatches + 1
    };
    assert_eq!(
        metrics.delete_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.delete_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );
    assert_eq!(
        guest.delete_effect_count(),
        1,
        "reopen after {stage:?} must produce exactly one delete effect"
    );

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_changed_delete_replays_fail_closed(
            &second_client,
            &reopened,
            &delete,
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
        .unwrap_or_else(|error| panic!("close replacement delete session for {stage:?}: {error}"));
    second_server
        .await
        .unwrap_or_else(|error| panic!("replacement delete server task for {stage:?}: {error}"))
        .unwrap_or_else(|error| panic!("replacement delete server close for {stage:?}: {error}"));
}

async fn verify_changed_delete_replays_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &DeleteRequest,
    guest: &JournaledLifecycleGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.delete_request_count();
    let driver_dispatches = metrics.delete_dispatches();
    let changed_guest = AgentDeleteRequest {
        context: request.context.clone(),
        target: request.target.clone(),
        mode: DeleteMode::Force,
    };
    let guest_conflict = client
        .delete(changed_guest)
        .await
        .expect_err("changed guest delete must fail closed");
    assert_eq!(guest_conflict.code, ErrorCode::Conflict);
    assert_eq!(guest.delete_request_count(), request_count + 1);
    assert_eq!(guest.delete_effect_count(), 1);

    let mut changed_host = request.clone();
    changed_host.mode = DeleteMode::Force;
    let host_conflict = service
        .delete(changed_host)
        .await
        .expect_err("changed durable delete retry must fail closed");
    assert_eq!(host_conflict.code, ErrorCode::FailedPrecondition);
    assert_eq!(metrics.delete_dispatches(), driver_dispatches);
    assert_eq!(guest.delete_request_count(), request_count + 1);
    assert_eq!(guest.delete_effect_count(), 1);
}
