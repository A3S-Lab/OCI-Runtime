use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentClient, AgentKillRequest, AgentOperation, AgentTransportFaultPoint,
    AgentTransportOperationStage,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, ErrorCode, KillRequest, ListRequest, OciRuntimeService, OperationContext,
    Signal, StartRequest,
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
async fn every_kill_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_kill_reopen(index, stage).await;
    }
}

async fn exercise_kill_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let create = create_request(
        &bundle_directory,
        &format!("agent-reopen-kill-create-{index}"),
    );
    let guest = Arc::new(JournaledLifecycleGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::Kill,
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
    .unwrap_or_else(|error| panic!("open first kill runtime for {stage:?}: {error}"));
    let created = first_service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare kill create for {stage:?}: {error}"));
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    let running = first_service
        .start(StartRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-kill-start-{index}"
            ))),
            target: target.clone(),
        })
        .await
        .unwrap_or_else(|error| panic!("prepare kill start for {stage:?}: {error}"));
    assert_eq!(
        *running.state.status(),
        ContainerState::Running,
        "{stage:?}"
    );
    let kill = KillRequest {
        context: OperationContext::new(operation_id(&format!("agent-reopen-kill-{index}"))),
        target: target.clone(),
        signal: Signal::new(9).expect("kill signal"),
        all: true,
    };
    assert_eq!(guest.create_effect_count(), 1, "{stage:?}");
    assert_eq!(guest.start_effect_count(), 1, "{stage:?}");
    assert_eq!(metrics.create_dispatches(), 1, "{stage:?}");
    assert_eq!(metrics.start_dispatches(), 1, "{stage:?}");

    let first_result = first_service.kill(kill.clone()).await;
    if response_reached_host(stage) {
        let stopped = first_result
            .unwrap_or_else(|error| panic!("written kill response for {stage:?}: {error}"));
        assert_eq!(
            *stopped.state.status(),
            ContainerState::Stopped,
            "{stage:?}"
        );
    } else {
        let error = first_result.expect_err("kill fault must remain visible before delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.kill_dispatches(), 1, "{stage:?}");

    let active = first_service
        .list(ListRequest::default())
        .await
        .unwrap_or_else(|error| panic!("list first kill record for {stage:?}: {error}"));
    assert_eq!(active.len(), 1, "{stage:?}");
    let expected_first_status = if response_reached_host(stage) {
        ContainerState::Stopped
    } else {
        ContainerState::Running
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
        .unwrap_or_else(|error| panic!("first kill server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest kill fault must end the first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(
        guest.kill_request_count(),
        first_guest_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.kill_effect_count(),
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
    .unwrap_or_else(|error| panic!("reopen kill runtime for {stage:?}: {error}"));
    assert_eq!(metrics.recoveries(), 1, "{stage:?}");

    let stopped = reopened
        .kill(kill.clone())
        .await
        .unwrap_or_else(|error| panic!("resume kill after {stage:?}: {error}"));
    assert_eq!(stopped.generation, created.generation, "{stage:?}");
    assert_eq!(
        *stopped.state.status(),
        ContainerState::Stopped,
        "{stage:?}"
    );
    assert_eq!(*stopped.state.pid(), None, "{stage:?}");

    let expected_driver_dispatches = if response_reached_host(stage) { 1 } else { 2 };
    let expected_guest_requests = if response_reached_host(stage) {
        1
    } else {
        first_guest_dispatches + 1
    };
    assert_eq!(
        metrics.kill_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.kill_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );
    assert_eq!(
        guest.kill_effect_count(),
        1,
        "reopen after {stage:?} must produce exactly one kill effect"
    );

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_changed_kill_replays_fail_closed(
            &second_client,
            &reopened,
            &kill,
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
        .unwrap_or_else(|error| panic!("close replacement kill session for {stage:?}: {error}"));
    second_server
        .await
        .unwrap_or_else(|error| panic!("replacement kill server task for {stage:?}: {error}"))
        .unwrap_or_else(|error| panic!("replacement kill server close for {stage:?}: {error}"));
}

async fn verify_changed_kill_replays_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &KillRequest,
    guest: &JournaledLifecycleGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.kill_request_count();
    let driver_dispatches = metrics.kill_dispatches();
    let changed_guest = AgentKillRequest {
        context: request.context.clone(),
        target: request.target.clone(),
        signal: Signal::new(15).expect("changed guest signal"),
        all: request.all,
    };
    let guest_conflict = client
        .kill(changed_guest)
        .await
        .expect_err("changed guest kill must fail closed");
    assert_eq!(guest_conflict.code, ErrorCode::Conflict);
    assert_eq!(guest.kill_request_count(), request_count + 1);
    assert_eq!(guest.kill_effect_count(), 1);

    let mut changed_host = request.clone();
    changed_host.signal = Signal::new(15).expect("changed host signal");
    let host_conflict = service
        .kill(changed_host)
        .await
        .expect_err("changed durable kill retry must fail closed");
    assert_eq!(host_conflict.code, ErrorCode::FailedPrecondition);
    assert_eq!(metrics.kill_dispatches(), driver_dispatches);
    assert_eq!(guest.kill_request_count(), request_count + 1);
    assert_eq!(guest.kill_effect_count(), 1);
}
