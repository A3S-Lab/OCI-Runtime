use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentClient, AgentOperation, AgentTransportFaultPoint, AgentTransportOperationStage,
    AgentWaitRequest,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, ErrorCode, ExitStatus, Generation, KillRequest, ListRequest,
    OciRuntimeService, OperationContext, Signal, StartRequest, WaitRequest,
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
async fn every_wait_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_wait_reopen(index, stage).await;
    }
}

async fn exercise_wait_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let create = create_request(
        &bundle_directory,
        &format!("agent-reopen-wait-create-{index}"),
    );
    let guest = Arc::new(JournaledLifecycleGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::Wait,
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
    .unwrap_or_else(|error| panic!("open first wait runtime for {stage:?}: {error}"));
    let created = first_service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare wait create for {stage:?}: {error}"));
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    first_service
        .start(StartRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-wait-start-{index}"
            ))),
            target: target.clone(),
        })
        .await
        .unwrap_or_else(|error| panic!("prepare wait start for {stage:?}: {error}"));
    let stopped = first_service
        .kill(KillRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-wait-kill-{index}"
            ))),
            target: target.clone(),
            signal: Signal::new(9).expect("kill signal"),
            all: true,
        })
        .await
        .unwrap_or_else(|error| panic!("prepare wait kill for {stage:?}: {error}"));
    assert_stopped(&stopped, created.generation, stage);
    let wait = WaitRequest {
        target: ContainerTarget::current(create.id.clone()),
        timeout_ms: Some(1_000),
    };
    let expected_exit = ExitStatus::signaled(9, false).expect("signal exit status");
    assert_eq!(guest.create_effect_count(), 1, "{stage:?}");
    assert_eq!(guest.start_effect_count(), 1, "{stage:?}");
    assert_eq!(guest.kill_effect_count(), 1, "{stage:?}");

    let first_result = first_service.wait(wait.clone()).await;
    if response_reached_host(stage) {
        assert_eq!(
            first_result
                .unwrap_or_else(|error| panic!("written wait response for {stage:?}: {error}")),
            expected_exit,
            "{stage:?}"
        );
    } else {
        let error = first_result.expect_err("wait fault must remain visible before delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.wait_dispatches(), 1, "{stage:?}");

    let durable = first_service
        .list(ListRequest::default())
        .await
        .unwrap_or_else(|error| panic!("list first wait record for {stage:?}: {error}"));
    assert_eq!(durable.len(), 1, "{stage:?}");
    assert_stopped(&durable[0], created.generation, stage);
    drop(first_service);
    drop(first_driver);

    let server_result = first_server
        .await
        .unwrap_or_else(|error| panic!("first wait server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest wait fault must end the first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(
        guest.wait_request_count(),
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
    .unwrap_or_else(|error| panic!("reopen wait runtime for {stage:?}: {error}"));
    assert_eq!(metrics.recoveries(), 1, "{stage:?}");

    let observed_exit = reopened
        .wait(wait.clone())
        .await
        .unwrap_or_else(|error| panic!("resume wait after {stage:?}: {error}"));
    assert_eq!(observed_exit, expected_exit, "{stage:?}");
    let expected_driver_dispatches = if response_reached_host(stage) { 1 } else { 2 };
    let expected_guest_requests = if response_reached_host(stage) {
        1
    } else {
        first_guest_dispatches + 1
    };
    assert_eq!(
        metrics.wait_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.wait_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );

    let cached_exit = reopened
        .wait(wait.clone())
        .await
        .unwrap_or_else(|error| panic!("replay cached wait after {stage:?}: {error}"));
    assert_eq!(cached_exit, expected_exit, "{stage:?}");
    assert_eq!(
        metrics.wait_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.wait_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_stale_wait_targets_fail_closed(
            &second_client,
            &reopened,
            &wait,
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
        .unwrap_or_else(|error| panic!("close replacement wait session for {stage:?}: {error}"));
    second_server
        .await
        .unwrap_or_else(|error| panic!("replacement wait server task for {stage:?}: {error}"))
        .unwrap_or_else(|error| panic!("replacement wait server close for {stage:?}: {error}"));
}

fn assert_stopped(
    record: &a3s_oci_sdk::ContainerRecord,
    generation: Generation,
    stage: AgentTransportOperationStage,
) {
    assert_eq!(record.generation, generation, "{stage:?}");
    assert_eq!(*record.state.status(), ContainerState::Stopped, "{stage:?}");
    assert_eq!(*record.state.pid(), None, "{stage:?}");
}

async fn verify_stale_wait_targets_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &WaitRequest,
    generation: Generation,
    guest: &JournaledLifecycleGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.wait_request_count();
    let driver_dispatches = metrics.wait_dispatches();
    let stale_target =
        ContainerTarget::exact(request.target.id.clone(), Generation(generation.0 + 1));
    let guest_error = client
        .wait(AgentWaitRequest {
            target: stale_target.clone(),
            timeout_ms: request.timeout_ms,
        })
        .await
        .expect_err("stale guest wait target must fail closed");
    assert_eq!(guest_error.code, ErrorCode::NotFound);
    assert_eq!(guest.wait_request_count(), request_count + 1);

    let host_error = service
        .wait(WaitRequest {
            target: stale_target,
            timeout_ms: request.timeout_ms,
        })
        .await
        .expect_err("stale durable wait target must fail closed");
    assert_eq!(host_error.code, ErrorCode::Conflict);
    assert_eq!(metrics.wait_dispatches(), driver_dispatches);
    assert_eq!(guest.wait_request_count(), request_count + 1);
}
