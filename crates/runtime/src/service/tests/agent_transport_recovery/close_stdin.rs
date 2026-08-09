use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentClient, AgentCloseStdinRequest, AgentOperation, AgentTransportFaultPoint,
    AgentTransportOperationStage,
};
use a3s_oci_sdk::{
    CloseStdinRequest, ContainerTarget, ErrorCode, OciRuntimeService, OperationContext, ProcessId,
    ProcessTarget, StartRequest,
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
async fn every_close_stdin_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_close_stdin_reopen(index, stage).await;
    }
}

async fn exercise_close_stdin_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let create = create_request(
        &bundle_directory,
        &format!("agent-reopen-close-stdin-create-{index}"),
    );
    let guest = Arc::new(JournaledLifecycleGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::CloseStdin,
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
    .unwrap_or_else(|error| panic!("open first close-stdin runtime for {stage:?}: {error}"));
    let created = first_service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare close-stdin create for {stage:?}: {error}"));
    let exact_process = ProcessTarget {
        container: ContainerTarget::exact(create.id.clone(), created.generation),
        process_id: ProcessId::init(),
    };
    first_service
        .start(StartRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-close-stdin-start-{index}"
            ))),
            target: exact_process.container.clone(),
        })
        .await
        .unwrap_or_else(|error| panic!("prepare close-stdin start for {stage:?}: {error}"));
    let close = CloseStdinRequest {
        context: OperationContext::new(operation_id(&format!("agent-reopen-close-stdin-{index}"))),
        process: ProcessTarget {
            container: ContainerTarget::current(create.id.clone()),
            process_id: ProcessId::init(),
        },
    };

    let first_result = first_service.close_stdin(close.clone()).await;
    if response_reached_host(stage) {
        first_result
            .unwrap_or_else(|error| panic!("written close-stdin response for {stage:?}: {error}"));
    } else {
        let error =
            first_result.expect_err("close-stdin fault must remain visible before delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.close_stdin_dispatches(), 1, "{stage:?}");
    drop(first_service);
    drop(first_driver);

    let server_result = first_server
        .await
        .unwrap_or_else(|error| panic!("first close-stdin server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest close-stdin fault must end first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(
        guest.close_stdin_request_count(),
        first_guest_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.close_stdin_effect_count(),
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
    .unwrap_or_else(|error| panic!("reopen close-stdin runtime for {stage:?}: {error}"));
    assert_eq!(metrics.recoveries(), 1, "{stage:?}");

    reopened
        .close_stdin(close.clone())
        .await
        .unwrap_or_else(|error| panic!("resume stdin close after {stage:?}: {error}"));
    let expected_driver_dispatches = if response_reached_host(stage) { 1 } else { 2 };
    let expected_guest_requests = if response_reached_host(stage) {
        1
    } else {
        first_guest_dispatches + 1
    };
    assert_eq!(
        metrics.close_stdin_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.close_stdin_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );
    assert_eq!(
        guest.close_stdin_effect_count(),
        1,
        "reopen after {stage:?} must produce exactly one stdin close effect"
    );
    assert_eq!(
        guest.recorded_close_stdin_request(),
        Some(AgentCloseStdinRequest {
            context: Some(close.context.clone()),
            process: exact_process.clone(),
        }),
        "{stage:?}"
    );

    reopened
        .close_stdin(close.clone())
        .await
        .unwrap_or_else(|error| panic!("replay cached stdin close after {stage:?}: {error}"));
    assert_eq!(
        metrics.close_stdin_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.close_stdin_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );
    assert_eq!(guest.close_stdin_effect_count(), 1, "{stage:?}");

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_changed_close_stdin_replays_fail_closed(
            &second_client,
            &reopened,
            &close,
            &exact_process,
            guest.as_ref(),
            metrics.as_ref(),
        )
        .await;
    }

    drop(reopened);
    drop(second_driver);
    second_client.close().await.unwrap_or_else(|error| {
        panic!("close replacement close-stdin session for {stage:?}: {error}")
    });
    second_server
        .await
        .unwrap_or_else(|error| {
            panic!("replacement close-stdin server task for {stage:?}: {error}")
        })
        .unwrap_or_else(|error| {
            panic!("replacement close-stdin server close for {stage:?}: {error}")
        });
}

async fn verify_changed_close_stdin_replays_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &CloseStdinRequest,
    target: &ProcessTarget,
    guest: &JournaledLifecycleGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.close_stdin_request_count();
    let driver_dispatches = metrics.close_stdin_dispatches();
    let changed_process = ProcessTarget {
        container: target.container.clone(),
        process_id: ProcessId::new("changed").expect("changed process ID"),
    };
    let guest_conflict = client
        .close_stdin(AgentCloseStdinRequest {
            context: Some(request.context.clone()),
            process: changed_process.clone(),
        })
        .await
        .expect_err("changed guest stdin-close target must fail closed");
    assert_eq!(guest_conflict.code, ErrorCode::Conflict);
    assert_eq!(guest.close_stdin_request_count(), request_count + 1);
    assert_eq!(guest.close_stdin_effect_count(), 1);

    let mut changed_host = request.clone();
    changed_host.process = changed_process;
    let host_conflict = service
        .close_stdin(changed_host)
        .await
        .expect_err("changed durable stdin-close target retry must fail closed");
    assert_eq!(host_conflict.code, ErrorCode::FailedPrecondition);
    assert_eq!(metrics.close_stdin_dispatches(), driver_dispatches);
    assert_eq!(guest.close_stdin_request_count(), request_count + 1);
    assert_eq!(guest.close_stdin_effect_count(), 1);
}
