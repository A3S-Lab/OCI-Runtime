use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentClient, AgentOperation, AgentTransportFaultPoint, AgentTransportOperationStage,
    AgentWriteStdinRequest,
};
use a3s_oci_sdk::{
    ContainerTarget, ErrorCode, OciRuntimeService, OperationContext, ProcessId, ProcessTarget,
    StartRequest, WriteStdinRequest,
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
async fn every_write_stdin_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_write_stdin_reopen(index, stage).await;
    }
}

async fn exercise_write_stdin_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let create = create_request(
        &bundle_directory,
        &format!("agent-reopen-write-stdin-create-{index}"),
    );
    let guest = Arc::new(JournaledLifecycleGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::WriteStdin,
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
    .unwrap_or_else(|error| panic!("open first write-stdin runtime for {stage:?}: {error}"));
    let created = first_service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare write-stdin create for {stage:?}: {error}"));
    let exact_process = ProcessTarget {
        container: ContainerTarget::exact(create.id.clone(), created.generation),
        process_id: ProcessId::init(),
    };
    first_service
        .start(StartRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-write-stdin-start-{index}"
            ))),
            target: exact_process.container.clone(),
        })
        .await
        .unwrap_or_else(|error| panic!("prepare write-stdin start for {stage:?}: {error}"));
    let write = WriteStdinRequest {
        context: OperationContext::new(operation_id(&format!("agent-reopen-write-stdin-{index}"))),
        process: ProcessTarget {
            container: ContainerTarget::current(create.id.clone()),
            process_id: ProcessId::init(),
        },
        data: format!("input-{index}").into_bytes(),
    };

    let first_result = first_service.write_stdin(write.clone()).await;
    if response_reached_host(stage) {
        first_result
            .unwrap_or_else(|error| panic!("written write-stdin response for {stage:?}: {error}"));
    } else {
        let error =
            first_result.expect_err("write-stdin fault must remain visible before delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.write_stdin_dispatches(), 1, "{stage:?}");
    drop(first_service);
    drop(first_driver);

    let server_result = first_server
        .await
        .unwrap_or_else(|error| panic!("first write-stdin server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest write-stdin fault must end first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(
        guest.write_stdin_request_count(),
        first_guest_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.write_stdin_effect_count(),
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
    .unwrap_or_else(|error| panic!("reopen write-stdin runtime for {stage:?}: {error}"));
    assert_eq!(metrics.recoveries(), 1, "{stage:?}");

    reopened
        .write_stdin(write.clone())
        .await
        .unwrap_or_else(|error| panic!("resume stdin write after {stage:?}: {error}"));
    let expected_driver_dispatches = if response_reached_host(stage) { 1 } else { 2 };
    let expected_guest_requests = if response_reached_host(stage) {
        1
    } else {
        first_guest_dispatches + 1
    };
    assert_eq!(
        metrics.write_stdin_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.write_stdin_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );
    assert_eq!(
        guest.write_stdin_effect_count(),
        1,
        "reopen after {stage:?} must produce exactly one stdin write effect"
    );
    assert_eq!(
        guest.recorded_write_stdin_request(),
        Some(AgentWriteStdinRequest {
            context: Some(write.context.clone()),
            process: exact_process.clone(),
            data: write.data.clone(),
        }),
        "{stage:?}"
    );

    reopened
        .write_stdin(write.clone())
        .await
        .unwrap_or_else(|error| panic!("replay cached stdin write after {stage:?}: {error}"));
    assert_eq!(
        metrics.write_stdin_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.write_stdin_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );
    assert_eq!(guest.write_stdin_effect_count(), 1, "{stage:?}");

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_changed_write_stdin_replays_fail_closed(
            &second_client,
            &reopened,
            &write,
            &exact_process,
            guest.as_ref(),
            metrics.as_ref(),
        )
        .await;
    }

    drop(reopened);
    drop(second_driver);
    second_client.close().await.unwrap_or_else(|error| {
        panic!("close replacement write-stdin session for {stage:?}: {error}")
    });
    second_server
        .await
        .unwrap_or_else(|error| {
            panic!("replacement write-stdin server task for {stage:?}: {error}")
        })
        .unwrap_or_else(|error| {
            panic!("replacement write-stdin server close for {stage:?}: {error}")
        });
}

async fn verify_changed_write_stdin_replays_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &WriteStdinRequest,
    target: &ProcessTarget,
    guest: &JournaledLifecycleGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.write_stdin_request_count();
    let driver_dispatches = metrics.write_stdin_dispatches();
    let changed_data = b"changed-input".to_vec();
    let guest_conflict = client
        .write_stdin(AgentWriteStdinRequest {
            context: Some(request.context.clone()),
            process: target.clone(),
            data: changed_data.clone(),
        })
        .await
        .expect_err("changed guest stdin payload must fail closed");
    assert_eq!(guest_conflict.code, ErrorCode::Conflict);
    assert_eq!(guest.write_stdin_request_count(), request_count + 1);
    assert_eq!(guest.write_stdin_effect_count(), 1);

    let mut changed_host = request.clone();
    changed_host.data = changed_data;
    let host_conflict = service
        .write_stdin(changed_host)
        .await
        .expect_err("changed durable stdin payload retry must fail closed");
    assert_eq!(host_conflict.code, ErrorCode::FailedPrecondition);
    assert_eq!(metrics.write_stdin_dispatches(), driver_dispatches);
    assert_eq!(guest.write_stdin_request_count(), request_count + 1);
    assert_eq!(guest.write_stdin_effect_count(), 1);
}
