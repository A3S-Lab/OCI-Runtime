use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentClient, AgentOperation, AgentReadOutputRequest, AgentTransportFaultPoint,
    AgentTransportOperationStage,
};
use a3s_oci_sdk::{
    ContainerTarget, ErrorCode, Generation, OciRuntimeService, OperationContext, OutputChunk,
    OutputStream, ProcessId, ProcessTarget, ReadOutputRequest, StartRequest,
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
async fn every_read_output_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_read_output_reopen(index, stage).await;
    }
}

async fn exercise_read_output_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let create = create_request(
        &bundle_directory,
        &format!("agent-reopen-read-output-create-{index}"),
    );
    let guest = Arc::new(JournaledLifecycleGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::ReadOutput,
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
    .unwrap_or_else(|error| panic!("open first read-output runtime for {stage:?}: {error}"));
    let created = first_service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare read-output create for {stage:?}: {error}"));
    first_service
        .start(StartRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-read-output-start-{index}"
            ))),
            target: ContainerTarget::exact(create.id.clone(), created.generation),
        })
        .await
        .unwrap_or_else(|error| panic!("prepare read-output start for {stage:?}: {error}"));
    let read = ReadOutputRequest {
        process: ProcessTarget {
            container: ContainerTarget::current(create.id.clone()),
            process_id: ProcessId::init(),
        },
        after_sequence: 0,
        max_bytes: 3,
        wait_timeout_ms: Some(0),
    };

    let first_result = first_service.read_output(read.clone()).await;
    if response_reached_host(stage) {
        let chunks = first_result
            .unwrap_or_else(|error| panic!("written read-output response for {stage:?}: {error}"));
        assert_output(&chunks, stage);
    } else {
        let error =
            first_result.expect_err("read-output fault must remain visible before delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.read_output_dispatches(), 1, "{stage:?}");
    drop(first_service);
    drop(first_driver);

    let server_result = first_server
        .await
        .unwrap_or_else(|error| panic!("first read-output server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest read-output fault must end first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(
        guest.read_output_request_count(),
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
    .unwrap_or_else(|error| panic!("reopen read-output runtime for {stage:?}: {error}"));
    assert_eq!(metrics.recoveries(), 1, "{stage:?}");

    let chunks = reopened
        .read_output(read.clone())
        .await
        .unwrap_or_else(|error| panic!("repeat read-output after {stage:?}: {error}"));
    assert_output(&chunks, stage);
    assert_eq!(metrics.read_output_dispatches(), 2, "{stage:?}");
    assert_eq!(
        guest.read_output_request_count(),
        first_guest_dispatches + 1,
        "{stage:?}"
    );

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_stale_read_output_targets_fail_closed(
            &second_client,
            &reopened,
            &read,
            created.generation,
            guest.as_ref(),
            metrics.as_ref(),
        )
        .await;
    }

    drop(reopened);
    drop(second_driver);
    second_client.close().await.unwrap_or_else(|error| {
        panic!("close replacement read-output session for {stage:?}: {error}")
    });
    second_server
        .await
        .unwrap_or_else(|error| {
            panic!("replacement read-output server task for {stage:?}: {error}")
        })
        .unwrap_or_else(|error| {
            panic!("replacement read-output server close for {stage:?}: {error}")
        });
}

fn assert_output(chunks: &[OutputChunk], stage: AgentTransportOperationStage) {
    assert_eq!(chunks.len(), 1, "{stage:?}");
    assert_eq!(chunks[0].sequence, 3, "{stage:?}");
    assert_eq!(chunks[0].stream, OutputStream::Stdout, "{stage:?}");
    assert_eq!(chunks[0].data, b"rea", "{stage:?}");
    assert!(!chunks[0].eof, "{stage:?}");
}

async fn verify_stale_read_output_targets_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &ReadOutputRequest,
    generation: Generation,
    guest: &JournaledLifecycleGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.read_output_request_count();
    let driver_dispatches = metrics.read_output_dispatches();
    let stale_process = ProcessTarget {
        container: ContainerTarget::exact(
            request.process.container.id.clone(),
            Generation(generation.0 + 1),
        ),
        process_id: request.process.process_id.clone(),
    };
    let guest_error = client
        .read_output(AgentReadOutputRequest {
            process: stale_process.clone(),
            after_sequence: request.after_sequence,
            max_bytes: request.max_bytes,
            wait_timeout_ms: request.wait_timeout_ms,
        })
        .await
        .expect_err("stale guest read-output target must fail closed");
    assert_eq!(guest_error.code, ErrorCode::NotFound);
    assert_eq!(guest.read_output_request_count(), request_count + 1);

    let host_error = service
        .read_output(ReadOutputRequest {
            process: stale_process,
            after_sequence: request.after_sequence,
            max_bytes: request.max_bytes,
            wait_timeout_ms: request.wait_timeout_ms,
        })
        .await
        .expect_err("stale durable read-output target must fail closed");
    assert_eq!(host_error.code, ErrorCode::Conflict);
    assert_eq!(metrics.read_output_dispatches(), driver_dispatches);
    assert_eq!(guest.read_output_request_count(), request_count + 1);
}
