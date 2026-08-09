use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentClient, AgentOperation, AgentTransportFaultPoint, AgentTransportOperationStage,
    AgentWaitProcessRequest,
};
use a3s_oci_sdk::{
    ContainerTarget, ErrorCode, ExitStatus, Generation, OciRuntimeService, OperationContext,
    ProcessTarget, Signal, SignalProcessRequest, StartRequest, WaitProcessRequest,
};
use tokio::io::DuplexStream;

use super::driver::{AgentLifecycleDriver, DriverMetrics};
use super::guest::JournaledLifecycleGuest;
use super::transport::{
    connect_faulted, connect_normal, guest_dispatch_reached, is_guest_stage, response_reached_host,
    FailOnceTransportFault,
};
use crate::service::tests::{create_request, exec_request, operation_id};
use crate::{HostRuntimeService, RuntimeDriver};

#[tokio::test]
async fn every_wait_process_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_wait_process_reopen(index, stage).await;
    }
}

async fn exercise_wait_process_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let create = create_request(
        &bundle_directory,
        &format!("agent-reopen-wait-process-create-{index}"),
    );
    let guest = Arc::new(JournaledLifecycleGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::WaitProcess,
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
    .unwrap_or_else(|error| panic!("open first wait-process runtime for {stage:?}: {error}"));
    let created = first_service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare wait-process create for {stage:?}: {error}"));
    let container = ContainerTarget::exact(create.id.clone(), created.generation);
    first_service
        .start(StartRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-wait-process-start-{index}"
            ))),
            target: container.clone(),
        })
        .await
        .unwrap_or_else(|error| panic!("prepare wait-process start for {stage:?}: {error}"));
    let exec = exec_request(
        ContainerTarget::current(create.id.clone()),
        &format!("agent-reopen-wait-process-exec-{index}"),
        &format!("worker-{index}"),
    );
    let process = first_service
        .exec(exec.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare wait-process exec for {stage:?}: {error}"));
    let expected_target = ProcessTarget {
        container,
        process_id: exec.process_id.clone(),
    };
    assert_eq!(process.target, expected_target, "{stage:?}");
    assert_eq!(process.pid, Some(6_202), "{stage:?}");
    let signal = Signal::new(15).expect("process signal");
    first_service
        .signal_process(SignalProcessRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-wait-process-signal-{index}"
            ))),
            process: ProcessTarget {
                container: ContainerTarget::current(create.id.clone()),
                process_id: exec.process_id.clone(),
            },
            signal,
        })
        .await
        .unwrap_or_else(|error| panic!("prepare wait-process signal for {stage:?}: {error}"));
    let wait = WaitProcessRequest {
        process: ProcessTarget {
            container: ContainerTarget::current(create.id.clone()),
            process_id: exec.process_id,
        },
        timeout_ms: Some(1_000),
    };
    let expected_exit = ExitStatus::signaled(signal.get(), false).expect("process exit status");
    assert_eq!(guest.exec_effect_count(), 1, "{stage:?}");
    assert_eq!(guest.signal_process_effect_count(), 1, "{stage:?}");

    let first_result = first_service.wait_process(wait.clone()).await;
    if response_reached_host(stage) {
        assert_eq!(
            first_result.unwrap_or_else(|error| panic!(
                "written wait-process response for {stage:?}: {error}"
            )),
            expected_exit,
            "{stage:?}"
        );
    } else {
        let error =
            first_result.expect_err("wait-process fault must remain visible before delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.wait_process_dispatches(), 1, "{stage:?}");
    drop(first_service);
    drop(first_driver);

    let server_result = first_server
        .await
        .unwrap_or_else(|error| panic!("first wait-process server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest wait-process fault must end first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(
        guest.wait_process_request_count(),
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
    .unwrap_or_else(|error| panic!("reopen wait-process runtime for {stage:?}: {error}"));
    assert_eq!(metrics.recoveries(), 1, "{stage:?}");

    let observed_exit = reopened
        .wait_process(wait.clone())
        .await
        .unwrap_or_else(|error| panic!("resume wait-process after {stage:?}: {error}"));
    assert_eq!(observed_exit, expected_exit, "{stage:?}");
    let expected_driver_dispatches = if response_reached_host(stage) { 1 } else { 2 };
    let expected_guest_requests = if response_reached_host(stage) {
        1
    } else {
        first_guest_dispatches + 1
    };
    assert_eq!(
        metrics.wait_process_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.wait_process_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );

    let cached_exit = reopened
        .wait_process(wait.clone())
        .await
        .unwrap_or_else(|error| panic!("replay cached process exit after {stage:?}: {error}"));
    assert_eq!(cached_exit, expected_exit, "{stage:?}");
    assert_eq!(
        metrics.wait_process_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.wait_process_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_stale_wait_process_targets_fail_closed(
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
    second_client.close().await.unwrap_or_else(|error| {
        panic!("close replacement wait-process session for {stage:?}: {error}")
    });
    second_server
        .await
        .unwrap_or_else(|error| {
            panic!("replacement wait-process server task for {stage:?}: {error}")
        })
        .unwrap_or_else(|error| {
            panic!("replacement wait-process server close for {stage:?}: {error}")
        });
}

async fn verify_stale_wait_process_targets_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &WaitProcessRequest,
    generation: Generation,
    guest: &JournaledLifecycleGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.wait_process_request_count();
    let driver_dispatches = metrics.wait_process_dispatches();
    let stale_target = ProcessTarget {
        container: ContainerTarget::exact(
            request.process.container.id.clone(),
            Generation(generation.0 + 1),
        ),
        process_id: request.process.process_id.clone(),
    };
    let guest_error = client
        .wait_process(AgentWaitProcessRequest {
            target: stale_target.clone(),
            timeout_ms: request.timeout_ms,
        })
        .await
        .expect_err("stale guest process wait target must fail closed");
    assert_eq!(guest_error.code, ErrorCode::NotFound);
    assert_eq!(guest.wait_process_request_count(), request_count + 1);

    let host_error = service
        .wait_process(WaitProcessRequest {
            process: stale_target,
            timeout_ms: request.timeout_ms,
        })
        .await
        .expect_err("stale durable process wait target must fail closed");
    assert_eq!(host_error.code, ErrorCode::Conflict);
    assert_eq!(metrics.wait_process_dispatches(), driver_dispatches);
    assert_eq!(guest.wait_process_request_count(), request_count + 1);
}
