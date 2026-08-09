use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentClient, AgentOperation, AgentProcessesRequest, AgentTransportFaultPoint,
    AgentTransportOperationStage,
};
use a3s_oci_sdk::{
    ContainerTarget, ErrorCode, Generation, OciRuntimeService, OperationContext, ProcessRecord,
    ProcessesRequest, StartRequest,
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
async fn every_processes_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_processes_reopen(index, stage).await;
    }
}

async fn exercise_processes_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let create = create_request(
        &bundle_directory,
        &format!("agent-reopen-processes-create-{index}"),
    );
    let guest = Arc::new(JournaledLifecycleGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::Processes,
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
    .unwrap_or_else(|error| panic!("open first processes runtime for {stage:?}: {error}"));
    let created = first_service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare processes create for {stage:?}: {error}"));
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    first_service
        .start(StartRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-processes-start-{index}"
            ))),
            target: target.clone(),
        })
        .await
        .unwrap_or_else(|error| panic!("prepare processes start for {stage:?}: {error}"));
    let worker = first_service
        .exec(exec_request(
            target,
            &format!("agent-reopen-processes-exec-{index}"),
            &format!("worker-{index}"),
        ))
        .await
        .unwrap_or_else(|error| panic!("prepare processes exec for {stage:?}: {error}"));
    let processes = ProcessesRequest {
        target: ContainerTarget::current(create.id.clone()),
    };

    let first_result = first_service.processes(processes.clone()).await;
    if response_reached_host(stage) {
        let inventory = first_result
            .unwrap_or_else(|error| panic!("written processes response for {stage:?}: {error}"));
        assert_inventory(&inventory, created.generation, &worker, stage);
    } else {
        let error = first_result.expect_err("processes fault must remain visible before delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.processes_dispatches(), 1, "{stage:?}");
    drop(first_service);
    drop(first_driver);

    let server_result = first_server
        .await
        .unwrap_or_else(|error| panic!("first processes server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest processes fault must end first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(
        guest.processes_request_count(),
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
    .unwrap_or_else(|error| panic!("reopen processes runtime for {stage:?}: {error}"));
    assert_eq!(metrics.recoveries(), 1, "{stage:?}");

    let inventory = reopened
        .processes(processes.clone())
        .await
        .unwrap_or_else(|error| panic!("repeat processes after {stage:?}: {error}"));
    assert_inventory(&inventory, created.generation, &worker, stage);
    assert_eq!(metrics.processes_dispatches(), 2, "{stage:?}");
    assert_eq!(
        guest.processes_request_count(),
        first_guest_dispatches + 1,
        "{stage:?}"
    );

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_stale_processes_targets_fail_closed(
            &second_client,
            &reopened,
            &processes,
            created.generation,
            guest.as_ref(),
            metrics.as_ref(),
        )
        .await;
    }

    drop(reopened);
    drop(second_driver);
    second_client.close().await.unwrap_or_else(|error| {
        panic!("close replacement processes session for {stage:?}: {error}")
    });
    second_server
        .await
        .unwrap_or_else(|error| panic!("replacement processes server task for {stage:?}: {error}"))
        .unwrap_or_else(|error| {
            panic!("replacement processes server close for {stage:?}: {error}")
        });
}

fn assert_inventory(
    inventory: &[ProcessRecord],
    generation: Generation,
    worker: &ProcessRecord,
    stage: AgentTransportOperationStage,
) {
    assert_eq!(inventory.len(), 2, "{stage:?}");
    let init = inventory
        .iter()
        .find(|process| process.target.process_id.is_init())
        .unwrap_or_else(|| panic!("init process missing after {stage:?}"));
    assert_eq!(
        init.target.container.generation,
        Some(generation),
        "{stage:?}"
    );
    assert_eq!(init.pid, Some(6_101), "{stage:?}");
    assert!(!init.terminal, "{stage:?}");
    assert!(
        inventory.iter().any(|process| process == worker),
        "worker process missing after {stage:?}"
    );
}

async fn verify_stale_processes_targets_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &ProcessesRequest,
    generation: Generation,
    guest: &JournaledLifecycleGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.processes_request_count();
    let driver_dispatches = metrics.processes_dispatches();
    let stale_target =
        ContainerTarget::exact(request.target.id.clone(), Generation(generation.0 + 1));
    let guest_error = client
        .processes(AgentProcessesRequest {
            target: stale_target.clone(),
        })
        .await
        .expect_err("stale guest processes target must fail closed");
    assert_eq!(guest_error.code, ErrorCode::NotFound);
    assert_eq!(guest.processes_request_count(), request_count + 1);

    let host_error = service
        .processes(ProcessesRequest {
            target: stale_target,
        })
        .await
        .expect_err("stale durable processes target must fail closed");
    assert_eq!(host_error.code, ErrorCode::Conflict);
    assert_eq!(metrics.processes_dispatches(), driver_dispatches);
    assert_eq!(guest.processes_request_count(), request_count + 1);
}
