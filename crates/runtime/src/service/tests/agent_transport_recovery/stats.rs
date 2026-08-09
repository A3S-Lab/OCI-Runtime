use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentClient, AgentOperation, AgentStatsRequest, AgentTransportFaultPoint,
    AgentTransportOperationStage,
};
use a3s_oci_sdk::{
    ContainerStats, ContainerTarget, ErrorCode, Generation, OciRuntimeService, OperationContext,
    StartRequest, StatsRequest,
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
async fn every_stats_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_stats_reopen(index, stage).await;
    }
}

async fn exercise_stats_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let create = create_request(
        &bundle_directory,
        &format!("agent-reopen-stats-create-{index}"),
    );
    let guest = Arc::new(JournaledLifecycleGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::Stats,
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
    .unwrap_or_else(|error| panic!("open first stats runtime for {stage:?}: {error}"));
    let created = first_service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare stats create for {stage:?}: {error}"));
    first_service
        .start(StartRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-stats-start-{index}"
            ))),
            target: ContainerTarget::exact(create.id.clone(), created.generation),
        })
        .await
        .unwrap_or_else(|error| panic!("prepare stats start for {stage:?}: {error}"));
    let stats = StatsRequest {
        target: ContainerTarget::current(create.id.clone()),
    };

    let first_result = first_service.stats(stats.clone()).await;
    if response_reached_host(stage) {
        let observed = first_result
            .unwrap_or_else(|error| panic!("written stats response for {stage:?}: {error}"));
        assert_stats(&observed, created.generation, stage);
    } else {
        let error = first_result.expect_err("stats fault must remain visible before delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.stats_dispatches(), 1, "{stage:?}");
    drop(first_service);
    drop(first_driver);

    let server_result = first_server
        .await
        .unwrap_or_else(|error| panic!("first stats server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest stats fault must end first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(
        guest.stats_request_count(),
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
    .unwrap_or_else(|error| panic!("reopen stats runtime for {stage:?}: {error}"));
    assert_eq!(metrics.recoveries(), 1, "{stage:?}");

    let observed = reopened
        .stats(stats.clone())
        .await
        .unwrap_or_else(|error| panic!("repeat stats after {stage:?}: {error}"));
    assert_stats(&observed, created.generation, stage);
    assert_eq!(metrics.stats_dispatches(), 2, "{stage:?}");
    assert_eq!(
        guest.stats_request_count(),
        first_guest_dispatches + 1,
        "{stage:?}"
    );

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_stale_stats_targets_fail_closed(
            &second_client,
            &reopened,
            &stats,
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
        .unwrap_or_else(|error| panic!("close replacement stats session for {stage:?}: {error}"));
    second_server
        .await
        .unwrap_or_else(|error| panic!("replacement stats server task for {stage:?}: {error}"))
        .unwrap_or_else(|error| panic!("replacement stats server close for {stage:?}: {error}"));
}

fn assert_stats(
    stats: &ContainerStats,
    generation: Generation,
    stage: AgentTransportOperationStage,
) {
    assert_eq!(stats.target.generation, Some(generation), "{stage:?}");
    assert_eq!(stats.timestamp_unix_ns, 1, "{stage:?}");
    assert_eq!(stats.cpu.usage_ns, 30, "{stage:?}");
    assert_eq!(stats.cpu.user_ns, 10, "{stage:?}");
    assert_eq!(stats.cpu.system_ns, 20, "{stage:?}");
    assert_eq!(stats.memory.usage_bytes, 1_024, "{stage:?}");
    assert_eq!(stats.memory.limit_bytes, Some(4_096), "{stage:?}");
    assert_eq!(stats.memory.peak_bytes, Some(2_048), "{stage:?}");
    assert_eq!(stats.process_count, 1, "{stage:?}");
    assert_eq!(stats.metrics.get("memory.events.oom_kill"), Some(&0));
}

async fn verify_stale_stats_targets_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &StatsRequest,
    generation: Generation,
    guest: &JournaledLifecycleGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.stats_request_count();
    let driver_dispatches = metrics.stats_dispatches();
    let stale_target =
        ContainerTarget::exact(request.target.id.clone(), Generation(generation.0 + 1));
    let guest_error = client
        .stats(AgentStatsRequest {
            target: stale_target.clone(),
        })
        .await
        .expect_err("stale guest stats target must fail closed");
    assert_eq!(guest_error.code, ErrorCode::NotFound);
    assert_eq!(guest.stats_request_count(), request_count + 1);

    let host_error = service
        .stats(StatsRequest {
            target: stale_target,
        })
        .await
        .expect_err("stale durable stats target must fail closed");
    assert_eq!(host_error.code, ErrorCode::Conflict);
    assert_eq!(metrics.stats_dispatches(), driver_dispatches);
    assert_eq!(guest.stats_request_count(), request_count + 1);
}
