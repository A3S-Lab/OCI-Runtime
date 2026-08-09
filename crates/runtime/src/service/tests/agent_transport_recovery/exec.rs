use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentClient, AgentExecRequest, AgentOperation, AgentTransportFaultPoint,
    AgentTransportOperationStage,
};
use a3s_oci_sdk::{
    ContainerTarget, ErrorCode, ExecRequest, IoMode, OciRuntimeService, OperationContext,
    ProcessIo, ProcessRecord, ProcessTarget, StartRequest, TerminalSize,
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
async fn every_exec_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_exec_reopen(index, stage).await;
    }
}

async fn exercise_exec_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let create = create_request(
        &bundle_directory,
        &format!("agent-reopen-exec-create-{index}"),
    );
    let guest = Arc::new(JournaledLifecycleGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::Exec,
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
    .unwrap_or_else(|error| panic!("open first exec runtime for {stage:?}: {error}"));
    let created = first_service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare exec create for {stage:?}: {error}"));
    let container = ContainerTarget::exact(create.id.clone(), created.generation);
    first_service
        .start(StartRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-exec-start-{index}"
            ))),
            target: container.clone(),
        })
        .await
        .unwrap_or_else(|error| panic!("prepare exec start for {stage:?}: {error}"));
    let mut exec = exec_request(
        ContainerTarget::current(create.id.clone()),
        &format!("agent-reopen-exec-{index}"),
        &format!("worker-{index}"),
    );
    exec.process = serde_json::from_value(serde_json::json!({
        "terminal": true,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh"],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .expect("valid terminal exec process");
    exec.io = ProcessIo {
        stdin: IoMode::Terminal,
        stdout: IoMode::Terminal,
        stderr: IoMode::Terminal,
        terminal_size: Some(TerminalSize {
            width: 80,
            height: 24,
        }),
    };
    let expected_target = ProcessTarget {
        container,
        process_id: exec.process_id.clone(),
    };
    assert_eq!(guest.create_effect_count(), 1, "{stage:?}");
    assert_eq!(guest.start_effect_count(), 1, "{stage:?}");

    let first_result = first_service.exec(exec.clone()).await;
    if response_reached_host(stage) {
        let process = first_result
            .unwrap_or_else(|error| panic!("written exec response for {stage:?}: {error}"));
        assert_process(&process, &expected_target, stage);
    } else {
        let error = first_result.expect_err("exec fault must remain visible before delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.exec_dispatches(), 1, "{stage:?}");
    drop(first_service);
    drop(first_driver);

    let server_result = first_server
        .await
        .unwrap_or_else(|error| panic!("first exec server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest exec fault must end the first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(
        guest.exec_request_count(),
        first_guest_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.exec_effect_count(),
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
    .unwrap_or_else(|error| panic!("reopen exec runtime for {stage:?}: {error}"));
    assert_eq!(metrics.recoveries(), 1, "{stage:?}");

    let process = reopened
        .exec(exec.clone())
        .await
        .unwrap_or_else(|error| panic!("resume exec after {stage:?}: {error}"));
    assert_process(&process, &expected_target, stage);
    let expected_driver_dispatches = if response_reached_host(stage) { 1 } else { 2 };
    let expected_guest_requests = if response_reached_host(stage) {
        1
    } else {
        first_guest_dispatches + 1
    };
    assert_eq!(
        metrics.exec_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.exec_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );
    assert_eq!(
        guest.exec_effect_count(),
        1,
        "reopen after {stage:?} must produce exactly one exec effect"
    );

    let replayed = reopened
        .exec(exec.clone())
        .await
        .unwrap_or_else(|error| panic!("replay cached exec after {stage:?}: {error}"));
    assert_process(&replayed, &expected_target, stage);
    assert_eq!(
        metrics.exec_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.exec_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );
    assert_eq!(guest.exec_effect_count(), 1, "{stage:?}");

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_changed_exec_replays_fail_closed(
            &second_client,
            &reopened,
            &exec,
            &expected_target,
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
        .unwrap_or_else(|error| panic!("close replacement exec session for {stage:?}: {error}"));
    second_server
        .await
        .unwrap_or_else(|error| panic!("replacement exec server task for {stage:?}: {error}"))
        .unwrap_or_else(|error| panic!("replacement exec server close for {stage:?}: {error}"));
}

fn assert_process(
    process: &ProcessRecord,
    expected_target: &ProcessTarget,
    stage: AgentTransportOperationStage,
) {
    assert_eq!(&process.target, expected_target, "{stage:?}");
    assert_eq!(process.pid, Some(6_202), "{stage:?}");
    assert!(process.terminal, "{stage:?}");
}

async fn verify_changed_exec_replays_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &ExecRequest,
    target: &ProcessTarget,
    guest: &JournaledLifecycleGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.exec_request_count();
    let driver_dispatches = metrics.exec_dispatches();
    let mut changed_guest_io = request.io.clone();
    changed_guest_io.terminal_size = Some(TerminalSize {
        width: 100,
        height: 40,
    });
    let guest_conflict = client
        .exec(AgentExecRequest {
            context: request.context.clone(),
            target: target.clone(),
            process: request.process.clone(),
            io: changed_guest_io,
        })
        .await
        .expect_err("changed guest exec must fail closed");
    assert_eq!(guest_conflict.code, ErrorCode::Conflict);
    assert_eq!(guest.exec_request_count(), request_count + 1);
    assert_eq!(guest.exec_effect_count(), 1);

    let mut changed_host = request.clone();
    changed_host.io.terminal_size = Some(TerminalSize {
        width: 100,
        height: 40,
    });
    let host_conflict = service
        .exec(changed_host)
        .await
        .expect_err("changed durable exec retry must fail closed");
    assert_eq!(host_conflict.code, ErrorCode::FailedPrecondition);
    assert_eq!(metrics.exec_dispatches(), driver_dispatches);
    assert_eq!(guest.exec_request_count(), request_count + 1);
    assert_eq!(guest.exec_effect_count(), 1);
}
