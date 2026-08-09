use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentClient, AgentOperation, AgentResizeRequest, AgentTransportFaultPoint,
    AgentTransportOperationStage,
};
use a3s_oci_sdk::{
    ContainerTarget, ErrorCode, IoMode, OciRuntimeService, OperationContext, ProcessIo,
    ProcessTarget, ResizeRequest, StartRequest, TerminalSize,
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
async fn every_resize_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_resize_reopen(index, stage).await;
    }
}

async fn exercise_resize_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let create = create_request(
        &bundle_directory,
        &format!("agent-reopen-resize-create-{index}"),
    );
    let guest = Arc::new(JournaledLifecycleGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::Resize,
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
    .unwrap_or_else(|error| panic!("open first resize runtime for {stage:?}: {error}"));
    let created = first_service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare resize create for {stage:?}: {error}"));
    let container = ContainerTarget::exact(create.id.clone(), created.generation);
    first_service
        .start(StartRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-resize-start-{index}"
            ))),
            target: container.clone(),
        })
        .await
        .unwrap_or_else(|error| panic!("prepare resize start for {stage:?}: {error}"));
    let mut exec = exec_request(
        ContainerTarget::current(create.id.clone()),
        &format!("agent-reopen-resize-exec-{index}"),
        &format!("terminal-{index}"),
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
    let process = first_service
        .exec(exec.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare resize exec for {stage:?}: {error}"));
    let exact_process = ProcessTarget {
        container,
        process_id: exec.process_id.clone(),
    };
    assert_eq!(process.target, exact_process, "{stage:?}");
    assert!(process.terminal, "{stage:?}");
    let resize = ResizeRequest {
        context: OperationContext::new(operation_id(&format!("agent-reopen-resize-{index}"))),
        process: ProcessTarget {
            container: ContainerTarget::current(create.id.clone()),
            process_id: exec.process_id.clone(),
        },
        size: TerminalSize {
            width: 120,
            height: 40,
        },
    };

    let first_result = first_service.resize(resize.clone()).await;
    if response_reached_host(stage) {
        first_result
            .unwrap_or_else(|error| panic!("written resize response for {stage:?}: {error}"));
    } else {
        let error = first_result.expect_err("resize fault must remain visible before delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.resize_dispatches(), 1, "{stage:?}");
    drop(first_service);
    drop(first_driver);

    let server_result = first_server
        .await
        .unwrap_or_else(|error| panic!("first resize server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest resize fault must end first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(
        guest.resize_request_count(),
        first_guest_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.resize_effect_count(),
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
    .unwrap_or_else(|error| panic!("reopen resize runtime for {stage:?}: {error}"));
    assert_eq!(metrics.recoveries(), 1, "{stage:?}");

    reopened
        .resize(resize.clone())
        .await
        .unwrap_or_else(|error| panic!("resume terminal resize after {stage:?}: {error}"));
    let expected_driver_dispatches = if response_reached_host(stage) { 1 } else { 2 };
    let expected_guest_requests = if response_reached_host(stage) {
        1
    } else {
        first_guest_dispatches + 1
    };
    assert_eq!(
        metrics.resize_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.resize_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );
    assert_eq!(
        guest.resize_effect_count(),
        1,
        "reopen after {stage:?} must produce exactly one terminal resize effect"
    );
    assert_eq!(
        guest.recorded_resize_request(),
        Some(AgentResizeRequest {
            context: Some(resize.context.clone()),
            process: exact_process.clone(),
            size: resize.size,
        }),
        "{stage:?}"
    );

    reopened
        .resize(resize.clone())
        .await
        .unwrap_or_else(|error| panic!("replay cached terminal resize after {stage:?}: {error}"));
    assert_eq!(
        metrics.resize_dispatches(),
        expected_driver_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.resize_request_count(),
        expected_guest_requests,
        "{stage:?}"
    );
    assert_eq!(guest.resize_effect_count(), 1, "{stage:?}");

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_changed_resize_replays_fail_closed(
            &second_client,
            &reopened,
            &resize,
            &exact_process,
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
        .unwrap_or_else(|error| panic!("close replacement resize session for {stage:?}: {error}"));
    second_server
        .await
        .unwrap_or_else(|error| panic!("replacement resize server task for {stage:?}: {error}"))
        .unwrap_or_else(|error| panic!("replacement resize server close for {stage:?}: {error}"));
}

async fn verify_changed_resize_replays_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &ResizeRequest,
    target: &ProcessTarget,
    guest: &JournaledLifecycleGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.resize_request_count();
    let driver_dispatches = metrics.resize_dispatches();
    let changed_size = TerminalSize {
        width: request.size.width + 1,
        height: request.size.height,
    };
    let guest_conflict = client
        .resize(AgentResizeRequest {
            context: Some(request.context.clone()),
            process: target.clone(),
            size: changed_size,
        })
        .await
        .expect_err("changed guest terminal size must fail closed");
    assert_eq!(guest_conflict.code, ErrorCode::Conflict);
    assert_eq!(guest.resize_request_count(), request_count + 1);
    assert_eq!(guest.resize_effect_count(), 1);

    let mut changed_host = request.clone();
    changed_host.size = changed_size;
    let host_conflict = service
        .resize(changed_host)
        .await
        .expect_err("changed durable terminal size retry must fail closed");
    assert_eq!(host_conflict.code, ErrorCode::FailedPrecondition);
    assert_eq!(metrics.resize_dispatches(), driver_dispatches);
    assert_eq!(guest.resize_request_count(), request_count + 1);
    assert_eq!(guest.resize_effect_count(), 1);
}
