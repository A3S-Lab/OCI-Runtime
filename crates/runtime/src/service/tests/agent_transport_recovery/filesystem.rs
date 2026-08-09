use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentClient, AgentOperation, AgentTransportFaultPoint, AgentTransportOperationStage,
};
use a3s_oci_sdk::{
    ContainerTarget, ErrorCode, FilesystemEntryKind, FilesystemOp, FilesystemRequest,
    FilesystemResponse, Generation, OciRuntimeService, OperationContext, StartRequest,
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

const DIRECTORY_PATH: &str = "/tmp/reopen-dir";

#[tokio::test]
async fn every_filesystem_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_filesystem_reopen(index, stage).await;
    }
}

async fn exercise_filesystem_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let create = create_request(
        &bundle_directory,
        &format!("agent-reopen-filesystem-create-{index}"),
    );
    let guest = Arc::new(JournaledLifecycleGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::Filesystem,
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
    .unwrap_or_else(|error| panic!("open first filesystem runtime for {stage:?}: {error}"));
    let created = first_service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare filesystem create for {stage:?}: {error}"));
    let exact_target = ContainerTarget::exact(create.id.clone(), created.generation);
    first_service
        .start(StartRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-filesystem-start-{index}"
            ))),
            target: exact_target.clone(),
        })
        .await
        .unwrap_or_else(|error| panic!("prepare filesystem start for {stage:?}: {error}"));
    let make_dir = FilesystemRequest {
        target: ContainerTarget::current(create.id.clone()),
        op: FilesystemOp::MakeDir,
        path: DIRECTORY_PATH.to_string(),
        destination: None,
        depth: 0,
        user: Some("1000:1000".to_string()),
        context: Some(OperationContext::new(operation_id(&format!(
            "agent-reopen-filesystem-mkdir-{index}"
        )))),
    };

    let first_result = first_service.filesystem(make_dir.clone()).await;
    if response_reached_host(stage) {
        let response = first_result
            .unwrap_or_else(|error| panic!("written filesystem response for {stage:?}: {error}"));
        assert_directory(&response, &exact_target, stage);
    } else {
        let error = first_result.expect_err("filesystem fault must remain visible before delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.filesystem_dispatches(), 1, "{stage:?}");
    drop(first_service);
    drop(first_driver);

    let server_result = first_server
        .await
        .unwrap_or_else(|error| panic!("first filesystem server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest filesystem fault must end first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(
        guest.filesystem_request_count(),
        first_guest_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.filesystem_effect_count(),
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
    .unwrap_or_else(|error| panic!("reopen filesystem runtime for {stage:?}: {error}"));
    assert_eq!(metrics.recoveries(), 1, "{stage:?}");

    let response = reopened
        .filesystem(make_dir.clone())
        .await
        .unwrap_or_else(|error| panic!("repeat filesystem mkdir after {stage:?}: {error}"));
    assert_directory(&response, &exact_target, stage);
    assert_eq!(metrics.filesystem_dispatches(), 2, "{stage:?}");
    assert_eq!(
        guest.filesystem_request_count(),
        first_guest_dispatches + 1,
        "{stage:?}"
    );
    assert_eq!(
        guest.filesystem_effect_count(),
        1,
        "reopen after {stage:?} must produce exactly one mkdir effect"
    );
    assert_eq!(
        guest.recorded_filesystem_request(),
        Some(FilesystemRequest {
            target: exact_target.clone(),
            ..make_dir.clone()
        }),
        "{stage:?}"
    );

    let replayed = reopened
        .filesystem(make_dir.clone())
        .await
        .unwrap_or_else(|error| panic!("replay filesystem mkdir after {stage:?}: {error}"));
    assert_directory(&replayed, &exact_target, stage);
    assert_eq!(metrics.filesystem_dispatches(), 3, "{stage:?}");
    assert_eq!(
        guest.filesystem_request_count(),
        first_guest_dispatches + 2,
        "{stage:?}"
    );
    assert_eq!(guest.filesystem_effect_count(), 1, "{stage:?}");

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_changed_and_stale_filesystem_requests_fail_closed(
            &second_client,
            &reopened,
            &make_dir,
            &exact_target,
            guest.as_ref(),
            metrics.as_ref(),
        )
        .await;
    }

    drop(reopened);
    drop(second_driver);
    second_client.close().await.unwrap_or_else(|error| {
        panic!("close replacement filesystem session for {stage:?}: {error}")
    });
    second_server
        .await
        .unwrap_or_else(|error| panic!("replacement filesystem server task for {stage:?}: {error}"))
        .unwrap_or_else(|error| {
            panic!("replacement filesystem server close for {stage:?}: {error}")
        });
}

fn assert_directory(
    response: &FilesystemResponse,
    target: &ContainerTarget,
    stage: AgentTransportOperationStage,
) {
    assert_eq!(&response.target, target, "{stage:?}");
    assert!(response.entries.is_empty(), "{stage:?}");
    let entry = response.entry.as_ref().expect("mkdir response entry");
    assert_eq!(entry.name, "reopen-dir", "{stage:?}");
    assert_eq!(entry.kind, FilesystemEntryKind::Directory, "{stage:?}");
    assert_eq!(entry.path, DIRECTORY_PATH, "{stage:?}");
}

async fn verify_changed_and_stale_filesystem_requests_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &FilesystemRequest,
    target: &ContainerTarget,
    guest: &JournaledLifecycleGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.filesystem_request_count();
    let driver_dispatches = metrics.filesystem_dispatches();
    let mut changed = request.clone();
    changed.target = target.clone();
    changed.path = "/tmp/changed-dir".to_string();
    let guest_conflict = client
        .filesystem(changed.clone())
        .await
        .expect_err("changed guest filesystem mutation must fail closed");
    assert_eq!(guest_conflict.code, ErrorCode::Conflict);
    assert_eq!(guest.filesystem_request_count(), request_count + 1);
    assert_eq!(guest.filesystem_effect_count(), 1);

    changed.target = request.target.clone();
    let host_conflict = service
        .filesystem(changed)
        .await
        .expect_err("changed host filesystem mutation must fail through the guest journal");
    assert_eq!(host_conflict.code, ErrorCode::Conflict);
    assert_eq!(metrics.filesystem_dispatches(), driver_dispatches + 1);
    assert_eq!(guest.filesystem_request_count(), request_count + 2);
    assert_eq!(guest.filesystem_effect_count(), 1);

    let stale_target = ContainerTarget::exact(
        target.id.clone(),
        Generation(target.generation.expect("exact filesystem generation").0 + 1),
    );
    let stale = FilesystemRequest {
        target: stale_target,
        op: request.op,
        path: request.path.clone(),
        destination: request.destination.clone(),
        depth: request.depth,
        user: request.user.clone(),
        context: Some(OperationContext::new(operation_id(
            "agent-reopen-filesystem-stale",
        ))),
    };
    let guest_stale = client
        .filesystem(stale.clone())
        .await
        .expect_err("stale guest filesystem target must fail closed");
    assert_eq!(guest_stale.code, ErrorCode::NotFound);
    assert_eq!(guest.filesystem_request_count(), request_count + 3);

    let host_stale = service
        .filesystem(stale)
        .await
        .expect_err("stale host filesystem target must fail before dispatch");
    assert_eq!(host_stale.code, ErrorCode::Conflict);
    assert_eq!(metrics.filesystem_dispatches(), driver_dispatches + 1);
    assert_eq!(guest.filesystem_request_count(), request_count + 3);
    assert_eq!(guest.filesystem_effect_count(), 1);
}
