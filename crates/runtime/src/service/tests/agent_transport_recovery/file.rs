use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentClient, AgentOperation, AgentTransportFaultPoint, AgentTransportOperationStage,
};
use a3s_oci_sdk::{
    ContainerTarget, ErrorCode, FileOp, FileRequest, FileResponse, Generation, OciRuntimeService,
    OperationContext, StartRequest,
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

const UPLOAD_DATA: &str = "cmVjb3Zlcnk=";
const UPLOAD_SIZE: u64 = 8;

#[tokio::test]
async fn every_file_transport_stage_recovers_after_host_service_reopen() {
    assert_eq!(AgentTransportOperationStage::ALL.len(), 9);
    for (index, stage) in AgentTransportOperationStage::ALL.into_iter().enumerate() {
        exercise_file_reopen(index, stage).await;
    }
}

async fn exercise_file_reopen(index: usize, stage: AgentTransportOperationStage) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let state_root = temporary.path().join("state");
    let create = create_request(
        &bundle_directory,
        &format!("agent-reopen-file-create-{index}"),
    );
    let guest = Arc::new(JournaledLifecycleGuest::new());
    let metrics = Arc::new(DriverMetrics::default());
    let fault_point = AgentTransportFaultPoint::Operation {
        protocol_version: a3s_oci_agent_protocol::AGENT_PROTOCOL_VERSION_MAX,
        operation: AgentOperation::File,
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
    .unwrap_or_else(|error| panic!("open first file runtime for {stage:?}: {error}"));
    let created = first_service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("prepare file create for {stage:?}: {error}"));
    let exact_target = ContainerTarget::exact(create.id.clone(), created.generation);
    first_service
        .start(StartRequest {
            context: OperationContext::new(operation_id(&format!(
                "agent-reopen-file-start-{index}"
            ))),
            target: exact_target.clone(),
        })
        .await
        .unwrap_or_else(|error| panic!("prepare file start for {stage:?}: {error}"));
    let upload = FileRequest {
        target: ContainerTarget::current(create.id.clone()),
        op: FileOp::Upload,
        path: "/tmp/reopen.txt".to_string(),
        data: Some(UPLOAD_DATA.to_string()),
        user: Some("1000:1000".to_string()),
        context: Some(OperationContext::new(operation_id(&format!(
            "agent-reopen-file-upload-{index}"
        )))),
    };

    let first_result = first_service.file(upload.clone()).await;
    if response_reached_host(stage) {
        let response = first_result
            .unwrap_or_else(|error| panic!("written file response for {stage:?}: {error}"));
        assert_upload(&response, &exact_target, stage);
    } else {
        let error = first_result.expect_err("file fault must remain visible before delivery");
        assert_eq!(error.code, ErrorCode::Unavailable, "{stage:?}");
        assert!(error.retryable, "{stage:?}");
    }
    assert_eq!(metrics.file_dispatches(), 1, "{stage:?}");
    drop(first_service);
    drop(first_driver);

    let server_result = first_server
        .await
        .unwrap_or_else(|error| panic!("first file server task for {stage:?}: {error}"));
    if is_guest_stage(stage) {
        let error = server_result.expect_err("guest file fault must end first server");
        assert_eq!(
            error.operation.as_deref(),
            Some("agent-transport-fault"),
            "{stage:?}"
        );
    }
    assert_eq!(faults.crossing_count(), 1, "{stage:?}");
    let first_guest_dispatches = usize::from(guest_dispatch_reached(stage));
    assert_eq!(
        guest.file_request_count(),
        first_guest_dispatches,
        "{stage:?}"
    );
    assert_eq!(
        guest.file_effect_count(),
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
    .unwrap_or_else(|error| panic!("reopen file runtime for {stage:?}: {error}"));
    assert_eq!(metrics.recoveries(), 1, "{stage:?}");

    let response = reopened
        .file(upload.clone())
        .await
        .unwrap_or_else(|error| panic!("repeat file upload after {stage:?}: {error}"));
    assert_upload(&response, &exact_target, stage);
    assert_eq!(metrics.file_dispatches(), 2, "{stage:?}");
    assert_eq!(
        guest.file_request_count(),
        first_guest_dispatches + 1,
        "{stage:?}"
    );
    assert_eq!(
        guest.file_effect_count(),
        1,
        "reopen after {stage:?} must produce exactly one file upload effect"
    );
    assert_eq!(
        guest.recorded_file_request(),
        Some(FileRequest {
            target: exact_target.clone(),
            ..upload.clone()
        }),
        "{stage:?}"
    );

    let replayed = reopened
        .file(upload.clone())
        .await
        .unwrap_or_else(|error| panic!("replay file upload after {stage:?}: {error}"));
    assert_upload(&replayed, &exact_target, stage);
    assert_eq!(metrics.file_dispatches(), 3, "{stage:?}");
    assert_eq!(
        guest.file_request_count(),
        first_guest_dispatches + 2,
        "{stage:?}"
    );
    assert_eq!(guest.file_effect_count(), 1, "{stage:?}");

    if stage == AgentTransportOperationStage::GuestBeforeResponseWrite {
        verify_changed_and_stale_file_requests_fail_closed(
            &second_client,
            &reopened,
            &upload,
            &exact_target,
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
        .unwrap_or_else(|error| panic!("close replacement file session for {stage:?}: {error}"));
    second_server
        .await
        .unwrap_or_else(|error| panic!("replacement file server task for {stage:?}: {error}"))
        .unwrap_or_else(|error| panic!("replacement file server close for {stage:?}: {error}"));
}

fn assert_upload(
    response: &FileResponse,
    target: &ContainerTarget,
    stage: AgentTransportOperationStage,
) {
    assert_eq!(&response.target, target, "{stage:?}");
    assert_eq!(response.size, UPLOAD_SIZE, "{stage:?}");
    assert!(response.data.is_none(), "{stage:?}");
}

async fn verify_changed_and_stale_file_requests_fail_closed(
    client: &AgentClient<DuplexStream>,
    service: &HostRuntimeService,
    request: &FileRequest,
    target: &ContainerTarget,
    guest: &JournaledLifecycleGuest,
    metrics: &DriverMetrics,
) {
    let request_count = guest.file_request_count();
    let driver_dispatches = metrics.file_dispatches();
    let mut changed = request.clone();
    changed.target = target.clone();
    changed.data = Some("Y2hhbmdlZA==".to_string());
    let guest_conflict = client
        .file(changed.clone())
        .await
        .expect_err("changed guest file upload must fail closed");
    assert_eq!(guest_conflict.code, ErrorCode::Conflict);
    assert_eq!(guest.file_request_count(), request_count + 1);
    assert_eq!(guest.file_effect_count(), 1);

    changed.target = request.target.clone();
    let host_conflict = service
        .file(changed)
        .await
        .expect_err("changed host file upload must fail through the guest journal");
    assert_eq!(host_conflict.code, ErrorCode::Conflict);
    assert_eq!(metrics.file_dispatches(), driver_dispatches + 1);
    assert_eq!(guest.file_request_count(), request_count + 2);
    assert_eq!(guest.file_effect_count(), 1);

    let stale_target = ContainerTarget::exact(
        target.id.clone(),
        Generation(target.generation.expect("exact file generation").0 + 1),
    );
    let stale = FileRequest {
        target: stale_target.clone(),
        op: FileOp::Upload,
        path: request.path.clone(),
        data: request.data.clone(),
        user: request.user.clone(),
        context: Some(OperationContext::new(operation_id(
            "agent-reopen-file-stale",
        ))),
    };
    let guest_stale = client
        .file(stale.clone())
        .await
        .expect_err("stale guest file target must fail closed");
    assert_eq!(guest_stale.code, ErrorCode::NotFound);
    assert_eq!(guest.file_request_count(), request_count + 3);

    let host_stale = service
        .file(stale)
        .await
        .expect_err("stale host file target must fail before dispatch");
    assert_eq!(host_stale.code, ErrorCode::Conflict);
    assert_eq!(metrics.file_dispatches(), driver_dispatches + 1);
    assert_eq!(guest.file_request_count(), request_count + 3);
    assert_eq!(guest.file_effect_count(), 1);
}
