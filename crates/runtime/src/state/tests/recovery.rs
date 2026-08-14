use a3s_oci_core::DriverKind;
use a3s_oci_sdk::oci_spec::runtime::{ContainerState, LinuxResources};
use a3s_oci_sdk::{
    ContainerOperationRequest, ContainerTarget, FileOp, FileRequest, FilesystemOp,
    FilesystemRequest, Generation, OperationContext, StartRequest, UpdateRequest,
};

use crate::state::FilesystemMutationPreparation;
use crate::DriverState;

use super::{
    create_container, create_request, operation_id, state_root, DurableStateStore,
    RecordOperationPreparation,
};

#[tokio::test]
async fn recreated_running_process_preserves_prepared_file_mutation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let create = create_request(
        &bundle_directory,
        "prepared-file-recovery-container",
        "prepared-file-recovery-create",
    );
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    create_container(&store, &create).await;
    let target = ContainerTarget::exact(create.id.clone(), Generation(1));
    let start = StartRequest {
        context: OperationContext::new(operation_id("prepared-file-recovery-start")),
        target: target.clone(),
    };
    store.prepare_start(&start).await.expect("prepare start");
    store
        .complete_start(
            &start.context.operation_id,
            ContainerState::Running,
            Some(4_242),
        )
        .await
        .expect("complete start");
    let file = FileRequest {
        target: target.clone(),
        op: FileOp::Upload,
        path: "/tmp/recovered-file".to_string(),
        data: Some("AA==".to_string()),
        user: None,
        context: Some(OperationContext::new(operation_id(
            "prepared-file-recovery-upload",
        ))),
    };
    store
        .prepare_file_mutation(&file)
        .await
        .expect("prepare File upload");

    let recovered = store
        .observe_recreated_running_process(
            &target,
            DriverState::running(5_151).expect("replacement running state"),
        )
        .await
        .expect("rebind running process while File remains prepared");
    assert_eq!(*recovered.state.pid(), Some(5_151));

    let RecordOperationPreparation::Replayed(created) = store
        .prepare_create(&create, DriverKind::LibkrunWhpx)
        .await
        .expect("replay rebound Create")
    else {
        panic!("Create must replay");
    };
    assert_eq!(*created.state.pid(), Some(5_151));

    let RecordOperationPreparation::Replayed(started) = store
        .prepare_start(&start)
        .await
        .expect("replay rebound Start")
    else {
        panic!("Start must replay");
    };
    assert_eq!(*started.state.pid(), Some(5_151));

    let FilesystemMutationPreparation::Resume(resumed) = store
        .prepare_file_mutation(&file)
        .await
        .expect("resume prepared File upload")
    else {
        panic!("File upload must remain prepared");
    };
    assert_eq!(resumed, target);
}

#[tokio::test]
async fn recreated_running_process_preserves_prepared_filesystem_mutation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let create = create_request(
        &bundle_directory,
        "prepared-filesystem-recovery-container",
        "prepared-filesystem-recovery-create",
    );
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    create_container(&store, &create).await;
    let target = ContainerTarget::exact(create.id.clone(), Generation(1));
    let start = StartRequest {
        context: OperationContext::new(operation_id("prepared-filesystem-recovery-start")),
        target: target.clone(),
    };
    store.prepare_start(&start).await.expect("prepare start");
    store
        .complete_start(
            &start.context.operation_id,
            ContainerState::Running,
            Some(4_242),
        )
        .await
        .expect("complete start");
    let filesystem = FilesystemRequest {
        target: target.clone(),
        op: FilesystemOp::MakeDir,
        path: "/tmp/recovered-directory".to_string(),
        destination: None,
        depth: 0,
        user: None,
        context: Some(OperationContext::new(operation_id(
            "prepared-filesystem-recovery-mkdir",
        ))),
    };
    store
        .prepare_filesystem_mutation(&filesystem)
        .await
        .expect("prepare Filesystem mkdir");

    let recovered = store
        .observe_recreated_running_process(
            &target,
            DriverState::running(5_151).expect("replacement running state"),
        )
        .await
        .expect("rebind running process while Filesystem remains prepared");
    assert_eq!(*recovered.state.pid(), Some(5_151));

    let RecordOperationPreparation::Replayed(created) = store
        .prepare_create(&create, DriverKind::LibkrunWhpx)
        .await
        .expect("replay rebound Create")
    else {
        panic!("Create must replay");
    };
    assert_eq!(*created.state.pid(), Some(5_151));

    let RecordOperationPreparation::Replayed(started) = store
        .prepare_start(&start)
        .await
        .expect("replay rebound Start")
    else {
        panic!("Start must replay");
    };
    assert_eq!(*started.state.pid(), Some(5_151));

    let FilesystemMutationPreparation::Resume(resumed) = store
        .prepare_filesystem_mutation(&filesystem)
        .await
        .expect("resume prepared Filesystem mkdir")
    else {
        panic!("Filesystem mkdir must remain prepared");
    };
    assert_eq!(resumed, target);
}

#[tokio::test]
async fn recreated_running_process_preserves_prepared_pause_and_rebinds_setup_journals() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let create = create_request(
        &bundle_directory,
        "prepared-pause-recovery-container",
        "prepared-pause-recovery-create",
    );
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    create_container(&store, &create).await;
    let target = ContainerTarget::exact(create.id.clone(), Generation(1));
    let start = StartRequest {
        context: OperationContext::new(operation_id("prepared-pause-recovery-start")),
        target: target.clone(),
    };
    store.prepare_start(&start).await.expect("prepare start");
    store
        .complete_start(
            &start.context.operation_id,
            ContainerState::Running,
            Some(4_242),
        )
        .await
        .expect("complete start");
    let pause = ContainerOperationRequest {
        context: OperationContext::new(operation_id("prepared-pause-recovery-pause")),
        target: target.clone(),
    };
    store.prepare_pause(&pause).await.expect("prepare pause");

    let recovered = store
        .observe_recreated_running_process(
            &target,
            DriverState::running(5_151).expect("replacement running state"),
        )
        .await
        .expect("rebind running process");
    assert_eq!(*recovered.state.pid(), Some(5_151));
    assert!(!recovered.is_paused());

    let RecordOperationPreparation::Replayed(created) = store
        .prepare_create(&create, DriverKind::LibkrunWhpx)
        .await
        .expect("replay rebound Create")
    else {
        panic!("Create must replay");
    };
    assert_eq!(*created.state.pid(), Some(5_151));

    let RecordOperationPreparation::Replayed(started) = store
        .prepare_start(&start)
        .await
        .expect("replay rebound Start")
    else {
        panic!("Start must replay");
    };
    assert_eq!(*started.state.pid(), Some(5_151));

    let RecordOperationPreparation::Resume(pausing) = store
        .prepare_pause(&pause)
        .await
        .expect("resume prepared Pause")
    else {
        panic!("Pause must remain prepared");
    };
    assert_eq!(*pausing.state.pid(), Some(5_151));
    assert!(!pausing.is_paused());
}

#[tokio::test]
async fn recreated_paused_process_preserves_prepared_resume_and_rebinds_setup_journals() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let create = create_request(
        &bundle_directory,
        "prepared-resume-recovery-container",
        "prepared-resume-recovery-create",
    );
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    create_container(&store, &create).await;
    let target = ContainerTarget::exact(create.id.clone(), Generation(1));
    let start = StartRequest {
        context: OperationContext::new(operation_id("prepared-resume-recovery-start")),
        target: target.clone(),
    };
    store.prepare_start(&start).await.expect("prepare start");
    store
        .complete_start(
            &start.context.operation_id,
            ContainerState::Running,
            Some(4_242),
        )
        .await
        .expect("complete start");
    let pause = ContainerOperationRequest {
        context: OperationContext::new(operation_id("prepared-resume-recovery-pause")),
        target: target.clone(),
    };
    store.prepare_pause(&pause).await.expect("prepare pause");
    store
        .complete_pause(
            &pause.context.operation_id,
            ContainerState::Running,
            Some(4_242),
            true,
        )
        .await
        .expect("complete pause");
    let resume = ContainerOperationRequest {
        context: OperationContext::new(operation_id("prepared-resume-recovery-resume")),
        target: target.clone(),
    };
    store.prepare_resume(&resume).await.expect("prepare resume");

    let replacement = DriverState::running(5_151)
        .and_then(|state| state.with_paused(true))
        .expect("replacement paused state");
    let recovered = store
        .observe_recreated_paused_running_process(&target, replacement)
        .await
        .expect("rebind paused process");
    assert_eq!(*recovered.state.pid(), Some(5_151));
    assert!(recovered.is_paused());

    let RecordOperationPreparation::Replayed(created) = store
        .prepare_create(&create, DriverKind::LibkrunWhpx)
        .await
        .expect("replay rebound Create")
    else {
        panic!("Create must replay");
    };
    assert_eq!(*created.state.pid(), Some(5_151));

    let RecordOperationPreparation::Replayed(started) = store
        .prepare_start(&start)
        .await
        .expect("replay rebound Start")
    else {
        panic!("Start must replay");
    };
    assert_eq!(*started.state.pid(), Some(5_151));

    let RecordOperationPreparation::Replayed(paused) = store
        .prepare_pause(&pause)
        .await
        .expect("replay rebound Pause")
    else {
        panic!("Pause must replay");
    };
    assert_eq!(*paused.state.pid(), Some(5_151));

    let RecordOperationPreparation::Resume(resuming) = store
        .prepare_resume(&resume)
        .await
        .expect("resume prepared Resume")
    else {
        panic!("Resume must remain prepared");
    };
    assert_eq!(*resuming.state.pid(), Some(5_151));
    assert!(resuming.is_paused());
}

#[tokio::test]
async fn recreated_running_process_rebinds_completed_pause_and_resume_history() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let create = create_request(
        &bundle_directory,
        "completed-resume-recovery-container",
        "completed-resume-recovery-create",
    );
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    create_container(&store, &create).await;
    let target = ContainerTarget::exact(create.id.clone(), Generation(1));
    let start = StartRequest {
        context: OperationContext::new(operation_id("completed-resume-recovery-start")),
        target: target.clone(),
    };
    store.prepare_start(&start).await.expect("prepare start");
    store
        .complete_start(
            &start.context.operation_id,
            ContainerState::Running,
            Some(4_242),
        )
        .await
        .expect("complete start");
    let pause = ContainerOperationRequest {
        context: OperationContext::new(operation_id("completed-resume-recovery-pause")),
        target: target.clone(),
    };
    store.prepare_pause(&pause).await.expect("prepare pause");
    store
        .complete_pause(
            &pause.context.operation_id,
            ContainerState::Running,
            Some(4_242),
            true,
        )
        .await
        .expect("complete pause");
    let resume = ContainerOperationRequest {
        context: OperationContext::new(operation_id("completed-resume-recovery-resume")),
        target: target.clone(),
    };
    store.prepare_resume(&resume).await.expect("prepare resume");
    store
        .complete_resume(
            &resume.context.operation_id,
            ContainerState::Running,
            Some(4_242),
            false,
        )
        .await
        .expect("complete resume");

    let recovered = store
        .observe_recreated_running_process(
            &target,
            DriverState::running(5_151).expect("replacement running state"),
        )
        .await
        .expect("rebind resumed process");
    assert_eq!(*recovered.state.pid(), Some(5_151));
    assert!(!recovered.is_paused());

    let RecordOperationPreparation::Replayed(created) = store
        .prepare_create(&create, DriverKind::LibkrunWhpx)
        .await
        .expect("replay rebound Create")
    else {
        panic!("Create must replay");
    };
    assert_eq!(*created.state.pid(), Some(5_151));

    let RecordOperationPreparation::Replayed(started) = store
        .prepare_start(&start)
        .await
        .expect("replay rebound Start")
    else {
        panic!("Start must replay");
    };
    assert_eq!(*started.state.pid(), Some(5_151));
    assert!(!started.is_paused());

    let RecordOperationPreparation::Replayed(paused) = store
        .prepare_pause(&pause)
        .await
        .expect("replay rebound Pause")
    else {
        panic!("Pause must replay");
    };
    assert_eq!(*paused.state.pid(), Some(5_151));
    assert!(paused.is_paused());

    let RecordOperationPreparation::Replayed(resumed) = store
        .prepare_resume(&resume)
        .await
        .expect("replay rebound Resume")
    else {
        panic!("Resume must replay");
    };
    assert_eq!(*resumed.state.pid(), Some(5_151));
    assert!(!resumed.is_paused());
}

#[tokio::test]
async fn recreated_running_process_preserves_prepared_update_and_rebinds_setup_journals() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let create = create_request(
        &bundle_directory,
        "prepared-update-recovery-container",
        "prepared-update-recovery-create",
    );
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    create_container(&store, &create).await;
    let target = ContainerTarget::exact(create.id.clone(), Generation(1));
    let start = StartRequest {
        context: OperationContext::new(operation_id("prepared-update-recovery-start")),
        target: target.clone(),
    };
    store.prepare_start(&start).await.expect("prepare start");
    store
        .complete_start(
            &start.context.operation_id,
            ContainerState::Running,
            Some(4_242),
        )
        .await
        .expect("complete start");
    let update = UpdateRequest {
        context: OperationContext::new(operation_id("prepared-update-recovery-update")),
        target: target.clone(),
        resources: update_resources(),
    };
    store.prepare_update(&update).await.expect("prepare update");

    let recovered = store
        .observe_recreated_running_process(
            &target,
            DriverState::running(5_151).expect("replacement running state"),
        )
        .await
        .expect("rebind running process while Update remains prepared");
    assert_eq!(*recovered.state.pid(), Some(5_151));

    let RecordOperationPreparation::Replayed(created) = store
        .prepare_create(&create, DriverKind::LibkrunWhpx)
        .await
        .expect("replay rebound Create")
    else {
        panic!("Create must replay");
    };
    assert_eq!(*created.state.pid(), Some(5_151));

    let RecordOperationPreparation::Replayed(started) = store
        .prepare_start(&start)
        .await
        .expect("replay rebound Start")
    else {
        panic!("Start must replay");
    };
    assert_eq!(*started.state.pid(), Some(5_151));

    let RecordOperationPreparation::Resume(updating) = store
        .prepare_update(&update)
        .await
        .expect("resume prepared Update")
    else {
        panic!("Update must remain prepared");
    };
    assert_eq!(*updating.state.pid(), Some(5_151));
}

#[tokio::test]
async fn recreated_running_process_rebinds_completed_update_response() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let create = create_request(
        &bundle_directory,
        "completed-update-recovery-container",
        "completed-update-recovery-create",
    );
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    create_container(&store, &create).await;
    let target = ContainerTarget::exact(create.id.clone(), Generation(1));
    let start = StartRequest {
        context: OperationContext::new(operation_id("completed-update-recovery-start")),
        target: target.clone(),
    };
    store.prepare_start(&start).await.expect("prepare start");
    store
        .complete_start(
            &start.context.operation_id,
            ContainerState::Running,
            Some(4_242),
        )
        .await
        .expect("complete start");
    let update = UpdateRequest {
        context: OperationContext::new(operation_id("completed-update-recovery-update")),
        target: target.clone(),
        resources: update_resources(),
    };
    store.prepare_update(&update).await.expect("prepare update");
    store
        .complete_update(
            &update.context.operation_id,
            ContainerState::Running,
            Some(4_242),
            false,
        )
        .await
        .expect("complete update");

    store
        .observe_recreated_running_process(
            &target,
            DriverState::running(5_151).expect("replacement running state"),
        )
        .await
        .expect("rebind updated process");

    let RecordOperationPreparation::Replayed(updated) = store
        .prepare_update(&update)
        .await
        .expect("replay rebound Update")
    else {
        panic!("Update must replay");
    };
    assert_eq!(*updated.state.pid(), Some(5_151));
    assert_eq!(*updated.state.status(), ContainerState::Running);
    assert!(!updated.is_paused());
}

fn update_resources() -> LinuxResources {
    serde_json::from_value(serde_json::json!({
        "memory": {"limit": 536_870_912, "reservation": 67_108_864},
        "cpu": {"shares": 512, "quota": 50_000, "period": 100_000},
        "pids": {"limit": 64}
    }))
    .expect("valid Update resources")
}
