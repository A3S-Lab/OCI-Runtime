use super::*;

async fn filesystem_fixture() -> (
    tempfile::TempDir,
    Arc<RecordingDriver>,
    HostRuntimeService,
    ContainerTarget,
) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::with_control_operations());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let create = create_request(&bundle_directory, "filesystem-create");
    let created = service.create(create.clone()).await.expect("create");
    let target = ContainerTarget::exact(create.id, created.generation);
    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("filesystem-start")),
            target: target.clone(),
        })
        .await
        .expect("start");
    (temporary, driver, service, target)
}

#[tokio::test]
async fn file_and_filesystem_requests_resolve_to_the_exact_generation() {
    let (_temporary, driver, service, target) = filesystem_fixture().await;
    let current = ContainerTarget::current(target.id.clone());
    let upload_context = OperationContext::new(operation_id("filesystem-upload"));
    let uploaded = service
        .file(FileRequest {
            target: current.clone(),
            op: FileOp::Upload,
            path: "/tmp/fixture.txt".to_string(),
            data: Some("aGVsbG8=".to_string()),
            user: Some("1000:1000".to_string()),
            context: Some(upload_context.clone()),
        })
        .await
        .expect("upload file");
    assert_eq!(uploaded.target, target);
    assert_eq!(uploaded.size, 5);
    assert!(uploaded.data.is_none());

    let downloaded = service
        .file(FileRequest {
            target: current.clone(),
            op: FileOp::Download,
            path: "/tmp/fixture.txt".to_string(),
            data: None,
            user: None,
            context: None,
        })
        .await
        .expect("download file");
    assert_eq!(downloaded.target, target);
    assert_eq!(downloaded.data.as_deref(), Some(""));

    let stat = service
        .filesystem(FilesystemRequest {
            target: current.clone(),
            op: FilesystemOp::Stat,
            path: "/tmp/fixture.txt".to_string(),
            destination: None,
            depth: 0,
            user: None,
            context: None,
        })
        .await
        .expect("stat file");
    assert_eq!(stat.target, target);
    assert_eq!(stat.entry.expect("stat entry").path, "/tmp/fixture.txt");

    let remove_context = OperationContext::new(operation_id("filesystem-remove"));
    let removed = service
        .filesystem(FilesystemRequest {
            target: current,
            op: FilesystemOp::Remove,
            path: "/tmp/fixture.txt".to_string(),
            destination: None,
            depth: 0,
            user: None,
            context: Some(remove_context.clone()),
        })
        .await
        .expect("remove file");
    assert_eq!(removed.target, target);
    assert!(removed.entry.is_none());
    assert!(removed.entries.is_empty());

    let calls = driver
        .calls()
        .into_iter()
        .filter(|call| matches!(call, DriverCall::File(_) | DriverCall::Filesystem(_)))
        .collect::<Vec<_>>();
    assert_eq!(
        calls,
        vec![
            DriverCall::File(FileRequest {
                target: target.clone(),
                op: FileOp::Upload,
                path: "/tmp/fixture.txt".to_string(),
                data: Some("aGVsbG8=".to_string()),
                user: Some("1000:1000".to_string()),
                context: Some(upload_context),
            }),
            DriverCall::File(FileRequest {
                target: target.clone(),
                op: FileOp::Download,
                path: "/tmp/fixture.txt".to_string(),
                data: None,
                user: None,
                context: None,
            }),
            DriverCall::Filesystem(FilesystemRequest {
                target: target.clone(),
                op: FilesystemOp::Stat,
                path: "/tmp/fixture.txt".to_string(),
                destination: None,
                depth: 0,
                user: None,
                context: None,
            }),
            DriverCall::Filesystem(FilesystemRequest {
                target,
                op: FilesystemOp::Remove,
                path: "/tmp/fixture.txt".to_string(),
                destination: None,
                depth: 0,
                user: None,
                context: Some(remove_context),
            }),
        ]
    );
}

#[tokio::test]
async fn filesystem_requests_fail_before_dispatch_on_invalid_identity_or_capability() {
    let (_temporary, driver, service, target) = filesystem_fixture().await;
    let wrong_generation = Generation(target.generation.expect("exact generation").0 + 1);
    let error = service
        .file(FileRequest {
            target: ContainerTarget::exact(target.id, wrong_generation),
            op: FileOp::Download,
            path: "/tmp/fixture.txt".to_string(),
            data: None,
            user: None,
            context: None,
        })
        .await
        .expect_err("stale generation must fail");
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(!driver
        .calls()
        .iter()
        .any(|call| matches!(call, DriverCall::File(_) | DriverCall::Filesystem(_))));

    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::supported());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let create = create_request(&bundle_directory, "unsupported-filesystem-create");
    let created = service.create(create.clone()).await.expect("create");
    let error = service
        .filesystem(FilesystemRequest {
            target: ContainerTarget::exact(create.id, created.generation),
            op: FilesystemOp::Stat,
            path: "/".to_string(),
            destination: None,
            depth: 0,
            user: None,
            context: None,
        })
        .await
        .expect_err("unadvertised filesystem operation must fail");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(!driver
        .calls()
        .iter()
        .any(|call| matches!(call, DriverCall::File(_) | DriverCall::Filesystem(_))));
}
