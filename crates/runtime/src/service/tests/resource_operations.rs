use super::*;

#[tokio::test]
async fn resource_updates_are_durable_and_stats_are_exactly_fenced() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::with_control_operations());
    let service = open_service(&temporary, Arc::clone(&driver)).await;

    let info = service.features().await.expect("configured features");
    assert!(info.operations.contains(&RuntimeOperation::Update));
    assert!(info.operations.contains(&RuntimeOperation::Stats));

    let create = create_request(&bundle_directory, "resource-create");
    let created = service.create(create.clone()).await.expect("create");
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("resource-start")),
            target: target.clone(),
        })
        .await
        .expect("start");

    let request = update_request(target.clone(), "resource-update");
    let updated = service
        .update(request.clone())
        .await
        .expect("update resources");
    assert_eq!(
        service.update(request).await.expect("replay update"),
        updated
    );
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Update(_)))
            .count(),
        1,
        "completed update must replay without another driver call"
    );

    let stats = service
        .stats(StatsRequest {
            target: target.clone(),
        })
        .await
        .expect("read stats");
    assert_eq!(stats.target, target);
    assert_eq!(stats.cpu.usage_ns, 30);
    assert_eq!(stats.memory.limit_bytes, Some(4_096));
    assert_eq!(stats.process_count, 1);
    assert_eq!(stats.metrics["memory.events.oom_kill"], 0);

    let retry = update_request(target, "resource-update-retry");
    driver.fail_next(
        "update",
        Error::new(ErrorCode::Unavailable, "resource controller busy")
            .for_operation("update")
            .retryable(true),
    );
    assert!(
        service
            .update(retry.clone())
            .await
            .expect_err("first update must be retryable")
            .retryable
    );
    service.update(retry).await.expect("retry update");
}
