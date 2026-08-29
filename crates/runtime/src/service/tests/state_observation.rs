use super::*;

#[tokio::test]
async fn state_caches_an_observed_init_exit_before_delete() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::supported());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let create = create_request(&bundle_directory, "state-exit-create");
    let created = service.create(create.clone()).await.expect("create");
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("state-exit-start")),
            target: target.clone(),
        })
        .await
        .expect("start");

    let expected = ExitStatus::exited(23).expect("exit status");
    driver.states.lock().expect("driver states lock").insert(
        create.id.clone(),
        (created.generation, DriverState::stopped()),
    );
    driver
        .exits
        .lock()
        .expect("driver exits lock")
        .insert(create.id.clone(), expected.clone());

    let observed = service
        .state(StateRequest {
            target: target.clone(),
        })
        .await
        .expect("observe stopped init");
    assert_eq!(observed.state.status(), &ContainerState::Stopped);
    let wait_calls = driver
        .calls()
        .into_iter()
        .filter_map(|call| match call {
            DriverCall::Wait(request) => Some(request),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(wait_calls.len(), 1);
    assert_eq!(wait_calls[0].target, target);
    assert_eq!(wait_calls[0].timeout_ms, Some(0));

    assert_eq!(
        service
            .wait(WaitRequest {
                target: target.clone(),
                timeout_ms: Some(0),
            })
            .await
            .expect("replay exit observed through state"),
        expected
    );
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Wait(_)))
            .count(),
        1,
        "an explicit wait must replay the exit cached by state"
    );

    let events = service
        .events(EventsRequest {
            container: Some(target.clone()),
            after_sequence: 0,
            limit: 32,
            wait_timeout_ms: None,
        })
        .await
        .expect("read lifecycle events");
    assert_eq!(
        events
            .events
            .iter()
            .filter(|event| event.kind == RuntimeEventKind::ProcessExited)
            .count(),
        1
    );
    assert_eq!(
        events
            .events
            .iter()
            .filter(|event| event.kind == RuntimeEventKind::ContainerStopped)
            .count(),
        1
    );
    assert_eq!(
        events
            .events
            .iter()
            .find(|event| event.kind == RuntimeEventKind::ProcessExited)
            .and_then(|event| event.attributes.get("exit-code"))
            .map(String::as_str),
        Some("23")
    );

    drop(service);
    let reopened = open_service(&temporary, Arc::clone(&driver)).await;
    assert_eq!(
        reopened
            .wait(WaitRequest {
                target,
                timeout_ms: Some(0),
            })
            .await
            .expect("replay cached exit after reopen"),
        expected
    );
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Wait(_)))
            .count(),
        1,
        "reopen must not ask the driver for an already cached exit"
    );
}

#[tokio::test]
async fn state_does_not_wait_when_the_selected_driver_omits_wait() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::without_wait());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let create = create_request(&bundle_directory, "state-without-wait-create");
    let created = service.create(create.clone()).await.expect("create");
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("state-without-wait-start")),
            target: target.clone(),
        })
        .await
        .expect("start");
    driver
        .states
        .lock()
        .expect("driver states lock")
        .insert(create.id, (created.generation, DriverState::stopped()));

    let observed = service
        .state(StateRequest { target })
        .await
        .expect("observe stopped state without wait support");
    assert_eq!(observed.state.status(), &ContainerState::Stopped);
    assert!(driver
        .calls()
        .iter()
        .all(|call| !matches!(call, DriverCall::Wait(_))));
}

#[tokio::test]
async fn state_preserves_a_stopped_tombstone_without_inventing_exit_evidence() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::supported());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let create = create_request(&bundle_directory, "state-tombstone-create");
    let created = service.create(create.clone()).await.expect("create");
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("state-tombstone-start")),
            target: target.clone(),
        })
        .await
        .expect("start");
    driver
        .states
        .lock()
        .expect("driver states lock")
        .insert(create.id, (created.generation, DriverState::stopped()));
    for _ in 0..2 {
        driver.fail_next(
            "wait",
            Error::new(
                ErrorCode::FailedPrecondition,
                "no authenticated parent retained exact init exit evidence",
            )
            .for_operation("driver-wait"),
        );
    }

    let observed = service
        .state(StateRequest {
            target: target.clone(),
        })
        .await
        .expect("observe stopped tombstone without exact exit evidence");
    assert_eq!(observed.state.status(), &ContainerState::Stopped);
    assert_eq!(
        service
            .wait(WaitRequest {
                target: target.clone(),
                timeout_ms: Some(0),
            })
            .await
            .expect_err("wait must not invent exit evidence")
            .code,
        ErrorCode::FailedPrecondition
    );

    let events = service
        .events(EventsRequest {
            container: Some(target),
            after_sequence: 0,
            limit: 32,
            wait_timeout_ms: None,
        })
        .await
        .expect("read tombstone events");
    assert!(events
        .events
        .iter()
        .all(|event| event.kind != RuntimeEventKind::ProcessExited));
    assert_eq!(
        events
            .events
            .iter()
            .filter(|event| event.kind == RuntimeEventKind::ContainerStopped)
            .count(),
        1
    );
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Wait(_)))
            .count(),
        2
    );
}
