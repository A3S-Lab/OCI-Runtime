use std::time::Duration;

use a3s_oci_sdk::{EventsRequest, RuntimeEventKind};
use sha2::{Digest, Sha256};

use super::*;

fn events_request(
    container: Option<ContainerTarget>,
    after_sequence: u64,
    limit: u32,
    wait_timeout_ms: Option<u64>,
) -> EventsRequest {
    EventsRequest {
        container,
        after_sequence,
        limit,
        wait_timeout_ms,
    }
}

fn exec_request(target: &ContainerTarget) -> ExecRequest {
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0},
        "args": ["/bin/true"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .expect("valid exec process");
    ExecRequest {
        context: OperationContext::new(operation_id("events-exec")),
        container: target.clone(),
        process_id: ProcessId::new("worker").expect("process ID"),
        process,
        io: ProcessIo::default(),
    }
}

#[tokio::test]
async fn lifecycle_and_process_events_are_durable_ordered_and_replay_safe() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let create = create_request(&bundle_directory, "events-container", "events-create");
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");

    let prepared = store
        .prepare_create(&create, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    let RecordOperationPreparation::Prepared(prepared) = prepared else {
        panic!("create must prepare");
    };
    let target = ContainerTarget::exact(create.id.clone(), prepared.generation);

    let creating = store
        .events(&events_request(None, 0, 128, None))
        .await
        .expect("poll creating event");
    assert_eq!(creating.events.len(), 1);
    assert_eq!(creating.events[0].kind, RuntimeEventKind::ContainerCreating);
    assert_eq!(creating.events[0].container, target);
    assert_eq!(creating.next_sequence, 1);

    assert!(matches!(
        store
            .prepare_create(&create, DriverKind::LibkrunWhpx)
            .await
            .expect("resume create"),
        RecordOperationPreparation::Resume(_)
    ));
    assert_eq!(
        store
            .events(&events_request(None, 0, 128, None))
            .await
            .expect("replayed create must not duplicate events")
            .events
            .len(),
        1
    );

    store
        .complete_create(&create.context.operation_id, 4_242)
        .await
        .expect("complete create");
    let start = StartRequest {
        context: OperationContext::new(operation_id("events-start")),
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
        context: OperationContext::new(operation_id("events-pause")),
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
        context: OperationContext::new(operation_id("events-resume")),
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

    let resources: LinuxResources = serde_json::from_value(serde_json::json!({
        "memory": {"limit": 4096}
    }))
    .expect("valid resource update");
    let update = UpdateRequest {
        context: OperationContext::new(operation_id("events-update")),
        target: target.clone(),
        resources,
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

    let exec = exec_request(&target);
    store.prepare_exec(&exec).await.expect("prepare exec");
    let process = store
        .complete_exec(&exec.context.operation_id, 5_000, false)
        .await
        .expect("complete exec");
    let process_target = process.target;
    store
        .complete_process_wait(
            &process_target,
            ExitStatus::exited(7).expect("exec exit status"),
        )
        .await
        .expect("cache exec exit");
    store
        .complete_process_wait(
            &ProcessTarget {
                container: target.clone(),
                process_id: ProcessId::init(),
            },
            ExitStatus::exited(0).expect("init exit status"),
        )
        .await
        .expect("cache init exit");

    let delete = DeleteRequest {
        context: OperationContext::new(operation_id("events-delete")),
        target: target.clone(),
        mode: DeleteMode::StoppedOnly,
    };
    store.prepare_delete(&delete).await.expect("prepare delete");
    store
        .complete_delete(&delete.context.operation_id)
        .await
        .expect("complete delete");

    let expected_kinds = [
        RuntimeEventKind::ContainerCreating,
        RuntimeEventKind::ContainerCreated,
        RuntimeEventKind::ContainerStarted,
        RuntimeEventKind::ContainerPaused,
        RuntimeEventKind::ContainerResumed,
        RuntimeEventKind::ResourcesUpdated,
        RuntimeEventKind::ProcessCreated,
        RuntimeEventKind::ProcessStarted,
        RuntimeEventKind::ProcessExited,
        RuntimeEventKind::ProcessExited,
        RuntimeEventKind::ContainerStopped,
        RuntimeEventKind::ContainerDeleted,
    ];
    let all = store
        .events(&events_request(None, 0, 128, None))
        .await
        .expect("poll all events");
    assert_eq!(
        all.events
            .iter()
            .map(|event| event.kind)
            .collect::<Vec<_>>(),
        expected_kinds
    );
    assert_eq!(all.next_sequence, expected_kinds.len() as u64);
    assert!(all
        .events
        .iter()
        .enumerate()
        .all(|(index, event)| event.sequence == index as u64 + 1));
    assert!(all.events.iter().all(|event| event.container == target));
    assert_eq!(
        all.events
            .iter()
            .map(|event| event.operation_id.as_ref())
            .collect::<Vec<_>>(),
        [
            None,
            None,
            None,
            Some(&pause.context.operation_id),
            Some(&resume.context.operation_id),
            Some(&update.context.operation_id),
            None,
            None,
            None,
            None,
            None,
            None,
        ]
    );
    assert_eq!(
        all.events[8]
            .attributes
            .get("exit-code")
            .map(String::as_str),
        Some("7")
    );
    assert_eq!(all.events[9].process_id.as_ref(), Some(&ProcessId::init()));

    let first_page = store
        .events(&events_request(Some(target.clone()), 0, 3, None))
        .await
        .expect("poll first page");
    assert_eq!(first_page.events, all.events[..3]);
    assert_eq!(first_page.next_sequence, 3);
    let second_page = store
        .events(&events_request(
            Some(target.clone()),
            first_page.next_sequence,
            3,
            None,
        ))
        .await
        .expect("poll second page");
    assert_eq!(second_page.events, all.events[3..6]);
    assert_eq!(second_page.next_sequence, 6);

    let other_generation = store
        .events(&events_request(
            Some(ContainerTarget::exact(
                target.id.clone(),
                Generation(target.generation.expect("exact generation").0 + 1),
            )),
            0,
            128,
            None,
        ))
        .await
        .expect("poll generation filter");
    assert!(other_generation.events.is_empty());
    assert_eq!(other_generation.next_sequence, all.next_sequence);

    drop(store);
    let reopened = DurableStateStore::open(&root)
        .await
        .expect("reopen durable event store");
    assert_eq!(
        reopened
            .events(&events_request(None, 0, 128, None))
            .await
            .expect("poll reopened events"),
        all
    );
}

#[tokio::test]
async fn force_delete_appends_stopped_before_deleted_for_a_created_container() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    let create = create_request(&bundle_directory, "force-delete", "force-delete-create");
    let prepared = store
        .prepare_create(&create, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    let RecordOperationPreparation::Prepared(prepared) = prepared else {
        panic!("create must prepare");
    };
    let target = ContainerTarget::exact(create.id.clone(), prepared.generation);
    store
        .complete_create(&create.context.operation_id, 4_242)
        .await
        .expect("complete create");

    let delete = DeleteRequest {
        context: OperationContext::new(operation_id("force-delete-operation")),
        target: target.clone(),
        mode: DeleteMode::Force,
    };
    store.prepare_delete(&delete).await.expect("prepare delete");
    store
        .complete_delete(&delete.context.operation_id)
        .await
        .expect("complete delete");

    let batch = store
        .events(&events_request(Some(target), 0, 16, None))
        .await
        .expect("poll force-delete events");
    assert_eq!(
        batch
            .events
            .iter()
            .map(|event| event.kind)
            .collect::<Vec<_>>(),
        [
            RuntimeEventKind::ContainerCreating,
            RuntimeEventKind::ContainerCreated,
            RuntimeEventKind::ContainerStopped,
            RuntimeEventKind::ContainerDeleted,
        ]
    );
}

#[tokio::test]
async fn event_poll_rejects_an_unclaimed_record() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    let create = create_request(&bundle_directory, "unclaimed-event", "unclaimed-create");
    store
        .prepare_create(&create, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");

    let claim = std::fs::read_dir(root.join("events/keys"))
        .expect("open event claims")
        .next()
        .expect("one event claim")
        .expect("read event claim")
        .path();
    std::fs::remove_file(claim).expect("remove event claim");

    let error = store
        .events(&events_request(None, 0, 16, None))
        .await
        .expect_err("an unclaimed event record must fail closed");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("has no durable identity claim"));
}

#[tokio::test]
async fn event_poll_rejects_duplicate_sequence_claims() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    let create = create_request(&bundle_directory, "duplicate-event", "duplicate-create");
    store
        .prepare_create(&create, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");

    let claims = root.join("events/keys");
    let original = std::fs::read_dir(&claims)
        .expect("open event claims")
        .next()
        .expect("one event claim")
        .expect("read event claim")
        .path();
    let mut claim: serde_json::Value =
        serde_json::from_slice(&std::fs::read(original).expect("read durable event claim"))
            .expect("decode durable event claim");
    let duplicate_identity = "corrupt-duplicate-event-identity";
    claim["identity"] = serde_json::Value::String(duplicate_identity.to_string());
    let duplicate_hash = Sha256::digest(duplicate_identity.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    std::fs::write(
        claims.join(format!("{duplicate_hash}.json")),
        serde_json::to_vec(&claim).expect("encode duplicate event claim"),
    )
    .expect("write duplicate event claim");

    let error = store
        .events(&events_request(None, 0, 16, None))
        .await
        .expect_err("duplicate sequence claims must fail closed");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error
        .message
        .contains("more than one durable identity claim"));
}

#[tokio::test]
async fn event_poll_rejects_a_process_kind_without_process_identity() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    let create = create_request(&bundle_directory, "invalid-kind", "invalid-kind-create");
    store
        .prepare_create(&create, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");

    let claim = std::fs::read_dir(root.join("events/keys"))
        .expect("open event claims")
        .next()
        .expect("one event claim")
        .expect("read event claim")
        .path();
    let mut contents: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&claim).expect("read durable event claim"))
            .expect("decode durable event claim");
    contents["event"]["kind"] = serde_json::Value::String("process-created".to_string());
    std::fs::write(
        claim,
        serde_json::to_vec(&contents).expect("encode invalid event claim"),
    )
    .expect("write invalid event claim");

    let error = store
        .events(&events_request(None, 0, 16, None))
        .await
        .expect_err("a process event without process identity must fail closed");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("has no process identity"));
}

#[tokio::test]
async fn non_operation_event_rejects_an_operation_identity_projection() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    let create = create_request(
        &bundle_directory,
        "non-operation-identity",
        "non-operation-identity-create",
    );
    store
        .prepare_create(&create, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");

    let claim = std::fs::read_dir(root.join("events/keys"))
        .expect("open event claims")
        .next()
        .expect("one event claim")
        .expect("read event claim")
        .path();
    let mut contents: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&claim).expect("read durable event claim"))
            .expect("decode durable event claim");
    contents["event"]["attributes"]["operation-id"] =
        serde_json::json!("forged-operation-identity");
    std::fs::write(
        claim,
        serde_json::to_vec(&contents).expect("encode forged event claim"),
    )
    .expect("write forged event claim");

    let error = store
        .events(&events_request(None, 0, 16, None))
        .await
        .expect_err("a non-operation event must reject operation identity projections");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("identity projection"));
}

#[tokio::test]
async fn operation_event_identity_tampering_fails_closed() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    let create = create_request(
        &bundle_directory,
        "operation-event-tampering",
        "operation-event-tampering-create",
    );
    let prepared = store
        .prepare_create(&create, DriverKind::LibkrunWhpx)
        .await
        .expect("prepare create");
    let RecordOperationPreparation::Prepared(prepared) = prepared else {
        panic!("create must prepare");
    };
    let target = ContainerTarget::exact(create.id.clone(), prepared.generation);
    store
        .complete_create(&create.context.operation_id, 4_242)
        .await
        .expect("complete create");
    let start = StartRequest {
        context: OperationContext::new(operation_id("operation-event-tampering-start")),
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
        context: OperationContext::new(operation_id("operation-event-tampering-pause")),
        target,
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

    let identity = format!("operation:{}:pause", pause.context.operation_id.as_str());
    let identity_hash = Sha256::digest(identity.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let claim_path = root
        .join("events/keys")
        .join(format!("{identity_hash}.json"));
    let original_claim = std::fs::read(&claim_path).expect("read pause event claim");
    let mut claim: serde_json::Value =
        serde_json::from_slice(&original_claim).expect("decode pause event claim");
    let event_sequence = claim["event"]["sequence"]
        .as_u64()
        .expect("pause event sequence");
    let record_path = root
        .join("events/records")
        .join(format!("{event_sequence:020}.json"));
    let original_record = std::fs::read(&record_path).expect("read pause event record");
    let mut legacy_claim = claim.clone();
    legacy_claim["event"]
        .as_object_mut()
        .expect("pause claim event")
        .remove("operation_id");
    let mut legacy_record: serde_json::Value =
        serde_json::from_slice(&original_record).expect("decode pause event record");
    legacy_record["event"]
        .as_object_mut()
        .expect("pause sequence event")
        .remove("operation_id");
    std::fs::write(
        &claim_path,
        serde_json::to_vec(&legacy_claim).expect("encode legacy pause event claim"),
    )
    .expect("write legacy pause event claim");
    std::fs::write(
        &record_path,
        serde_json::to_vec(&legacy_record).expect("encode legacy pause event record"),
    )
    .expect("write legacy pause event record");
    let legacy = store
        .events(&events_request(None, 0, 16, None))
        .await
        .expect("legacy operation attribute remains valid");
    let legacy_pause = legacy
        .events
        .iter()
        .find(|event| event.kind == RuntimeEventKind::ContainerPaused)
        .expect("legacy pause event");
    assert_eq!(legacy_pause.operation_id, None);
    assert_eq!(
        legacy_pause
            .attributes
            .get("operation-id")
            .map(String::as_str),
        Some(pause.context.operation_id.as_str())
    );

    std::fs::write(&claim_path, &original_claim).expect("restore pause event claim");
    std::fs::write(&record_path, &original_record).expect("restore pause event record");
    claim["event"]["operation_id"] = serde_json::json!("another-pause-operation");
    claim["event"]["attributes"]["operation-id"] = serde_json::json!("another-pause-operation");
    std::fs::write(
        &claim_path,
        serde_json::to_vec(&claim).expect("encode tampered pause event claim"),
    )
    .expect("write tampered pause event claim");

    let error = store
        .events(&events_request(None, 0, 16, None))
        .await
        .expect_err("operation event identity drift must fail closed");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("durable identity"));
}

#[tokio::test]
async fn event_long_poll_wakes_for_a_matching_event_and_times_out_cleanly() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let store = DurableStateStore::open(state_root(&temporary))
        .await
        .expect("initialize state root");
    let create = create_request(&bundle_directory, "long-poll", "long-poll-create");

    let waiting_store = store.clone();
    let waiter = tokio::spawn(async move {
        waiting_store
            // The Windows CI runner can spend several seconds scanning the
            // durable journal while the full workspace test suite is under
            // heavy filesystem load. Keep this deadline comfortably above
            // that scheduling variance; a successful wake still returns as
            // soon as the event is committed.
            .events(&events_request(None, 0, 8, Some(30_000)))
            .await
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    store
        .prepare_create(&create, DriverKind::LibkrunWhpx)
        .await
        .expect("create must wake event poll");
    let batch = waiter
        .await
        .expect("event poll task")
        .expect("event long poll");
    assert_eq!(batch.events.len(), 1);
    assert_eq!(batch.events[0].kind, RuntimeEventKind::ContainerCreating);
    assert_eq!(batch.next_sequence, 1);

    let started = tokio::time::Instant::now();
    let timeout = store
        .events(&events_request(None, batch.next_sequence, 8, Some(25)))
        .await
        .expect("event timeout");
    assert!(timeout.events.is_empty());
    assert_eq!(timeout.next_sequence, batch.next_sequence);
    assert!(started.elapsed() >= Duration::from_millis(20));
}
