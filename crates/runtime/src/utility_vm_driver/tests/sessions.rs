use super::*;

const SESSION_ID: &str = "shared-guest";
const TRUST_DOMAIN: &str = "tenant-alpha";

fn shared_request(
    fixture: &Fixture,
    operation: &str,
    target: ContainerTarget,
    capacity: u16,
    reset: GuestSessionReset,
) -> DriverCreateRequest {
    fixture.shared_handoff_request(
        operation,
        target,
        SharedSessionFixture {
            id: SESSION_ID,
            generation: 7,
            trust_domain: TRUST_DOMAIN,
            capacity,
            reset,
        },
    )
}

async fn delete(fixture: &Fixture, operation: &str, target: ContainerTarget) -> Result<()> {
    fixture
        .driver
        .delete(DriverDeleteRequest {
            context: context(operation),
            target,
            mode: DeleteMode::Force,
        })
        .await
}

#[tokio::test]
async fn shared_members_use_one_vm_and_session_scoped_guest_paths() {
    let fixture = Fixture::with_shared_guest_sessions();
    assert!(fixture
        .driver
        .attachment_capabilities()
        .supports_schema(a3s_oci_sdk::ATTACHMENT_SCHEMA_V4));
    let alpha = named_target("shared-alpha", 1);
    let beta = named_target("shared-beta", 3);

    let alpha_request = fixture
        .stage(shared_request(
            &fixture,
            "shared-alpha-create",
            alpha.clone(),
            2,
            GuestSessionReset::DestroyOnEmpty,
        ))
        .await;
    let expected_launch_contract = alpha_request.attachment_contract.clone();
    fixture
        .driver
        .create(alpha_request)
        .await
        .expect("create first shared member");
    let beta_request = fixture
        .stage(shared_request(
            &fixture,
            "shared-beta-create",
            beta.clone(),
            2,
            GuestSessionReset::DestroyOnEmpty,
        ))
        .await;
    fixture
        .driver
        .create(beta_request)
        .await
        .expect("create second shared member");

    let session_root = fixture.shared_session_root(SESSION_ID, 7);
    let marker = std::fs::metadata(session_root.join(".a3s-oci-guest-session.json"))
        .expect("session ownership marker");
    assert_eq!(marker.permissions().mode() & 0o777, 0o600);
    assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
    assert_eq!(
        fixture
            .factory
            .launch_contracts
            .lock()
            .expect("launch contracts lock")
            .as_slice(),
        std::slice::from_ref(&expected_launch_contract)
    );
    assert_eq!(fixture.driver.active_session_count().await, 1);
    assert_eq!(
        fixture
            .factory
            .launch_shares
            .lock()
            .expect("launch shares lock")
            .as_slice(),
        std::slice::from_ref(&session_root)
    );
    assert_eq!(
        fixture
            .guest
            .create_bundle_paths
            .lock()
            .expect("create bundle paths lock")
            .as_slice(),
        [
            format!("{AGENT_RUNTIME_SHARE_GUEST_ROOT}/shared-alpha/1/bundle"),
            format!("{AGENT_RUNTIME_SHARE_GUEST_ROOT}/shared-beta/3/bundle"),
        ]
    );

    delete(&fixture, "delete-alpha", alpha)
        .await
        .expect("delete first member");
    assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 0);
    assert_eq!(fixture.driver.active_session_count().await, 1);
    assert!(session_root.is_dir());

    delete(&fixture, "delete-beta", beta)
        .await
        .expect("delete final member");
    assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.driver.active_session_count().await, 0);
    assert!(!session_root.exists());
}

#[tokio::test]
async fn shared_session_capacity_rejects_a_new_member_without_reaping_the_vm() {
    let fixture = Fixture::with_shared_guest_sessions();
    let alpha = named_target("capacity-alpha", 1);
    let beta = named_target("capacity-beta", 1);
    fixture
        .driver
        .create(
            fixture
                .stage(shared_request(
                    &fixture,
                    "capacity-alpha-create",
                    alpha.clone(),
                    1,
                    GuestSessionReset::DestroyOnEmpty,
                ))
                .await,
        )
        .await
        .expect("create capacity owner");

    let beta_request = fixture
        .stage(shared_request(
            &fixture,
            "capacity-beta-create",
            beta.clone(),
            1,
            GuestSessionReset::DestroyOnEmpty,
        ))
        .await;
    let error = fixture
        .driver
        .create(beta_request)
        .await
        .expect_err("capacity must reject a second member");
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert!(!error.retryable);
    assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 0);
    assert!(!fixture
        .shared_session_root(SESSION_ID, 7)
        .join("capacity-beta/1")
        .exists());

    delete(&fixture, "capacity-alpha-delete", alpha)
        .await
        .expect("delete capacity owner");
}

#[tokio::test]
async fn same_session_incarnation_rejects_contract_drift_before_handoff() {
    let fixture = Fixture::with_shared_guest_sessions();
    let alpha = named_target("drift-alpha", 1);
    fixture
        .driver
        .create(
            fixture
                .stage(shared_request(
                    &fixture,
                    "drift-alpha-create",
                    alpha.clone(),
                    2,
                    GuestSessionReset::RetainWithinTrustDomain,
                ))
                .await,
        )
        .await
        .expect("create retained member");

    let drifted = fixture.shared_handoff_request(
        "drift-beta-create",
        named_target("drift-beta", 1),
        SharedSessionFixture {
            id: SESSION_ID,
            generation: 7,
            trust_domain: "tenant-beta",
            capacity: 2,
            reset: GuestSessionReset::RetainWithinTrustDomain,
        },
    );
    let source = drifted.bundle.directory().to_path_buf();
    let error = fixture
        .driver
        .prepare_create_bundle(&drifted)
        .await
        .expect_err("same incarnation must reject trust-domain drift");
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(source.is_dir());
    assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);

    delete(&fixture, "drift-alpha-delete", alpha)
        .await
        .expect("delete retained member");
    fixture
        .driver
        .shutdown()
        .await
        .expect("shutdown retained VM");
}

#[tokio::test]
async fn retained_empty_session_is_reused_then_rotated_by_a_new_generation() {
    let fixture = Fixture::with_shared_guest_sessions();
    let alpha = named_target("retain-alpha", 1);
    fixture
        .driver
        .create(
            fixture
                .stage(shared_request(
                    &fixture,
                    "retain-alpha-create",
                    alpha.clone(),
                    2,
                    GuestSessionReset::RetainWithinTrustDomain,
                ))
                .await,
        )
        .await
        .expect("create retained member");
    delete(&fixture, "retain-alpha-delete", alpha)
        .await
        .expect("empty retained session");
    assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 0);
    assert_eq!(fixture.driver.active_session_count().await, 1);

    let beta = named_target("retain-beta", 1);
    fixture
        .driver
        .create(
            fixture
                .stage(shared_request(
                    &fixture,
                    "retain-beta-create",
                    beta.clone(),
                    2,
                    GuestSessionReset::RetainWithinTrustDomain,
                ))
                .await,
        )
        .await
        .expect("reuse retained session");
    assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
    delete(&fixture, "retain-beta-delete", beta)
        .await
        .expect("retain session again");

    let gamma = named_target("retain-gamma", 1);
    let next_generation = fixture.shared_handoff_request(
        "retain-gamma-create",
        gamma.clone(),
        SharedSessionFixture {
            id: SESSION_ID,
            generation: 8,
            trust_domain: "tenant-beta",
            capacity: 2,
            reset: GuestSessionReset::RetainWithinTrustDomain,
        },
    );
    fixture
        .driver
        .create(fixture.stage(next_generation).await)
        .await
        .expect("rotate an empty retained session");
    assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 2);
    assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
    assert!(!fixture.shared_session_root(SESSION_ID, 7).exists());
    assert!(fixture.shared_session_root(SESSION_ID, 8).is_dir());

    delete(&fixture, "retain-gamma-delete", gamma)
        .await
        .expect("retain replacement session");
    fixture
        .driver
        .shutdown()
        .await
        .expect("shutdown replacement session");
    assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 2);
    assert!(!fixture.shared_session_root(SESSION_ID, 8).exists());
}

#[tokio::test]
async fn terminal_member_failure_does_not_reap_an_occupied_shared_vm() {
    let fixture = Fixture::with_shared_guest_sessions();
    let alpha = named_target("failure-alpha", 1);
    fixture
        .driver
        .create(
            fixture
                .stage(shared_request(
                    &fixture,
                    "failure-alpha-create",
                    alpha.clone(),
                    2,
                    GuestSessionReset::DestroyOnEmpty,
                ))
                .await,
        )
        .await
        .expect("create healthy member");
    fixture.guest.fail_next_create(
        Error::new(ErrorCode::InvalidArgument, "terminal member failure")
            .for_operation("fake-create"),
    );
    let beta = named_target("failure-beta", 1);
    let error = fixture
        .driver
        .create(
            fixture
                .stage(shared_request(
                    &fixture,
                    "failure-beta-create",
                    beta.clone(),
                    2,
                    GuestSessionReset::DestroyOnEmpty,
                ))
                .await,
        )
        .await
        .expect_err("terminal member create must fail");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 0);
    assert_eq!(fixture.driver.active_session_count().await, 1);
    assert!(!fixture
        .shared_session_root(SESSION_ID, 7)
        .join("failure-beta/1")
        .exists());

    delete(&fixture, "failure-alpha-delete", alpha)
        .await
        .expect("delete surviving member");
}

#[tokio::test]
async fn driver_shutdown_reaps_one_shared_owner_and_leaves_exact_tombstones() {
    let fixture = Fixture::with_shared_guest_sessions();
    let alpha = named_target("shutdown-alpha", 1);
    let beta = named_target("shutdown-beta", 1);
    for (operation, target) in [
        ("shutdown-alpha-create", alpha.clone()),
        ("shutdown-beta-create", beta.clone()),
    ] {
        fixture
            .driver
            .create(
                fixture
                    .stage(shared_request(
                        &fixture,
                        operation,
                        target,
                        2,
                        GuestSessionReset::DestroyOnEmpty,
                    ))
                    .await,
            )
            .await
            .expect("create shutdown member");
    }

    fixture.driver.shutdown().await.expect("shutdown shared VM");
    assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.driver.active_session_count().await, 0);
    for target in [&alpha, &beta] {
        assert_eq!(
            fixture
                .driver
                .state(target.clone())
                .await
                .expect("stopped tombstone")
                .status(),
            ContainerState::Stopped
        );
    }

    delete(&fixture, "shutdown-alpha-delete", alpha)
        .await
        .expect("clean first tombstone");
    delete(&fixture, "shutdown-beta-delete", beta)
        .await
        .expect("clean final tombstone");
    assert!(!fixture.shared_session_root(SESSION_ID, 7).exists());
}

#[tokio::test]
async fn replacement_owner_rejects_an_orphaned_session_root_before_handoff() {
    let fixture = Fixture::with_shared_guest_sessions();
    let alpha = named_target("orphan-alpha", 1);
    fixture
        .driver
        .create(
            fixture
                .stage(shared_request(
                    &fixture,
                    "orphan-alpha-create",
                    alpha,
                    2,
                    GuestSessionReset::DestroyOnEmpty,
                ))
                .await,
        )
        .await
        .expect("create the original session member");

    // Model an owner-process replacement: the persisted marker and exact
    // share remain, but the replacement has no process-local guest registry.
    {
        let mut sessions = fixture.driver.sessions.lock().await;
        sessions.attachments.clear();
        sessions.reusable.clear();
        assert!(sessions.pending.is_empty());
    }

    let beta = named_target("orphan-beta", 1);
    let request = fixture.shared_handoff_request(
        "orphan-beta-create",
        beta,
        SharedSessionFixture {
            id: SESSION_ID,
            generation: 8,
            trust_domain: TRUST_DOMAIN,
            capacity: 2,
            reset: GuestSessionReset::DestroyOnEmpty,
        },
    );
    let source = request.bundle.directory().to_path_buf();
    let error = fixture
        .driver
        .prepare_create_bundle(&request)
        .await
        .expect_err("an unowned persisted session must fail closed");
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(error.message.contains("unowned persisted root"));
    assert!(source.is_dir(), "the caller handoff must not be consumed");
    assert!(fixture.shared_session_root(SESSION_ID, 7).is_dir());
    assert!(!fixture.shared_session_root(SESSION_ID, 8).exists());
    assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn pending_session_admission_rejects_contract_drift_before_bundle_move() {
    let fixture = Fixture::with_shared_guest_sessions();
    let alpha = named_target("pending-alpha", 1);
    let alpha_request = shared_request(
        &fixture,
        "pending-alpha-create",
        alpha,
        2,
        GuestSessionReset::DestroyOnEmpty,
    );
    fixture
        .driver
        .prepare_create_bundle(&alpha_request)
        .await
        .expect("record the first pending admission");

    let beta = named_target("pending-beta", 1);
    let drifted = fixture.shared_handoff_request(
        "pending-beta-create",
        beta,
        SharedSessionFixture {
            id: SESSION_ID,
            generation: 7,
            trust_domain: "different-domain",
            capacity: 2,
            reset: GuestSessionReset::DestroyOnEmpty,
        },
    );
    let source = drifted.bundle.directory().to_path_buf();
    let error = fixture
        .driver
        .prepare_create_bundle(&drifted)
        .await
        .expect_err("a pending session must not change its ownership contract");
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(
        source.is_dir(),
        "the drifted handoff must remain caller-owned"
    );
    assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 0);
}
