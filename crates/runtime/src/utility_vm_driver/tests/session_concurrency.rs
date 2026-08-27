use super::*;

const SESSION_ID: &str = "concurrent-guest";
const TRUST_DOMAIN: &str = "concurrent-domain";

fn request(
    fixture: &Fixture,
    operation: &str,
    target: ContainerTarget,
    generation: u64,
) -> DriverCreateRequest {
    fixture.shared_handoff_request(
        operation,
        target,
        SharedSessionFixture {
            id: SESSION_ID,
            generation,
            trust_domain: TRUST_DOMAIN,
            capacity: 2,
            reset: GuestSessionReset::DestroyOnEmpty,
        },
    )
}

async fn delete(fixture: &Fixture, operation: &str, target: ContainerTarget) {
    fixture
        .driver
        .delete(DriverDeleteRequest {
            context: context(operation),
            target,
            mode: DeleteMode::Force,
        })
        .await
        .expect("delete shared member");
}

#[tokio::test]
async fn concurrent_members_serialize_one_session_launch() {
    let fixture = Fixture::with_shared_guest_sessions();
    let alpha = named_target("concurrent-alpha", 1);
    let beta = named_target("concurrent-beta", 1);
    let alpha_request = fixture
        .stage(request(
            &fixture,
            "concurrent-alpha-create",
            alpha.clone(),
            11,
        ))
        .await;
    let beta_request = fixture
        .stage(request(
            &fixture,
            "concurrent-beta-create",
            beta.clone(),
            11,
        ))
        .await;

    let (alpha_result, beta_result) = tokio::join!(
        fixture.driver.create(alpha_request),
        fixture.driver.create(beta_request)
    );
    alpha_result.expect("create concurrent alpha");
    beta_result.expect("create concurrent beta");
    assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.driver.active_session_count().await, 1);

    delete(&fixture, "concurrent-alpha-delete", alpha).await;
    delete(&fixture, "concurrent-beta-delete", beta).await;
    assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn occupied_incarnation_fences_a_new_session_generation() {
    let fixture = Fixture::with_shared_guest_sessions();
    let alpha = named_target("occupied-alpha", 1);
    fixture
        .driver
        .create(
            fixture
                .stage(request(
                    &fixture,
                    "occupied-alpha-create",
                    alpha.clone(),
                    11,
                ))
                .await,
        )
        .await
        .expect("create occupied session member");

    let beta = named_target("occupied-beta", 1);
    let beta_request = fixture
        .stage(request(&fixture, "occupied-beta-create", beta, 12))
        .await;
    let error = fixture
        .driver
        .create(beta_request)
        .await
        .expect_err("occupied session cannot rotate");
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(!error.retryable);
    assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 0);
    assert!(fixture.shared_session_root(SESSION_ID, 11).is_dir());
    assert!(!fixture.shared_session_root(SESSION_ID, 12).exists());

    delete(&fixture, "occupied-alpha-delete", alpha).await;
}

#[tokio::test]
async fn distinct_sessions_prepare_and_launch_without_a_global_gate() {
    let fixture = Fixture::with_shared_guest_sessions();
    let alpha = named_target("distinct-alpha", 1);
    let beta = named_target("distinct-beta", 1);
    let alpha_request = fixture.shared_handoff_request(
        "distinct-alpha-create",
        alpha.clone(),
        SharedSessionFixture {
            id: "distinct-session-alpha",
            generation: 1,
            trust_domain: "distinct-domain-alpha",
            capacity: 1,
            reset: GuestSessionReset::DestroyOnEmpty,
        },
    );
    let beta_request = fixture.shared_handoff_request(
        "distinct-beta-create",
        beta.clone(),
        SharedSessionFixture {
            id: "distinct-session-beta",
            generation: 1,
            trust_domain: "distinct-domain-beta",
            capacity: 1,
            reset: GuestSessionReset::DestroyOnEmpty,
        },
    );

    let (alpha_request, beta_request) =
        tokio::join!(fixture.stage(alpha_request), fixture.stage(beta_request));
    let (alpha_result, beta_result) = tokio::join!(
        fixture.driver.create(alpha_request),
        fixture.driver.create(beta_request)
    );
    alpha_result.expect("create distinct alpha session");
    beta_result.expect("create distinct beta session");
    assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 2);
    assert_eq!(fixture.driver.active_session_count().await, 2);

    let (alpha_delete, beta_delete) = tokio::join!(
        fixture.driver.delete(DriverDeleteRequest {
            context: context("distinct-alpha-delete"),
            target: alpha,
            mode: DeleteMode::Force,
        }),
        fixture.driver.delete(DriverDeleteRequest {
            context: context("distinct-beta-delete"),
            target: beta,
            mode: DeleteMode::Force,
        })
    );
    alpha_delete.expect("delete distinct alpha session");
    beta_delete.expect("delete distinct beta session");
    assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 2);
    assert!(!fixture.runtime_share_root.join(".guest-sessions").exists());
}
