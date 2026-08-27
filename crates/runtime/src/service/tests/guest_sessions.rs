use std::sync::Arc;

use a3s_oci_core::IsolationClass;
use a3s_oci_sdk::{
    AttachmentCapabilities, CreateAttachments, CreateRequest, ErrorCode, GuestSessionCapacity,
    GuestSessionGeneration, GuestSessionId, GuestSessionReset, IsolationRequest, OciBundle,
    OciRuntimeService, OperationContext, ProcessIo, TrustDomainId, ATTACHMENT_SCHEMA_V4,
};

use super::{container_id, open_service, operation_id, DriverCall, RecordingDriver, TEST_CONFIG};

fn guest_session_request(bundle_directory: std::path::PathBuf, generation: u64) -> CreateRequest {
    let bundle = OciBundle::from_json(bundle_directory, TEST_CONFIG).expect("guest-session bundle");
    let trust_domain =
        TrustDomainId::new("service-guest-trust-domain").expect("guest-session trust domain");
    let isolation = IsolationRequest::SharedGuestKernel {
        trust_domain: trust_domain.clone(),
    };
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("base attachments")
        .attach_reusable_guest_session(
            &bundle,
            &isolation,
            GuestSessionId::new("service-guest-session").expect("guest-session ID"),
            GuestSessionGeneration::new(generation).expect("guest-session generation"),
            GuestSessionCapacity::new(4).expect("guest-session capacity"),
            GuestSessionReset::RetainWithinTrustDomain,
        )
        .expect("guest-session attachments");
    CreateRequest {
        context: OperationContext::new(operation_id("guest-session-v4-create")),
        id: container_id("guest-session-v4-container"),
        bundle,
        isolation,
        attachments,
    }
}

#[tokio::test]
async fn guest_session_v4_is_capability_gated_durable_and_passed_exactly() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let create = guest_session_request(temporary.path().join("guest-session-bundle"), 7);

    let mut v3_recording = RecordingDriver::shared_guest_supported();
    v3_recording.attachments = AttachmentCapabilities::base_v3();
    let v3_driver = Arc::new(v3_recording);
    let v3_service = open_service(&temporary, Arc::clone(&v3_driver)).await;
    let error = v3_service
        .create(create.clone())
        .await
        .expect_err("v3-only driver must reject guest sessions before dispatch");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(v3_driver.calls().is_empty());
    drop(v3_service);

    let mut v4_recording = RecordingDriver::shared_guest_supported();
    v4_recording.attachments = AttachmentCapabilities::base_v4();
    let v4_driver = Arc::new(v4_recording);
    let v4_service = open_service(&temporary, Arc::clone(&v4_driver)).await;
    let info = v4_service.features().await.expect("runtime features");
    assert!(info.attachments.supports_schema(ATTACHMENT_SCHEMA_V4));
    let created = v4_service
        .create(create.clone())
        .await
        .expect("v4 guest-session create");
    let expected_session = create
        .attachments
        .guest_session()
        .expect("guest-session attachment");
    assert_eq!(created.isolation, IsolationClass::SharedGuestKernel);
    assert_eq!(created.guest_session.as_ref(), Some(expected_session));
    assert_eq!(
        created.attachments_digest.as_deref(),
        Some(
            create
                .attachments
                .digest()
                .expect("attachment digest")
                .as_str()
        )
    );
    let calls = v4_driver.calls();
    let DriverCall::Create(driver_create) = calls.first().expect("driver create call") else {
        panic!("first driver call must be create");
    };
    assert_eq!(driver_create.attachment_contract, create.attachments);
    assert_eq!(
        driver_create.attachment_contract.guest_session(),
        Some(expected_session)
    );

    drop(v4_service);
    let reopened = open_service(&temporary, Arc::clone(&v4_driver)).await;
    assert_eq!(
        reopened
            .create(create.clone())
            .await
            .expect("replay guest-session create after reopen"),
        created
    );
    assert_eq!(
        v4_driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Create(_)))
            .count(),
        1
    );

    let mut changed = create;
    changed.attachments = CreateAttachments::from_bundle(&changed.bundle, ProcessIo::default())
        .expect("changed base attachments")
        .attach_reusable_guest_session(
            &changed.bundle,
            &changed.isolation,
            GuestSessionId::new("service-guest-session").expect("guest-session ID"),
            GuestSessionGeneration::new(8).expect("changed guest-session generation"),
            GuestSessionCapacity::new(4).expect("guest-session capacity"),
            GuestSessionReset::RetainWithinTrustDomain,
        )
        .expect("changed guest-session attachments");
    let error = reopened
        .create(changed)
        .await
        .expect_err("one operation ID cannot change guest-session generation");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("different request"));
}
