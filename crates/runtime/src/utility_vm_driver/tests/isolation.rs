use std::os::unix::fs::{symlink, PermissionsExt};

use super::*;

fn assert_preflight_rejection(fixture: &Fixture, error: &Error, code: ErrorCode) {
    assert_eq!(error.code, code);
    assert!(!error.retryable);
    assert!(!fixture.generation_share().exists());
    assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn current_directory_rootfs_is_a_portable_bundle_root() {
    let fixture = Fixture::new();
    let mut request = fixture.handoff_request("dot-rootfs");
    let directory = request.bundle.directory().to_path_buf();
    let config_path = directory.join("config.json");
    let mut config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config_path).expect("read handoff config"))
            .expect("decode handoff config");
    config["root"]["path"] = serde_json::json!(".");
    let encoded = serde_json::to_string_pretty(&config).expect("encode dot-rootfs config");
    std::fs::write(&config_path, encoded.as_bytes()).expect("write dot-rootfs config");
    request.bundle = OciBundle::from_json(directory, encoded).expect("dot-rootfs bundle");
    request.attachment_contract =
        CreateAttachments::from_bundle(&request.bundle, ProcessIo::default())
            .expect("base dot-rootfs attachments")
            .with_runtime_bundle_handoff(&request.bundle)
            .expect("dot-rootfs handoff attachment");

    let staged = fixture
        .driver
        .prepare_create_bundle(&request)
        .await
        .expect("stage current-directory rootfs");

    assert_eq!(
        staged
            .spec()
            .root()
            .as_ref()
            .expect("root configuration")
            .path(),
        Path::new(".")
    );
    assert!(staged.directory().is_dir());
}

#[tokio::test]
async fn create_requires_dedicated_vm_and_an_exact_generation_before_handoff() {
    let fixture = Fixture::new();
    let shared_host = fixture.handoff_request_for(
        "shared-host-kernel",
        target(),
        IsolationRequest::SharedHostKernel,
    );
    let shared_host_source = shared_host.bundle.directory().to_path_buf();
    let error = fixture
        .driver
        .prepare_create_bundle(&shared_host)
        .await
        .expect_err("shared host kernel must fail before handoff");
    assert_preflight_rejection(&fixture, &error, ErrorCode::Unsupported);
    assert!(shared_host_source.is_dir());

    let shared = fixture.handoff_request_for(
        "shared-guest-kernel",
        target(),
        IsolationRequest::SharedGuestKernel {
            trust_domain: a3s_oci_sdk::TrustDomainId::new("test-domain").expect("trust domain"),
        },
    );
    let shared_source = shared.bundle.directory().to_path_buf();
    let error = fixture
        .driver
        .prepare_create_bundle(&shared)
        .await
        .expect_err("shared guest kernel must fail before handoff");
    assert_preflight_rejection(&fixture, &error, ErrorCode::Unsupported);
    assert!(shared_source.is_dir());

    let current = fixture.handoff_request_for(
        "current-generation",
        ContainerTarget::current(target().id),
        IsolationRequest::DedicatedVm,
    );
    let current_source = current.bundle.directory().to_path_buf();
    let error = fixture
        .driver
        .prepare_create_bundle(&current)
        .await
        .expect_err("current generation must fail before handoff");
    assert_preflight_rejection(&fixture, &error, ErrorCode::InvalidArgument);
    assert!(current_source.is_dir());

    let mut fixed_bundle = fixture.handoff_request("fixed-bundle");
    fixed_bundle.attachment_contract =
        CreateAttachments::from_bundle(&fixed_bundle.bundle, ProcessIo::default())
            .expect("fixed-bundle attachment contract");
    let fixed_source = fixed_bundle.bundle.directory().to_path_buf();
    let error = fixture
        .driver
        .prepare_create_bundle(&fixed_bundle)
        .await
        .expect_err("utility VM create must require a bundle handoff");
    assert_preflight_rejection(&fixture, &error, ErrorCode::Unsupported);
    assert!(fixed_source.is_dir());
}

#[tokio::test]
async fn shared_isolation_does_not_implicitly_advertise_attachment_v4() {
    let mut capability = candidate_capability();
    capability
        .isolation_classes
        .push(IsolationClass::SharedGuestKernel);
    let fixture = Fixture::with_profile(capability, a3s_oci_sdk::AttachmentCapabilities::base_v1());
    let request = fixture.shared_handoff_request(
        "unadvertised-v4",
        named_target("unadvertised-v4", 1),
        SharedSessionFixture {
            id: "unadvertised-session",
            generation: 1,
            trust_domain: "unadvertised-domain",
            capacity: 1,
            reset: GuestSessionReset::DestroyOnEmpty,
        },
    );
    let source = request.bundle.directory().to_path_buf();

    let error = fixture
        .driver
        .prepare_create_bundle(&request)
        .await
        .expect_err("v4 must require an explicit attachment capability");

    assert_preflight_rejection(&fixture, &error, ErrorCode::Unsupported);
    assert!(source.is_dir());
}

#[tokio::test]
async fn missing_handoff_source_does_not_create_an_exact_runtime_share() {
    let fixture = Fixture::new();
    let request = fixture.handoff_request("missing-handoff-source");
    std::fs::remove_dir_all(request.bundle.directory()).expect("remove handoff source");

    let error = fixture
        .driver
        .prepare_create_bundle(&request)
        .await
        .expect_err("missing handoff source must fail before share creation");

    assert_preflight_rejection(&fixture, &error, ErrorCode::FailedPrecondition);
}

#[tokio::test]
async fn linked_handoff_source_does_not_create_an_exact_runtime_share() {
    let fixture = Fixture::new();
    let request = fixture.handoff_request("linked-handoff-source");
    let source = request.bundle.directory().to_path_buf();
    let retained = source
        .parent()
        .expect("handoff operation directory")
        .join("retained-bundle");
    std::fs::rename(&source, &retained).expect("retain real handoff source");
    symlink(&retained, &source).expect("link handoff source");

    let error = fixture
        .driver
        .prepare_create_bundle(&request)
        .await
        .expect_err("linked handoff source must fail before share creation");

    assert_preflight_rejection(&fixture, &error, ErrorCode::PermissionDenied);
}

#[tokio::test]
async fn insecure_handoff_source_does_not_create_an_exact_runtime_share() {
    let fixture = Fixture::new();
    let request = fixture.handoff_request("insecure-handoff-source");
    std::fs::set_permissions(
        request.bundle.directory(),
        std::fs::Permissions::from_mode(0o755),
    )
    .expect("make handoff source insecure");

    let error = fixture
        .driver
        .prepare_create_bundle(&request)
        .await
        .expect_err("insecure handoff source must fail before share creation");

    assert_preflight_rejection(&fixture, &error, ErrorCode::PermissionDenied);
}

#[tokio::test]
async fn drifted_handoff_config_does_not_create_an_exact_runtime_share() {
    let fixture = Fixture::new();
    let request = fixture.handoff_request("drifted-handoff-config");
    let config_path = request.bundle.directory().join("config.json");
    let mut config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config_path).expect("read original handoff config"))
            .expect("decode original handoff config");
    config["annotations"]["dev.a3s.qualification-drift"] =
        serde_json::Value::String("changed".to_string());
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).expect("encode drifted handoff config"),
    )
    .expect("write drifted handoff config");

    let error = fixture
        .driver
        .prepare_create_bundle(&request)
        .await
        .expect_err("drifted handoff config must fail before share creation");

    assert_preflight_rejection(&fixture, &error, ErrorCode::Conflict);
}

#[tokio::test]
async fn linked_portable_rootfs_does_not_create_an_exact_runtime_share() {
    let fixture = Fixture::new();
    let request = fixture.handoff_request("linked-portable-rootfs");
    let rootfs = request.bundle.directory().join("rootfs");
    let escaped_rootfs = fixture
        .runtime_root
        .parent()
        .expect("fixture root")
        .join("escaped-rootfs");
    std::fs::rename(&rootfs, &escaped_rootfs).expect("move portable rootfs");
    symlink(&escaped_rootfs, &rootfs).expect("link portable rootfs");

    let error = fixture
        .driver
        .prepare_create_bundle(&request)
        .await
        .expect_err("linked portable rootfs must fail before share creation");

    assert_preflight_rejection(&fixture, &error, ErrorCode::FailedPrecondition);
}

#[tokio::test]
async fn absolute_portable_bind_source_does_not_create_an_exact_runtime_share() {
    let fixture = Fixture::new();
    let request = fixture.handoff_request("absolute-portable-bind");
    let config_path = request.bundle.directory().join("config.json");
    let mut config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config_path).expect("read original handoff config"))
            .expect("decode original handoff config");
    config["mounts"] = serde_json::json!([{
        "destination": "/mnt/host",
        "type": "none",
        "source": "/host",
        "options": ["bind", "ro"]
    }]);
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).expect("encode absolute-bind config"),
    )
    .expect("write absolute-bind config");

    let error = fixture
        .driver
        .prepare_create_bundle(&request)
        .await
        .expect_err("absolute bind source must fail before share creation");

    assert_preflight_rejection(&fixture, &error, ErrorCode::InvalidArgument);
}
