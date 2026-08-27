use std::sync::Arc;

use a3s_oci_sdk::{
    AttachmentCapabilities, CreateAttachments, CreateRequest, ErrorCode, IsolationRequest,
    LocalNetworkRedirectAttachment, NetworkAttachmentIdentity, NetworkCleanup, NetworkCleanupId,
    NetworkEnforcementAttachment, NetworkEnforcementId, NetworkInterfaceId, NetworkMechanismDigest,
    NetworkMechanismGeneration, NetworkNamespaceId, NetworkRedirectId, OciBundle,
    OciRuntimeService, OperationContext, ProcessIo, ATTACHMENT_SCHEMA_V3,
    NETWORK_ENFORCEMENT_EXTENSION, NETWORK_ENFORCEMENT_EXTENSION_VERSION,
};

use super::{container_id, open_service, operation_id, DriverCall, RecordingDriver};

fn network_bundle(directory: std::path::PathBuf) -> OciBundle {
    OciBundle::from_json(
        directory,
        serde_json::to_string(&serde_json::json!({
            "ociVersion": "1.3.0",
            "process": {
                "terminal": false,
                "user": {"uid": 0, "gid": 0},
                "args": ["/bin/true"],
                "cwd": "/"
            },
            "root": {"path": "rootfs", "readonly": true},
            "linux": {
                "namespaces": [{"type": "network"}],
                "netDevices": {"tap0": {"name": "eth0"}}
            }
        }))
        .expect("network configuration"),
    )
    .expect("network bundle")
}

fn network_identity(interface: &str) -> NetworkAttachmentIdentity {
    NetworkAttachmentIdentity::new(
        NetworkNamespaceId::new("authorized-network-namespace-31").expect("namespace identity"),
        NetworkInterfaceId::new(interface).expect("interface identity"),
        NetworkCleanupId::new("authorized-network-cleanup-31").expect("cleanup identity"),
    )
}

fn enforcement_attachment(generation: u64, digest_byte: char) -> NetworkEnforcementAttachment {
    NetworkEnforcementAttachment::new(
        NetworkEnforcementId::new("compiled-egress-31").expect("enforcement identity"),
        NetworkMechanismGeneration::new(generation).expect("enforcement generation"),
        NetworkMechanismDigest::new(format!("sha256:{}", digest_byte.to_string().repeat(64)))
            .expect("compiled-policy digest"),
        NetworkNamespaceId::new("authorized-network-namespace-31").expect("namespace identity"),
        Some(LocalNetworkRedirectAttachment::new(
            NetworkRedirectId::new("local-redirect-31").expect("redirect identity"),
            NetworkMechanismGeneration::new(31).expect("redirect generation"),
            NetworkMechanismDigest::new(format!("sha256:{}", "b".repeat(64)))
                .expect("redirect digest"),
        )),
    )
}

fn enforcement_bundle(
    directory: std::path::PathBuf,
    attachment: &NetworkEnforcementAttachment,
) -> OciBundle {
    let mut configuration = serde_json::json!({
        "ociVersion": "1.3.0",
        "process": {
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/true"],
            "cwd": "/"
        },
        "root": {"path": "rootfs", "readonly": true},
        "linux": {
            "namespaces": [{
                "type": "network",
                "path": "/run/a3s/network/authorized-network-namespace-31"
            }],
            "netDevices": {"tap0": {"name": "eth0"}}
        },
        "annotations": {}
    });
    configuration["annotations"][NETWORK_ENFORCEMENT_EXTENSION] = serde_json::json!(attachment
        .to_annotation_value()
        .expect("network-enforcement annotation"));
    OciBundle::from_json(
        directory,
        serde_json::to_string(&configuration).expect("network-enforcement configuration"),
    )
    .expect("network-enforcement bundle")
}

fn enforcement_attachments(bundle: &OciBundle) -> CreateAttachments {
    CreateAttachments::from_bundle(bundle, ProcessIo::default())
        .expect("base attachments")
        .attach_linux_network_interface(
            bundle,
            0,
            "tap0",
            network_identity("authorized-network-interface-31"),
            NetworkCleanup::PreserveCallerNamespace,
        )
        .expect("joined network attachment")
        .attach_network_enforcement(bundle)
        .expect("network-enforcement attachment")
}

#[tokio::test]
async fn network_attachment_v3_is_capability_gated_durable_and_passed_exactly() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle = network_bundle(temporary.path().join("network-bundle"));
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("base attachments")
        .attach_linux_network_interface(
            &bundle,
            0,
            "tap0",
            network_identity("authorized-network-interface-31"),
            NetworkCleanup::ReleaseRuntimeNamespace,
        )
        .expect("network attachments");
    let create = CreateRequest {
        context: OperationContext::new(operation_id("network-v3-create")),
        id: container_id("network-v3-container"),
        bundle,
        isolation: IsolationRequest::DedicatedVm,
        attachments,
    };

    let v2_driver = Arc::new(RecordingDriver::with_storage_attachments());
    let v2_service = open_service(&temporary, Arc::clone(&v2_driver)).await;
    let error = v2_service
        .create(create.clone())
        .await
        .expect_err("v2-only driver must reject network before dispatch");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(v2_driver.calls().is_empty());
    drop(v2_service);

    let mut network_driver = RecordingDriver::supported();
    network_driver.attachments = AttachmentCapabilities::base_v3();
    let v3_driver = Arc::new(network_driver);
    let v3_service = open_service(&temporary, Arc::clone(&v3_driver)).await;
    let info = v3_service.features().await.expect("runtime features");
    assert!(info.attachments.supports_schema(ATTACHMENT_SCHEMA_V3));
    let created = v3_service
        .create(create.clone())
        .await
        .expect("v3 network create");
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
    let calls = v3_driver.calls();
    let DriverCall::Create(driver_create) = calls.first().expect("driver create call") else {
        panic!("first driver call must be create");
    };
    assert_eq!(driver_create.attachment_contract, create.attachments);
    let network = &driver_create.attachment_contract.network_attachments()[0];
    assert_eq!(
        network.identity().namespace().as_str(),
        "authorized-network-namespace-31"
    );
    assert_eq!(
        network.identity().interface().as_str(),
        "authorized-network-interface-31"
    );
    assert_eq!(
        network.identity().cleanup().as_str(),
        "authorized-network-cleanup-31"
    );
    assert_eq!(network.namespace().json_pointer(), "/linux/namespaces/0");
    assert_eq!(network.interface().json_pointer(), "/linux/netDevices/tap0");
    assert_eq!(network.cleanup(), NetworkCleanup::ReleaseRuntimeNamespace);

    drop(v3_service);
    let reopened = open_service(&temporary, Arc::clone(&v3_driver)).await;
    assert_eq!(
        reopened
            .create(create.clone())
            .await
            .expect("replay network create after reopen"),
        created
    );
    assert_eq!(
        v3_driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Create(_)))
            .count(),
        1
    );

    let mut changed = create.clone();
    changed.attachments = CreateAttachments::from_bundle(&changed.bundle, ProcessIo::default())
        .expect("changed base attachments")
        .attach_linux_network_interface(
            &changed.bundle,
            0,
            "tap0",
            network_identity("authorized-network-interface-32"),
            NetworkCleanup::ReleaseRuntimeNamespace,
        )
        .expect("changed network attachments");
    let error = reopened
        .create(changed)
        .await
        .expect_err("one operation ID cannot change immutable network identity");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("different request"));
}

#[tokio::test]
async fn network_enforcement_v1_is_exactly_negotiated_durable_and_drift_safe() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("network-enforcement-bundle");
    let expected = enforcement_attachment(31, 'a');
    let bundle = enforcement_bundle(bundle_directory.clone(), &expected);
    let create = CreateRequest {
        context: OperationContext::new(operation_id("network-enforcement-v1-create")),
        id: container_id("network-enforcement-v1-container"),
        attachments: enforcement_attachments(&bundle),
        bundle,
        isolation: IsolationRequest::DedicatedVm,
    };

    let mut schema_only_driver = RecordingDriver::supported();
    schema_only_driver.attachments = AttachmentCapabilities::base_v3();
    let schema_only_driver = Arc::new(schema_only_driver);
    let schema_only_service = open_service(&temporary, Arc::clone(&schema_only_driver)).await;
    let error = schema_only_service
        .create(create.clone())
        .await
        .expect_err("schema support alone must not authorize enforcement v1");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains(NETWORK_ENFORCEMENT_EXTENSION));
    assert!(schema_only_driver.calls().is_empty());
    drop(schema_only_service);

    let mut enforcement_driver = RecordingDriver::supported();
    enforcement_driver.attachments = AttachmentCapabilities::base_v3()
        .with_extension(
            NETWORK_ENFORCEMENT_EXTENSION,
            vec![NETWORK_ENFORCEMENT_EXTENSION_VERSION],
        )
        .expect("network-enforcement capability");
    let enforcement_driver = Arc::new(enforcement_driver);
    let service = open_service(&temporary, Arc::clone(&enforcement_driver)).await;
    let info = service.features().await.expect("runtime features");
    assert!(info.attachments.supports_extension(
        NETWORK_ENFORCEMENT_EXTENSION,
        NETWORK_ENFORCEMENT_EXTENSION_VERSION
    ));

    let created = service
        .create(create.clone())
        .await
        .expect("network-enforcement create");
    assert_eq!(created.network_enforcement.as_ref(), Some(&expected));
    let calls = enforcement_driver.calls();
    let DriverCall::Create(driver_create) = calls.first().expect("driver create call") else {
        panic!("first driver call must be create");
    };
    assert_eq!(driver_create.attachment_contract, create.attachments);
    assert_eq!(
        driver_create
            .attachment_contract
            .network_enforcement(&create.bundle)
            .expect("decode driver network-enforcement contract")
            .as_ref(),
        Some(&expected)
    );

    drop(service);
    let reopened = open_service(&temporary, Arc::clone(&enforcement_driver)).await;
    assert_eq!(
        reopened
            .create(create.clone())
            .await
            .expect("replay network-enforcement create after reopen"),
        created
    );
    assert_eq!(
        enforcement_driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Create(_)))
            .count(),
        1
    );

    let changed_attachment = enforcement_attachment(32, 'c');
    let changed_bundle = enforcement_bundle(bundle_directory, &changed_attachment);
    let mut changed = create;
    changed.attachments = enforcement_attachments(&changed_bundle);
    changed.bundle = changed_bundle;
    let error = reopened
        .create(changed)
        .await
        .expect_err("one operation ID cannot change enforcement generation or digest");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("different request"));
}
