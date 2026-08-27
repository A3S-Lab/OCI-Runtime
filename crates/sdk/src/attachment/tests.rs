use serde_json::json;

use super::{
    AttachmentCapabilities, AttachmentSource, CreateAttachments, GuestSessionOwnership,
    GuestSessionReset, LocalNetworkRedirectAttachment, NetworkAttachmentIdentity, NetworkCleanup,
    NetworkEnforcementAttachment, NetworkEnforcementCleanup, NetworkEnforcementOwnership,
    NetworkMechanismDigest, NetworkMechanismGeneration, NetworkOwnership, StorageAccessMode,
    StorageCleanup, StorageOwnership, ATTACHMENT_SCHEMA_V1, ATTACHMENT_SCHEMA_V2,
    ATTACHMENT_SCHEMA_V3, ATTACHMENT_SCHEMA_V4, NETWORK_ENFORCEMENT_EXTENSION,
    NETWORK_ENFORCEMENT_EXTENSION_VERSION, NETWORK_ENFORCEMENT_SCHEMA_V1,
    RUNTIME_BUNDLE_HANDOFF_EXTENSION, RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION,
    RUNTIME_BUNDLE_HANDOFF_MOVE_V1,
};
use crate::{
    ErrorCode, GuestSessionCapacity, GuestSessionGeneration, GuestSessionId, IoMode,
    IsolationClass, IsolationRequest, NetworkCleanupId, NetworkEnforcementId, NetworkInterfaceId,
    NetworkNamespaceId, NetworkRedirectId, OciBundle, ProcessIo, StorageAttachmentId, TerminalSize,
    TrustDomainId, MAX_GUEST_SESSION_CAPACITY,
};

fn bundle() -> OciBundle {
    OciBundle::from_json(
        std::env::temp_dir().join("a3s-attachment-bundle"),
        serde_json::to_string(&json!({
            "ociVersion": "1.3.0",
            "root": {"path": "rootfs", "readonly": true},
            "process": {
                "cwd": "/",
                "args": ["/bin/true"],
                "user": {"uid": 0, "gid": 0}
            },
            "mounts": [
                {"destination": "/data", "type": "bind", "source": "data", "options": ["ro"]},
                {"destination": "/run/secret", "type": "bind", "source": "secret", "options": ["ro"]}
            ],
            "linux": {
                "namespaces": [{"type": "mount"}, {"type": "network"}],
                "netDevices": {"tap0": {"name": "eth0"}}
            },
            "annotations": {
                "dev.a3s.network.tsi": "{\"mode\":\"proxy\"}",
                "dev.a3s.secret.channel": "fd-broker"
            }
        }))
        .expect("encode configuration"),
    )
    .expect("attachment fixture bundle")
}

fn handoff_bundle() -> OciBundle {
    let mut configuration: serde_json::Value =
        serde_json::from_str(bundle().config_json()).expect("fixture configuration");
    configuration["annotations"][RUNTIME_BUNDLE_HANDOFF_EXTENSION] =
        json!(RUNTIME_BUNDLE_HANDOFF_MOVE_V1);
    OciBundle::from_json(
        std::env::temp_dir().join("a3s-bundle-handoff"),
        serde_json::to_string(&configuration).expect("handoff configuration"),
    )
    .expect("handoff bundle")
}

fn terminal_bundle() -> OciBundle {
    let mut configuration: serde_json::Value =
        serde_json::from_str(bundle().config_json()).expect("fixture configuration");
    configuration["process"]["terminal"] = json!(true);
    configuration["process"]["consoleSize"] = json!({"width": 120, "height": 40});
    OciBundle::from_json(
        std::env::temp_dir().join("a3s-terminal-attachment-bundle"),
        serde_json::to_string(&configuration).expect("terminal configuration"),
    )
    .expect("terminal attachment fixture bundle")
}

fn storage_bundle() -> OciBundle {
    let mut configuration: serde_json::Value =
        serde_json::from_str(bundle().config_json()).expect("fixture configuration");
    configuration["mounts"][1]["destination"] = json!("/cache");
    configuration["mounts"][1]["source"] = json!("cache");
    configuration["mounts"][1]["options"] = json!(["rbind", "rw"]);
    OciBundle::from_json(
        std::env::temp_dir().join("a3s-storage-attachment-bundle"),
        serde_json::to_string(&configuration).expect("storage configuration"),
    )
    .expect("storage attachment fixture bundle")
}

fn multi_interface_network_bundle() -> OciBundle {
    let mut configuration: serde_json::Value =
        serde_json::from_str(storage_bundle().config_json()).expect("storage configuration");
    configuration["linux"]["netDevices"] = json!({
        "veth-z": {"name": "eth1"},
        "veth-a": {"name": "eth0"}
    });
    OciBundle::from_json(
        std::env::temp_dir().join("a3s-network-attachment-bundle"),
        serde_json::to_string(&configuration).expect("network configuration"),
    )
    .expect("network attachment fixture bundle")
}

fn network_enforcement_attachment(namespace: &str) -> NetworkEnforcementAttachment {
    NetworkEnforcementAttachment::new(
        NetworkEnforcementId::new("compiled-egress-7").expect("enforcement identity"),
        NetworkMechanismGeneration::new(7).expect("enforcement generation"),
        NetworkMechanismDigest::new(format!("sha256:{}", "a".repeat(64))).expect("policy digest"),
        NetworkNamespaceId::new(namespace).expect("namespace identity"),
        Some(LocalNetworkRedirectAttachment::new(
            NetworkRedirectId::new("local-redirect-11").expect("redirect identity"),
            NetworkMechanismGeneration::new(11).expect("redirect generation"),
            NetworkMechanismDigest::new(format!("sha256:{}", "b".repeat(64)))
                .expect("redirect digest"),
        )),
    )
}

fn network_enforcement_bundle() -> OciBundle {
    let mut configuration: serde_json::Value =
        serde_json::from_str(bundle().config_json()).expect("base configuration");
    configuration["linux"]["namespaces"][1]["path"] =
        json!("/run/a3s/network/authorized-namespace-7");
    configuration["annotations"][NETWORK_ENFORCEMENT_EXTENSION] = json!(
        network_enforcement_attachment("authorized-network-namespace-7")
            .to_annotation_value()
            .expect("network enforcement annotation")
    );
    OciBundle::from_json(
        std::env::temp_dir().join("a3s-network-enforcement-bundle"),
        serde_json::to_string(&configuration).expect("network enforcement configuration"),
    )
    .expect("network enforcement bundle")
}

fn network_enforcement_attachments(bundle: &OciBundle) -> CreateAttachments {
    CreateAttachments::from_bundle(bundle, ProcessIo::default())
        .expect("base attachments")
        .attach_linux_network_interface(
            bundle,
            1,
            "tap0",
            network_identity("authorized-network-interface-7"),
            NetworkCleanup::PreserveCallerNamespace,
        )
        .expect("authorized joined network")
        .attach_network_enforcement(bundle)
        .expect("network enforcement")
}

fn network_identity(interface: &str) -> NetworkAttachmentIdentity {
    NetworkAttachmentIdentity::new(
        NetworkNamespaceId::new("authorized-network-namespace-7").expect("namespace identity"),
        NetworkInterfaceId::new(interface).expect("interface identity"),
        NetworkCleanupId::new("authorized-network-cleanup-7").expect("cleanup identity"),
    )
}

#[test]
fn network_enforcement_is_opaque_digest_bound_and_independently_negotiated() {
    let bundle = network_enforcement_bundle();
    let attachments = network_enforcement_attachments(&bundle);
    attachments
        .validate(&bundle)
        .expect("valid network enforcement attachments");

    assert_eq!(attachments.schema_version(), ATTACHMENT_SCHEMA_V3);
    let enforcement = attachments
        .network_enforcement(&bundle)
        .expect("decode network enforcement")
        .expect("network enforcement attachment");
    assert_eq!(enforcement.schema_version(), NETWORK_ENFORCEMENT_SCHEMA_V1);
    assert_eq!(enforcement.identity().as_str(), "compiled-egress-7");
    assert_eq!(enforcement.generation().get(), 7);
    assert_eq!(
        enforcement.namespace().as_str(),
        "authorized-network-namespace-7"
    );
    assert_eq!(enforcement.ownership(), NetworkEnforcementOwnership::Caller);
    assert_eq!(
        enforcement.cleanup(),
        NetworkEnforcementCleanup::PreserveCallerMechanism
    );
    let redirect = enforcement.local_redirect().expect("local redirect");
    assert_eq!(redirect.identity().as_str(), "local-redirect-11");
    assert_eq!(redirect.generation().get(), 11);

    let encoded = enforcement
        .to_annotation_value()
        .expect("encode network enforcement");
    for forbidden in ["hostname", "address", "credential", "allow", "deny", "rule"] {
        assert!(!encoded.contains(forbidden), "{forbidden}");
    }

    let unsupported = AttachmentCapabilities::base_v3()
        .require(&attachments)
        .expect_err("extension must be independently capability gated");
    assert_eq!(unsupported.code, ErrorCode::Unsupported);
    AttachmentCapabilities::base_v3()
        .with_extension(
            NETWORK_ENFORCEMENT_EXTENSION,
            vec![NETWORK_ENFORCEMENT_EXTENSION_VERSION],
        )
        .expect("network enforcement capability")
        .require(&attachments)
        .expect("independently supported network enforcement");
}

#[test]
fn network_enforcement_rejects_unbound_or_mutable_namespace_mechanisms() {
    let bundle = network_enforcement_bundle();
    let base = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("base attachments")
        .attach_linux_network_interface(
            &bundle,
            1,
            "tap0",
            network_identity("authorized-network-interface-7"),
            NetworkCleanup::PreserveCallerNamespace,
        )
        .expect("authorized joined network");

    let advisory = base
        .clone()
        .add_extension_from_annotation(
            &bundle,
            NETWORK_ENFORCEMENT_EXTENSION,
            NETWORK_ENFORCEMENT_EXTENSION_VERSION,
            false,
        )
        .expect_err("known network enforcement cannot be advisory");
    assert_eq!(advisory.code, ErrorCode::InvalidArgument);

    let mut configuration: serde_json::Value =
        serde_json::from_str(bundle.config_json()).expect("network enforcement configuration");
    configuration["annotations"][NETWORK_ENFORCEMENT_EXTENSION] =
        json!(network_enforcement_attachment("another-network-namespace")
            .to_annotation_value()
            .expect("mismatched annotation"));
    let mismatched = OciBundle::from_json(
        std::env::temp_dir().join("a3s-network-enforcement-mismatch"),
        configuration.to_string(),
    )
    .expect("mismatched network enforcement bundle");
    let error = CreateAttachments::from_bundle(&mismatched, ProcessIo::default())
        .expect("mismatched base attachments")
        .attach_linux_network_interface(
            &mismatched,
            1,
            "tap0",
            network_identity("authorized-network-interface-7"),
            NetworkCleanup::PreserveCallerNamespace,
        )
        .expect("authorized joined network")
        .attach_network_enforcement(&mismatched)
        .expect_err("namespace identity drift must fail closed");
    assert_eq!(error.code, ErrorCode::InvalidArgument);

    let mut configuration: serde_json::Value =
        serde_json::from_str(bundle.config_json()).expect("network enforcement configuration");
    configuration["linux"]["namespaces"][1]
        .as_object_mut()
        .expect("network namespace")
        .remove("path");
    let runtime_owned = OciBundle::from_json(
        std::env::temp_dir().join("a3s-network-enforcement-runtime-namespace"),
        configuration.to_string(),
    )
    .expect("runtime namespace bundle");
    let error = CreateAttachments::from_bundle(&runtime_owned, ProcessIo::default())
        .expect("runtime namespace attachments")
        .attach_linux_network_interface(
            &runtime_owned,
            1,
            "tap0",
            network_identity("authorized-network-interface-7"),
            NetworkCleanup::ReleaseRuntimeNamespace,
        )
        .expect("runtime-owned namespace attachment")
        .attach_network_enforcement(&runtime_owned)
        .expect_err("runtime-owned namespace cannot stand in for caller enforcement");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
}

#[test]
fn network_enforcement_wire_values_reject_tampering_and_policy_content() {
    let attachment = network_enforcement_attachment("authorized-network-namespace-7");
    let encoded = attachment
        .to_annotation_value()
        .expect("network enforcement annotation");

    for (pointer, replacement) in [
        ("/generation", json!(0)),
        (
            "/compiledPolicyDigest",
            json!(format!("sha256:{}", "A".repeat(64))),
        ),
        ("/localRedirect/generation", json!(0)),
    ] {
        let mut value: serde_json::Value =
            serde_json::from_str(&encoded).expect("network enforcement JSON");
        *value.pointer_mut(pointer).expect("mutated field") = replacement;
        assert!(NetworkEnforcementAttachment::from_annotation_value(&value.to_string()).is_err());
    }

    let mut value: serde_json::Value =
        serde_json::from_str(&encoded).expect("network enforcement JSON");
    value["hostnameRules"] = json!(["example.com"]);
    let error = NetworkEnforcementAttachment::from_annotation_value(&value.to_string())
        .expect_err("policy content must not enter the attachment contract");
    assert_eq!(error.code, ErrorCode::InvalidArgument);

    let non_canonical = format!(" {encoded}");
    let error = NetworkEnforcementAttachment::from_annotation_value(&non_canonical)
        .expect_err("wire evidence must use one canonical representation");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("canonical"));
}

fn shared_guest_isolation(domain: &str) -> IsolationRequest {
    IsolationRequest::SharedGuestKernel {
        trust_domain: TrustDomainId::new(domain).expect("trust-domain identity"),
    }
}

#[test]
fn derives_and_digest_binds_every_standard_attachment_category() {
    let bundle = bundle();
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("derive attachments")
        .mark_secret_mount(1)
        .expect("classify secret mount")
        .add_extension_from_annotation(&bundle, "dev.a3s.network.tsi", 1, true)
        .expect("declare network extension")
        .attach_network_extension("dev.a3s.network.tsi")
        .expect("classify network extension")
        .add_extension_from_annotation(&bundle, "dev.a3s.secret.channel", 1, false)
        .expect("declare secret extension")
        .attach_secret_extension("dev.a3s.secret.channel")
        .expect("classify secret extension");

    attachments.validate(&bundle).expect("valid attachments");
    assert_eq!(attachments.schema_version(), ATTACHMENT_SCHEMA_V1);
    assert!(attachments
        .digest()
        .expect("attachment digest")
        .starts_with("sha256:"));
    assert_eq!(attachments.mounts.len(), 2);
    assert_eq!(attachments.network.len(), 3);
    assert_eq!(attachments.secrets.len(), 2);
    assert_eq!(attachments.extensions.len(), 2);
}

#[test]
fn storage_attachments_are_v2_digest_bound_and_explicitly_caller_owned() {
    let bundle = storage_bundle();
    let v1 = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("derive v1 attachments");
    let v1_json = serde_json::to_string(&v1).expect("encode v1 attachments");
    assert_eq!(v1.schema_version(), ATTACHMENT_SCHEMA_V1);
    assert!(!v1_json.contains("storage"));
    assert!(!v1_json.contains("networkAttachments"));
    assert!(!v1_json.contains("guestSession"));

    let attachments = v1
        .attach_storage_mount(
            &bundle,
            0,
            StorageAttachmentId::new("authorized-dataset-7").expect("storage identity"),
            StorageAccessMode::ReadOnly,
            StorageOwnership::Caller,
            StorageCleanup::DetachOnly,
        )
        .expect("attach read-only storage")
        .attach_storage_mount(
            &bundle,
            1,
            StorageAttachmentId::new("authorized-cache-3").expect("storage identity"),
            StorageAccessMode::ReadWrite,
            StorageOwnership::Caller,
            StorageCleanup::DetachOnly,
        )
        .expect("attach read-write storage");

    attachments.validate(&bundle).expect("validate storage");
    assert_eq!(attachments.schema_version(), ATTACHMENT_SCHEMA_V2);
    assert_eq!(attachments.storage().len(), 2);
    assert_eq!(
        attachments.storage()[0].identity().as_str(),
        "authorized-cache-3"
    );
    assert_eq!(attachments.storage()[0].mount().json_pointer(), "/mounts/1");
    assert_eq!(
        attachments.storage()[0].access_mode(),
        StorageAccessMode::ReadWrite
    );
    assert_eq!(
        attachments.storage()[0].ownership(),
        StorageOwnership::Caller
    );
    assert_eq!(
        attachments.storage()[0].cleanup(),
        StorageCleanup::DetachOnly
    );
    assert!(attachments
        .digest()
        .expect("storage digest")
        .starts_with("sha256:"));

    let unsupported = AttachmentCapabilities::base_v1()
        .require(&attachments)
        .expect_err("v1-only runtime must reject storage schema");
    assert_eq!(unsupported.code, ErrorCode::Unsupported);
    AttachmentCapabilities::base_v2()
        .require(&attachments)
        .expect("v2 runtime accepts storage schema");
}

#[test]
fn storage_attachment_validation_rejects_identity_mount_and_access_drift() {
    let bundle = storage_bundle();
    let base =
        CreateAttachments::from_bundle(&bundle, ProcessIo::default()).expect("derive attachments");
    let identity =
        StorageAttachmentId::new("authorized-storage-1").expect("storage attachment identity");

    let error = base
        .clone()
        .attach_storage_mount(
            &bundle,
            0,
            identity.clone(),
            StorageAccessMode::ReadWrite,
            StorageOwnership::Caller,
            StorageCleanup::DetachOnly,
        )
        .expect_err("declared access must match the OCI mount");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("access mode"));

    let attached = base
        .attach_storage_mount(
            &bundle,
            0,
            identity.clone(),
            StorageAccessMode::ReadOnly,
            StorageOwnership::Caller,
            StorageCleanup::DetachOnly,
        )
        .expect("attach storage");
    assert!(attached
        .clone()
        .attach_storage_mount(
            &bundle,
            1,
            identity,
            StorageAccessMode::ReadWrite,
            StorageOwnership::Caller,
            StorageCleanup::DetachOnly,
        )
        .expect_err("immutable identity cannot select two mounts")
        .message
        .contains("identity"));
    assert!(attached
        .clone()
        .attach_storage_mount(
            &bundle,
            0,
            StorageAttachmentId::new("authorized-storage-2").expect("second identity"),
            StorageAccessMode::ReadOnly,
            StorageOwnership::Caller,
            StorageCleanup::DetachOnly,
        )
        .expect_err("one OCI mount cannot have two storage owners")
        .message
        .contains("mount"));

    let mut encoded = serde_json::to_value(&attached).expect("encode storage attachments");
    encoded["schemaVersion"] = json!(ATTACHMENT_SCHEMA_V1);
    let downgraded: CreateAttachments =
        serde_json::from_value(encoded).expect("decode downgraded manifest");
    let error = downgraded
        .validate(&bundle)
        .expect_err("v1 cannot silently carry v2 storage");
    assert!(error.message.contains("schema"));

    assert!(StorageAttachmentId::new("../mutable-volume").is_err());
}

#[test]
fn caller_owned_storage_cannot_be_transferred_with_a_runtime_owned_bundle() {
    let mut configuration: serde_json::Value =
        serde_json::from_str(storage_bundle().config_json()).expect("storage configuration");
    configuration["annotations"][RUNTIME_BUNDLE_HANDOFF_EXTENSION] =
        json!(RUNTIME_BUNDLE_HANDOFF_MOVE_V1);
    let bundle = OciBundle::from_json(
        std::env::temp_dir().join("a3s-storage-handoff-bundle"),
        serde_json::to_string(&configuration).expect("storage handoff configuration"),
    )
    .expect("storage handoff bundle");
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("base attachments")
        .attach_storage_mount(
            &bundle,
            0,
            StorageAttachmentId::new("caller-owned-dataset").expect("storage identity"),
            StorageAccessMode::ReadOnly,
            StorageOwnership::Caller,
            StorageCleanup::DetachOnly,
        )
        .expect("storage attachment");

    let error = attachments
        .with_runtime_bundle_handoff(&bundle)
        .expect_err("runtime ownership transfer must not absorb caller-owned storage");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("caller-owned storage"));
}

#[test]
fn network_attachments_are_v3_digest_bound_and_canonical() {
    let bundle = multi_interface_network_bundle();
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("base attachments")
        .attach_linux_network_interface(
            &bundle,
            1,
            "veth-z",
            network_identity("authorized-interface-z"),
            NetworkCleanup::ReleaseRuntimeNamespace,
        )
        .expect("attach second interface")
        .attach_linux_network_interface(
            &bundle,
            1,
            "veth-a",
            network_identity("authorized-interface-a"),
            NetworkCleanup::ReleaseRuntimeNamespace,
        )
        .expect("attach first interface");

    attachments.validate(&bundle).expect("validate network");
    assert_eq!(attachments.schema_version(), ATTACHMENT_SCHEMA_V3);
    assert_eq!(attachments.network_attachments().len(), 2);
    let first = &attachments.network_attachments()[0];
    assert_eq!(
        first.identity().namespace().as_str(),
        "authorized-network-namespace-7"
    );
    assert_eq!(
        first.identity().interface().as_str(),
        "authorized-interface-a"
    );
    assert_eq!(
        first.identity().cleanup().as_str(),
        "authorized-network-cleanup-7"
    );
    assert_eq!(first.namespace().json_pointer(), "/linux/namespaces/1");
    assert_eq!(first.interface().json_pointer(), "/linux/netDevices/veth-a");
    assert_eq!(first.ownership(), NetworkOwnership::Caller);
    assert_eq!(first.cleanup(), NetworkCleanup::ReleaseRuntimeNamespace);
    assert!(attachments
        .digest()
        .expect("network attachment digest")
        .starts_with("sha256:"));

    let unsupported = AttachmentCapabilities::base_v2()
        .require(&attachments)
        .expect_err("v2-only runtime must reject network schema");
    assert_eq!(unsupported.code, ErrorCode::Unsupported);
    AttachmentCapabilities::base_v3()
        .require(&attachments)
        .expect("v3 runtime accepts network schema");
}

#[test]
fn network_and_storage_attachment_order_is_canonical_and_cumulative() {
    let bundle = storage_bundle();
    let base =
        CreateAttachments::from_bundle(&bundle, ProcessIo::default()).expect("base attachments");
    let storage_id = StorageAttachmentId::new("authorized-storage-21").expect("storage identity");
    let network_id = network_identity("authorized-interface-21");

    let storage_first = base
        .clone()
        .attach_storage_mount(
            &bundle,
            0,
            storage_id.clone(),
            StorageAccessMode::ReadOnly,
            StorageOwnership::Caller,
            StorageCleanup::DetachOnly,
        )
        .expect("attach storage")
        .attach_linux_network_interface(
            &bundle,
            1,
            "tap0",
            network_id.clone(),
            NetworkCleanup::ReleaseRuntimeNamespace,
        )
        .expect("attach network after storage");
    let network_first = base
        .attach_linux_network_interface(
            &bundle,
            1,
            "tap0",
            network_id,
            NetworkCleanup::ReleaseRuntimeNamespace,
        )
        .expect("attach network")
        .attach_storage_mount(
            &bundle,
            0,
            storage_id,
            StorageAccessMode::ReadOnly,
            StorageOwnership::Caller,
            StorageCleanup::DetachOnly,
        )
        .expect("attach storage after network");

    assert_eq!(storage_first, network_first);
    assert_eq!(storage_first.schema_version(), ATTACHMENT_SCHEMA_V3);
    assert_eq!(
        storage_first.digest().expect("storage-first digest"),
        network_first.digest().expect("network-first digest")
    );
}

#[test]
fn reusable_guest_session_is_v4_digest_bound_and_cumulative() {
    let bundle = storage_bundle();
    let isolation = shared_guest_isolation("authorized-trust-domain-41");
    let session_id = GuestSessionId::new("authorized-guest-session-41").expect("session ID");
    let session_generation = GuestSessionGeneration::new(7).expect("session generation");
    let capacity = GuestSessionCapacity::new(8).expect("session capacity");
    let storage_id = StorageAttachmentId::new("authorized-storage-41").expect("storage identity");
    let network_id = network_identity("authorized-interface-41");
    let base =
        CreateAttachments::from_bundle(&bundle, ProcessIo::default()).expect("base attachments");

    let session_last = base
        .clone()
        .attach_storage_mount(
            &bundle,
            0,
            storage_id.clone(),
            StorageAccessMode::ReadOnly,
            StorageOwnership::Caller,
            StorageCleanup::DetachOnly,
        )
        .expect("attach storage")
        .attach_linux_network_interface(
            &bundle,
            1,
            "tap0",
            network_id.clone(),
            NetworkCleanup::ReleaseRuntimeNamespace,
        )
        .expect("attach network")
        .attach_reusable_guest_session(
            &bundle,
            &isolation,
            session_id.clone(),
            session_generation,
            capacity,
            GuestSessionReset::RetainWithinTrustDomain,
        )
        .expect("attach guest session");
    let session_first = base
        .attach_reusable_guest_session(
            &bundle,
            &isolation,
            session_id,
            session_generation,
            capacity,
            GuestSessionReset::RetainWithinTrustDomain,
        )
        .expect("attach guest session first")
        .attach_linux_network_interface(
            &bundle,
            1,
            "tap0",
            network_id,
            NetworkCleanup::ReleaseRuntimeNamespace,
        )
        .expect("attach network after session")
        .attach_storage_mount(
            &bundle,
            0,
            storage_id,
            StorageAccessMode::ReadOnly,
            StorageOwnership::Caller,
            StorageCleanup::DetachOnly,
        )
        .expect("attach storage after session");

    assert_eq!(session_last, session_first);
    assert_eq!(session_last.schema_version(), ATTACHMENT_SCHEMA_V4);
    assert_eq!(
        session_last.digest().expect("session-last digest"),
        session_first.digest().expect("session-first digest")
    );
    let session = session_last.guest_session().expect("guest session binding");
    assert_eq!(session.id().as_str(), "authorized-guest-session-41");
    assert_eq!(session.generation(), session_generation);
    assert_eq!(
        session.trust_domain().as_str(),
        "authorized-trust-domain-41"
    );
    assert_eq!(session.isolation(), IsolationClass::SharedGuestKernel);
    assert_eq!(session.capacity(), capacity);
    assert_eq!(session.reset(), GuestSessionReset::RetainWithinTrustDomain);
    assert_eq!(session.ownership(), GuestSessionOwnership::Runtime);
    session_last
        .validate_isolation(&isolation)
        .expect("matching shared-guest isolation");
    AttachmentCapabilities::base_v4()
        .require(&session_last)
        .expect("v4 runtime accepts guest session schema");
    assert_eq!(
        AttachmentCapabilities::base_v3()
            .require(&session_last)
            .expect_err("v3 runtime must reject guest sessions")
            .code,
        ErrorCode::Unsupported
    );
}

#[test]
fn reusable_guest_session_fails_closed_on_boundary_drift() {
    assert!(GuestSessionGeneration::new(0).is_err());
    assert!(GuestSessionCapacity::new(0).is_err());
    assert!(GuestSessionCapacity::new(MAX_GUEST_SESSION_CAPACITY + 1).is_err());

    let bundle = storage_bundle();
    let isolation = shared_guest_isolation("authorized-trust-domain-51");
    let base =
        CreateAttachments::from_bundle(&bundle, ProcessIo::default()).expect("base attachments");
    let error = base
        .clone()
        .attach_reusable_guest_session(
            &bundle,
            &IsolationRequest::DedicatedVm,
            GuestSessionId::new("must-not-bind-dedicated").expect("session ID"),
            GuestSessionGeneration::new(1).expect("session generation"),
            GuestSessionCapacity::new(2).expect("session capacity"),
            GuestSessionReset::DestroyOnEmpty,
        )
        .expect_err("dedicated isolation cannot bind a reusable session");
    assert!(error.message.contains("shared-guest-kernel"));

    let attached = base
        .attach_reusable_guest_session(
            &bundle,
            &isolation,
            GuestSessionId::new("authorized-guest-session-51").expect("session ID"),
            GuestSessionGeneration::new(3).expect("session generation"),
            GuestSessionCapacity::new(4).expect("session capacity"),
            GuestSessionReset::DestroyOnEmpty,
        )
        .expect("guest session attachment");
    let mismatch = attached
        .validate_isolation(&shared_guest_isolation("different-trust-domain"))
        .expect_err("trust-domain drift must fail");
    assert!(mismatch.message.contains("trust domain"));
    let duplicate = attached
        .clone()
        .attach_reusable_guest_session(
            &bundle,
            &isolation,
            GuestSessionId::new("another-session").expect("session ID"),
            GuestSessionGeneration::new(4).expect("session generation"),
            GuestSessionCapacity::new(4).expect("session capacity"),
            GuestSessionReset::DestroyOnEmpty,
        )
        .expect_err("one create cannot bind two guest sessions");
    assert!(duplicate.message.contains("one reusable guest session"));

    let mut encoded = serde_json::to_value(&attached).expect("encode guest session attachments");
    encoded["schemaVersion"] = json!(ATTACHMENT_SCHEMA_V3);
    let downgraded: CreateAttachments =
        serde_json::from_value(encoded).expect("decode downgraded manifest");
    assert!(downgraded.validate(&bundle).is_err());

    let mut encoded = serde_json::to_value(&attached).expect("encode guest session attachments");
    encoded["guestSession"]["isolation"] = json!("dedicated-vm");
    let drifted: CreateAttachments =
        serde_json::from_value(encoded).expect("decode isolation drift");
    assert!(drifted.validate(&bundle).is_err());

    for (field, invalid) in [
        ("generation", json!(0)),
        ("capacity", json!(MAX_GUEST_SESSION_CAPACITY + 1)),
    ] {
        let mut encoded =
            serde_json::to_value(&attached).expect("encode guest session attachments");
        encoded["guestSession"][field] = invalid;
        serde_json::from_value::<CreateAttachments>(encoded)
            .expect_err("numeric guest-session boundary drift must fail during decoding");
    }

    let missing = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("base attachments")
        .validate_isolation(&isolation)
        .expect_err("shared guest isolation requires an explicit session");
    assert!(missing.message.contains("reusable guest session"));
}

#[test]
fn network_attachment_validation_rejects_identity_cleanup_and_target_drift() {
    let bundle = multi_interface_network_bundle();
    let base =
        CreateAttachments::from_bundle(&bundle, ProcessIo::default()).expect("base attachments");
    let attached = base
        .attach_linux_network_interface(
            &bundle,
            1,
            "veth-a",
            network_identity("authorized-interface-a"),
            NetworkCleanup::ReleaseRuntimeNamespace,
        )
        .expect("first interface");

    let error = attached
        .clone()
        .attach_linux_network_interface(
            &bundle,
            1,
            "veth-z",
            network_identity("authorized-interface-a"),
            NetworkCleanup::ReleaseRuntimeNamespace,
        )
        .expect_err("one interface identity cannot bind two OCI devices");
    assert!(error.message.contains("interface identity"));

    let drifted_cleanup = NetworkAttachmentIdentity::new(
        NetworkNamespaceId::new("authorized-network-namespace-7").expect("namespace identity"),
        NetworkInterfaceId::new("authorized-interface-z").expect("interface identity"),
        NetworkCleanupId::new("different-cleanup").expect("cleanup identity"),
    );
    let error = attached
        .attach_linux_network_interface(
            &bundle,
            1,
            "veth-z",
            drifted_cleanup,
            NetworkCleanup::ReleaseRuntimeNamespace,
        )
        .expect_err("one namespace cannot drift cleanup identity");
    assert!(error.message.contains("cleanup identity"));

    let valid = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("base attachments")
        .attach_linux_network_interface(
            &bundle,
            1,
            "veth-a",
            network_identity("authorized-wire-interface"),
            NetworkCleanup::ReleaseRuntimeNamespace,
        )
        .expect("wire network attachment");
    let mut encoded = serde_json::to_value(&valid).expect("encode network attachments");
    encoded["schemaVersion"] = json!(ATTACHMENT_SCHEMA_V2);
    let downgraded: CreateAttachments =
        serde_json::from_value(encoded.clone()).expect("decode downgraded manifest");
    let error = downgraded
        .validate(&bundle)
        .expect_err("v2 cannot silently carry v3 network identities");
    assert!(error.message.contains("schema"));
    encoded["networkAttachments"][0]["identity"]["interface"] = json!("../interface");
    assert!(serde_json::from_value::<CreateAttachments>(encoded).is_err());

    let mut invalid_schema = serde_json::to_value(
        CreateAttachments::from_bundle(&bundle, ProcessIo::default()).expect("base attachments"),
    )
    .expect("encode base attachments");
    invalid_schema["schemaVersion"] = json!("a3s.oci.attachments.unknown");
    let invalid: CreateAttachments =
        serde_json::from_value(invalid_schema).expect("decode unknown schema");
    let error = invalid
        .attach_storage_mount(
            &bundle,
            0,
            StorageAttachmentId::new("must-not-launder-schema").expect("storage identity"),
            StorageAccessMode::ReadOnly,
            StorageOwnership::Caller,
            StorageCleanup::DetachOnly,
        )
        .expect_err("builder must not sanitize an unsupported schema");
    assert!(error.message.contains("unsupported attachment schema"));

    let error = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .expect("base attachments")
        .attach_linux_network_interface(
            &bundle,
            1,
            "veth-a",
            network_identity("authorized-interface-a"),
            NetworkCleanup::PreserveCallerNamespace,
        )
        .expect_err("a new namespace must use runtime namespace cleanup");
    assert!(error.message.contains("new OCI network namespace"));

    let mut template_configuration: serde_json::Value =
        serde_json::from_str(bundle.config_json()).expect("network configuration");
    template_configuration["linux"]["netDevices"]["veth-a"]["name"] = json!("eth%d");
    let template_bundle = OciBundle::from_json(
        std::env::temp_dir().join("a3s-network-template-bundle"),
        serde_json::to_string(&template_configuration).expect("template configuration"),
    )
    .expect("template bundle");
    let error = CreateAttachments::from_bundle(&template_bundle, ProcessIo::default())
        .expect("template base attachments")
        .attach_linux_network_interface(
            &template_bundle,
            1,
            "veth-a",
            network_identity("authorized-template-interface"),
            NetworkCleanup::ReleaseRuntimeNamespace,
        )
        .expect_err("authorized attachments require an exact target name");
    assert!(error.message.contains("exact target"));
}

#[test]
fn joined_network_namespace_requires_caller_preservation_cleanup() {
    let mut configuration: serde_json::Value =
        serde_json::from_str(storage_bundle().config_json()).expect("network configuration");
    configuration["linux"]["namespaces"][1]["path"] = json!("/run/netns/authorized-7");
    let bundle = OciBundle::from_json(
        std::env::temp_dir().join("a3s-joined-network-attachment-bundle"),
        serde_json::to_string(&configuration).expect("joined network configuration"),
    )
    .expect("joined network attachment bundle");
    let base =
        CreateAttachments::from_bundle(&bundle, ProcessIo::default()).expect("base attachments");

    let error = base
        .clone()
        .attach_linux_network_interface(
            &bundle,
            1,
            "tap0",
            network_identity("authorized-joined-interface"),
            NetworkCleanup::ReleaseRuntimeNamespace,
        )
        .expect_err("runtime cannot release a caller-owned joined namespace");
    assert!(error.message.contains("joined OCI network namespace"));

    base.attach_linux_network_interface(
        &bundle,
        1,
        "tap0",
        network_identity("authorized-joined-interface"),
        NetworkCleanup::PreserveCallerNamespace,
    )
    .expect("caller-owned joined namespace remains explicit")
    .validate(&bundle)
    .expect("validate joined network attachment");
}

#[test]
fn terminal_attachment_binds_the_oci_console_size() {
    let bundle = terminal_bundle();
    let io = ProcessIo {
        stdin: IoMode::Terminal,
        stdout: IoMode::Terminal,
        stderr: IoMode::Terminal,
        terminal_size: None,
    };
    let attachments = CreateAttachments::from_bundle(&bundle, io)
        .expect("derive console-sized terminal attachments");
    assert_eq!(
        attachments.process_io().terminal_size,
        Some(TerminalSize {
            width: 120,
            height: 40,
        })
    );

    let mut encoded = serde_json::to_value(&attachments).expect("encode attachments");
    encoded["processIo"]
        .as_object_mut()
        .expect("process I/O object")
        .remove("terminal_size");
    let unbound: CreateAttachments =
        serde_json::from_value(encoded).expect("decode unbound attachment");
    let error = unbound
        .validate(&bundle)
        .expect_err("wire input must retain the derived OCI console size");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("process I/O"));
}

#[test]
fn rejects_drift_unknown_references_and_unversioned_extensions() {
    let bundle = bundle();
    let attachments =
        CreateAttachments::from_bundle(&bundle, ProcessIo::default()).expect("derive attachments");
    assert!(attachments.clone().mark_secret_mount(9).is_err());
    assert!(attachments
        .clone()
        .attach_network_extension("dev.a3s.missing")
        .is_err());
    assert!(attachments
        .clone()
        .add_extension_from_annotation(&bundle, "dev.a3s.network.tsi", 0, true)
        .is_err());

    let mut encoded = serde_json::to_value(&attachments).expect("encode attachments");
    encoded["rootfs"]["valueDigest"] = json!("sha256:deadbeef");
    let corrupt: CreateAttachments =
        serde_json::from_value(encoded).expect("decode structurally valid corruption");
    let error = corrupt
        .validate(&bundle)
        .expect_err("configuration evidence drift must fail");
    assert_eq!(error.code, ErrorCode::InvalidArgument);

    let mut encoded = serde_json::to_value(&attachments).expect("encode attachments");
    encoded["network"]
        .as_array_mut()
        .expect("network array")
        .push(json!({
            "kind": "runtime-extension",
            "name": "dev.a3s.missing"
        }));
    let corrupt: CreateAttachments =
        serde_json::from_value(encoded).expect("decode missing extension reference");
    assert!(corrupt.validate(&bundle).is_err());
}

#[test]
fn required_extensions_are_fail_closed_but_advisory_extensions_are_explicit() {
    let bundle = bundle();
    let base =
        CreateAttachments::from_bundle(&bundle, ProcessIo::default()).expect("derive attachments");
    let required = base
        .clone()
        .add_extension_from_annotation(&bundle, "dev.a3s.network.tsi", 1, true)
        .expect("required extension");
    let unsupported = AttachmentCapabilities::base_v1()
        .require(&required)
        .expect_err("required unsupported extension must fail");
    assert_eq!(unsupported.code, ErrorCode::Unsupported);

    let supported = AttachmentCapabilities::base_v1()
        .with_extension("dev.a3s.network.tsi", vec![2, 1, 2])
        .expect("extension capability");
    supported.require(&required).expect("supported extension");

    let advisory = base
        .add_extension_from_annotation(&bundle, "dev.a3s.secret.channel", 1, false)
        .expect("advisory extension");
    AttachmentCapabilities::base_v1()
        .require(&advisory)
        .expect("unsupported advisory extension remains explicit and non-enforcing");
}

#[test]
fn extension_names_follow_the_canonical_capability_order() {
    let capabilities = AttachmentCapabilities::base_v1()
        .with_extension("dev.a3s.network.zeta", vec![1])
        .expect("zeta extension capability")
        .with_extension("dev.a3s.network.alpha", vec![2, 1])
        .expect("alpha extension capability");

    assert_eq!(
        capabilities.extension_names().collect::<Vec<_>>(),
        vec!["dev.a3s.network.alpha", "dev.a3s.network.zeta"]
    );
}

#[test]
fn capability_intersection_is_exact_and_wire_inventories_must_be_canonical() {
    let common = AttachmentCapabilities::base_v1()
        .with_extension("dev.a3s.network.tsi", vec![1, 2])
        .expect("left capabilities")
        .common_with(
            &AttachmentCapabilities::base_v1()
                .with_extension("dev.a3s.network.tsi", vec![2, 3])
                .expect("right capabilities")
                .with_extension("dev.a3s.storage.volume", vec![1])
                .expect("right-only capabilities"),
        );
    common.validate().expect("canonical intersection");
    assert!(common.supports_schema(ATTACHMENT_SCHEMA_V1));
    assert!(common.supports_extension("dev.a3s.network.tsi", 2));
    assert!(!common.supports_extension("dev.a3s.network.tsi", 1));
    assert!(!common.supports_extension("dev.a3s.storage.volume", 1));

    let invalid: AttachmentCapabilities = serde_json::from_value(json!({
        "schemas": [ATTACHMENT_SCHEMA_V1],
        "extensions": {"dev.a3s.network.tsi": [2, 1]}
    }))
    .expect("decode structurally valid non-canonical inventory");
    let error = invalid
        .validate()
        .expect_err("wire version order must fail closed");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
}

#[test]
fn runtime_bundle_handoff_is_explicit_digest_bound_and_capability_checked() {
    let handoff = handoff_bundle();
    let attachments = CreateAttachments::from_bundle(&handoff, ProcessIo::default())
        .expect("base attachments")
        .with_runtime_bundle_handoff(&handoff)
        .expect("bundle handoff extension");
    assert!(attachments.uses_runtime_bundle_handoff());

    let unsupported = AttachmentCapabilities::base_v1()
        .require(&attachments)
        .expect_err("base runtime must reject required handoff");
    assert_eq!(unsupported.code, ErrorCode::Unsupported);
    AttachmentCapabilities::base_v1()
        .with_extension(
            RUNTIME_BUNDLE_HANDOFF_EXTENSION,
            vec![RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION],
        )
        .expect("handoff capability")
        .require(&attachments)
        .expect("handoff-capable runtime");

    let ordinary = bundle();
    let error = CreateAttachments::from_bundle(&ordinary, ProcessIo::default())
        .expect("ordinary attachments")
        .with_runtime_bundle_handoff(&ordinary)
        .expect_err("missing exact annotation must fail");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
}

#[test]
fn serialized_manifest_contains_no_secret_value_or_runtime_identity() {
    let bundle = bundle();
    let encoded = serde_json::to_string(
        &CreateAttachments::from_bundle(&bundle, ProcessIo::default())
            .expect("derive attachments")
            .mark_secret_mount(1)
            .expect("classify secret mount"),
    )
    .expect("encode attachments");
    assert!(!encoded.contains("fd-broker"));
    assert!(!encoded.contains("secret.channel"));
    assert!(!encoded.contains("pid"));
    assert!(encoded.contains("/mounts/1"));
    assert!(encoded.contains("valueDigest"));
    assert!(matches!(
        serde_json::from_str::<CreateAttachments>(&encoded)
            .expect("round trip")
            .secrets[0],
        AttachmentSource::OciConfiguration { .. }
    ));
}
