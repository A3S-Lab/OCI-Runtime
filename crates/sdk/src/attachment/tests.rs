use serde_json::json;

use super::{
    AttachmentCapabilities, AttachmentSource, CreateAttachments, NetworkAttachmentIdentity,
    NetworkCleanup, NetworkOwnership, StorageAccessMode, StorageCleanup, StorageOwnership,
    ATTACHMENT_SCHEMA_V1, ATTACHMENT_SCHEMA_V2, ATTACHMENT_SCHEMA_V3,
    RUNTIME_BUNDLE_HANDOFF_EXTENSION, RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION,
    RUNTIME_BUNDLE_HANDOFF_MOVE_V1,
};
use crate::{
    ErrorCode, IoMode, NetworkCleanupId, NetworkInterfaceId, NetworkNamespaceId, OciBundle,
    ProcessIo, StorageAttachmentId, TerminalSize,
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

fn network_identity(interface: &str) -> NetworkAttachmentIdentity {
    NetworkAttachmentIdentity::new(
        NetworkNamespaceId::new("authorized-network-namespace-7").expect("namespace identity"),
        NetworkInterfaceId::new(interface).expect("interface identity"),
        NetworkCleanupId::new("authorized-network-cleanup-7").expect("cleanup identity"),
    )
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
