use std::fs;

use serde_json::json;

use super::{open_read_pinned, strict_json, ALPINE_ARCHIVE_SHA256, IMAGE_NAME, SCHEMA_VERSION};

fn valid_manifest() -> serde_json::Value {
    json!({
        "schema_version": "a3s.oci.windows-system-image.v1",
        "compatibility_level": "a3s-oci-runtime-0.2.0-agent-protocol-v10",
        "architecture": "x86_64",
        "image": {
            "name": "a3s-oci-system.ext4",
            "size": 67108864,
            "sha256": "1".repeat(64),
            "archive_name": "a3s-oci-system.ext4.xz",
            "archive_size": 1,
            "archive_sha256": "2".repeat(64),
            "filesystem": "ext4",
            "filesystem_uuid": "a3a30c1a-2026-4000-8000-000000000011",
            "filesystem_label": "a3s-oci-system",
            "directory_hash_seed": "a3a30c1a-2026-4000-8000-000000000012"
        },
        "sources": {
            "alpine": {
                "version": "3.22.5",
                "url": "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-minirootfs-3.22.5-x86_64.tar.gz",
                "archive_size": 3638276,
                "archive_sha256": "4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282"
            },
            "agent": {
                "version": "0.2.0",
                "size": 1,
                "sha256": "3".repeat(64)
            },
            "builder": {
                "source_date_epoch": 1735689600,
                "e2fsprogs_version": "1.47.0"
            }
        },
        "runtime": {
            "archive_size": 8108976,
            "archive_sha256": "734f69936e5c6caee5f67ff5daf68a52d90d7f6f0be3dae41907f009db39c847",
            "krun_dll": {
                "name": "krun.dll",
                "size": 7433728,
                "sha256": "ac7724209635505c4ae7b3ba36edeb7fc5597353e6ffcc7351fbf97af1e0d5e5"
            },
            "import_library": {
                "name": "krun.lib",
                "size": 11870,
                "sha256": "3ac760758158bd4d2d6570db58037d47cd370a8e6ea04ccf54a8b24fd1fdec3d"
            },
            "firmware": {
                "name": "libkrunfw.dll",
                "size": 21473280,
                "sha256": "44f25540f58155c01258fe123617636fdc6cff27873e38e71dbc75f139602077"
            },
            "sources": {
                "box_revision": "93fc281a798cdfd8ee463f69add3f6989d561ee3",
                "libkrun_revision": "75ec19097a337a60076a2ebff7cdad6acf8ca69c",
                "firmware_wrapper_revision": "2692169b7567363244fdd21cb83de3220ebf3021",
                "libkrunfw_revision": "ec4b297964877d83432f9ccda6dad8ff6e9de3e4",
                "kernel_version": "6.12.91",
                "kernel_source_sha256": "0ff2ab9e169f9f1948557471fbb450d3018f8c5b77caf288e1a3982582597969"
            },
            "kernel": {
                "bundle_size": 21364736,
                "bundle_sha256": "781375ea09f4279ec5bfeab26ecc7067358a3fc98190467e2ab01cc6e98936dd",
                "guest_load_address": "0x0000000001000000",
                "entry_address": "0x0000000001000123"
            }
        }
    })
}

#[test]
fn rejects_unknown_manifest_fields() {
    let error = strict_json(br#"{"schema_version":"x","unexpected":true}"#)
        .expect_err("unknown Windows manifest fields must fail closed");
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn rejects_trailing_manifest_data() {
    let error =
        strict_json(br#"{} {}"#).expect_err("trailing Windows manifest data must fail closed");
    assert!(error.to_string().contains("invalid"));
}

#[test]
fn manifest_constants_are_canonical() {
    assert_eq!(SCHEMA_VERSION, "a3s.oci.windows-system-image.v1");
    assert_eq!(IMAGE_NAME, "a3s-oci-system.ext4");
    assert_eq!(ALPINE_ARCHIVE_SHA256.len(), 64);
    assert!(json!({ "digest": ALPINE_ARCHIVE_SHA256 }).is_object());
}

#[test]
fn accepts_the_exact_windows_boot_asset_manifest() {
    let bytes = serde_json::to_vec(&valid_manifest()).expect("serialize manifest fixture");
    strict_json(&bytes)
        .and_then(|manifest| manifest.validate())
        .expect("the exact Windows manifest contract must remain valid");
}

#[test]
fn rejects_runtime_provenance_or_compatibility_drift() {
    let mut manifest = valid_manifest();
    manifest["runtime"]["sources"]["box_revision"] = json!("0".repeat(40));
    let bytes = serde_json::to_vec(&manifest).expect("serialize drifted manifest");
    let error = strict_json(&bytes)
        .and_then(|manifest| manifest.validate())
        .expect_err("runtime provenance drift must fail closed");
    assert!(error.to_string().contains("box_revision"));

    let mut manifest = valid_manifest();
    manifest["compatibility_level"] = json!("future-incompatible-level");
    let bytes = serde_json::to_vec(&manifest).expect("serialize drifted manifest");
    let error = strict_json(&bytes)
        .and_then(|manifest| manifest.validate())
        .expect_err("compatibility drift must fail closed");
    assert!(error.to_string().contains("compatibility_level"));
}

#[test]
fn pinned_read_handle_denies_mutation_and_delete() {
    let directory = tempfile::tempdir().expect("create pinned-file fixture");
    let path = directory.path().join("system-image.ext4");
    fs::write(&path, b"immutable").expect("write pinned-file fixture");

    let pinned = open_read_pinned(&path, "test system image").expect("pin fixture");
    fs::File::open(&path).expect("read sharing must remain available");
    assert!(fs::write(&path, b"mutated").is_err());
    assert!(fs::remove_file(&path).is_err());

    drop(pinned);
    fs::remove_file(&path).expect("file must be removable after the pin is released");
}
