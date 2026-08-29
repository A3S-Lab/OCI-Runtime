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
            "archive_size": 8967364,
            "archive_sha256": "5650721e43c2a1825314367d60bc2bdace2a88be4a424ba42711f9580c4b69af",
            "krun_dll": {
                "name": "krun.dll",
                "size": 7579648,
                "sha256": "cc18d354fec2c235fdce53b723b96dccb2ef3994a7dda141c923a0efa0bba7db"
            },
            "import_library": {
                "name": "krun.lib",
                "size": 11870,
                "sha256": "3ac760758158bd4d2d6570db58037d47cd370a8e6ea04ccf54a8b24fd1fdec3d"
            },
            "firmware": {
                "name": "libkrunfw.dll",
                "size": 29413376,
                "sha256": "295e8a8e660f396fd0007d48c43175d9ed5b19243570640ad65fc47b41e7596a"
            },
            "sources": {
                "box_revision": "93fc281a798cdfd8ee463f69add3f6989d561ee3",
                "libkrun_revision": "de07dd8a4f94b1e5f70ce2d8e3f99359b3a02eb9",
                "firmware_wrapper_revision": "10dca312c63080916dbb456c3a019dba3e8b4da0",
                "libkrunfw_revision": "ec4b297964877d83432f9ccda6dad8ff6e9de3e4",
                "kernel_version": "6.12.91",
                "kernel_source_sha256": "0ff2ab9e169f9f1948557471fbb450d3018f8c5b77caf288e1a3982582597969"
            },
            "kernel": {
                "bundle_size": 23158784,
                "bundle_sha256": "1c211df81b481a906409cb32f25f392577389a2f5ccf48bc2dd913bb64a1f6b4",
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
