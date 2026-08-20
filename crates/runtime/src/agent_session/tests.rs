use a3s_oci_core::HostPlatform;
use serde_json::{json, Value};

#[cfg(unix)]
use super::canonical_file;
use super::{
    bounded_unverified_shim_report, parse_shim_report, paths_overlap,
    require_expected_manifest_digest, BoundedOutput,
};

fn valid_output(platform: &str) -> BoundedOutput {
    BoundedOutput {
        bytes: serde_json::to_vec(&json!({
            "schema_version": "a3s.oci.krun-agent-vm-smoke.v5",
            "platform": platform,
            "status": "available",
            "runtime_bundle_loaded": true,
            "context_created": true,
            "vm_configured": true,
            "rootfs_configured": true,
            "runtime_share_configured": true,
            "kvm_device_opened": true,
            "kvm_api_verified": true,
            "linux_boot_assets": {
                "target_arch": std::env::consts::ARCH,
                "manifest_sha256": "0".repeat(64),
                "system_image_sha256": "1".repeat(64),
                "system_image_size": 67108864,
                "guest_agent_sha256": "2".repeat(64),
                "guest_agent_size": 1024,
                "runtime_archive_sha256": "3".repeat(64),
                "libkrun_sha256": "4".repeat(64),
                "firmware_sha256": "5".repeat(64),
                "kernel_bundle_sha256": "6".repeat(64),
                "kernel_bundle_size": 1024,
                "kernel_guest_load_address": "0x0000000080000000",
                "kernel_entry_address": "0x0000000080000000",
                "root_disk_read_only": true
            },
            "macos_boot_assets": {
                "manifest_sha256": "1".repeat(64),
                "system_image_sha256": "2".repeat(64),
                "system_image_size": 67108864,
                "runtime_archive_sha256": "3".repeat(64),
                "libkrun_sha256": "4".repeat(64),
                "firmware_sha256": "5".repeat(64),
                "kernel_bundle_sha256": "6".repeat(64),
                "kernel_bundle_size": 22740992,
                "kernel_guest_load_address": "0x0000000080000000",
                "kernel_entry_address": "0x0000000080000000",
                "root_disk_read_only": true,
                "runtime_share_separate": true
            },
            "windows_boot_assets": {
                "manifest_sha256": "7".repeat(64),
                "system_image_sha256": "8".repeat(64),
                "system_image_size": 67108864,
                "runtime_archive_sha256": "9".repeat(64),
                "krun_dll_sha256": "a".repeat(64),
                "firmware_sha256": "b".repeat(64),
                "box_revision": "c".repeat(40),
                "libkrun_revision": "d".repeat(40),
                "firmware_wrapper_revision": "e".repeat(40),
                "libkrunfw_revision": "f".repeat(40),
                "kernel_version": "6.12.91",
                "kernel_source_sha256": "1".repeat(64),
                "kernel_bundle_sha256": "2".repeat(64),
                "kernel_bundle_size": 21364736,
                "kernel_guest_load_address": "0x0000000001000000",
                "kernel_entry_address": "0x0000000001000123",
                "root_disk_read_only": true,
                "runtime_share_separate": true
            },
            "agent_binary_present": true,
            "agent_vsock_configured": true,
            "workload_configured": true,
            "console_configured": true,
            "vm_entered": true,
            "guest_exit_code": 0,
            "console_created": true,
            "vcpus": 1,
            "memory_mib": 512
        }))
        .expect("serialize test evidence"),
        truncated: false,
    }
}

#[test]
fn accepts_complete_shim_evidence() {
    let report = parse_shim_report(
        &valid_output("linux"),
        HostPlatform::Linux,
        true,
        Some(&"0".repeat(64)),
    )
    .expect("valid Linux KVM shim evidence");
    assert_eq!(report["guest_exit_code"], 0);

    let report = parse_shim_report(
        &valid_output("windows"),
        HostPlatform::Windows,
        true,
        Some(&"7".repeat(64)),
    )
    .expect("valid Windows shim evidence");
    assert_eq!(report["guest_exit_code"], 0);

    let report = parse_shim_report(
        &valid_output("macos"),
        HostPlatform::Macos,
        false,
        Some(&"1".repeat(64)),
    )
    .expect("valid macOS shim evidence");
    assert_eq!(report["guest_exit_code"], 0);
}

#[test]
fn rejects_incomplete_or_truncated_shim_evidence() {
    let mut incomplete = valid_output("windows");
    let mut value: Value = serde_json::from_slice(&incomplete.bytes).expect("decode test evidence");
    value["agent_vsock_configured"] = json!(false);
    incomplete.bytes = serde_json::to_vec(&value).expect("serialize test evidence");
    assert!(parse_shim_report(
        &incomplete,
        HostPlatform::Windows,
        true,
        Some(&"7".repeat(64)),
    )
    .is_err());

    let mut truncated = valid_output("windows");
    truncated.truncated = true;
    assert!(parse_shim_report(
        &truncated,
        HostPlatform::Windows,
        true,
        Some(&"7".repeat(64)),
    )
    .is_err());
}

#[test]
fn retains_only_bounded_versioned_failure_evidence() {
    let output = valid_output("linux");
    let retained = bounded_unverified_shim_report(&output)
        .expect("bounded versioned shim evidence must be retained for diagnostics");
    assert_eq!(retained["platform"], "linux");

    let mut truncated = valid_output("linux");
    truncated.truncated = true;
    assert!(bounded_unverified_shim_report(&truncated).is_none());

    let mut wrong_schema = valid_output("linux");
    let mut value: Value =
        serde_json::from_slice(&wrong_schema.bytes).expect("decode test evidence");
    value["schema_version"] = json!("a3s.oci.krun-agent-vm-smoke.unsupported");
    wrong_schema.bytes = serde_json::to_vec(&value).expect("serialize test evidence");
    assert!(bounded_unverified_shim_report(&wrong_schema).is_none());
}

#[test]
fn rejects_a_shim_report_for_the_wrong_host() {
    assert!(parse_shim_report(
        &valid_output("windows"),
        HostPlatform::Macos,
        false,
        Some(&"1".repeat(64)),
    )
    .is_err());
}

#[test]
fn rejects_a_shim_report_with_a_different_system_image_manifest() {
    let error = parse_shim_report(
        &valid_output("macos"),
        HostPlatform::Macos,
        false,
        Some(&"9".repeat(64)),
    )
    .expect_err("host and shim manifest digests must agree");
    assert!(error.contains("manifest digest does not match"));
}

#[test]
fn requires_explicit_runtime_share_evidence_for_the_driver_path() {
    let mut output = valid_output("windows");
    let mut value: Value = serde_json::from_slice(&output.bytes).expect("decode test evidence");
    value["runtime_share_configured"] = json!(false);
    output.bytes = serde_json::to_vec(&value).expect("serialize test evidence");
    assert!(
        parse_shim_report(&output, HostPlatform::Windows, true, Some(&"7".repeat(64)),).is_err()
    );

    value["runtime_share_configured"] = json!(true);
    output.bytes = serde_json::to_vec(&value).expect("serialize test evidence");
    parse_shim_report(&output, HostPlatform::Windows, true, Some(&"7".repeat(64)))
        .expect("runtime-share driver evidence");
}

#[test]
fn rejects_a_windows_shim_report_with_a_different_system_image_manifest() {
    let error = parse_shim_report(
        &valid_output("windows"),
        HostPlatform::Windows,
        true,
        Some(&"0".repeat(64)),
    )
    .expect_err("host and Windows shim manifest digests must agree");
    assert!(error.contains("manifest digest does not match"));
}

#[test]
fn detects_asset_bootstrap_and_runtime_share_path_overlap() {
    let assets = std::path::Path::new("/qualification/system-image");
    assert!(paths_overlap(
        assets,
        std::path::Path::new("/qualification/system-image/runtime")
    ));
    assert!(paths_overlap(
        assets,
        std::path::Path::new("/qualification")
    ));
    assert!(!paths_overlap(
        assets,
        std::path::Path::new("/qualification/runtime")
    ));
}

#[test]
fn driver_bound_manifest_digest_rejects_prelaunch_drift() {
    let expected = "1".repeat(64);
    require_expected_manifest_digest(&expected, Some(&expected))
        .expect("the exact driver-bound digest must remain valid");

    let error = require_expected_manifest_digest(&"2".repeat(64), Some(&expected))
        .expect_err("manifest drift after driver open must fail closed");
    assert!(error.contains("changed after the runtime driver was opened"));
    assert!(require_expected_manifest_digest(&expected, Some("not-a-digest")).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn rejects_a_symlink_before_canonicalizing_a_trusted_file() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("create trusted-file fixture");
    let target = directory.path().join("target");
    let link = directory.path().join("link");
    std::fs::write(&target, b"trusted").expect("write trusted-file fixture");
    symlink(&target, &link).expect("create trusted-file symlink");

    let error = canonical_file(&link, "trusted fixture")
        .await
        .expect_err("trusted file symlink must fail closed");
    assert!(error.contains("not a symlink"));
}
