use a3s_oci_core::HostPlatform;
use serde_json::{json, Value};

#[cfg(unix)]
use super::canonical_file;
use super::{parse_shim_report, BoundedOutput};

fn valid_output(platform: &str) -> BoundedOutput {
    BoundedOutput {
        bytes: serde_json::to_vec(&json!({
            "schema_version": "a3s.oci.krun-agent-vm-smoke.v3",
            "platform": platform,
            "status": "available",
            "runtime_bundle_loaded": true,
            "context_created": true,
            "vm_configured": true,
            "rootfs_configured": true,
            "runtime_share_configured": false,
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
    let report = parse_shim_report(&valid_output("windows"), HostPlatform::Windows, false, None)
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
    assert!(parse_shim_report(&incomplete, HostPlatform::Windows, false, None).is_err());

    let mut truncated = valid_output("windows");
    truncated.truncated = true;
    assert!(parse_shim_report(&truncated, HostPlatform::Windows, false, None).is_err());
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
    assert!(parse_shim_report(&output, HostPlatform::Windows, true, None).is_err());

    let mut value: Value = serde_json::from_slice(&output.bytes).expect("decode test evidence");
    value["runtime_share_configured"] = json!(true);
    output.bytes = serde_json::to_vec(&value).expect("serialize test evidence");
    parse_shim_report(&output, HostPlatform::Windows, true, None)
        .expect("runtime-share driver evidence");
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
