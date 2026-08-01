use a3s_oci_core::HostPlatform;
use serde_json::{json, Value};

use super::{parse_shim_report, BoundedOutput};

fn valid_output(platform: &str) -> BoundedOutput {
    BoundedOutput {
        bytes: serde_json::to_vec(&json!({
            "schema_version": "a3s.oci.krun-agent-vm-smoke.v2",
            "platform": platform,
            "status": "available",
            "runtime_bundle_loaded": true,
            "context_created": true,
            "vm_configured": true,
            "rootfs_configured": true,
            "runtime_share_configured": false,
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
    let report = parse_shim_report(&valid_output("windows"), HostPlatform::Windows, false)
        .expect("valid Windows shim evidence");
    assert_eq!(report["guest_exit_code"], 0);

    let report = parse_shim_report(&valid_output("macos"), HostPlatform::Macos, false)
        .expect("valid macOS shim evidence");
    assert_eq!(report["guest_exit_code"], 0);
}

#[test]
fn rejects_incomplete_or_truncated_shim_evidence() {
    let mut incomplete = valid_output("windows");
    let mut value: Value = serde_json::from_slice(&incomplete.bytes).expect("decode test evidence");
    value["agent_vsock_configured"] = json!(false);
    incomplete.bytes = serde_json::to_vec(&value).expect("serialize test evidence");
    assert!(parse_shim_report(&incomplete, HostPlatform::Windows, false).is_err());

    let mut truncated = valid_output("windows");
    truncated.truncated = true;
    assert!(parse_shim_report(&truncated, HostPlatform::Windows, false).is_err());
}

#[test]
fn rejects_a_shim_report_for_the_wrong_host() {
    assert!(parse_shim_report(&valid_output("windows"), HostPlatform::Macos, false).is_err());
}

#[test]
fn requires_explicit_runtime_share_evidence_for_the_driver_path() {
    let mut output = valid_output("windows");
    assert!(parse_shim_report(&output, HostPlatform::Windows, true).is_err());

    let mut value: Value = serde_json::from_slice(&output.bytes).expect("decode test evidence");
    value["runtime_share_configured"] = json!(true);
    output.bytes = serde_json::to_vec(&value).expect("serialize test evidence");
    parse_shim_report(&output, HostPlatform::Windows, true).expect("runtime-share driver evidence");
}
