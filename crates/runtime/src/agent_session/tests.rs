use serde_json::{json, Value};

use super::{parse_shim_report, BoundedOutput};

fn valid_output() -> BoundedOutput {
    BoundedOutput {
        bytes: serde_json::to_vec(&json!({
            "schema_version": "a3s.oci.krun-agent-vm-smoke.v1",
            "platform": "windows",
            "status": "available",
            "runtime_bundle_loaded": true,
            "context_created": true,
            "vm_configured": true,
            "rootfs_configured": true,
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
    let report = parse_shim_report(&valid_output()).expect("valid shim evidence");
    assert_eq!(report["guest_exit_code"], 0);
}

#[test]
fn rejects_incomplete_or_truncated_shim_evidence() {
    let mut incomplete = valid_output();
    let mut value: Value = serde_json::from_slice(&incomplete.bytes).expect("decode test evidence");
    value["agent_vsock_configured"] = json!(false);
    incomplete.bytes = serde_json::to_vec(&value).expect("serialize test evidence");
    assert!(parse_shim_report(&incomplete).is_err());

    let mut truncated = valid_output();
    truncated.truncated = true;
    assert!(parse_shim_report(&truncated).is_err());
}
