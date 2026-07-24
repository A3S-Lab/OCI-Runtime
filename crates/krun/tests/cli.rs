use std::process::Command;

#[test]
fn context_smoke_emits_consistent_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci-krun-shim"))
        .arg("context-smoke")
        .output()
        .expect("context smoke command must start");

    let report: a3s_oci_krun::KrunContextSmokeReport =
        serde_json::from_slice(&output.stdout).expect("smoke output must be valid JSON");
    assert_eq!(report.schema_version, "a3s.oci.krun-context-smoke.v2");
    assert_eq!(output.status.success(), report.is_success());

    if cfg!(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )) {
        assert!(
            output.status.success(),
            "supported context smoke failed: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(report.runtime_bundle_loaded);
        assert!(report.context_created);
        assert!(report.vm_configured);
        assert!(report.agent_vsock_configured);
        assert!(report.context_released);
    } else {
        assert_eq!(output.status.code(), Some(2));
    }
}
