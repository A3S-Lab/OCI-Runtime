use std::process::Command;

use a3s_oci_core::{DriverKind, DriverReadiness, RuntimeFeatures};

#[test]
fn features_command_emits_versioned_machine_readable_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .arg("features")
        .output()
        .expect("features command must start");

    assert!(
        output.status.success(),
        "features failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let features: RuntimeFeatures =
        serde_json::from_slice(&output.stdout).expect("features output must be valid JSON");
    let whpx = features
        .driver(DriverKind::LibkrunWhpx)
        .expect("features must include the WHPX driver");

    assert_eq!(features.schema_version, "a3s.oci.features.v1");
    assert_eq!(whpx.readiness, DriverReadiness::ProbeOnly);
    assert!(!whpx.can_launch());
}
