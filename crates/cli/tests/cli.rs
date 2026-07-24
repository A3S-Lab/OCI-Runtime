use std::process::Command;

use a3s_oci_core::{DriverKind, DriverReadiness, HostPlatform, RuntimeFeatures};

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
    assert_eq!(features.schema_version, "a3s.oci.features.v1");
    match features.platform {
        HostPlatform::Linux => {
            assert!(features.driver(DriverKind::NativeLinux).is_some());
            assert!(features.driver(DriverKind::LibkrunKvm).is_some());
            assert_eq!(features.drivers.len(), 2);
        }
        HostPlatform::Macos => {
            assert!(features.driver(DriverKind::LibkrunHvf).is_some());
            assert_eq!(features.drivers.len(), 1);
        }
        HostPlatform::Windows => {
            assert!(features.driver(DriverKind::LibkrunWhpx).is_some());
            assert_eq!(features.drivers.len(), 1);
        }
        HostPlatform::Unsupported => {
            assert!(features.driver(DriverKind::LibkrunWhpx).is_some());
        }
    }
    assert!(features
        .drivers
        .iter()
        .all(|driver| driver.readiness == DriverReadiness::ProbeOnly && !driver.can_launch()));
}

#[test]
fn agent_vm_smoke_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "agent-vm-smoke",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--rootfs",
            "missing-a3s-oci-rootfs",
            "--console",
            "missing-a3s-oci-console",
        ])
        .output()
        .expect("agent VM smoke command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("smoke output must be valid JSON");
    assert_eq!(report["schema_version"], "a3s.oci.agent-vm-smoke.v1");
    assert_ne!(report["status"], "available");
}

#[test]
fn native_linux_smoke_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "native-linux-smoke",
            "--agent",
            "missing-a3s-oci-agent",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--work-parent",
            "missing-a3s-oci-work-parent",
        ])
        .output()
        .expect("native Linux smoke command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("smoke output must be valid JSON");
    assert_eq!(report["schema_version"], "a3s.oci.native-linux-smoke.v1");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_smoke_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-smoke",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console",
            "missing-a3s-oci-console",
        ])
        .output()
        .expect("OCI VM smoke command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("smoke output must be valid JSON");
    assert_eq!(report["schema_version"], "a3s.oci.oci-vm-smoke.v2");
    assert_ne!(report["status"], "available");
}
