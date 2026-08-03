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
    assert_eq!(report["schema_version"], "a3s.oci.agent-vm-smoke.v9");
    assert_ne!(report["status"], "available");
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        let cleanup = &report["macos_cleanup"];
        assert_eq!(cleanup["endpoint_removed"], true);
        assert_eq!(cleanup["shim_reaped"], true);
        assert_eq!(cleanup["bridge_reaped"], true);
        assert_eq!(cleanup["descriptor_inventory_restored"], true);
        assert_eq!(
            cleanup["open_descriptors_before"],
            cleanup["open_descriptors_after"]
        );
    }
}

#[test]
fn hvf_smoke_emits_consistent_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .arg("hvf-smoke")
        .output()
        .expect("HVF smoke command must start");

    assert!(
        output.status.success() || output.status.code() == Some(2),
        "HVF smoke exited unexpectedly: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: a3s_oci_runtime::HvfSmokeReport =
        serde_json::from_slice(&output.stdout).expect("smoke output must be valid JSON");
    assert_eq!(report.schema_version, "a3s.oci.hvf-smoke.v1");
    assert_eq!(output.status.success(), report.is_success());
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
    assert_eq!(report["schema_version"], "a3s.oci.native-linux-smoke.v12");
    assert_ne!(report["status"], "available");
}

#[test]
fn native_linux_rootless_smoke_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "native-linux-rootless-smoke",
            "--agent",
            "missing-a3s-oci-agent",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--work-parent",
            "missing-a3s-oci-work-parent",
        ])
        .output()
        .expect("native Linux rootless smoke command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("rootless smoke output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.native-linux-rootless-smoke.v1"
    );
    assert_ne!(report["status"], "available");
}

#[cfg(target_os = "linux")]
#[test]
fn native_linux_service_requires_explicit_box_descriptor_contract() {
    let root = format!("/tmp/a3s-oci-cli-service-contract-{}", std::process::id());
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "native-linux-service",
            "--root",
            &root,
            "--agent",
            "/bin/true",
            "--container-id",
            "box-contract-test",
        ])
        .output()
        .expect("native Linux service command must start");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--a3s-box-control-fds"));
    assert!(!std::path::Path::new(&root).exists());
}

#[cfg(target_os = "linux")]
#[test]
fn native_linux_host_service_requires_both_owner_paths() {
    let root = format!(
        "/tmp/a3s-oci-cli-host-service-contract-{}",
        std::process::id()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args(["native-linux-host-service", "--root", &root])
        .output()
        .expect("native Linux host service command must start");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--agent"));
    assert!(!std::path::Path::new(&root).exists());
}

#[test]
fn native_linux_service_smoke_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "native-linux-service-smoke",
            "--agent",
            "missing-a3s-oci-agent",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--work-parent",
            "missing-a3s-oci-work-parent",
        ])
        .output()
        .expect("native Linux service smoke command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("native service smoke output must be valid JSON");
    assert_eq!(report["schema_version"], "a3s.oci.native-linux-smoke.v12");
    assert_ne!(report["status"], "available");
}

#[test]
fn native_linux_multi_container_smoke_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "native-linux-multi-container-smoke",
            "--agent",
            "missing-a3s-oci-agent",
            "--bundle-a",
            "missing-a3s-oci-bundle-a",
            "--bundle-b",
            "missing-a3s-oci-bundle-b",
            "--work-parent",
            "missing-a3s-oci-work-parent",
        ])
        .output()
        .expect("native Linux multi-container command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.native-linux-multi-container-smoke.v14"
    );
    assert_ne!(report["status"], "available");
}

#[test]
fn native_linux_soak_fails_closed_with_versioned_configuration() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "native-linux-soak",
            "--agent",
            "missing-a3s-oci-agent",
            "--bundle",
            "missing-a3s-oci-bundle-a",
            "--bundle",
            "missing-a3s-oci-bundle-b",
            "--work-parent",
            "missing-a3s-oci-work-parent",
            "--iterations",
            "3",
            "--concurrent-containers",
            "2",
            "--operation-timeout-ms",
            "1000",
        ])
        .output()
        .expect("native Linux soak command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("soak output must be valid JSON");
    assert_eq!(report["schema_version"], "a3s.oci.native-linux-soak.v1");
    assert_eq!(report["configuration"]["iterations"], 3);
    assert_eq!(report["configuration"]["concurrent_containers"], 2);
    assert_eq!(report["configuration"]["operation_timeout_ms"], 1000);
    assert_ne!(report["status"], "available");
}

#[test]
fn native_linux_fault_cleanup_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "native-linux-fault-cleanup",
            "--agent",
            "missing-a3s-oci-agent",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--work-parent",
            "missing-a3s-oci-work-parent",
            "--fault-after",
            "after-start",
        ])
        .output()
        .expect("native Linux fault-cleanup command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.native-linux-fault-cleanup.v6"
    );
    assert_eq!(report["lifecycle"]["requested_fault"], "after-start");
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
    assert_eq!(report["schema_version"], "a3s.oci.oci-vm-smoke.v9");
    assert_ne!(report["status"], "available");
}

#[test]
fn whpx_driver_smoke_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "whpx-driver-smoke",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--runtime-root",
            "missing-a3s-oci-runtime-root",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--container-id",
            "whpx-driver-smoke-test",
            "--generation",
            "1",
        ])
        .output()
        .expect("WHPX driver smoke command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("WHPX driver smoke output must be valid JSON");
    assert_eq!(report["schema_version"], "a3s.oci.whpx-driver-smoke.v1");
    assert_ne!(report["status"], "available");
}

#[test]
fn box_whpx_qualification_service_fails_before_publishing_readiness() {
    let temporary =
        std::env::temp_dir().join(format!("a3s-oci-box-whpx-cli-test-{}", std::process::id()));
    let ready = temporary.join("ready.json");
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .arg("box-whpx-qualification-service")
        .arg("--shim")
        .arg(temporary.join("missing-shim"))
        .arg("--runtime-root")
        .arg(temporary.join("missing-runtime"))
        .arg("--vm-rootfs")
        .arg(temporary.join("missing-system"))
        .arg("--state-root")
        .arg(temporary.join("missing-state"))
        .arg("--pipe")
        .arg(format!(
            r"\\.\pipe\a3s-oci-box-cli-test-{}",
            std::process::id()
        ))
        .arg("--ready-file")
        .arg(&ready)
        .output()
        .expect("Box WHPX qualification service command must start");

    assert!(!output.status.success());
    assert!(!ready.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("runtime request failed"));
}

#[test]
fn whpx_recovery_resume_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "whpx-recovery-resume",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--runtime-root",
            "missing-a3s-oci-runtime-root",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--state-root",
            "missing-a3s-oci-state-root",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--container-id",
            "whpx-recovery-smoke-test",
            "--generation",
            "1",
        ])
        .output()
        .expect("WHPX recovery resume command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("WHPX recovery resume output must be valid JSON");
    assert_eq!(report["schema_version"], "a3s.oci.whpx-recovery-smoke.v1");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_multi_container_smoke_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-multi-container-smoke",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--bundle-a",
            "missing-a3s-oci-bundle-a",
            "--bundle-b",
            "missing-a3s-oci-bundle-b",
            "--console",
            "missing-a3s-oci-console",
        ])
        .output()
        .expect("OCI VM multi-container command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-multi-container-smoke.v9"
    );
    assert_ne!(report["status"], "available");
}

#[test]
fn macos_hvf_soak_fails_closed_with_versioned_configuration() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "macos-hvf-soak",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--bundle-a",
            "missing-a3s-oci-bundle-a",
            "--bundle-b",
            "missing-a3s-oci-bundle-b",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--iterations",
            "7",
        ])
        .output()
        .expect("macOS HVF soak command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("soak output must be valid JSON");
    assert_eq!(report["schema_version"], "a3s.oci.macos-hvf-soak.v1");
    assert_eq!(report["configuration"]["iterations"], 7);
    assert_eq!(report["configuration"]["concurrent_containers"], 2);
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_fault_cleanup_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-fault-cleanup",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console",
            "missing-a3s-oci-console",
            "--fault-after",
            "after-kill",
        ])
        .output()
        .expect("OCI VM fault-cleanup command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("diagnostic output must be valid JSON");
    assert_eq!(report["schema_version"], "a3s.oci.oci-vm-fault-cleanup.v4");
    assert_eq!(report["lifecycle"]["requested_fault"], "after-kill");
    assert_ne!(report["status"], "available");
}
