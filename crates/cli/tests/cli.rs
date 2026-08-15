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
    for driver in &features.drivers {
        if driver.driver == DriverKind::LibkrunHvf {
            assert_eq!(driver.readiness, DriverReadiness::Experimental);
            assert_eq!(
                driver.can_launch(),
                driver.status == a3s_oci_core::CapabilityStatus::Available
            );
        } else {
            assert_eq!(driver.readiness, DriverReadiness::ProbeOnly);
            assert!(!driver.can_launch());
        }
    }
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
    assert_eq!(report["schema_version"], "a3s.oci.native-linux-smoke.v15");
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
        "a3s.oci.native-linux-rootless-smoke.v4"
    );
    assert_ne!(report["status"], "available");
}

#[test]
fn rootless_device_bootstrap_requires_an_explicit_delegation() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "native-linux-rootless-smoke",
            "--agent",
            "missing-a3s-oci-agent",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--work-parent",
            "missing-a3s-oci-work-parent",
            "--rootless-device-bootstrap",
        ])
        .output()
        .expect("native Linux rootless command must start");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--delegated-cgroup-root"));
    assert!(output.stdout.is_empty());
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

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn macos_hvf_host_service_requires_all_owner_paths_without_creating_root() {
    let root = format!(
        "/tmp/a3s-oci-cli-hvf-host-service-contract-{}",
        std::process::id()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "macos-hvf-host-service",
            "--root",
            &root,
            "--shim",
            "/tmp/missing-a3s-oci-hvf-shim",
        ])
        .output()
        .expect("macOS HVF host service command must start");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--system-image-manifest"));
    assert!(!std::path::Path::new(&root).exists());
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn macos_hvf_host_service_smoke_fails_closed_without_creating_evidence() {
    let missing_parent = format!(
        "/tmp/a3s-oci-cli-hvf-host-smoke-missing-{}",
        std::process::id()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "macos-hvf-host-service-smoke",
            "--shim",
            "/tmp/missing-a3s-oci-hvf-shim",
            "--system-image-manifest",
            "/tmp/missing-a3s-oci-system-image.json",
            "--bundle",
            "/tmp/missing-a3s-oci-bundle",
            "--work-parent",
            &missing_parent,
            "--source-revision",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ])
        .output()
        .expect("macOS HVF Host Service smoke command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Host Service smoke output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.macos-hvf-host-service-smoke.v1"
    );
    assert_ne!(report["status"], "available");
    assert!(!std::path::Path::new(&missing_parent).exists());
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
    assert_eq!(report["schema_version"], "a3s.oci.native-linux-smoke.v15");
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
        "a3s.oci.native-linux-multi-container-smoke.v17"
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
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
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
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
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
        .arg("--system-image-manifest")
        .arg(temporary.join("missing-system-image-manifest"))
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
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
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
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
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
        "a3s.oci.oci-vm-multi-container-smoke.v11"
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
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
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

#[test]
fn oci_vm_transport_fault_cleanup_fails_closed_with_versioned_output() {
    for stage in ["host-after-request-write", "host-before-shutdown"] {
        let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
            .args([
                "oci-vm-transport-fault-cleanup",
                "--shim",
                "missing-a3s-oci-krun-shim",
                "--vm-rootfs",
                "missing-a3s-oci-vm-rootfs",
                "--bundle",
                "missing-a3s-oci-bundle",
                "--console",
                "missing-a3s-oci-console",
                "--fault-at",
                stage,
            ])
            .output()
            .expect("OCI VM transport fault-cleanup command must start");

        assert_eq!(output.status.code(), Some(2));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)
            .expect("transport diagnostic output must be valid JSON");
        assert_eq!(
            report["schema_version"],
            "a3s.oci.oci-vm-transport-fault-cleanup.v3"
        );
        assert_eq!(report["requested_operation"], "create");
        assert_eq!(report["requested_stage"], stage);
        assert_ne!(report["status"], "available");
    }
}

#[test]
fn oci_vm_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
        ])
        .output()
        .expect("OCI VM reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-reopen-replacement.v2"
    );
    assert_eq!(report["requested_operation"], "create");
    assert_eq!(report["requested_stage"], "host-before-request-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_state_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "state",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM State reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("State reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v1"
    );
    assert_eq!(report["requested_operation"], "state");
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_start_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "start",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM Start reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Start reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v2"
    );
    assert_eq!(report["requested_operation"], "start");
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_kill_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "kill",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM Kill reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Kill reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v3"
    );
    assert_eq!(report["requested_operation"], "kill");
    assert_eq!(report["kill_signal"], 9);
    assert_eq!(report["kill_all"], true);
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_delete_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "delete",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM Delete reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Delete reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v4"
    );
    assert_eq!(report["requested_operation"], "delete");
    assert_eq!(report["delete_mode"], "stopped-only");
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_wait_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "wait",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM Wait reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Wait reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v5"
    );
    assert_eq!(report["requested_operation"], "wait");
    assert_eq!(report["kill_signal"], 9);
    assert_eq!(report["kill_all"], true);
    assert_eq!(report["wait_timeout_ms"], 15_000);
    assert_eq!(report["expected_exit_status"]["signal"], 9);
    assert_eq!(report["expected_exit_status"]["oom_killed"], false);
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_exec_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "exec",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM Exec reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Exec reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v6"
    );
    assert_eq!(report["requested_operation"], "exec");
    assert_eq!(report["exec_terminal"], true);
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_signal_process_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "signal-process",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM SignalProcess reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("SignalProcess reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v7"
    );
    assert_eq!(report["requested_operation"], "signal-process");
    assert_eq!(report["signal_process_signal"], 10);
    assert_eq!(report["exec_terminal"], true);
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_wait_process_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "wait-process",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM WaitProcess reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("WaitProcess reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v8"
    );
    assert_eq!(report["requested_operation"], "wait-process");
    assert_eq!(report["wait_process_timeout_ms"], 15_000);
    assert_eq!(
        report["expected_exit_status"],
        serde_json::json!({"signal": 10, "oom_killed": false})
    );
    assert_eq!(report["exec_terminal"], true);
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_pause_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "pause",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM Pause reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Pause reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v9"
    );
    assert_eq!(report["requested_operation"], "pause");
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_resume_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "resume",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM Resume reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Resume reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v10"
    );
    assert_eq!(report["requested_operation"], "resume");
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_processes_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "processes",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM Processes reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Processes reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v11"
    );
    assert_eq!(report["requested_operation"], "processes");
    assert_eq!(report["exec_terminal"], true);
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_read_output_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "read-output",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM ReadOutput reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("ReadOutput reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v14"
    );
    assert_eq!(report["requested_operation"], "read-output");
    assert_eq!(report["exec_terminal"], false);
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_write_stdin_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "write-stdin",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM WriteStdin reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("WriteStdin reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v15"
    );
    assert_eq!(report["requested_operation"], "write-stdin");
    assert_eq!(report["exec_terminal"], false);
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_close_stdin_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "close-stdin",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM CloseStdin reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("CloseStdin reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v16"
    );
    assert_eq!(report["requested_operation"], "close-stdin");
    assert_eq!(report["exec_terminal"], false);
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_resize_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "resize",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM Resize reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Resize reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v17"
    );
    assert_eq!(report["requested_operation"], "resize");
    assert_eq!(report["exec_terminal"], true);
    assert_eq!(report["resize_size"]["width"], 120);
    assert_eq!(report["resize_size"]["height"], 40);
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_file_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "file",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM File reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("File reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v18"
    );
    assert_eq!(report["requested_operation"], "file");
    assert_eq!(report["file_op"], "upload");
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_filesystem_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "filesystem",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM Filesystem reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Filesystem reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v19"
    );
    assert_eq!(report["requested_operation"], "filesystem");
    assert_eq!(report["filesystem_op"], "make-dir");
    assert_eq!(report["filesystem_depth"], 0);
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_update_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "update",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM Update reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Update reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v12"
    );
    assert_eq!(report["requested_operation"], "update");
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_stats_reopen_replacement_fails_closed_with_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
        .args([
            "oci-vm-reopen-replacement",
            "--shim",
            "missing-a3s-oci-krun-shim",
            "--vm-rootfs",
            "missing-a3s-oci-vm-rootfs",
            "--system-image-manifest",
            "missing-a3s-oci-system-image-manifest",
            "--bundle",
            "missing-a3s-oci-bundle",
            "--console-dir",
            "missing-a3s-oci-console-directory",
            "--operation",
            "stats",
            "--fault-at",
            "guest-after-response-write",
        ])
        .output()
        .expect("OCI VM Stats reopen-replacement command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("Stats reopen-replacement diagnostic output must be valid JSON");
    assert_eq!(
        report["schema_version"],
        "a3s.oci.oci-vm-operation-reopen-replacement.v13"
    );
    assert_eq!(report["requested_operation"], "stats");
    assert_eq!(report["requested_stage"], "guest-after-response-write");
    assert_ne!(report["status"], "available");
}

#[test]
fn oci_vm_reopen_replacement_accepts_each_create_transport_stage() {
    for stage in [
        "host-before-request-write",
        "host-after-request-write",
        "host-before-response-read",
        "host-after-response-read",
        "guest-after-request-read",
        "guest-before-dispatch",
        "guest-after-dispatch",
        "guest-before-response-write",
        "guest-after-response-write",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci"))
            .args([
                "oci-vm-reopen-replacement",
                "--shim",
                "missing-a3s-oci-krun-shim",
                "--vm-rootfs",
                "missing-a3s-oci-vm-rootfs",
                "--system-image-manifest",
                "missing-a3s-oci-system-image-manifest",
                "--bundle",
                "missing-a3s-oci-bundle",
                "--console-dir",
                "missing-a3s-oci-console-directory",
                "--fault-at",
                stage,
            ])
            .output()
            .expect("OCI VM reopen-replacement command must start");

        assert_eq!(output.status.code(), Some(2));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)
            .expect("reopen-replacement diagnostic output must be valid JSON");
        assert_eq!(report["requested_stage"], stage);
        assert_ne!(report["status"], "available");
    }
}
