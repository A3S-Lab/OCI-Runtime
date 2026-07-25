use std::path::Path;

use a3s_oci_sdk::{ErrorCode, IoMode, OciBundle, ProcessIo};

use super::plan::InitPlan;
use super::rootfs::RootfsPropagation;

const ROOTFS_CONFIG: &str = r#"{
  "ociVersion": "1.3.0",
  "root": {"path": "rootfs", "readonly": true},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "printf ready"],
    "cwd": "/",
    "noNewPrivileges": true
  },
  "linux": {
    "namespaces": [{"type": "mount"}],
    "rootfsPropagation": "shared",
    "maskedPaths": ["/proc/kcore", "/proc/../proc/kcore"],
    "readonlyPaths": ["/proc/sys", "/sys/firmware"]
  }
}"#;

fn bundle(config: &str) -> OciBundle {
    OciBundle::from_json(
        std::env::current_dir()
            .expect("current directory")
            .join("rootfs-test-bundle"),
        config,
    )
    .expect("schema-valid rootfs test bundle")
}

fn null_io() -> ProcessIo {
    ProcessIo {
        stdin: IoMode::Null,
        stdout: IoMode::Null,
        stderr: IoMode::Null,
        terminal_size: None,
    }
}

#[test]
fn accepts_complete_rootfs_enforcement_in_a_new_mount_namespace() {
    let plan =
        InitPlan::from_bundle(&bundle(ROOTFS_CONFIG), &null_io()).expect("rootfs enforcement plan");

    assert!(plan.root_readonly);
    assert_eq!(plan.rootfs_propagation, Some(RootfsPropagation::Shared));
    assert_eq!(plan.masked_paths, [Path::new("/proc/kcore")]);
    assert_eq!(
        plan.readonly_paths,
        [Path::new("/proc/sys"), Path::new("/sys/firmware")]
    );
}

#[test]
fn accepts_every_oci_rootfs_propagation_mode() {
    for (mode, expected) in [
        ("private", RootfsPropagation::Private),
        ("shared", RootfsPropagation::Shared),
        ("slave", RootfsPropagation::Slave),
        ("unbindable", RootfsPropagation::Unbindable),
    ] {
        let config = ROOTFS_CONFIG.replace(
            r#""rootfsPropagation": "shared""#,
            &format!(r#""rootfsPropagation": "{mode}""#),
        );
        let plan = InitPlan::from_bundle(&bundle(&config), &null_io())
            .expect("schema-defined rootfs propagation mode");
        assert_eq!(plan.rootfs_propagation, Some(expected));
    }
}

#[test]
fn rejects_rootfs_mount_mutation_outside_a_new_mount_namespace() {
    let mut configurations = Vec::new();

    let mut readonly_root: serde_json::Value =
        serde_json::from_str(ROOTFS_CONFIG).expect("decode rootfs configuration");
    readonly_root["linux"] = serde_json::json!({"namespaces": []});
    configurations.push(readonly_root);

    let mut propagation: serde_json::Value =
        serde_json::from_str(ROOTFS_CONFIG).expect("decode rootfs configuration");
    propagation["root"]["readonly"] = serde_json::json!(false);
    propagation["linux"]["namespaces"] = serde_json::json!([]);
    propagation["linux"]["maskedPaths"] = serde_json::json!([]);
    propagation["linux"]["readonlyPaths"] = serde_json::json!([]);
    configurations.push(propagation);

    for field in ["maskedPaths", "readonlyPaths"] {
        let mut restricted: serde_json::Value =
            serde_json::from_str(ROOTFS_CONFIG).expect("decode rootfs configuration");
        restricted["root"]["readonly"] = serde_json::json!(false);
        restricted["linux"]
            .as_object_mut()
            .expect("Linux object")
            .remove(if field == "maskedPaths" {
                "readonlyPaths"
            } else {
                "maskedPaths"
            });
        restricted["linux"]
            .as_object_mut()
            .expect("Linux object")
            .remove("rootfsPropagation");
        restricted["linux"]["namespaces"] =
            serde_json::json!([{"type": "mount", "path": "/proc/42/ns/mnt"}]);
        configurations.push(restricted);
    }

    for configuration in configurations {
        let config = serde_json::to_string(&configuration).expect("encode rootfs configuration");
        let error = InitPlan::from_bundle(&bundle(&config), &null_io())
            .expect_err("rootfs mutation outside a new mount namespace");
        assert_eq!(error.code, ErrorCode::Unsupported);
        assert!(
            error.message.contains("newly created mount namespace"),
            "{error}"
        );
    }
}

#[test]
fn rejects_masking_the_container_root() {
    let mut configuration: serde_json::Value =
        serde_json::from_str(ROOTFS_CONFIG).expect("decode rootfs configuration");
    configuration["linux"]["maskedPaths"] = serde_json::json!(["/"]);
    let config = serde_json::to_string(&configuration).expect("encode rootfs configuration");
    let error =
        InitPlan::from_bundle(&bundle(&config), &null_io()).expect_err("unsafe root masking");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(
        error
            .message
            .contains("must not replace the container root"),
        "{error}"
    );
}
