use std::path::Path;

use a3s_oci_sdk::{ErrorCode, IoMode, OciBundle, ProcessIo};

use super::plan::InitPlan;

const MOUNT_CONFIG: &str = r#"{
  "ociVersion": "1.3.0",
  "root": {"path": "rootfs", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "printf ready"],
    "cwd": "/",
    "noNewPrivileges": true
  },
  "mounts": [
    {
      "destination": "/proc",
      "type": "proc",
      "source": "proc",
      "options": ["nosuid", "noexec", "nodev"]
    },
    {
      "destination": "tmp",
      "type": "tmpfs",
      "source": "tmpfs",
      "options": ["nosuid", "nodev", "mode=1777", "size=16m"]
    }
  ],
  "linux": {"namespaces": [{"type": "mount"}]}
}"#;

fn bundle(config: &str) -> OciBundle {
    OciBundle::from_json(
        std::env::current_dir()
            .expect("current directory")
            .join("mount-test-bundle"),
        config,
    )
    .expect("schema-valid mount test bundle")
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
fn preserves_mount_order_and_normalizes_relative_destinations() {
    let plan = InitPlan::from_bundle(&bundle(MOUNT_CONFIG), &null_io())
        .expect("supported ordered mount profile");
    assert!(plan.new_mount_namespace);
    assert_eq!(plan.mounts.len(), 2);
    assert_eq!(plan.mounts[0].index, 0);
    assert_eq!(plan.mounts[0].destination, Path::new("/proc"));
    assert_eq!(plan.mounts[0].filesystem_type.as_deref(), Some("proc"));
    assert_eq!(plan.mounts[1].index, 1);
    assert_eq!(plan.mounts[1].destination, Path::new("/tmp"));
    assert_eq!(plan.mounts[1].filesystem_type.as_deref(), Some("tmpfs"));
    assert_eq!(plan.mounts[1].data, ["mode=1777", "size=16m"]);
}

#[test]
fn parses_bind_remount_and_propagation_options_without_silent_loss() {
    let config = MOUNT_CONFIG.replace(
        r#"{
      "destination": "/proc",
      "type": "proc",
      "source": "proc",
      "options": ["nosuid", "noexec", "nodev"]
    }"#,
        r#"{
      "destination": "/proc",
      "type": "none",
      "source": "rootfs/proc",
      "options": ["rbind", "ro", "nosuid", "rprivate"]
    }"#,
    );
    let plan =
        InitPlan::from_bundle(&bundle(&config), &null_io()).expect("supported bind mount profile");
    let mount = &plan.mounts[0];
    assert!(mount.bind);
    assert!(mount.remount_bind);
    assert_eq!(mount.source.as_deref(), Some(Path::new("rootfs/proc")));
    assert_ne!(mount.flags & libc::MS_BIND, 0);
    assert_ne!(mount.flags & libc::MS_REC, 0);
    assert_ne!(mount.flags & libc::MS_RDONLY, 0);
    assert_eq!(mount.propagation, Some(libc::MS_PRIVATE | libc::MS_REC));
}

#[test]
fn rejects_mounts_without_isolating_the_runtime_mount_namespace() {
    let config = MOUNT_CONFIG.replace(
        r#",
  "linux": {"namespaces": [{"type": "mount"}]}"#,
        "",
    );
    let error = InitPlan::from_bundle(&bundle(&config), &null_io())
        .expect_err("mounts without a new mount namespace");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("applies mounts only"));
}

#[test]
fn rejects_unimplemented_or_ambiguous_mount_semantics() {
    for (replacement, expected) in [
        (
            r#""options": ["nosuid", "nodev", "idmap"]"#,
            "idmapped mounts",
        ),
        (r#""options": ["nosuid", "nodev", "rro"]"#, "mount_setattr"),
        (r#""options": ["private", "slave"]"#, "multiple propagation"),
        (r#""options": ["mode=1777,size=16m"]"#, "comma separators"),
    ] {
        let config = MOUNT_CONFIG.replace(
            r#""options": ["nosuid", "nodev", "mode=1777", "size=16m"]"#,
            replacement,
        );
        let error =
            InitPlan::from_bundle(&bundle(&config), &null_io()).expect_err("unsupported mount");
        assert!(error.message.contains(expected), "{error}");
    }
}

#[test]
fn rejects_bind_without_source_and_additional_root_replacement() {
    let bind_without_source = MOUNT_CONFIG.replace(
        r#""type": "proc",
      "source": "proc",
      "options": ["nosuid", "noexec", "nodev"]"#,
        r#""type": "none",
      "options": ["bind"]"#,
    );
    let error = InitPlan::from_bundle(&bundle(&bind_without_source), &null_io())
        .expect_err("bind source is required");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("source is required"));

    let root = MOUNT_CONFIG.replace(r#""destination": "/proc""#, r#""destination": "/""#);
    let error =
        InitPlan::from_bundle(&bundle(&root), &null_io()).expect_err("additional root mount");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("replacing the container root"));
}
