use std::path::{Path, PathBuf};

use a3s_oci_sdk::{ErrorCode, IoMode, OciBundle, ProcessIo};
use tempfile::tempdir;

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
    bundle_at(
        std::env::current_dir()
            .expect("current directory")
            .join("mount-test-bundle"),
        config,
    )
}

fn bundle_at(directory: PathBuf, config: &str) -> OciBundle {
    OciBundle::from_json(directory, config).expect("schema-valid mount test bundle")
}

fn null_io() -> ProcessIo {
    ProcessIo {
        stdin: IoMode::Null,
        stdout: IoMode::Null,
        stderr: IoMode::Null,
        terminal_size: None,
    }
}

fn with_bind_source(config: &str) -> String {
    config.replace(
        r#""type": "tmpfs",
      "source": "tmpfs""#,
        r#""type": "none",
      "source": "rootfs""#,
    )
}

fn with_user_namespace(config: &str) -> String {
    config.replace(
        r#""linux": {"namespaces": [{"type": "mount"}]}"#,
        r#""linux": {
    "namespaces": [{"type": "mount"}, {"type": "user"}],
    "uidMappings": [{"containerID": 0, "hostID": 100000, "size": 65536}],
    "gidMappings": [{"containerID": 0, "hostID": 200000, "size": 65536}]
  }"#,
    )
}

#[test]
fn preserves_mount_order_and_normalizes_relative_destinations() {
    let plan = InitPlan::from_bundle(&bundle(MOUNT_CONFIG), &null_io())
        .expect("supported ordered mount profile");
    assert!(plan.namespaces.new_mount());
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
    assert!(!mount.detached_bind);
}

#[test]
fn prepares_readonly_binds_before_entering_a_new_user_namespace() {
    for options in [
        r#"["rbind", "ro", "nosuid", "nodev", "noexec", "rprivate"]"#,
        r#"["rbind", "rro", "rnosuid", "rnodev", "rnoexec", "rprivate"]"#,
    ] {
        let config = with_user_namespace(&with_bind_source(
            &MOUNT_CONFIG.replace(r#"["nosuid", "nodev", "mode=1777", "size=16m"]"#, options),
        ));
        let plan = InitPlan::from_bundle(&bundle(&config), &null_io())
            .expect("read-only bind in a new user namespace");
        assert!(plan.mounts[1].detached_bind, "options: {options}");
    }
}

#[test]
fn keeps_legacy_remount_for_unrepresentable_bind_attributes() {
    let config = with_user_namespace(&with_bind_source(&MOUNT_CONFIG.replace(
        r#"["nosuid", "nodev", "mode=1777", "size=16m"]"#,
        r#"["rbind", "ro", "sync"]"#,
    )));
    let plan = InitPlan::from_bundle(&bundle(&config), &null_io())
        .expect("legacy-compatible read-only bind plan");

    assert!(plan.mounts[1].remount_bind);
    assert!(!plan.mounts[1].detached_bind);
}

#[test]
fn parses_recursive_mount_attributes_in_listed_order() {
    let config = MOUNT_CONFIG.replace(
        r#""options": ["nosuid", "nodev", "mode=1777", "size=16m"]"#,
        r#""options": [
        "rro",
        "rnosuid",
        "rnodev",
        "rnoexec",
        "rnoatime",
        "rnodiratime",
        "rnosymfollow",
        "rrw",
        "rsuid"
      ]"#,
    );
    let plan = InitPlan::from_bundle(&bundle(&config), &null_io())
        .expect("supported recursive mount attributes");
    let attributes = plan.mounts[1]
        .recursive_attributes
        .expect("recursive attributes");

    assert_eq!(
        attributes.attr_set,
        super::mount::MOUNT_ATTR_NODEV
            | super::mount::MOUNT_ATTR_NOEXEC
            | super::mount::MOUNT_ATTR_NOATIME
            | super::mount::MOUNT_ATTR_NODIRATIME
            | super::mount::MOUNT_ATTR_NOSYMFOLLOW
    );
    assert_eq!(
        attributes.attr_clr,
        super::mount::MOUNT_ATTR_RDONLY
            | super::mount::MOUNT_ATTR_NOSUID
            | super::mount::MOUNT_ATTR_ATIME
    );
}

#[test]
fn recursive_mount_attribute_inverse_options_clear_prior_values() {
    let config = MOUNT_CONFIG.replace(
        r#""options": ["nosuid", "nodev", "mode=1777", "size=16m"]"#,
        r#""options": [
        "rro", "rrw",
        "rnosuid", "rsuid",
        "rnodev", "rdev",
        "rnoexec", "rexec",
        "rnoatime", "ratime",
        "rnodiratime", "rdiratime",
        "rstrictatime", "rnostrictatime",
        "rnosymfollow", "rsymfollow",
        "rrelatime"
      ]"#,
    );
    let plan = InitPlan::from_bundle(&bundle(&config), &null_io())
        .expect("supported recursive inverse attributes");
    let attributes = plan.mounts[1]
        .recursive_attributes
        .expect("recursive attributes");

    assert_eq!(attributes.attr_set, 0);
    assert_eq!(
        attributes.attr_clr,
        super::mount::MOUNT_ATTR_RDONLY
            | super::mount::MOUNT_ATTR_NOSUID
            | super::mount::MOUNT_ATTR_NODEV
            | super::mount::MOUNT_ATTR_NOEXEC
            | super::mount::MOUNT_ATTR_ATIME
            | super::mount::MOUNT_ATTR_NODIRATIME
            | super::mount::MOUNT_ATTR_NOSYMFOLLOW
    );
}

#[test]
fn plans_explicit_idmapped_mounts_even_without_an_option_hint() {
    let config = with_bind_source(&MOUNT_CONFIG.replace(
        r#""options": ["nosuid", "nodev", "mode=1777", "size=16m"]"#,
        r#""options": ["rbind", "nosuid", "nodev"],
      "uidMappings": [{"containerID": 1000, "hostID": 0, "size": 1}],
      "gidMappings": [{"containerID": 2000, "hostID": 0, "size": 1}]"#,
    ));
    let plan = InitPlan::from_bundle(&bundle(&config), &null_io())
        .expect("explicit mount mappings enable a non-recursive idmap");
    let idmap = plan.mounts[1].idmap.as_ref().expect("idmap plan");

    assert!(!idmap.recursive);
    assert_eq!(idmap.uid_mappings.len(), 1);
    assert_eq!(idmap.uid_mappings[0].container_id, 1000);
    assert_eq!(idmap.uid_mappings[0].host_id, 0);
    assert_eq!(idmap.gid_mappings.len(), 1);
    assert_eq!(idmap.gid_mappings[0].container_id, 2000);
    assert_eq!(idmap.gid_mappings[0].host_id, 0);
}

#[test]
fn recursive_idmap_inherits_the_new_container_user_namespace_mappings() {
    let config = with_bind_source(
        &MOUNT_CONFIG
            .replace(
                r#""options": ["nosuid", "nodev", "mode=1777", "size=16m"]"#,
                r#""options": ["rbind", "nosuid", "nodev", "ridmap"]"#,
            )
            .replace(
                r#""linux": {"namespaces": [{"type": "mount"}]}"#,
                r#""linux": {
    "namespaces": [{"type": "mount"}, {"type": "user"}],
    "uidMappings": [{"containerID": 0, "hostID": 100000, "size": 65536}],
    "gidMappings": [{"containerID": 0, "hostID": 100000, "size": 65536}]
  }"#,
            ),
    );
    let plan = InitPlan::from_bundle(&bundle(&config), &null_io())
        .expect("ridmap inherits complete container mappings");
    let idmap = plan.mounts[1].idmap.as_ref().expect("idmap plan");

    assert!(idmap.recursive);
    assert_eq!(idmap.uid_mappings, plan.namespaces.uid_mappings());
    assert_eq!(idmap.gid_mappings, plan.namespaces.gid_mappings());
}

#[test]
fn idmap_and_ridmap_select_non_recursive_and_recursive_enforcement() {
    for (mode, recursive) in [("idmap", false), ("ridmap", true)] {
        let replacement = format!(
            r#""options": ["rbind", "nosuid", "nodev", "{mode}"],
      "uidMappings": [{{"containerID": 1000, "hostID": 0, "size": 1}}],
      "gidMappings": [{{"containerID": 1000, "hostID": 0, "size": 1}}]"#
        );
        let config = with_bind_source(&MOUNT_CONFIG.replace(
            r#""options": ["nosuid", "nodev", "mode=1777", "size=16m"]"#,
            &replacement,
        ));
        let plan =
            InitPlan::from_bundle(&bundle(&config), &null_io()).expect("explicit ID-mapping mode");
        assert_eq!(
            plan.mounts[1].idmap.as_ref().expect("idmap plan").recursive,
            recursive
        );
    }
}

#[test]
fn plans_idmapped_filesystems_for_the_detached_fsopen_path() {
    let config = MOUNT_CONFIG.replace(
        r#""options": ["nosuid", "nodev", "mode=1777", "size=16m"]"#,
        r#""options": ["nosuid", "nodev", "mode=1777", "size=16m", "idmap"],
      "uidMappings": [{"containerID": 1000, "hostID": 0, "size": 1}],
      "gidMappings": [{"containerID": 1000, "hostID": 0, "size": 1}]"#,
    );
    let plan = InitPlan::from_bundle(&bundle(&config), &null_io()).expect("ID-mapped tmpfs plan");
    let mount = &plan.mounts[1];

    assert!(!mount.bind);
    assert_eq!(mount.filesystem_type.as_deref(), Some("tmpfs"));
    assert_eq!(mount.data, ["mode=1777", "size=16m"]);
    assert!(!mount.idmap.as_ref().expect("idmap plan").recursive);
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

    let duplicate_idmap = with_bind_source(&MOUNT_CONFIG.replace(
        r#""options": ["nosuid", "nodev", "mode=1777", "size=16m"]"#,
        r#""options": ["rbind", "idmap", "idmap"],
      "uidMappings": [{"containerID": 1000, "hostID": 0, "size": 1}],
      "gidMappings": [{"containerID": 1000, "hostID": 0, "size": 1}]"#,
    ));
    let error = InitPlan::from_bundle(&bundle(&duplicate_idmap), &null_io())
        .expect_err("duplicate ID-mapping modes");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("multiple idmap/ridmap modes"));

    let empty_idmap = with_bind_source(&MOUNT_CONFIG.replace(
        r#""options": ["nosuid", "nodev", "mode=1777", "size=16m"]"#,
        r#""options": ["rbind", "nosuid", "nodev"],
      "uidMappings": [],
      "gidMappings": []"#,
    ));
    let error =
        InitPlan::from_bundle(&bundle(&empty_idmap), &null_io()).expect_err("empty ID mappings");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("must both contain mappings"));
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

#[test]
fn creates_missing_directory_and_file_mount_targets_inside_the_rootfs() {
    let temporary = tempdir().expect("temporary mount bundle");
    let bundle_directory = temporary.path();
    let rootfs = bundle_directory.join("rootfs");
    std::fs::create_dir(&rootfs).expect("rootfs");

    let directory_source = bundle_directory.join("source-directory");
    std::fs::create_dir(&directory_source).expect("bind directory source");
    let file_source = bundle_directory.join("source-file");
    std::fs::write(&file_source, b"source").expect("bind file source");

    let config = MOUNT_CONFIG.replace(
        r#"{
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
    }"#,
        r#"{
      "destination": "/created/filesystem",
      "type": "tmpfs",
      "source": "tmpfs"
    },
    {
      "destination": "/created/directory-target",
      "type": "none",
      "source": "source-directory",
      "options": ["bind"]
    },
    {
      "destination": "/created/file-target",
      "type": "none",
      "source": "source-file",
      "options": ["bind"]
    }"#,
    );
    let bundle = bundle_at(bundle_directory.to_path_buf(), &config);
    let plan = InitPlan::from_bundle(&bundle, &null_io()).expect("mount target creation plan");

    for mount in &plan.mounts {
        mount
            .prepare_target(bundle_directory, &rootfs)
            .expect("create the requested mount target");
    }

    assert!(rootfs.join("created/filesystem").is_dir());
    assert!(rootfs.join("created/directory-target").is_dir());
    assert!(rootfs.join("created/file-target").is_file());
}

#[test]
fn refuses_to_create_a_mount_target_through_an_escaping_symlink() {
    let temporary = tempdir().expect("temporary mount bundle");
    let bundle_directory = temporary.path();
    let rootfs = bundle_directory.join("rootfs");
    let outside = bundle_directory.join("outside");
    std::fs::create_dir(&rootfs).expect("rootfs");
    std::fs::create_dir(&outside).expect("outside directory");
    std::os::unix::fs::symlink(&outside, rootfs.join("escape")).expect("escaping symlink");

    let config = MOUNT_CONFIG.replace("/proc", "/escape/created");
    let bundle = bundle_at(bundle_directory.to_path_buf(), &config);
    let plan = InitPlan::from_bundle(&bundle, &null_io()).expect("mount target creation plan");
    let error = plan.mounts[0]
        .prepare_target(bundle_directory, &rootfs)
        .expect_err("escaping target must fail");

    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert!(!outside.join("created").exists());
}
