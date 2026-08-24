use std::path::Path;

use a3s_oci_sdk::{ErrorCode, IoMode, ProcessIo, TerminalSize};
use tempfile::tempdir;

use super::{prepare_container_init, RootfsScope};

fn configuration(rootfs: &Path) -> String {
    serde_json::json!({
        "ociVersion": "1.3.0",
        "root": {
            "path": rootfs.to_str().expect("UTF-8 test rootfs"),
            "readonly": false
        },
        "process": {
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/true"],
            "cwd": "/",
            "noNewPrivileges": true
        }
    })
    .to_string()
}

fn write_configuration(directory: &Path, rootfs: &Path) -> std::path::PathBuf {
    let path = directory.join("config.json");
    std::fs::write(&path, configuration(rootfs)).expect("write test configuration");
    path
}

#[test]
fn native_scope_accepts_an_explicit_absolute_rootfs_outside_the_bundle() {
    let temporary = tempdir().expect("temporary rootfs fixture");
    let bundle = temporary.path().join("sandbox/bundle");
    let rootfs = temporary.path().join("rootfs");
    std::fs::create_dir_all(&bundle).expect("bundle directory");
    std::fs::create_dir(&rootfs).expect("external rootfs directory");
    let config = write_configuration(temporary.path(), &rootfs);

    let (_, canonical_bundle, canonical_rootfs, _, _) = prepare_container_init(
        config,
        bundle.clone(),
        RootfsScope::NativeAbsolute,
        None,
        None,
        &ProcessIo::default(),
    )
    .expect("native absolute rootfs");

    assert_eq!(
        canonical_bundle,
        bundle.canonicalize().expect("canonical bundle")
    );
    assert_eq!(
        canonical_rootfs,
        rootfs.canonicalize().expect("canonical rootfs")
    );
}

#[test]
fn rejects_missing_or_non_directory_rootfs_before_namespace_entry() {
    let temporary = tempdir().expect("temporary rootfs fixture");
    let bundle = temporary.path().join("sandbox/bundle");
    std::fs::create_dir_all(&bundle).expect("bundle directory");
    let config = write_configuration(temporary.path(), Path::new("rootfs"));

    let missing = prepare_container_init(
        config.clone(),
        bundle.clone(),
        RootfsScope::BundleOnly,
        None,
        None,
        &ProcessIo::default(),
    )
    .expect_err("the declared rootfs directory must exist");
    assert_eq!(missing.code, ErrorCode::InvalidArgument);
    assert!(missing
        .message
        .contains("failed to resolve container rootfs"));

    std::fs::write(bundle.join("rootfs"), b"not a directory")
        .expect("non-directory rootfs fixture");
    let non_directory = prepare_container_init(
        config,
        bundle,
        RootfsScope::BundleOnly,
        None,
        None,
        &ProcessIo::default(),
    )
    .expect_err("the declared rootfs path must resolve to a directory");
    assert_eq!(non_directory.code, ErrorCode::InvalidArgument);
    assert!(non_directory.message.contains("rootfs is not a directory"));
}

#[test]
fn bundle_scope_rejects_the_same_external_absolute_rootfs() {
    let temporary = tempdir().expect("temporary rootfs fixture");
    let bundle = temporary.path().join("sandbox/bundle");
    let rootfs = temporary.path().join("rootfs");
    std::fs::create_dir_all(&bundle).expect("bundle directory");
    std::fs::create_dir(&rootfs).expect("external rootfs directory");
    let config = write_configuration(temporary.path(), &rootfs);

    let error = prepare_container_init(
        config,
        bundle,
        RootfsScope::BundleOnly,
        None,
        None,
        &ProcessIo::default(),
    )
    .expect_err("guest rootfs must remain bundle-confined");

    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert!(error.message.contains("escapes its guest bundle"));
}

#[test]
fn native_scope_does_not_let_a_relative_symlink_escape_the_bundle() {
    let temporary = tempdir().expect("temporary rootfs fixture");
    let bundle = temporary.path().join("sandbox/bundle");
    let external = temporary.path().join("rootfs");
    std::fs::create_dir_all(&bundle).expect("bundle directory");
    std::fs::create_dir(&external).expect("external rootfs directory");
    std::os::unix::fs::symlink(&external, bundle.join("rootfs")).expect("escaping rootfs symlink");
    let config = write_configuration(temporary.path(), Path::new("rootfs"));

    let error = prepare_container_init(
        config,
        bundle,
        RootfsScope::NativeAbsolute,
        None,
        None,
        &ProcessIo::default(),
    )
    .expect_err("relative rootfs must remain bundle-confined");

    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert!(error.message.contains("escapes its guest bundle"));
}

#[test]
fn prepared_init_reloads_terminal_bundle_with_forwarded_process_io() {
    let temporary = tempdir().expect("temporary rootfs fixture");
    let bundle = temporary.path().join("sandbox/bundle");
    let rootfs = temporary.path().join("rootfs");
    std::fs::create_dir_all(&bundle).expect("bundle directory");
    std::fs::create_dir(&rootfs).expect("external rootfs directory");
    let mut config: serde_json::Value =
        serde_json::from_str(&configuration(&rootfs)).expect("decode configuration");
    config["process"]["terminal"] = serde_json::Value::Bool(true);
    let config_path = temporary.path().join("config.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec(&config).expect("encode terminal configuration"),
    )
    .expect("write terminal configuration");
    let terminal_io = ProcessIo {
        stdin: IoMode::Terminal,
        stdout: IoMode::Terminal,
        stderr: IoMode::Terminal,
        terminal_size: Some(TerminalSize {
            width: 120,
            height: 40,
        }),
    };

    let (plan, _, _, _, _) = prepare_container_init(
        config_path,
        bundle,
        RootfsScope::NativeAbsolute,
        None,
        None,
        &terminal_io,
    )
    .expect("prepared terminal init");

    assert!(plan.terminal);
}

#[tokio::test]
async fn descriptor_pinned_rootfs_rejects_an_entry_swap_before_namespace_entry() {
    use a3s_oci_agent_protocol::GuestPath;

    use crate::executor::bundle_scope::BundleDirectoryScope;

    let temporary = tempdir().expect("temporary utility VM share");
    let share = temporary.path().join("share");
    let state = share.join("run");
    let bundle = share.join("bundle");
    let rootfs = bundle.join("rootfs");
    let retained = bundle.join("retained-rootfs");
    std::fs::create_dir_all(&state).expect("runtime state");
    std::fs::create_dir_all(&rootfs).expect("rootfs");
    let config = write_configuration(temporary.path(), Path::new("rootfs"));
    let (_, scope) = BundleDirectoryScope::utility_vm(&state)
        .await
        .expect("utility VM scope");
    let pinned = scope
        .pin(&GuestPath::new(bundle.to_string_lossy()).expect("guest bundle"))
        .expect("pin bundle")
        .expect("utility VM pin");
    let pinned_rootfs = pinned
        .open_relative(
            Path::new("rootfs"),
            libc::O_PATH,
            true,
            "container rootfs",
            "run-container-init",
        )
        .expect("open rootfs")
        .expect("rootfs exists");

    std::fs::rename(&rootfs, &retained).expect("move validated rootfs");
    std::fs::create_dir(&rootfs).expect("replace rootfs entry");
    let error = prepare_container_init(
        config,
        bundle,
        RootfsScope::BundleOnly,
        Some(&pinned),
        Some(pinned_rootfs),
        &ProcessIo::default(),
    )
    .expect_err("changed rootfs entry must fail closed");

    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert!(error.message.contains("rootfs changed"));
}
