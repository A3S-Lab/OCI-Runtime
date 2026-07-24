use a3s_oci_sdk::{ErrorCode, IoMode, OciBundle, ProcessIo};

use super::plan::InitPlan;

const FIXED_CONFIG: &str = r#"{
  "ociVersion": "1.3.0",
  "root": {"path": "rootfs", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0, "umask": 18},
    "args": ["/bin/sh", "-c", "printf ready"],
    "env": ["PATH=/bin:/usr/bin"],
    "cwd": "/",
    "noNewPrivileges": true
  }
}"#;
const UTS_CONFIG: &str = r#"{
  "ociVersion": "1.3.0",
  "root": {"path": "rootfs", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "printf ready"],
    "cwd": "/",
    "noNewPrivileges": true
  },
  "hostname": "a3s-smoke",
  "domainname": "runtime.test",
  "linux": {"namespaces": [{"type": "uts"}]}
}"#;

fn bundle(config: &str) -> OciBundle {
    OciBundle::from_json(
        std::env::current_dir()
            .expect("current directory")
            .join("bootstrap-test-bundle"),
        config,
    )
    .expect("schema-valid test bundle")
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
fn accepts_the_exact_bootstrap_profile() {
    let bundle = bundle(FIXED_CONFIG);
    let plan = InitPlan::from_bundle(&bundle, &null_io()).expect("supported fixed profile");
    assert_eq!(plan.rootfs, bundle.directory().join("rootfs"));
    assert_eq!(plan.args[0], "/bin/sh");
    assert_eq!(plan.umask, Some(0o22));
    assert!(plan.no_new_privileges);
    assert!(!plan.new_uts_namespace);
    assert!(!plan.new_mount_namespace);
    assert!(!plan.new_ipc_namespace);
    assert!(!plan.new_network_namespace);
    assert!(!plan.new_cgroup_namespace);
    assert!(!plan.new_pid_namespace);
}

#[test]
fn rejects_every_unimplemented_property_instead_of_ignoring_it() {
    let config = FIXED_CONFIG.replace(
        r#""ociVersion": "1.3.0","#,
        r#""ociVersion": "1.3.0",
           "annotations": {"dev.a3s.unsupported": "true"},"#,
    );
    let error =
        InitPlan::from_bundle(&bundle(&config), &null_io()).expect_err("annotations unsupported");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("config.annotations"));

    let config = FIXED_CONFIG.replace(
        r#""noNewPrivileges": true"#,
        r#""noNewPrivileges": true,
           "capabilities": {"bounding": [], "effective": [], "inheritable": [],
                            "permitted": [], "ambient": []}"#,
    );
    let error = InitPlan::from_bundle(&bundle(&config), &null_io())
        .expect_err("capability enforcement unsupported");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("process.capabilities"));
}

#[test]
fn rejects_non_null_process_io() {
    let mut io = null_io();
    io.stdout = IoMode::Capture;
    let error = InitPlan::from_bundle(&bundle(FIXED_CONFIG), &io)
        .expect_err("capture should remain unsupported");
    assert_eq!(error.code, ErrorCode::Unsupported);
}

#[test]
fn accepts_a_new_uts_namespace_and_bounded_uts_names() {
    let plan =
        InitPlan::from_bundle(&bundle(UTS_CONFIG), &null_io()).expect("UTS namespace profile");
    assert!(plan.new_uts_namespace);
    assert!(!plan.new_mount_namespace);
    assert_eq!(plan.hostname.as_deref(), Some("a3s-smoke"));
    assert_eq!(plan.domainname.as_deref(), Some("runtime.test"));

    let maximum = "h".repeat(64);
    let config = UTS_CONFIG
        .replace("a3s-smoke", &maximum)
        .replace("runtime.test", &maximum);
    let plan = InitPlan::from_bundle(&bundle(&config), &null_io()).expect("64-byte UTS names");
    assert_eq!(plan.hostname.as_deref(), Some(maximum.as_str()));
    assert_eq!(plan.domainname.as_deref(), Some(maximum.as_str()));
}

#[test]
fn accepts_new_uts_and_mount_namespaces_in_any_order() {
    let mut mount_only: serde_json::Value =
        serde_json::from_str(FIXED_CONFIG).expect("decode mount-only configuration");
    mount_only["linux"] = serde_json::json!({
        "namespaces": [{"type": "mount"}]
    });
    let mount_only = serde_json::to_string(&mount_only).expect("encode mount-only configuration");
    let plan =
        InitPlan::from_bundle(&bundle(&mount_only), &null_io()).expect("new mount namespace");
    assert!(!plan.new_uts_namespace);
    assert!(plan.new_mount_namespace);

    for namespaces in [
        r#"{"type": "uts"}, {"type": "mount"}"#,
        r#"{"type": "mount"}, {"type": "uts"}"#,
    ] {
        let config = UTS_CONFIG.replace(r#"{"type": "uts"}"#, namespaces);
        let plan = InitPlan::from_bundle(&bundle(&config), &null_io())
            .expect("new UTS and mount namespaces");
        assert!(plan.new_uts_namespace);
        assert!(plan.new_mount_namespace);
    }
}

#[test]
fn accepts_new_ipc_network_and_cgroup_namespaces_in_any_order() {
    for namespaces in [
        ["ipc", "network", "cgroup"],
        ["cgroup", "ipc", "network"],
        ["network", "cgroup", "ipc"],
    ] {
        let mut config: serde_json::Value =
            serde_json::from_str(FIXED_CONFIG).expect("decode namespace configuration");
        config["linux"] = serde_json::json!({
            "namespaces": namespaces
                .into_iter()
                .map(|namespace| serde_json::json!({"type": namespace}))
                .collect::<Vec<_>>()
        });
        let config = serde_json::to_string(&config).expect("encode namespace configuration");
        let plan = InitPlan::from_bundle(&bundle(&config), &null_io())
            .expect("new IPC, network, and cgroup namespaces");
        assert!(plan.new_ipc_namespace);
        assert!(plan.new_network_namespace);
        assert!(plan.new_cgroup_namespace);
    }
}

#[test]
fn accepts_a_new_pid_namespace_in_any_supported_order() {
    for namespaces in [
        ["pid", "uts", "mount"],
        ["mount", "pid", "uts"],
        ["uts", "mount", "pid"],
    ] {
        let mut config: serde_json::Value =
            serde_json::from_str(FIXED_CONFIG).expect("decode namespace configuration");
        config["linux"] = serde_json::json!({
            "namespaces": namespaces
                .into_iter()
                .map(|namespace| serde_json::json!({"type": namespace}))
                .collect::<Vec<_>>()
        });
        let config = serde_json::to_string(&config).expect("encode namespace configuration");
        let plan = InitPlan::from_bundle(&bundle(&config), &null_io())
            .expect("new PID namespace with supported peers");
        assert!(plan.new_pid_namespace);
        assert!(plan.new_uts_namespace);
        assert!(plan.new_mount_namespace);
    }
}

#[test]
fn rejects_uts_names_outside_the_supported_profile() {
    let too_long = UTS_CONFIG.replace("a3s-smoke", &"h".repeat(65));
    let error =
        InitPlan::from_bundle(&bundle(&too_long), &null_io()).expect_err("65-byte hostname");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("at most 64 bytes"));

    let too_long = UTS_CONFIG.replace("runtime.test", &"d".repeat(65));
    let error =
        InitPlan::from_bundle(&bundle(&too_long), &null_io()).expect_err("65-byte domainname");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("domainname"));

    let empty_without_uts = FIXED_CONFIG.replace(
        r#""ociVersion": "1.3.0","#,
        r#""ociVersion": "1.3.0", "hostname": "", "domainname": "","#,
    );
    let error = InitPlan::from_bundle(&bundle(&empty_without_uts), &null_io())
        .expect_err("UTS name fields outside UTS profile");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("hostname/domainname"));
}

#[test]
fn rejects_unimplemented_or_joined_namespaces() {
    let mut user: serde_json::Value =
        serde_json::from_str(UTS_CONFIG).expect("decode test configuration");
    let root = user
        .as_object_mut()
        .expect("test configuration must be an object");
    root.remove("hostname");
    root.remove("domainname");
    user["linux"]["namespaces"][0]["type"] = serde_json::Value::String("user".into());
    let user = serde_json::to_string(&user).expect("encode user namespace test");
    let error = InitPlan::from_bundle(&bundle(&user), &null_io())
        .expect_err("single user namespace unsupported");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("namespaces[0].type"));

    let multiple = UTS_CONFIG.replace(r#""type": "uts""#, r#""type": "uts"}, {"type": "user""#);
    let error = InitPlan::from_bundle(&bundle(&multiple), &null_io())
        .expect_err("mixed UTS and user namespaces unsupported");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("linux.namespaces"));

    let joined = UTS_CONFIG.replace(
        r#""type": "uts""#,
        r#""type": "uts", "path": "/proc/1/ns/uts""#,
    );
    let error = InitPlan::from_bundle(&bundle(&joined), &null_io())
        .expect_err("joined UTS namespace unsupported");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("namespaces[0].path"));

    let joined_mount = UTS_CONFIG.replace(
        r#"{"type": "uts"}"#,
        r#"{"type": "uts"}, {"type": "mount", "path": "/proc/1/ns/mnt"}"#,
    );
    let error = InitPlan::from_bundle(&bundle(&joined_mount), &null_io())
        .expect_err("joined mount namespace unsupported");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("namespaces[1].path"));

    let joined_network = UTS_CONFIG.replace(
        r#"{"type": "uts"}"#,
        r#"{"type": "uts"}, {"type": "network", "path": "/proc/1/ns/net"}"#,
    );
    let error = InitPlan::from_bundle(&bundle(&joined_network), &null_io())
        .expect_err("joined network namespace unsupported");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("namespaces[1].path"));

    let joined_pid = UTS_CONFIG.replace(
        r#"{"type": "uts"}"#,
        r#"{"type": "uts"}, {"type": "pid", "path": "/proc/1/ns/pid"}"#,
    );
    let error = InitPlan::from_bundle(&bundle(&joined_pid), &null_io())
        .expect_err("joined PID namespace unsupported");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("namespaces[1].path"));
}
