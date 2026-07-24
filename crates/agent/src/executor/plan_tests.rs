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
    assert!(!plan.namespaces.new_uts());
    assert!(!plan.namespaces.new_mount());
    assert!(!plan.namespaces.new_ipc());
    assert!(!plan.namespaces.new_network());
    assert!(!plan.namespaces.new_cgroup());
    assert!(!plan.namespaces.new_pid());
    assert!(!plan.namespaces.new_user());
    assert!(!plan.namespaces.new_time());
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
    assert!(plan.namespaces.new_uts());
    assert!(!plan.namespaces.new_mount());
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
    assert!(!plan.namespaces.new_uts());
    assert!(plan.namespaces.new_mount());

    for namespaces in [
        r#"{"type": "uts"}, {"type": "mount"}"#,
        r#"{"type": "mount"}, {"type": "uts"}"#,
    ] {
        let config = UTS_CONFIG.replace(r#"{"type": "uts"}"#, namespaces);
        let plan = InitPlan::from_bundle(&bundle(&config), &null_io())
            .expect("new UTS and mount namespaces");
        assert!(plan.namespaces.new_uts());
        assert!(plan.namespaces.new_mount());
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
        assert!(plan.namespaces.new_ipc());
        assert!(plan.namespaces.new_network());
        assert!(plan.namespaces.new_cgroup());
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
        assert!(plan.namespaces.new_pid());
        assert!(plan.namespaces.new_uts());
        assert!(plan.namespaces.new_mount());
    }
}

#[test]
fn accepts_new_user_and_time_namespaces_with_exact_mappings_and_offsets() {
    let mut config: serde_json::Value =
        serde_json::from_str(FIXED_CONFIG).expect("decode namespace configuration");
    config["linux"] = serde_json::json!({
        "namespaces": [
            {"type": "user"},
            {"type": "time"},
            {"type": "pid"}
        ],
        "uidMappings": [
            {"containerID": 0, "hostID": 1000, "size": 1}
        ],
        "gidMappings": [
            {"containerID": 0, "hostID": 1000, "size": 1}
        ],
        "timeOffsets": {
            "monotonic": {"secs": 3600, "nanosecs": 7},
            "boottime": {"secs": 7200, "nanosecs": 11}
        }
    });
    let config = serde_json::to_string(&config).expect("encode namespace configuration");

    let plan = InitPlan::from_bundle(&bundle(&config), &null_io())
        .expect("new user and time namespace profile");
    assert!(plan.namespaces.new_user());
    assert!(plan.namespaces.new_time());
    assert!(plan.namespaces.requires_child_process());
    assert_eq!(plan.namespaces.uid_mappings().len(), 1);
    assert_eq!(plan.namespaces.gid_mappings().len(), 1);
    assert_eq!(
        plan.namespaces.monotonic_offset(),
        Some(super::namespace::TimeOffset {
            secs: 3600,
            nanosecs: 7,
        })
    );
    assert_eq!(
        plan.namespaces.boottime_offset(),
        Some(super::namespace::TimeOffset {
            secs: 7200,
            nanosecs: 11,
        })
    );
}

#[test]
fn accepts_the_last_uint32_id_in_user_namespace_mappings() {
    let mut config: serde_json::Value =
        serde_json::from_str(FIXED_CONFIG).expect("decode namespace configuration");
    config["process"]["user"]["uid"] = serde_json::json!(u32::MAX);
    config["process"]["user"]["gid"] = serde_json::json!(u32::MAX);
    config["linux"] = serde_json::json!({
        "namespaces": [{"type": "user"}],
        "uidMappings": [
            {"containerID": u32::MAX, "hostID": u32::MAX, "size": 1}
        ],
        "gidMappings": [
            {"containerID": u32::MAX, "hostID": u32::MAX, "size": 1}
        ]
    });
    let config = serde_json::to_string(&config).expect("encode maximum-ID configuration");

    let plan = InitPlan::from_bundle(&bundle(&config), &null_io())
        .expect("the final uint32 ID is a one-element valid range");
    assert!(plan.namespaces.new_user());
    assert!(!plan.namespaces.requires_child_process());
    assert_eq!(plan.namespaces.uid_mappings()[0].container_id, u32::MAX);
    assert_eq!(plan.namespaces.uid_mappings()[0].host_id, u32::MAX);
}

#[test]
fn rejects_incomplete_or_unusable_user_namespace_mappings() {
    let mut missing_gid: serde_json::Value =
        serde_json::from_str(FIXED_CONFIG).expect("decode namespace configuration");
    missing_gid["linux"] = serde_json::json!({
        "namespaces": [{"type": "user"}],
        "uidMappings": [
            {"containerID": 0, "hostID": 1000, "size": 1}
        ]
    });
    let missing_gid =
        serde_json::to_string(&missing_gid).expect("encode incomplete mapping configuration");
    let error = InitPlan::from_bundle(&bundle(&missing_gid), &null_io())
        .expect_err("executor requires both mapping classes");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("both UID and GID mappings"));

    let mut unmapped_uid: serde_json::Value =
        serde_json::from_str(FIXED_CONFIG).expect("decode namespace configuration");
    unmapped_uid["process"]["user"]["uid"] = serde_json::json!(7);
    unmapped_uid["linux"] = serde_json::json!({
        "namespaces": [{"type": "user"}],
        "uidMappings": [
            {"containerID": 0, "hostID": 1000, "size": 1}
        ],
        "gidMappings": [
            {"containerID": 0, "hostID": 1000, "size": 1}
        ]
    });
    let unmapped_uid =
        serde_json::to_string(&unmapped_uid).expect("encode unmapped UID configuration");
    let error = InitPlan::from_bundle(&bundle(&unmapped_uid), &null_io())
        .expect_err("process UID must be mapped");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("process.user.uid value 7"));

    let mut unmapped_gid: serde_json::Value =
        serde_json::from_str(FIXED_CONFIG).expect("decode namespace configuration");
    unmapped_gid["process"]["user"]["gid"] = serde_json::json!(7);
    unmapped_gid["linux"] = serde_json::json!({
        "namespaces": [{"type": "user"}],
        "uidMappings": [
            {"containerID": 0, "hostID": 1000, "size": 1}
        ],
        "gidMappings": [
            {"containerID": 0, "hostID": 1000, "size": 1}
        ]
    });
    let unmapped_gid =
        serde_json::to_string(&unmapped_gid).expect("encode unmapped GID configuration");
    let error = InitPlan::from_bundle(&bundle(&unmapped_gid), &null_io())
        .expect_err("process GID must be mapped");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("process.user.gid value 7"));

    let mut unmapped_additional_gid: serde_json::Value =
        serde_json::from_str(FIXED_CONFIG).expect("decode namespace configuration");
    unmapped_additional_gid["process"]["user"]["additionalGids"] = serde_json::json!([7]);
    unmapped_additional_gid["linux"] = serde_json::json!({
        "namespaces": [{"type": "user"}],
        "uidMappings": [
            {"containerID": 0, "hostID": 1000, "size": 1}
        ],
        "gidMappings": [
            {"containerID": 0, "hostID": 1000, "size": 1}
        ]
    });
    let unmapped_additional_gid = serde_json::to_string(&unmapped_additional_gid)
        .expect("encode unmapped supplementary GID configuration");
    let error = InitPlan::from_bundle(&bundle(&unmapped_additional_gid), &null_io())
        .expect_err("supplementary GIDs must be mapped");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error
        .message
        .contains("process.user.additionalGids[0] value 7"));
}

#[test]
fn rejects_noncanonical_time_namespace_nanoseconds() {
    let mut config: serde_json::Value =
        serde_json::from_str(FIXED_CONFIG).expect("decode namespace configuration");
    config["linux"] = serde_json::json!({
        "namespaces": [{"type": "time"}],
        "timeOffsets": {
            "monotonic": {"secs": 0, "nanosecs": 1000000000}
        }
    });
    let config = serde_json::to_string(&config).expect("encode time offset configuration");
    let error = InitPlan::from_bundle(&bundle(&config), &null_io())
        .expect_err("nanoseconds must be normalized");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("nanosecs"));
}

#[test]
fn bounds_user_namespace_mapping_count() {
    let mappings = (0..=340_u32)
        .map(|id| serde_json::json!({"containerID": id, "hostID": id, "size": 1}))
        .collect::<Vec<_>>();
    let mut config: serde_json::Value =
        serde_json::from_str(FIXED_CONFIG).expect("decode namespace configuration");
    config["linux"] = serde_json::json!({
        "namespaces": [{"type": "user"}],
        "uidMappings": mappings,
        "gidMappings": [
            {"containerID": 0, "hostID": 0, "size": 1}
        ]
    });
    let config = serde_json::to_string(&config).expect("encode excessive mapping configuration");
    let error = InitPlan::from_bundle(&bundle(&config), &null_io())
        .expect_err("kernel mapping count must remain bounded");
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert!(error.message.contains("maximum is 340"));
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
fn accepts_all_joined_namespace_types_and_retains_their_absolute_paths() {
    let mut config: serde_json::Value =
        serde_json::from_str(FIXED_CONFIG).expect("decode namespace configuration");
    config["hostname"] = serde_json::json!("joined-host");
    config["domainname"] = serde_json::json!("joined.test");
    config["linux"] = serde_json::json!({
        "namespaces": [
            {"type": "time", "path": "/proc/42/ns/time"},
            {"type": "pid", "path": "/proc/42/ns/pid"},
            {"type": "user", "path": "/proc/42/ns/user"},
            {"type": "mount", "path": "/proc/42/ns/mnt"},
            {"type": "network", "path": "/proc/42/ns/net"},
            {"type": "ipc", "path": "/proc/42/ns/ipc"},
            {"type": "cgroup", "path": "/proc/42/ns/cgroup"},
            {"type": "uts", "path": "/proc/42/ns/uts"}
        ]
    });
    let config = serde_json::to_string(&config).expect("encode namespace configuration");

    let plan =
        InitPlan::from_bundle(&bundle(&config), &null_io()).expect("all existing Linux namespaces");
    assert_eq!(
        plan.namespaces.joined_uts(),
        Some(std::path::Path::new("/proc/42/ns/uts"))
    );
    assert_eq!(
        plan.namespaces.joined_mount(),
        Some(std::path::Path::new("/proc/42/ns/mnt"))
    );
    assert_eq!(
        plan.namespaces.joined_ipc(),
        Some(std::path::Path::new("/proc/42/ns/ipc"))
    );
    assert_eq!(
        plan.namespaces.joined_network(),
        Some(std::path::Path::new("/proc/42/ns/net"))
    );
    assert_eq!(
        plan.namespaces.joined_cgroup(),
        Some(std::path::Path::new("/proc/42/ns/cgroup"))
    );
    assert_eq!(
        plan.namespaces.joined_pid(),
        Some(std::path::Path::new("/proc/42/ns/pid"))
    );
    assert_eq!(
        plan.namespaces.joined_user(),
        Some(std::path::Path::new("/proc/42/ns/user"))
    );
    assert_eq!(
        plan.namespaces.joined_time(),
        Some(std::path::Path::new("/proc/42/ns/time"))
    );
    assert!(plan.namespaces.requires_child_process());
    assert_eq!(plan.hostname.as_deref(), Some("joined-host"));
    assert_eq!(plan.domainname.as_deref(), Some("joined.test"));
}

#[test]
fn joined_mount_namespaces_do_not_enable_unimplemented_mount_mutation() {
    let mut config: serde_json::Value =
        serde_json::from_str(FIXED_CONFIG).expect("decode namespace configuration");
    config["mounts"] = serde_json::json!([{
        "destination": "/proc",
        "type": "proc",
        "source": "proc"
    }]);
    config["linux"] = serde_json::json!({
        "namespaces": [
            {"type": "mount", "path": "/proc/42/ns/mnt"}
        ]
    });
    let config = serde_json::to_string(&config).expect("encode namespace configuration");

    let error = InitPlan::from_bundle(&bundle(&config), &null_io())
        .expect_err("mount mutation in a shared namespace must remain fail-closed");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error
        .message
        .contains("only in a newly created mount namespace"));
}
