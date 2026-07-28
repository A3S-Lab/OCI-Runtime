use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{
    ErrorCode, IoMode, OciBundle, ProcessIo, TerminalSize, CONTROL_CGROUP_CPU_HEADROOM_ANNOTATION,
    CONTROL_CGROUP_MEMORY_HEADROOM_ANNOTATION, CONTROL_CGROUP_PIDS_HEADROOM_ANNOTATION,
    CONTROL_CGROUP_PROCS_FD, CONTROL_CGROUP_PROCS_FD_ENV,
    CONTROL_WORKLOAD_CGROUP_LAYOUT_ANNOTATION, CONTROL_WORKLOAD_CGROUP_LAYOUT_V1,
    WORKLOAD_CGROUP_PROCS_FD, WORKLOAD_CGROUP_PROCS_FD_ENV,
};

use super::hook::HookSet;
use super::plan::{InitPlan, ProcessPlan};

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
const A3S_BOX_CONFIG: &str = include_str!("../../../../fixtures/a3s-box/config.json");

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
    assert_eq!(plan.capabilities.bounding_count(), 0);
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
fn plans_all_oci_hook_phases_instead_of_rejecting_the_configuration() {
    let mut config: serde_json::Value =
        serde_json::from_str(FIXED_CONFIG).expect("decode fixed config");
    config["hooks"] = serde_json::json!({
        "prestart": [{"path": "/bin/true"}],
        "createRuntime": [{"path": "/bin/true"}],
        "createContainer": [{"path": "/bin/true"}],
        "startContainer": [{"path": "/bin/true"}],
        "poststart": [{"path": "/bin/true"}],
        "poststop": [{"path": "/bin/true"}]
    });
    let config = serde_json::to_string(&config).expect("encode hook configuration");
    let plan = InitPlan::from_bundle(&bundle(&config), &null_io()).expect("complete hook plan");
    assert_ne!(plan.hooks, HookSet::default());
}

#[test]
fn plans_the_exact_a3s_box_compiler_output() {
    let bundle = OciBundle::from_json(
        std::path::PathBuf::from("/var/lib/a3s/boxes/box-123"),
        A3S_BOX_CONFIG,
    )
    .expect("schema-valid A3S Box bundle");
    let plan = InitPlan::from_bundle(&bundle, &null_io())
        .expect("A3S Box compiler output must be executable without translation");

    assert_eq!(
        plan.rootfs,
        std::path::PathBuf::from("/var/lib/a3s/boxes/box-123/rootfs")
    );
    assert_eq!(plan.args, ["/sbin/init"]);
    assert_eq!(plan.mounts.len(), 10);
    assert_eq!(plan.mounts[6].filesystem_type.as_deref(), Some("cgroup2"));
    assert!(plan.namespaces.new_user());
    assert!(plan.namespaces.new_mount());
    assert!(plan.namespaces.new_pid());
    assert!(plan.namespaces.new_ipc());
    assert!(plan.namespaces.new_network());
    assert!(plan.namespaces.new_cgroup());
    assert_eq!(plan.capabilities.bounding_count(), 11);
    assert_eq!(plan.annotations.len(), 4);
    assert_eq!(plan.devices.len(), 6);
    assert!(plan.seccomp.is_enabled());
    assert_eq!(plan.seccomp.filter_count(), 2);
}

#[test]
fn plans_versioned_control_workload_cgroups_with_reserved_descriptors() {
    let mut config: serde_json::Value =
        serde_json::from_str(A3S_BOX_CONFIG).expect("decode A3S Box config");
    config["annotations"][CONTROL_WORKLOAD_CGROUP_LAYOUT_ANNOTATION] =
        serde_json::json!(CONTROL_WORKLOAD_CGROUP_LAYOUT_V1);
    config["annotations"][CONTROL_CGROUP_MEMORY_HEADROOM_ANNOTATION] =
        serde_json::json!("67108864");
    config["annotations"][CONTROL_CGROUP_CPU_HEADROOM_ANNOTATION] = serde_json::json!("25000");
    config["annotations"][CONTROL_CGROUP_PIDS_HEADROOM_ANNOTATION] = serde_json::json!("16");
    let config = serde_json::to_string(&config).expect("encode cgroup layout config");
    let plan = InitPlan::from_bundle(&bundle(&config), &null_io())
        .expect("control/workload cgroup layout");

    assert!(plan.cgroup.uses_control_workload_layout());
    assert!(plan.namespaces.new_cgroup());
    assert!(plan.environment.contains(&format!(
        "{CONTROL_CGROUP_PROCS_FD_ENV}={CONTROL_CGROUP_PROCS_FD}"
    )));
    assert!(plan.environment.contains(&format!(
        "{WORKLOAD_CGROUP_PROCS_FD_ENV}={WORKLOAD_CGROUP_PROCS_FD}"
    )));
}

#[test]
fn rejects_control_workload_layout_without_new_namespace_or_with_spoofed_environment() {
    let mut config: serde_json::Value =
        serde_json::from_str(A3S_BOX_CONFIG).expect("decode A3S Box config");
    config["annotations"][CONTROL_WORKLOAD_CGROUP_LAYOUT_ANNOTATION] =
        serde_json::json!(CONTROL_WORKLOAD_CGROUP_LAYOUT_V1);
    config["annotations"][CONTROL_CGROUP_MEMORY_HEADROOM_ANNOTATION] =
        serde_json::json!("67108864");
    config["annotations"][CONTROL_CGROUP_CPU_HEADROOM_ANNOTATION] = serde_json::json!("25000");
    config["annotations"][CONTROL_CGROUP_PIDS_HEADROOM_ANNOTATION] = serde_json::json!("16");

    let mut no_namespace = config.clone();
    no_namespace["linux"]["namespaces"]
        .as_array_mut()
        .expect("namespace array")
        .retain(|namespace| namespace["type"] != "cgroup");
    let no_namespace = serde_json::to_string(&no_namespace).expect("encode namespace config");
    assert!(InitPlan::from_bundle(&bundle(&no_namespace), &null_io())
        .expect_err("new cgroup namespace is required")
        .message
        .contains("newly created Linux cgroup namespace"));

    let mut writable_mount = config.clone();
    let cgroup_mount = writable_mount["mounts"]
        .as_array_mut()
        .expect("mount array")
        .iter_mut()
        .find(|mount| mount["destination"] == "/sys/fs/cgroup")
        .expect("cgroup mount");
    cgroup_mount["options"] = serde_json::json!(["nosuid", "noexec", "nodev", "rw"]);
    let writable_mount =
        serde_json::to_string(&writable_mount).expect("encode writable cgroup mount config");
    assert!(InitPlan::from_bundle(&bundle(&writable_mount), &null_io())
        .expect_err("writable cgroup mount must fail")
        .message
        .contains("exactly one read-only cgroup2 mount"));

    config["process"]["env"]
        .as_array_mut()
        .expect("process environment")
        .push(serde_json::json!(format!(
            "{CONTROL_CGROUP_PROCS_FD_ENV}=99"
        )));
    let spoofed = serde_json::to_string(&config).expect("encode spoofed environment config");
    assert!(InitPlan::from_bundle(&bundle(&spoofed), &null_io())
        .expect_err("reserved cgroup environment must not be spoofed")
        .message
        .contains("reserved by the control/workload cgroup layout"));
}

#[test]
fn builds_the_same_fail_closed_plan_for_an_exec_process() {
    let process: Process = serde_json::from_value(
        serde_json::from_str::<serde_json::Value>(FIXED_CONFIG).expect("decode fixed config")
            ["process"]
            .clone(),
    )
    .expect("decode fixed process");
    let plan = ProcessPlan::from_process(&process, &null_io()).expect("supported exec process");
    assert_eq!(plan.args, ["/bin/sh", "-c", "printf ready"]);
    assert_eq!(plan.cwd, "/");
    assert_eq!(plan.umask, Some(0o22));
    assert!(plan.no_new_privileges);

    let encoded = serde_json::to_vec(&plan).expect("encode process plan");
    assert_eq!(
        serde_json::from_slice::<ProcessPlan>(&encoded).expect("decode process plan"),
        plan
    );
}

#[test]
fn plans_and_serializes_every_oci_process_rlimit() {
    let rlimits = serde_json::json!([
        {"type": "RLIMIT_CPU", "hard": 101, "soft": 100},
        {"type": "RLIMIT_FSIZE", "hard": 201, "soft": 200},
        {"type": "RLIMIT_DATA", "hard": 301, "soft": 300},
        {"type": "RLIMIT_STACK", "hard": 401, "soft": 400},
        {"type": "RLIMIT_CORE", "hard": 501, "soft": 500},
        {"type": "RLIMIT_RSS", "hard": 601, "soft": 600},
        {"type": "RLIMIT_NPROC", "hard": 701, "soft": 700},
        {"type": "RLIMIT_NOFILE", "hard": 801, "soft": 800},
        {"type": "RLIMIT_MEMLOCK", "hard": 901, "soft": 900},
        {"type": "RLIMIT_AS", "hard": 1001, "soft": 1000},
        {"type": "RLIMIT_LOCKS", "hard": 1101, "soft": 1100},
        {"type": "RLIMIT_SIGPENDING", "hard": 1201, "soft": 1200},
        {"type": "RLIMIT_MSGQUEUE", "hard": 1301, "soft": 1300},
        {"type": "RLIMIT_NICE", "hard": 1401, "soft": 1400},
        {"type": "RLIMIT_RTPRIO", "hard": 1501, "soft": 1500},
        {"type": "RLIMIT_RTTIME", "hard": 1601, "soft": 1600}
    ]);
    let mut config: serde_json::Value =
        serde_json::from_str(FIXED_CONFIG).expect("decode fixed config");
    config["process"]["rlimits"] = rlimits;
    let encoded_config = serde_json::to_string(&config).expect("encode rlimit configuration");

    let init = InitPlan::from_bundle(&bundle(&encoded_config), &null_io())
        .expect("plan every OCI rlimit for init");
    assert_eq!(init.rlimits.len(), 16);

    let process: Process =
        serde_json::from_value(config["process"].clone()).expect("decode rlimit process");
    let exec =
        ProcessPlan::from_process(&process, &null_io()).expect("plan every OCI rlimit for exec");
    assert_eq!(exec.rlimits.len(), 16);
    let encoded = serde_json::to_vec(&exec).expect("encode exec process plan");
    assert_eq!(
        serde_json::from_slice::<ProcessPlan>(&encoded).expect("decode exec process plan"),
        exec
    );
}

#[test]
fn rejects_invalid_or_unbounded_process_rlimits() {
    let mut config: serde_json::Value =
        serde_json::from_str(FIXED_CONFIG).expect("decode fixed config");
    config["process"]["rlimits"] = serde_json::json!([
        {"type": "RLIMIT_NOFILE", "hard": 64, "soft": 32},
        {"type": "RLIMIT_NOFILE", "hard": 128, "soft": 64}
    ]);
    let duplicate: Process = serde_json::from_value(config["process"].clone())
        .expect("decode duplicate process rlimits");
    let error = ProcessPlan::from_process(&duplicate, &null_io())
        .expect_err("duplicate rlimit types must fail");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("duplicate RLIMIT_NOFILE"));

    config["process"]["rlimits"] =
        serde_json::json!([{"type": "RLIMIT_NOFILE", "hard": 31, "soft": 32}]);
    let inverted: Process =
        serde_json::from_value(config["process"].clone()).expect("decode inverted process rlimit");
    let error = ProcessPlan::from_process(&inverted, &null_io())
        .expect_err("rlimit soft above hard must fail");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("soft must not exceed hard"));

    config["process"]["rlimits"] = serde_json::Value::Array(
        (0..17)
            .map(|_| serde_json::json!({"type": "RLIMIT_CPU", "hard": 1, "soft": 1}))
            .collect(),
    );
    let excessive: Process = serde_json::from_value(config["process"].clone())
        .expect("decode excessive process rlimits");
    let error = ProcessPlan::from_process(&excessive, &null_io())
        .expect_err("rlimit count must remain bounded");
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert!(error.message.contains("maximum is 16"));
}

#[test]
fn exec_process_planning_enforces_capabilities_and_rejects_unsupported_io() {
    let mut value = serde_json::from_str::<serde_json::Value>(FIXED_CONFIG)
        .expect("decode fixed config")["process"]
        .clone();
    value["capabilities"] = serde_json::json!({
        "bounding": [],
        "effective": [],
        "inheritable": [],
        "permitted": [],
        "ambient": []
    });
    let process: Process = serde_json::from_value(value).expect("decode process");
    let plan = ProcessPlan::from_process(&process, &null_io()).expect("empty capability profile");
    assert_eq!(plan.capabilities.bounding_count(), 0);

    let process: Process = serde_json::from_value(
        serde_json::from_str::<serde_json::Value>(FIXED_CONFIG).expect("decode fixed config")
            ["process"]
            .clone(),
    )
    .expect("decode fixed process");
    let mut io = null_io();
    io.stdout = IoMode::Capture;
    let plan = ProcessPlan::from_process(&process, &io).expect("captured stdout");
    assert_eq!(plan.args[0], "/bin/sh");

    io.stdout = IoMode::Pipe;
    let error =
        ProcessPlan::from_process(&process, &io).expect_err("streaming stdout remains unsupported");
    assert_eq!(error.code, ErrorCode::Unsupported);
}

#[test]
fn bounded_device_profiles_reject_cap_mknod() {
    let mut config: serde_json::Value =
        serde_json::from_str(FIXED_CONFIG).expect("decode fixed config");
    config["process"]["capabilities"] = serde_json::json!({
        "bounding": ["CAP_MKNOD"],
        "effective": ["CAP_MKNOD"],
        "inheritable": [],
        "permitted": ["CAP_MKNOD"],
        "ambient": []
    });
    config["linux"] = serde_json::json!({
        "namespaces": [{"type": "mount"}],
        "resources": {
            "devices": [{"allow": false, "access": "rwm"}]
        }
    });
    let config = serde_json::to_string(&config).expect("encode device configuration");
    let error = InitPlan::from_bundle(&bundle(&config), &null_io())
        .expect_err("CAP_MKNOD would bypass the bounded device profile");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("CAP_MKNOD"));
}

#[test]
fn rejects_every_unimplemented_property_instead_of_ignoring_it() {
    let config = FIXED_CONFIG.replace(
        r#""noNewPrivileges": true"#,
        r#""noNewPrivileges": true,
           "apparmorProfile": "a3s-test""#,
    );
    let error = InitPlan::from_bundle(&bundle(&config), &null_io())
        .expect_err("AppArmor profile remains unsupported");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("process.apparmorProfile"));

    let config = FIXED_CONFIG.replace(
        r#""ociVersion": "1.3.0","#,
        r#""ociVersion": "1.3.0",
           "linux": {"mountLabel": "system_u:object_r:container_file_t:s0"},"#,
    );
    let error = InitPlan::from_bundle(&bundle(&config), &null_io())
        .expect_err("mount label enforcement remains unsupported");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("linux.mountLabel"));
}

#[test]
fn accepts_capture_pipe_and_inherited_process_io() {
    let mut io = null_io();
    io.stdin = IoMode::Pipe;
    io.stdout = IoMode::Capture;
    io.stderr = IoMode::Capture;
    InitPlan::from_bundle(&bundle(FIXED_CONFIG), &io).expect("captured process I/O");

    io.stdin = IoMode::Inherit;
    io.stdout = IoMode::Inherit;
    io.stderr = IoMode::Inherit;
    InitPlan::from_bundle(&bundle(FIXED_CONFIG), &io).expect("inherited process I/O");
}

#[test]
fn accepts_only_the_exact_terminal_process_io_contract() {
    let mut value =
        serde_json::from_str::<serde_json::Value>(FIXED_CONFIG).expect("decode fixed config");
    value["process"]["terminal"] = serde_json::Value::Bool(true);
    let config = serde_json::to_string(&value).expect("encode terminal config");
    let terminal_io = ProcessIo {
        stdin: IoMode::Terminal,
        stdout: IoMode::Terminal,
        stderr: IoMode::Terminal,
        terminal_size: Some(TerminalSize {
            width: 80,
            height: 24,
        }),
    };

    let plan =
        InitPlan::from_bundle(&bundle(&config), &terminal_io).expect("terminal init process plan");
    assert!(plan.terminal);

    let process: Process =
        serde_json::from_value(value["process"].clone()).expect("decode terminal process");
    let plan =
        ProcessPlan::from_process(&process, &terminal_io).expect("terminal exec process plan");
    assert!(plan.terminal);

    let mut partial = terminal_io.clone();
    partial.stderr = IoMode::Capture;
    let error = ProcessPlan::from_process(&process, &partial)
        .expect_err("partial terminal descriptors must fail");
    assert_eq!(error.code, ErrorCode::InvalidArgument);

    let mut missing_size = terminal_io;
    missing_size.terminal_size = None;
    let error = ProcessPlan::from_process(&process, &missing_size)
        .expect_err("terminal dimensions are required");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
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
            {"containerID": 0, "hostID": 0, "size": 1},
            {"containerID": u32::MAX, "hostID": u32::MAX, "size": 1}
        ],
        "gidMappings": [
            {"containerID": 0, "hostID": 0, "size": 1},
            {"containerID": u32::MAX, "hostID": u32::MAX, "size": 1}
        ]
    });
    let config = serde_json::to_string(&config).expect("encode maximum-ID configuration");

    let plan = InitPlan::from_bundle(&bundle(&config), &null_io())
        .expect("the final uint32 ID is a one-element valid range");
    assert!(plan.namespaces.new_user());
    assert_eq!(plan.namespaces.uid_mappings()[1].container_id, u32::MAX);
    assert_eq!(plan.namespaces.uid_mappings()[1].host_id, u32::MAX);
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

    let mut unmapped_root: serde_json::Value =
        serde_json::from_str(FIXED_CONFIG).expect("decode namespace configuration");
    unmapped_root["process"]["user"]["uid"] = serde_json::json!(7);
    unmapped_root["process"]["user"]["gid"] = serde_json::json!(7);
    unmapped_root["linux"] = serde_json::json!({
        "namespaces": [{"type": "user"}],
        "uidMappings": [
            {"containerID": 7, "hostID": 1000, "size": 1}
        ],
        "gidMappings": [
            {"containerID": 7, "hostID": 1000, "size": 1}
        ]
    });
    let unmapped_root =
        serde_json::to_string(&unmapped_root).expect("encode rootless mapping configuration");
    let error = InitPlan::from_bundle(&bundle(&unmapped_root), &null_io())
        .expect_err("rootful executor requires container root mappings");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("container root UID value 0"));

    let mut unmapped_root_gid: serde_json::Value =
        serde_json::from_str(FIXED_CONFIG).expect("decode namespace configuration");
    unmapped_root_gid["process"]["user"]["gid"] = serde_json::json!(7);
    unmapped_root_gid["linux"] = serde_json::json!({
        "namespaces": [{"type": "user"}],
        "uidMappings": [
            {"containerID": 0, "hostID": 1000, "size": 1}
        ],
        "gidMappings": [
            {"containerID": 7, "hostID": 1000, "size": 1}
        ]
    });
    let unmapped_root_gid = serde_json::to_string(&unmapped_root_gid)
        .expect("encode rootless GID mapping configuration");
    let error = InitPlan::from_bundle(&bundle(&unmapped_root_gid), &null_io())
        .expect_err("rootful executor requires a container root GID mapping");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("container root GID value 0"));

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
