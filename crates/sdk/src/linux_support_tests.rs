use oci_spec::runtime::{LinuxResources, Spec};
use serde_json::{json, Value};

use super::OciLinuxSupport;
use crate::{
    ErrorCode, OCI_LINUX_CAPABILITY_NAMES, OCI_LINUX_MEMORY_POLICY_FLAGS,
    OCI_LINUX_MEMORY_POLICY_MODES, OCI_LINUX_SECCOMP_ACTIONS, OCI_LINUX_SECCOMP_ARCHITECTURES,
    OCI_LINUX_SECCOMP_KNOWN_FLAGS, OCI_LINUX_SECCOMP_OPERATORS,
};

const TEST_OPERATION: &str = "test-linux-support";

#[test]
fn shared_executor_profile_is_complete_deterministic_and_self_consistent() {
    let support = OciLinuxSupport::shared_executor().expect("shared Linux support");
    assert!(support
        .mount_options()
        .windows(2)
        .all(|pair| pair[0] < pair[1]));
    assert!(support
        .mount_options()
        .iter()
        .any(|option| option == "rnodev"));
    assert!(!support
        .mount_options()
        .iter()
        .any(|option| option == "tmpcopyup"));

    let linux = support.linux();
    assert_eq!(
        linux.capabilities().as_deref(),
        Some(
            OCI_LINUX_CAPABILITY_NAMES
                .iter()
                .map(|name| (*name).to_string())
                .collect::<Vec<_>>()
                .as_slice()
        )
    );
    let cgroup = linux.cgroup().as_ref().expect("cgroup support");
    assert_eq!(*cgroup.v1(), Some(false));
    assert_eq!(*cgroup.v2(), Some(true));
    assert_eq!(*cgroup.systemd(), Some(false));
    assert_eq!(*cgroup.systemd_user(), Some(false));
    assert_eq!(*cgroup.rdma(), Some(true));

    let seccomp = linux.seccomp().as_ref().expect("seccomp support");
    assert_eq!(
        seccomp.actions().as_deref(),
        Some(OCI_LINUX_SECCOMP_ACTIONS)
    );
    assert_eq!(
        seccomp.archs().as_deref(),
        Some(OCI_LINUX_SECCOMP_ARCHITECTURES)
    );
    assert_eq!(
        seccomp.operators().as_deref(),
        Some(
            OCI_LINUX_SECCOMP_OPERATORS
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .as_slice()
        )
    );
    assert_eq!(
        seccomp.known_flags().as_deref(),
        Some(
            OCI_LINUX_SECCOMP_KNOWN_FLAGS
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .as_slice()
        )
    );
    assert_eq!(seccomp.supported_flags().as_deref(), Some([].as_slice()));

    let policy = linux
        .memory_policy()
        .as_ref()
        .expect("memory-policy support");
    assert_eq!(
        policy.modes().as_deref(),
        Some(
            OCI_LINUX_MEMORY_POLICY_MODES
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .as_slice()
        )
    );
    assert_eq!(
        policy.flags().as_deref(),
        Some(
            OCI_LINUX_MEMORY_POLICY_FLAGS
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .as_slice()
        )
    );
}

#[test]
fn shared_executor_profile_accepts_the_complete_native_configuration() {
    let spec: Spec =
        serde_json::from_str(include_str!("../../../fixtures/native-linux/config.json"))
            .expect("decode native Linux fixture");
    OciLinuxSupport::shared_executor()
        .expect("shared Linux support")
        .validate_spec(&spec, TEST_OPERATION)
        .expect("native Linux fixture must fit the shared support profile");
}

#[test]
fn support_profile_rejects_every_unadvertised_linux_feature_class() {
    let support = OciLinuxSupport::shared_executor().expect("shared Linux support");
    for (field, mutation) in [
        (
            "process.apparmorProfile",
            json!({"process": {"apparmorProfile": "a3s-test"}}),
        ),
        (
            "process.selinuxLabel",
            json!({"process": {"selinuxLabel": "system_u:system_r:container_t:s0"}}),
        ),
        (
            "linux.mountLabel",
            json!({"linux": {"mountLabel": "system_u:object_r:container_file_t:s0"}}),
        ),
        (
            "mounts[0].options",
            json!({"mounts": [{"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["tmpcopyup"]}]}),
        ),
        (
            "linux.resources.memory.kernel",
            json!({"linux": {"resources": {"memory": {"kernel": 4096}}}}),
        ),
        (
            "linux.resources.cpu.realtimeRuntime",
            json!({"linux": {"resources": {"cpu": {"realtimeRuntime": 1000}}}}),
        ),
        (
            "linux.resources.blockIO.leafWeight",
            json!({"linux": {"resources": {"blockIO": {"leafWeight": 100}}}}),
        ),
        (
            "linux.resources.network",
            json!({"linux": {"resources": {"network": {"classID": 1}}}}),
        ),
        (
            "linux.seccomp.defaultAction",
            json!({"linux": {"seccomp": {"defaultAction": "SCMP_ACT_NOTIFY"}}}),
        ),
        (
            "linux.seccomp.flags[0]",
            json!({"linux": {"seccomp": {"defaultAction": "SCMP_ACT_ALLOW", "flags": ["SECCOMP_FILTER_FLAG_LOG"]}}}),
        ),
    ] {
        let spec = spec_with(mutation);
        let error = support
            .validate_spec(&spec, TEST_OPERATION)
            .expect_err("unadvertised Linux feature must be rejected");
        assert_eq!(error.code, ErrorCode::Unsupported, "{field}");
        assert_eq!(error.operation.as_deref(), Some(TEST_OPERATION), "{field}");
        assert!(error.message.contains(field), "{field}: {}", error.message);
    }
}

#[test]
fn resource_update_uses_the_same_cgroup_support_profile() {
    let support = OciLinuxSupport::shared_executor().expect("shared Linux support");
    let resources: LinuxResources = serde_json::from_value(json!({
        "memory": {"checkBeforeUpdate": true}
    }))
    .expect("decode schema-valid resource update");
    let error = support
        .validate_resources(&resources, "update")
        .expect_err("cgroup v1-only update must be rejected");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error
        .message
        .contains("linux.resources.memory.checkBeforeUpdate"));
}

#[test]
fn custom_profiles_are_canonical_and_reject_contradictory_registries() {
    let shared = OciLinuxSupport::shared_executor().expect("shared Linux support");
    let mut linux = serde_json::to_value(shared.linux()).expect("encode Linux Features");
    linux["seccomp"]["supportedFlags"] = json!(["SECCOMP_FILTER_FLAG_LOG"]);
    linux["seccomp"]["knownFlags"] = json!([]);
    let linux = serde_json::from_value(linux).expect("decode inconsistent Linux Features");
    let error = OciLinuxSupport::new(shared.mount_options().to_vec(), linux)
        .expect_err("supportedFlags must be a subset of knownFlags");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("absent from knownFlags"));

    let error = OciLinuxSupport::new(
        vec!["ro".to_string(), "ro".to_string()],
        shared.linux().clone(),
    )
    .expect_err("duplicate mount options must be rejected");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
}

fn spec_with(mutation: Value) -> Spec {
    let mut value = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"},
        "process": {
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/true"],
            "cwd": "/",
            "noNewPrivileges": true
        }
    });
    merge(&mut value, mutation);
    serde_json::from_value(value).expect("decode Linux support fixture")
}

fn merge(target: &mut Value, source: Value) {
    match (target, source) {
        (Value::Object(target), Value::Object(source)) => {
            for (key, value) in source {
                merge(target.entry(key).or_insert(Value::Null), value);
            }
        }
        (target, source) => *target = source,
    }
}
