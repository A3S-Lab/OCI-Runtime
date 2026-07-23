use std::collections::BTreeSet;

use oci_spec::runtime::Spec;
use serde_json::{json, Value};

use super::{OciSemanticPhase, OciSemanticValidator, OciSemanticViolationKind};
use crate::ErrorCode;

fn rules(value: &Value, phase: OciSemanticPhase) -> BTreeSet<String> {
    OciSemanticValidator::new()
        .expect("construct semantic validator")
        .inspect(phase, value)
        .expect("inspect schema-valid configuration")
        .violations
        .into_iter()
        .map(|violation| violation.rule)
        .collect()
}

#[test]
fn semantic_rule_registry_is_complete_and_unique() {
    let registry = OciSemanticValidator::rules();
    assert_eq!(registry.len(), 67);
    assert_eq!(
        registry
            .iter()
            .map(|rule| rule.id)
            .collect::<BTreeSet<_>>()
            .len(),
        registry.len()
    );
}

#[test]
fn accepts_upstream_minimal_linux_configuration_and_start_fixtures() {
    let minimal: Value = serde_json::from_str(include_str!(
        "../../../../vendor/runtime-spec/v1.3.0/schema/test/config/good/minimal.json"
    ))
    .expect("decode upstream minimal fixture");
    OciSemanticValidator::new()
        .expect("construct validator")
        .validate(OciSemanticPhase::Configuration, &minimal)
        .expect("minimal configuration semantics");

    let runnable: Value = serde_json::from_str(include_str!(
        "../../../../vendor/runtime-spec/v1.3.0/schema/test/config/good/minimal-for-start.json"
    ))
    .expect("decode upstream runnable fixture");
    OciSemanticValidator::new()
        .expect("construct validator")
        .validate(OciSemanticPhase::Start, &runnable)
        .expect("minimal start semantics");

    let spec: Spec = serde_json::from_value(runnable).expect("decode typed OCI spec");
    OciSemanticValidator::new()
        .expect("construct validator")
        .validate_spec(OciSemanticPhase::Start, &spec)
        .expect("typed start semantics");
}

#[test]
fn start_requires_a_process_but_configuration_loading_does_not() {
    let value = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"}
    });
    OciSemanticValidator::new()
        .expect("construct validator")
        .validate(OciSemanticPhase::Configuration, &value)
        .expect("configuration can omit process");

    let error = OciSemanticValidator::new()
        .expect("construct validator")
        .validate(OciSemanticPhase::Start, &value)
        .expect_err("start must require process");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error
        .message
        .contains("oci.common.process.required-for-start"));
}

#[test]
fn requires_a_root_for_linux_workloads() {
    let value = json!({"ociVersion": "1.3.0"});
    let rules = rules(&value, OciSemanticPhase::Configuration);
    assert!(rules.contains("oci.common.root.required"));
}

#[test]
fn accepts_validated_normative_cross_field_boundaries() {
    let value = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"},
        "process": {
            "cwd": "/",
            "args": ["/bin/true"],
            "user": {"uid": 0, "gid": 0},
            "ioPriority": {
                "class": "IOPRIO_CLASS_BE",
                "priority": 4
            },
            "rlimits": [{
                "type": "RLIMIT_NOFILE",
                "soft": 1024,
                "hard": 1024
            }]
        },
        "mounts": [{
            "destination": "relative-is-valid-but-deprecated",
            "uidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}],
            "gidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}]
        }],
        "hooks": {
            "createRuntime": [{
                "path": "/bin/true",
                "env": ["VALID=yes"]
            }]
        },
        "annotations": {"com.example.valid": "yes"},
        "linux": {
            "uidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}],
            "gidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}],
            "namespaces": [
                {"type": "pid", "path": "/proc/1/ns/pid"},
                {"type": "user"},
                {"type": "mount"}
            ],
            "maskedPaths": ["/proc/kcore"],
            "readonlyPaths": ["/proc/sys"],
            "resources": {
                "cpu": {"quota": 20, "burst": 10},
                "blockIO": {
                    "weightDevice": [{
                        "major": 8,
                        "minor": 0,
                        "weight": 100
                    }]
                },
                "rdma": {"mlx5_0": {"hcaHandles": 1}}
            }
        },
        "vm": {
            "hypervisor": {"path": "/usr/bin/a3s-vmm"},
            "kernel": {
                "path": "/usr/lib/a3s/vmlinux",
                "initrd": "/usr/lib/a3s/initrd"
            },
            "image": {
                "path": "/var/lib/a3s/root.raw",
                "format": "raw"
            }
        }
    });
    OciSemanticValidator::new()
        .expect("construct validator")
        .validate(OciSemanticPhase::Start, &value)
        .expect("normative semantic boundaries must accept valid relationships");
}

#[test]
fn schema_good_net_device_fixture_still_requires_runtime_namespace_semantics() {
    let value: Value = serde_json::from_str(include_str!(
        "../../../../vendor/runtime-spec/v1.3.0/schema/test/config/good/linux-netdevice.json"
    ))
    .expect("decode upstream net-device fixture");
    let rules = rules(&value, OciSemanticPhase::Configuration);
    assert!(rules.contains("oci.linux.net-device.requires-network-namespace"));
}

#[test]
fn reports_common_cross_field_violations_with_stable_rules() {
    let value = json!({
        "ociVersion": "1.3.0",
        "root": {"path": ""},
        "process": {
            "cwd": "relative",
            "args": [],
            "env": ["MISSING_EQUALS", "=empty"],
            "ioPriority": {"class": "IOPRIO_CLASS_BE", "priority": 8},
            "scheduler": {
                "policy": "SCHED_OTHER",
                "nice": 30,
                "priority": 1,
                "runtime": 1
            },
            "rlimits": [
                {"type": "RLIMIT_NOFILE", "soft": 20, "hard": 10},
                {"type": "RLIMIT_NOFILE", "soft": 1, "hard": 2}
            ]
        },
        "mounts": [{
            "destination": "",
            "uidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}]
        }],
        "hooks": {
            "createRuntime": [{"path": "relative-hook"}]
        },
        "annotations": {"": "invalid"}
    });
    let rules = rules(&value, OciSemanticPhase::Configuration);
    for expected in [
        "oci.common.root.path.non-empty",
        "oci.common.process.cwd.absolute",
        "oci.common.process.args.non-empty",
        "oci.common.environment.assignment",
        "oci.common.environment.name.non-empty",
        "oci.linux.io-priority.range",
        "oci.linux.scheduler.nice.range",
        "oci.linux.scheduler.priority.policy",
        "oci.linux.scheduler.deadline-fields.policy",
        "oci.common.rlimit.soft-at-most-hard",
        "oci.common.rlimit.type.unique",
        "oci.common.mount.destination.non-empty",
        "oci.common.mount.id-mappings.paired",
        "oci.common.hook.path.absolute",
        "oci.common.annotation.key.non-empty",
    ] {
        assert!(rules.contains(expected), "missing rule {expected}");
    }
}

#[test]
fn reports_linux_namespace_security_and_resource_relationships() {
    let value = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"},
        "hostname": "semantic-test",
        "domainname": "example.test",
        "linux": {
            "uidMappings": [
                {"containerID": 0, "hostID": 1000, "size": 2},
                {"containerID": 1, "hostID": 2000, "size": 1}
            ],
            "namespaces": [
                {"type": "user", "path": "relative"},
                {"type": "user"}
            ],
            "netDevices": {"bad/name": {}},
            "timeOffsets": {"boottime": {"secs": 1}},
            "sysctl": {
                "net.ipv4.ip_forward": "1",
                "kernel.msgmax": "1024",
                "kernel.hostname": "forbidden",
                "vm.swappiness": "1"
            },
            "maskedPaths": ["relative"],
            "readonlyPaths": ["relative"],
            "seccomp": {
                "defaultAction": "SCMP_ACT_ALLOW",
                "defaultErrnoRet": 1,
                "listenerMetadata": "opaque",
                "syscalls": [{
                    "names": ["read"],
                    "action": "SCMP_ACT_KILL",
                    "errnoRet": 1
                }]
            },
            "resources": {
                "cpu": {
                    "quota": 10,
                    "burst": 20,
                    "realtimeRuntime": 20,
                    "realtimePeriod": 10
                },
                "memory": {"limit": 10, "reservation": 20},
                "blockIO": {
                    "weightDevice": [{"major": 8, "minor": 0}]
                },
                "rdma": {"mlx5_0": {}},
                "hugepageLimits": [
                    {"pageSize": "2MB", "limit": 1},
                    {"pageSize": "2MB", "limit": 2}
                ]
            },
            "intelRdt": {
                "closID": "../escape",
                "l3CacheSchema": "invalid",
                "schemata": ["L3:0=ff\nMB:0=20"]
            },
            "memoryPolicy": {"mode": "MPOL_BIND"}
        }
    });
    let rules = rules(&value, OciSemanticPhase::Configuration);
    for expected in [
        "oci.linux.namespace.type.unique",
        "oci.linux.namespace.path.absolute",
        "oci.linux.id-mapping.container-range.unique",
        "oci.linux.hostname.requires-uts-namespace",
        "oci.linux.domainname.requires-uts-namespace",
        "oci.linux.restricted-path.requires-mount-namespace",
        "oci.linux.net-device.requires-network-namespace",
        "oci.linux.net-device.host-name.valid",
        "oci.linux.time-offset.requires-new-time-namespace",
        "oci.linux.sysctl.requires-network-namespace",
        "oci.linux.sysctl.requires-ipc-namespace",
        "oci.linux.sysctl.hostname-conflict",
        "oci.linux.sysctl.not-namespaced",
        "oci.linux.container-path.absolute",
        "oci.linux.seccomp.listener-metadata.requires-path",
        "oci.linux.seccomp.errno-action",
        "oci.linux.cpu.burst-at-most-quota",
        "oci.linux.cpu.realtime-runtime-at-most-period",
        "oci.linux.block-io.weight-device.weight-required",
        "oci.linux.rdma.limit-required",
        "oci.linux.intel-rdt.clos-id.safe-name",
        "oci.linux.intel-rdt.schemata.single-line",
        "oci.linux.intel-rdt.l3-schema",
        "oci.linux.memory-policy.nodes-required",
    ] {
        assert!(rules.contains(expected), "missing rule {expected}");
    }
}

#[test]
fn validates_vm_paths_without_inventing_hardware_minima() {
    let value = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"},
        "vm": {
            "hypervisor": {"path": "relative-hypervisor"},
            "kernel": {
                "path": "relative-kernel",
                "initrd": "relative-initrd"
            },
            "image": {"path": "relative-image", "format": "raw"},
            "hwConfig": {"vcpus": 0, "memory": 0}
        }
    });
    let report = OciSemanticValidator::new()
        .expect("construct validator")
        .inspect(OciSemanticPhase::Configuration, &value)
        .expect("inspect VM configuration");
    assert_eq!(
        report
            .violations
            .iter()
            .filter(|violation| violation.rule == "oci.vm.path.absolute")
            .count(),
        4
    );
    assert!(!report
        .violations
        .iter()
        .any(|violation| violation.rule == "oci.vm.hardware.nonzero"));

    let windows_paths = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"},
        "vm": {
            "hypervisor": {"path": "C:\\runtime\\vmm.exe"},
            "kernel": {"path": "C:\\runtime\\vmlinux"},
            "image": {"path": "\\\\?\\C:\\runtime\\root.raw", "format": "raw"}
        }
    });
    OciSemanticValidator::new()
        .expect("construct validator")
        .validate(OciSemanticPhase::Configuration, &windows_paths)
        .expect("absolute Windows runtime paths");
}

#[test]
fn rejects_native_non_linux_workload_sections_as_unsupported() {
    let value = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"},
        "windows": {"layerFolders": ["C:\\layers\\base"]}
    });
    let report = OciSemanticValidator::new()
        .expect("construct validator")
        .inspect(OciSemanticPhase::Configuration, &value)
        .expect("inspect native Windows configuration");
    assert_eq!(report.violations.len(), 1);
    assert_eq!(
        report.violations[0].kind,
        OciSemanticViolationKind::UnsupportedPlatform
    );

    let error = OciSemanticValidator::new()
        .expect("construct validator")
        .validate(OciSemanticPhase::Configuration, &value)
        .expect_err("native Windows workload must be rejected");
    assert_eq!(error.code, ErrorCode::Unsupported);
}

#[test]
fn semantic_reports_are_bounded_and_mark_truncation() {
    let mounts = (0..70)
        .map(|_| json!({"destination": ""}))
        .collect::<Vec<_>>();
    let value = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"},
        "mounts": mounts
    });

    let report = OciSemanticValidator::new()
        .expect("construct validator")
        .inspect(OciSemanticPhase::Configuration, &value)
        .expect("inspect schema-valid configuration");
    assert!(!report.valid);
    assert_eq!(report.violations.len(), 64);
    assert!(report.truncated);
}
