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
    assert_eq!(registry.len(), 88);
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
            "oomScoreAdj": 100,
            "ioPriority": {
                "class": "IOPRIO_CLASS_BE",
                "priority": 4
            },
            "scheduler": {
                "policy": "SCHED_BATCH",
                "nice": 7,
                "flags": ["SCHED_FLAG_RESET_ON_FORK"]
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
                "cpu": {"quota": 20, "burst": 10, "idle": 1},
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
fn validates_linux_network_device_names_templates_and_exact_targets() {
    let valid = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"},
        "linux": {
            "namespaces": [{"type": "network"}],
            "netDevices": {
                "veth0": {"name": "eth%d"},
                "veth1": {"name": "eth%d"},
                "veth2": {"name": "lan0"}
            }
        }
    });
    OciSemanticValidator::new()
        .expect("construct validator")
        .validate(OciSemanticPhase::Configuration, &valid)
        .expect("valid appended templates and exact target");

    let invalid = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"},
        "linux": {
            "namespaces": [{"type": "network"}],
            "netDevices": {
                "interface-name-too-long": {},
                "veth0": {"name": "eth%d-rest"},
                "veth1": {"name": "lan0"},
                "veth2": {"name": "lan0"},
                "veth3": {"name": "eth%%d"}
            }
        }
    });
    let rules = rules(&invalid, OciSemanticPhase::Configuration);
    for expected in [
        "oci.linux.net-device.host-name.valid",
        "oci.linux.net-device.target-template",
        "oci.linux.net-device.target.unique",
    ] {
        assert!(rules.contains(expected), "missing rule {expected}");
    }
}

#[test]
fn reports_common_cross_field_violations_with_stable_rules() {
    let value = json!({
        "ociVersion": "1.3.0",
        "root": {"path": ""},
        "process": {
            "cwd": "relative",
            "args": [],
            "oomScoreAdj": 1001,
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
        "oci.common.process.oom-score-adj.kernel-range",
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
fn validates_pinned_oci_image_annotation_values() {
    let valid = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"},
        "annotations": {
            "org.opencontainers.image.os": "linux",
            "org.opencontainers.image.os.version": "6.8.0",
            "org.opencontainers.image.architecture": "arm64",
            "org.opencontainers.image.variant": "v8",
            "org.opencontainers.image.author": "A3S Lab <dev@a3s.dev>",
            "org.opencontainers.image.created": "2026-08-17T10:11:12.123456789+08:00",
            "org.opencontainers.image.stopSignal": "SIGRTMIN+3"
        }
    });
    OciSemanticValidator::new()
        .expect("construct semantic validator")
        .validate(OciSemanticPhase::Configuration, &valid)
        .expect("pinned OCI Image Specification values must be accepted");

    let invalid = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"},
        "annotations": {
            "org.opencontainers.image.created": "2026-02-30 10:11:12",
            "org.opencontainers.image.stopSignal": "SIGUNKNOWN"
        }
    });
    let reported = rules(&invalid, OciSemanticPhase::Configuration);
    assert!(reported.contains("oci.common.annotation.image-config.created"));
    assert!(reported.contains("oci.common.annotation.image-config.stop-signal"));
}

#[test]
fn idle_io_priority_rejects_nonzero_class_data() {
    let value = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"},
        "process": {
            "cwd": "/",
            "args": ["/bin/true"],
            "user": {"uid": 0, "gid": 0},
            "ioPriority": {"class": "IOPRIO_CLASS_IDLE", "priority": 4}
        }
    });
    let rules = rules(&value, OciSemanticPhase::Configuration);
    assert!(rules.contains("oci.linux.io-priority.idle-class-data-zero"));
    assert!(!rules.contains("oci.linux.io-priority.range"));
}

#[test]
fn scheduler_semantics_match_the_linux_sched_attr_boundary() {
    let process = |scheduler: Value| {
        json!({
            "ociVersion": "1.3.0",
            "root": {"path": "rootfs"},
            "process": {
                "cwd": "/",
                "args": ["/bin/true"],
                "user": {"uid": 0, "gid": 0},
                "scheduler": scheduler
            }
        })
    };

    let valid_deadline = process(json!({
        "policy": "SCHED_DEADLINE",
        "runtime": 1024,
        "deadline": 2048,
        "period": 0,
        "flags": ["SCHED_FLAG_RECLAIM", "SCHED_FLAG_DL_OVERRUN"]
    }));
    OciSemanticValidator::new()
        .expect("construct validator")
        .validate(OciSemanticPhase::Start, &valid_deadline)
        .expect("deadline period zero uses the kernel-defined deadline default");

    let realtime = rules(
        &process(json!({"policy": "SCHED_FIFO", "priority": 0})),
        OciSemanticPhase::Start,
    );
    assert!(realtime.contains("oci.linux.scheduler.realtime-priority.range"));

    let flags = rules(
        &process(json!({
            "policy": "SCHED_OTHER",
            "flags": ["SCHED_FLAG_RECLAIM", "SCHED_FLAG_RECLAIM"]
        })),
        OciSemanticPhase::Start,
    );
    assert!(flags.contains("oci.linux.scheduler.flag.policy"));
    assert!(flags.contains("oci.linux.scheduler.flags.unique"));

    let deadline = rules(
        &process(json!({
            "policy": "SCHED_DEADLINE",
            "runtime": 1000,
            "deadline": 900,
            "period": 800
        })),
        OciSemanticPhase::Start,
    );
    assert!(deadline.contains("oci.linux.scheduler.deadline-order"));
    assert!(deadline.contains("oci.linux.scheduler.deadline.kernel-range"));
}

#[test]
fn reports_linux_namespace_security_and_resource_relationships() {
    let value = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"},
        "hostname": "semantic-test",
        "domainname": "example.test",
        "linux": {
            "cgroupsPath": "tenant/../workload",
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
                    "idle": 2,
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
                "memBwSchema": "MB:0=20\u{0}",
                "schemata": ["L3:0=ff\nMB:0=20"]
            },
            "memoryPolicy": {"mode": "MPOL_BIND"},
            "personality": {
                "flags": ["ADDR_NO_RANDOMIZE"]
            }
        }
    });
    let rules = rules(&value, OciSemanticPhase::Configuration);
    for expected in [
        "oci.linux.namespace.type.unique",
        "oci.linux.cgroups-path.safe-path",
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
        "oci.linux.cpu.idle-range",
        "oci.linux.cpu.realtime-runtime-at-most-period",
        "oci.linux.block-io.weight-device.weight-required",
        "oci.linux.rdma.limit-required",
        "oci.linux.intel-rdt.clos-id.safe-name",
        "oci.linux.intel-rdt.schemata.single-line",
        "oci.linux.intel-rdt.l3-schema",
        "oci.linux.intel-rdt.memory-bandwidth-schema",
        "oci.linux.memory-policy.nodes-required",
        "oci.linux.personality.domain.required",
        "oci.linux.personality.flags-empty",
    ] {
        assert!(rules.contains(expected), "missing rule {expected}");
    }
}

#[test]
fn bounds_intel_rdt_names_and_schemata_without_rejecting_new_resource_lines() {
    let mut lines = vec!["L2:0=fff".repeat(34); 257];
    lines[0] = format!("L3:0={}", "f".repeat(5_000));
    lines[1] = String::new();
    let bounded = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"},
        "linux": {
            "intelRdt": {
                "closID": "",
                "schemata": lines
            }
        }
    });
    let reported = rules(&bounded, OciSemanticPhase::Configuration);
    for expected in [
        "oci.linux.intel-rdt.clos-id.safe-name",
        "oci.linux.intel-rdt.schemata.count-bounded",
        "oci.linux.intel-rdt.schemata.line-bounded",
        "oci.linux.intel-rdt.schemata.single-line",
        "oci.linux.intel-rdt.schemata.total-bounded",
    ] {
        assert!(reported.contains(expected), "missing rule {expected}");
    }

    let extensible = json!({
        "ociVersion": "1.3.0",
        "root": {"path": "rootfs"},
        "linux": {
            "intelRdt": {
                "closID": "/",
                "schemata": ["L2:0=f", "MBps:0=1024", "SMBA:0=10"]
            }
        }
    });
    OciSemanticValidator::new()
        .expect("construct semantic validator")
        .validate(OciSemanticPhase::Configuration, &extensible)
        .expect("unknown single-line resctrl resources remain extensible");
}

#[test]
fn reports_linux_memory_policy_shape_and_flag_relationships() {
    let cases = [
        json!({
            "ociVersion": "1.3.0",
            "root": {"path": "rootfs"},
            "linux": {"memoryPolicy": {}}
        }),
        json!({
            "ociVersion": "1.3.0",
            "root": {"path": "rootfs"},
            "linux": {
                "memoryPolicy": {
                    "mode": "MPOL_DEFAULT",
                    "nodes": "0-",
                    "flags": ["MPOL_F_NUMA_BALANCING", "MPOL_F_STATIC_NODES"]
                }
            }
        }),
        json!({
            "ociVersion": "1.3.0",
            "root": {"path": "rootfs"},
            "linux": {
                "memoryPolicy": {
                    "mode": "MPOL_BIND",
                    "nodes": "0",
                    "flags": ["MPOL_F_RELATIVE_NODES", "MPOL_F_STATIC_NODES"]
                }
            }
        }),
    ];
    let reported = cases
        .iter()
        .flat_map(|value| rules(value, OciSemanticPhase::Configuration))
        .collect::<BTreeSet<_>>();

    for expected in [
        "oci.linux.memory-policy.mode.required",
        "oci.linux.memory-policy.nodes.format",
        "oci.linux.memory-policy.nodes-forbidden",
        "oci.linux.memory-policy.flags-compatible",
    ] {
        assert!(reported.contains(expected), "missing rule {expected}");
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
