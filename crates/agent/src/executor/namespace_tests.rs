use std::path::Path;

use a3s_oci_sdk::oci_spec::runtime::Linux;
use a3s_oci_sdk::ErrorCode;

use super::{
    ensure_id_mapped, validate_observed_mappings, IdMapping, NamespacePlan, TimeOffset,
    MAX_ID_MAPPINGS,
};

fn mapping(container_id: u32, host_id: u32, size: u32) -> IdMapping {
    IdMapping {
        container_id,
        host_id,
        size,
    }
}

#[test]
fn observed_joined_user_mappings_are_bounded_validated_and_sorted() {
    let mappings =
        validate_observed_mappings("UID", vec![mapping(500, 5_000, 10), mapping(0, 1_000, 100)])
            .expect("valid observed mappings");

    assert_eq!(
        mappings,
        vec![mapping(0, 1_000, 100), mapping(500, 5_000, 10)]
    );
    ensure_id_mapped("container root UID", 0, &mappings).expect("mapped namespace root");
    ensure_id_mapped("process.user.uid", 509, &mappings).expect("mapped process UID");
    assert!(ensure_id_mapped("process.user.uid", 510, &mappings).is_err());
}

#[test]
fn observed_joined_user_mappings_reject_unusable_kernel_rows() {
    for (label, mappings) in [
        ("empty", Vec::new()),
        ("zero-sized", vec![mapping(0, 1_000, 0)]),
        ("container overflow", vec![mapping(u32::MAX, 1_000, 2)]),
        ("host overflow", vec![mapping(0, u32::MAX, 2)]),
        (
            "container overlap",
            vec![mapping(0, 1_000, 10), mapping(9, 2_000, 10)],
        ),
        (
            "host overlap",
            vec![mapping(0, 1_000, 10), mapping(20, 1_009, 10)],
        ),
    ] {
        let error = validate_observed_mappings("UID", mappings)
            .expect_err(&format!("reject {label} mapping"));
        assert_eq!(error.code, ErrorCode::FailedPrecondition, "{label}");
    }

    let error = validate_observed_mappings(
        "UID",
        (0..=MAX_ID_MAPPINGS)
            .map(|index| mapping(index as u32, index as u32, 1))
            .collect(),
    )
    .expect_err("reject excessive mapping count");
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
}

#[test]
fn namespace_plan_preserves_inherit_create_and_join_for_every_type() {
    let inherited = NamespacePlan::from_linux(Some(&linux(serde_json::json!({}))), 0, 0, &[])
        .expect("inherited namespace plan");
    assert!(!inherited.new_uts());
    assert!(!inherited.new_mount());
    assert!(!inherited.new_ipc());
    assert!(!inherited.new_network());
    assert!(!inherited.new_cgroup());
    assert!(!inherited.new_pid());
    assert!(!inherited.new_user());
    assert!(!inherited.new_time());
    assert!(inherited.joined_uts().is_none());
    assert!(inherited.joined_mount().is_none());
    assert!(inherited.joined_ipc().is_none());
    assert!(inherited.joined_network().is_none());
    assert!(inherited.joined_cgroup().is_none());
    assert!(inherited.joined_pid().is_none());
    assert!(inherited.joined_user().is_none());
    assert!(inherited.joined_time().is_none());

    let created = NamespacePlan::from_linux(
        Some(&linux(serde_json::json!({
            "namespaces": [
                {"type": "uts"},
                {"type": "mount"},
                {"type": "ipc"},
                {"type": "network"},
                {"type": "cgroup"},
                {"type": "pid"},
                {"type": "user"},
                {"type": "time"}
            ],
            "uidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}],
            "gidMappings": [{"containerID": 0, "hostID": 2000, "size": 1}]
        }))),
        0,
        0,
        &[],
    )
    .expect("created namespace plan");
    assert!(created.new_uts());
    assert!(created.new_mount());
    assert!(created.new_ipc());
    assert!(created.new_network());
    assert!(created.new_cgroup());
    assert!(created.new_pid());
    assert!(created.new_user());
    assert!(created.new_time());

    let joined = NamespacePlan::from_linux(
        Some(&linux(serde_json::json!({
            "namespaces": [
                {"type": "uts", "path": "/proc/42/ns/uts"},
                {"type": "mount", "path": "/proc/42/ns/mnt"},
                {"type": "ipc", "path": "/proc/42/ns/ipc"},
                {"type": "network", "path": "/proc/42/ns/net"},
                {"type": "cgroup", "path": "/proc/42/ns/cgroup"},
                {"type": "pid", "path": "/proc/42/ns/pid"},
                {"type": "user", "path": "/proc/42/ns/user"},
                {"type": "time", "path": "/proc/42/ns/time"}
            ]
        }))),
        0,
        0,
        &[],
    )
    .expect("joined namespace plan");
    assert_eq!(joined.joined_uts(), Some(Path::new("/proc/42/ns/uts")));
    assert_eq!(joined.joined_mount(), Some(Path::new("/proc/42/ns/mnt")));
    assert_eq!(joined.joined_ipc(), Some(Path::new("/proc/42/ns/ipc")));
    assert_eq!(joined.joined_network(), Some(Path::new("/proc/42/ns/net")));
    assert_eq!(
        joined.joined_cgroup(),
        Some(Path::new("/proc/42/ns/cgroup"))
    );
    assert_eq!(joined.joined_pid(), Some(Path::new("/proc/42/ns/pid")));
    assert_eq!(joined.joined_user(), Some(Path::new("/proc/42/ns/user")));
    assert_eq!(joined.joined_time(), Some(Path::new("/proc/42/ns/time")));
}

#[test]
fn configured_user_mappings_preserve_exact_ranges_and_host_translation() {
    let plan = NamespacePlan::from_linux(
        Some(&linux(serde_json::json!({
            "namespaces": [{"type": "user"}],
            "uidMappings": [
                {"containerID": 100, "hostID": 5000, "size": 10},
                {"containerID": 0, "hostID": 1000, "size": 1}
            ],
            "gidMappings": [
                {"containerID": 100, "hostID": 6000, "size": 10},
                {"containerID": 0, "hostID": 2000, "size": 1}
            ]
        }))),
        109,
        109,
        &[108],
    )
    .expect("exact user mapping plan");

    assert_eq!(
        plan.uid_mappings(),
        &[mapping(0, 1000, 1), mapping(100, 5000, 10)]
    );
    assert_eq!(
        plan.gid_mappings(),
        &[mapping(0, 2000, 1), mapping(100, 6000, 10)]
    );
    assert_eq!(plan.host_uid(109), Some(5009));
    assert_eq!(plan.host_gid(108), Some(6008));
}

#[test]
fn inherited_user_namespace_preserves_host_identity_translation() {
    let plan = NamespacePlan::from_linux(Some(&linux(serde_json::json!({}))), 0, 0, &[])
        .expect("inherited user namespace plan");

    assert!(!plan.has_user());
    assert_eq!(plan.host_uid(0), Some(0));
    assert_eq!(plan.host_uid(4_294), Some(4_294));
    assert_eq!(plan.host_gid(0), Some(0));
    assert_eq!(plan.host_gid(6_553), Some(6_553));
}

#[test]
fn time_offset_plan_defaults_omitted_members_without_losing_signed_seconds() {
    let plan = NamespacePlan::from_linux(
        Some(&linux(serde_json::json!({
            "namespaces": [{"type": "time"}],
            "timeOffsets": {
                "monotonic": {"secs": -7},
                "boottime": {"nanosecs": 11}
            }
        }))),
        0,
        0,
        &[],
    )
    .expect("time offset plan");

    assert_eq!(
        plan.monotonic_offset(),
        Some(TimeOffset {
            secs: -7,
            nanosecs: 0,
        })
    );
    assert_eq!(
        plan.boottime_offset(),
        Some(TimeOffset {
            secs: 0,
            nanosecs: 11,
        })
    );
}

fn linux(value: serde_json::Value) -> Linux {
    serde_json::from_value(value).expect("decode Linux namespace fixture")
}
