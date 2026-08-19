use a3s_oci_sdk::oci_spec::runtime::LinuxResources;
use a3s_oci_sdk::ErrorCode;

use super::state::parse_state;
use super::{RdmaLimit, RdmaPlan};

fn plan(value: serde_json::Value) -> Result<RdmaPlan, a3s_oci_sdk::Error> {
    let resources: LinuxResources =
        serde_json::from_value(serde_json::json!({"rdma": value})).expect("decode RDMA resources");
    RdmaPlan::from_oci(resources.rdma().as_ref())
}

#[test]
fn plans_sorted_partial_and_complete_kernel_limits() {
    let plan = plan(serde_json::json!({
        "rxe3": {"hcaHandles": 2147483647_u32, "hcaObjects": 4294967295_u32},
        "mlx5_1": {"hcaHandles": 3, "hcaObjects": 10000},
        "mlx4_0": {"hcaObjects": 1000}
    }))
    .expect("RDMA plan");
    let values = plan
        .mutations()
        .iter()
        .map(|mutation| mutation.write_value())
        .collect::<Vec<_>>();

    assert_eq!(
        values,
        [
            "mlx4_0 hca_object=1000",
            "mlx5_1 hca_handle=3 hca_object=10000",
            "rxe3 hca_handle=max hca_object=max",
        ]
    );
}

#[test]
fn rejects_empty_or_unsafe_device_entries() {
    let mut oversized = serde_json::Map::new();
    oversized.insert("x".repeat(64), serde_json::json!({"hcaHandles": 1}));
    for value in [
        serde_json::json!({"mlx5_0": {}}),
        serde_json::json!({"": {"hcaHandles": 1}}),
        serde_json::json!({"mlx5 0": {"hcaHandles": 1}}),
        serde_json::json!({"../mlx5_0": {"hcaHandles": 1}}),
        serde_json::json!({"mlx5\n0": {"hcaHandles": 1}}),
        serde_json::Value::Object(oversized),
    ] {
        let error = plan(value).expect_err("invalid RDMA entry must fail planning");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }
}

#[test]
fn parses_complete_kernel_state_and_ignores_future_fields() {
    let state = parse_state(
        "mlx5_1 hca_handle=3 hca_object=10000 future_resource=7\n\
         mlx4_0 hca_handle=max hca_object=1000\n",
    )
    .expect("RDMA state");
    let mlx5 = state
        .get(&super::RdmaDevice::parse("mlx5_1").expect("device"))
        .expect("mlx5 state");
    assert_eq!(mlx5.hca_handles, Some(RdmaLimit::Value(3)));
    assert_eq!(mlx5.hca_objects, Some(RdmaLimit::Value(10_000)));
    let mlx4 = state
        .get(&super::RdmaDevice::parse("mlx4_0").expect("device"))
        .expect("mlx4 state");
    assert_eq!(mlx4.hca_handles, Some(RdmaLimit::Max));
}

#[test]
fn rejects_ambiguous_or_unrepresentable_kernel_state() {
    for value in [
        "mlx5_0 hca_handle=1\n",
        "mlx5_0 hca_handle=1 hca_handle=2 hca_object=3\n",
        "mlx5_0 hca_handle=2147483647 hca_object=3\n",
        "mlx5_0 hca_handle=1 hca_object=2\nmlx5_0 hca_handle=3 hca_object=4\n",
        "mlx5_0 hca_handle hca_object=3\n",
    ] {
        assert!(
            parse_state(value).is_err(),
            "unexpected valid state: {value}"
        );
    }
}

#[test]
fn prepares_partial_update_and_exact_rollback_without_touching_omitted_fields() {
    let state = parse_state("mlx5_0 hca_handle=7 hca_object=11\n").expect("RDMA state");
    let plan = plan(serde_json::json!({
        "mlx5_0": {"hcaObjects": 19}
    }))
    .expect("partial RDMA update");
    let prepared = plan
        .prepare_from_state(&state)
        .expect("prepared RDMA update");

    assert_eq!(prepared.len(), 1);
    assert!(!prepared[0].is_noop());
    assert_eq!(prepared[0].mutation.write_value(), "mlx5_0 hca_object=19");
    assert_eq!(
        prepared[0].rollback_mutation().write_value(),
        "mlx5_0 hca_object=11"
    );
}

#[test]
fn recognizes_noop_updates_after_kernel_max_normalization() {
    let state = parse_state("mlx5_0 hca_handle=max hca_object=max\n").expect("RDMA state");
    let plan = plan(serde_json::json!({
        "mlx5_0": {"hcaHandles": 4294967295_u32}
    }))
    .expect("maximum RDMA update");
    let prepared = plan
        .prepare_from_state(&state)
        .expect("prepared maximum RDMA update");

    assert!(prepared[0].is_noop());
}

#[test]
fn creates_complete_limits_with_exact_read_back() {
    let directory = tempfile::tempdir().expect("temporary RDMA cgroup");
    std::fs::write(
        directory.path().join(super::MAX_FILE),
        "mlx5_0 hca_handle=max hca_object=max\n",
    )
    .expect("initial RDMA state");
    let plan = plan(serde_json::json!({
        "mlx5_0": {"hcaHandles": 3, "hcaObjects": 10000}
    }))
    .expect("RDMA create plan");

    plan.apply_create(directory.path())
        .expect("apply complete RDMA create limits");
    assert_eq!(
        std::fs::read_to_string(directory.path().join(super::MAX_FILE))
            .expect("applied RDMA state"),
        "mlx5_0 hca_handle=3 hca_object=10000"
    );
}

#[test]
fn rejects_missing_controls_and_unknown_devices_before_create_writes() {
    let directory = tempfile::tempdir().expect("temporary RDMA cgroup");
    let plan = plan(serde_json::json!({
        "mlx5_0": {"hcaHandles": 3, "hcaObjects": 10000}
    }))
    .expect("RDMA create plan");

    let error = plan
        .apply_create(directory.path())
        .expect_err("missing RDMA control must fail");
    assert_eq!(error.code, ErrorCode::Unsupported);

    let state = "mlx5_1 hca_handle=max hca_object=max\n";
    std::fs::write(directory.path().join(super::MAX_FILE), state).expect("unrelated RDMA state");
    let error = plan
        .apply_create(directory.path())
        .expect_err("unknown RDMA device must fail");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert_eq!(
        std::fs::read_to_string(directory.path().join(super::MAX_FILE))
            .expect("unchanged RDMA state"),
        state
    );
}

#[tokio::test]
async fn applies_and_rolls_back_complete_live_updates() {
    let directory = tempfile::tempdir().expect("temporary RDMA cgroup");
    std::fs::write(
        directory.path().join(super::MAX_FILE),
        "mlx5_0 hca_handle=7 hca_object=11\n",
    )
    .expect("initial RDMA state");
    let plan = plan(serde_json::json!({
        "mlx5_0": {"hcaHandles": 3, "hcaObjects": 10000}
    }))
    .expect("RDMA update plan");

    let applied = plan
        .prepare_update(directory.path())
        .await
        .expect("prepare RDMA update")
        .apply()
        .await
        .expect("apply RDMA update");
    assert_eq!(
        std::fs::read_to_string(directory.path().join(super::MAX_FILE))
            .expect("updated RDMA state"),
        "mlx5_0 hca_handle=3 hca_object=10000"
    );

    assert!(applied.rollback().await.is_empty());
    assert_eq!(
        std::fs::read_to_string(directory.path().join(super::MAX_FILE))
            .expect("rolled-back RDMA state"),
        "mlx5_0 hca_handle=7 hca_object=11"
    );
}
