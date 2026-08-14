use a3s_oci_sdk::ErrorCode;

use super::{ensure_id_mapped, validate_observed_mappings, IdMapping, MAX_ID_MAPPINGS};

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
