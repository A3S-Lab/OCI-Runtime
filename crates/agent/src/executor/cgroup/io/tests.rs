use std::collections::BTreeMap;

use a3s_oci_sdk::oci_spec::runtime::LinuxBlockIo;
use a3s_oci_sdk::ErrorCode;

use super::state::{parse_max_state, parse_weight_state};
use super::{
    BlockDevice, BlockIoPlan, IoLimit, IoMaxField, IoMaxValues, IoMutation, PreparedIoMutation,
    PreviousValue, WeightBackend, WeightKey,
};

fn block_io(value: serde_json::Value) -> LinuxBlockIo {
    serde_json::from_value(value).expect("valid block I/O shape")
}

#[test]
fn plans_complete_cgroup_v2_block_io_controls() {
    let value = block_io(serde_json::json!({
        "weight": 500,
        "weightDevice": [
            {"major": 8, "minor": 16, "weight": 250},
            {"major": 8, "minor": 0, "weight": 750}
        ],
        "throttleReadBpsDevice": [
            {"major": 8, "minor": 0, "rate": 1048576},
            {"major": 8, "minor": 16, "rate": 2097152}
        ],
        "throttleWriteBpsDevice": [
            {"major": 8, "minor": 0, "rate": 524288}
        ],
        "throttleReadIOPSDevice": [
            {"major": 8, "minor": 16, "rate": 400}
        ],
        "throttleWriteIOPSDevice": [
            {"major": 8, "minor": 0, "rate": 200}
        ]
    }));
    let plan = BlockIoPlan::from_oci(Some(&value)).expect("complete block I/O plan");
    let generic = plan.mutations(Some(WeightBackend::Generic));
    let commands = generic
        .iter()
        .map(|mutation| (mutation.file(), mutation.write_value().expect("command")))
        .collect::<Vec<_>>();

    assert_eq!(
        commands,
        [
            ("io.weight", "4950".to_string()),
            ("io.weight", "8:0 7475".to_string()),
            ("io.weight", "8:16 2425".to_string()),
            (
                "io.max",
                "8:0 rbps=1048576 wbps=524288 wiops=200".to_string()
            ),
            ("io.max", "8:16 rbps=2097152 riops=400".to_string()),
        ]
    );
    let bfq = plan.mutations(Some(WeightBackend::Bfq));
    assert_eq!(bfq[0].write_value().expect("BFQ default"), "500");
    assert_eq!(bfq[1].write_value().expect("BFQ device"), "8:0 750");
}

#[test]
fn rejects_unrepresentable_and_ambiguous_block_io_values() {
    for (value, code, fragment) in [
        (
            serde_json::json!({"leafWeight": 100}),
            ErrorCode::Unsupported,
            "leafWeight",
        ),
        (
            serde_json::json!({"weight": 9}),
            ErrorCode::InvalidArgument,
            "between 10 and 1000",
        ),
        (
            serde_json::json!({"weightDevice": [{"major": 8, "minor": 0}]}),
            ErrorCode::InvalidArgument,
            "must specify weight",
        ),
        (
            serde_json::json!({
                "weightDevice": [{"major": 8, "minor": 0, "leafWeight": 100}]
            }),
            ErrorCode::Unsupported,
            "leafWeight",
        ),
        (
            serde_json::json!({
                "weightDevice": [{
                    "major": 8,
                    "minor": 0,
                    "weight": 100,
                    "leafWeight": 200
                }]
            }),
            ErrorCode::Unsupported,
            "leafWeight",
        ),
        (
            serde_json::json!({
                "weightDevice": [
                    {"major": 8, "minor": 0, "weight": 100},
                    {"major": 8, "minor": 0, "weight": 200}
                ]
            }),
            ErrorCode::InvalidArgument,
            "duplicate device 8:0",
        ),
        (
            serde_json::json!({
                "throttleReadBpsDevice": [{"major": -1, "minor": 0, "rate": 1}]
            }),
            ErrorCode::InvalidArgument,
            "major must be a non-negative u32",
        ),
        (
            serde_json::json!({
                "throttleReadBpsDevice": [{"major": 8, "minor": 0, "rate": 0}]
            }),
            ErrorCode::InvalidArgument,
            "rate must be positive",
        ),
        (
            serde_json::json!({
                "throttleWriteIOPSDevice": [
                    {"major": 8, "minor": 0, "rate": 10},
                    {"major": 8, "minor": 0, "rate": 20}
                ]
            }),
            ErrorCode::InvalidArgument,
            "duplicate device 8:0",
        ),
    ] {
        let block_io = block_io(value);
        let error = BlockIoPlan::from_oci(Some(&block_io)).expect_err("invalid block I/O");
        assert_eq!(error.code, code);
        assert!(error.message.contains(fragment), "{}", error.message);
    }
}

#[test]
fn parses_flat_and_nested_keyed_kernel_state() {
    let weight =
        parse_weight_state("default 100\n8:16 200\n8:0 50\n").expect("generic weight state");
    assert_eq!(weight.default, Some(100));
    assert!(weight.device_overrides_supported);
    assert_eq!(
        weight.devices.get(&BlockDevice { major: 8, minor: 0 }),
        Some(&50)
    );
    let legacy_bfq = parse_weight_state("500\n").expect("legacy BFQ weight state");
    assert_eq!(legacy_bfq.default, Some(500));
    assert!(!legacy_bfq.device_overrides_supported);

    let max = parse_max_state(
        "8:16 rbps=1048576 wbps=max riops=400 wiops=max\n\
         8:0 rbps=max wbps=524288 riops=max wiops=200\n",
    )
    .expect("io.max state");
    assert_eq!(
        max.value(
            BlockDevice {
                major: 8,
                minor: 16
            },
            IoMaxField::ReadBytes
        ),
        IoLimit::Value(1_048_576)
    );
    assert_eq!(
        max.value(
            BlockDevice {
                major: 8,
                minor: 16
            },
            IoMaxField::WriteBytes
        ),
        IoLimit::Max
    );
    assert_eq!(
        max.value(BlockDevice { major: 7, minor: 0 }, IoMaxField::ReadBytes),
        IoLimit::Max,
        "an absent device inherits the unlimited value"
    );
}

#[test]
fn prepares_exact_keyed_rollback_commands() {
    let device = BlockDevice { major: 8, minor: 0 };
    let weight = PreparedIoMutation {
        mutation: IoMutation::Weight {
            backend: WeightBackend::Generic,
            key: WeightKey::Device(device),
            value: 4_950,
        },
        previous: PreviousValue::Weight(None),
    };
    assert_eq!(
        weight
            .rollback_mutation()
            .expect("weight rollback")
            .write_value()
            .expect("weight rollback command"),
        "8:0 default"
    );

    let mut desired = IoMaxValues::default();
    desired.insert(IoMaxField::ReadBytes, 1_048_576);
    desired.insert(IoMaxField::WriteOperations, 200);
    let max = PreparedIoMutation {
        mutation: IoMutation::Max {
            device,
            values: desired,
        },
        previous: PreviousValue::Max(BTreeMap::from([
            (IoMaxField::ReadBytes, IoLimit::Max),
            (IoMaxField::WriteOperations, IoLimit::Value(100)),
        ])),
    };
    assert_eq!(
        max.rollback_mutation()
            .expect("io.max rollback")
            .write_value()
            .expect("io.max rollback command"),
        "8:0 rbps=max wiops=100"
    );
}

#[tokio::test]
async fn applies_reads_back_and_rolls_back_real_io_max_when_requested() {
    let (Some(path), Some(device)) = (
        std::env::var_os("A3S_OCI_TEST_CGROUP_IO_PATH"),
        std::env::var_os("A3S_OCI_TEST_CGROUP_IO_DEVICE"),
    ) else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    let device = BlockDevice::parse(&device.to_string_lossy()).expect("test block device");
    let initial = block_io(serde_json::json!({
        "throttleReadBpsDevice": [{
            "major": device.major,
            "minor": device.minor,
            "rate": 1048576
        }],
        "throttleWriteBpsDevice": [{
            "major": device.major,
            "minor": device.minor,
            "rate": 524288
        }]
    }));
    let initial = BlockIoPlan::from_oci(Some(&initial)).expect("initial block I/O plan");
    initial
        .apply_create(&path)
        .expect("apply initial real io.max profile");
    let state = super::state::read_max_state(&path, super::CREATE_OPERATION)
        .expect("read initial real io.max profile");
    assert_eq!(
        state.value(device, IoMaxField::ReadBytes),
        IoLimit::Value(1_048_576)
    );
    assert_eq!(
        state.value(device, IoMaxField::WriteBytes),
        IoLimit::Value(524_288)
    );

    let update = block_io(serde_json::json!({
        "throttleReadBpsDevice": [{
            "major": device.major,
            "minor": device.minor,
            "rate": 2097152
        }],
        "throttleReadIOPSDevice": [{
            "major": device.major,
            "minor": device.minor,
            "rate": 400
        }]
    }));
    let update = BlockIoPlan::from_oci(Some(&update)).expect("updated block I/O plan");
    let applied = update
        .prepare_update(&path)
        .await
        .expect("prepare real io.max update")
        .apply()
        .await
        .expect("apply real io.max update");
    let state = super::state::read_max_state(&path, super::UPDATE_OPERATION)
        .expect("read updated real io.max profile");
    assert_eq!(
        state.value(device, IoMaxField::ReadBytes),
        IoLimit::Value(2_097_152)
    );
    assert_eq!(
        state.value(device, IoMaxField::WriteBytes),
        IoLimit::Value(524_288),
        "a partial update must preserve an unspecified keyed field"
    );
    assert_eq!(
        state.value(device, IoMaxField::ReadOperations),
        IoLimit::Value(400)
    );

    assert_eq!(applied.rollback().await, Vec::<String>::new());
    let state = super::state::read_max_state(&path, super::UPDATE_OPERATION)
        .expect("read rolled-back real io.max profile");
    assert_eq!(
        state.value(device, IoMaxField::ReadBytes),
        IoLimit::Value(1_048_576)
    );
    assert_eq!(
        state.value(device, IoMaxField::WriteBytes),
        IoLimit::Value(524_288)
    );
    assert_eq!(
        state.value(device, IoMaxField::ReadOperations),
        IoLimit::Max
    );
}
