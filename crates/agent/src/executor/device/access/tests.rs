use a3s_oci_sdk::oci_spec::runtime::LinuxResources;

use super::{
    BpfInsn, DeviceAccessBoundary, DeviceAccessKind, DeviceAccessPolicy, BPF_ALU64, BPF_AND,
    BPF_DEVCG_ACC_MKNOD, BPF_DEVCG_ACC_READ, BPF_DEVCG_ACC_WRITE, BPF_DEVCG_DEV_BLOCK,
    BPF_DEVCG_DEV_CHAR, BPF_EXIT, BPF_JNE, BPF_MOV, BPF_OR, BPF_REG_0, BPF_REG_1, BPF_RSH,
};

#[derive(Debug, Clone, Copy)]
struct AccessRequest {
    kind: DeviceAccessKind,
    major: u32,
    minor: u32,
    access: u8,
}

fn policy(value: serde_json::Value) -> DeviceAccessPolicy {
    let resources: LinuxResources = serde_json::from_value(value).expect("decode resources");
    DeviceAccessPolicy::from_oci(resources.devices().as_deref().expect("device rules"))
        .expect("valid policy")
        .expect("active policy")
}

fn request(kind: DeviceAccessKind, major: u32, minor: u32, access: &str) -> AccessRequest {
    let mut mask = 0;
    for permission in access.chars() {
        mask |= match permission {
            'r' => BPF_DEVCG_ACC_READ as u8,
            'w' => BPF_DEVCG_ACC_WRITE as u8,
            'm' => BPF_DEVCG_ACC_MKNOD as u8,
            _ => panic!("invalid test permission"),
        };
    }
    AccessRequest {
        kind,
        major,
        minor,
        access: mask,
    }
}

fn evaluate(policy: &DeviceAccessPolicy, request: AccessRequest) -> bool {
    let program = policy.build_program().expect("build program");
    run_program(&program, request) != 0
}

fn evaluate_boundary(boundary: &DeviceAccessBoundary, request: AccessRequest) -> bool {
    let program = boundary.build_program().expect("build bounded program");
    run_program(&program, request) != 0
}

#[test]
fn oci_inventory_is_a_fail_closed_upper_bound_for_every_device_operation() {
    let boundary = DeviceAccessBoundary::for_oci_nodes(
        [
            (DeviceAccessKind::Character, 1, 3),
            (DeviceAccessKind::Block, 8, 0),
        ],
        None,
    )
    .expect("bounded OCI device inventory");

    for access in ["r", "w", "m", "rwm"] {
        assert!(evaluate_boundary(
            &boundary,
            request(DeviceAccessKind::Character, 1, 3, access),
        ));
        assert!(evaluate_boundary(
            &boundary,
            request(DeviceAccessKind::Block, 8, 0, access),
        ));
        assert!(!evaluate_boundary(
            &boundary,
            request(DeviceAccessKind::Character, 10, 229, access),
        ));
    }
}

#[test]
fn oci_inventory_includes_only_the_normative_ptmx_and_pty_family() {
    let boundary = DeviceAccessBoundary::for_oci_nodes([(DeviceAccessKind::Character, 1, 3)], None)
        .expect("bounded OCI device inventory");

    assert!(evaluate_boundary(
        &boundary,
        request(DeviceAccessKind::Character, 5, 2, "rwm"),
    ));
    assert!(evaluate_boundary(
        &boundary,
        request(DeviceAccessKind::Character, 136, 42, "rw"),
    ));
    assert!(!evaluate_boundary(
        &boundary,
        request(DeviceAccessKind::Character, 5, 1, "r"),
    ));
    assert!(!evaluate_boundary(
        &boundary,
        request(DeviceAccessKind::Block, 136, 42, "r"),
    ));
}

#[test]
fn maximum_planned_inventory_includes_defaults_and_dynamic_ptys() {
    let maximum_planned_nodes = (0..262_u32)
        .map(|major| (DeviceAccessKind::Block, major + 1_000, 0))
        .collect::<Vec<_>>();
    DeviceAccessBoundary::for_oci_nodes(maximum_planned_nodes.clone(), None)
        .expect("256 explicit devices, six defaults, PTMX, and PTYs fit the boundary");

    let mut oversized = maximum_planned_nodes;
    oversized.push((DeviceAccessKind::Block, 2_000, 0));
    let error = DeviceAccessBoundary::for_oci_nodes(oversized, None)
        .expect_err("an inventory above the planner limit must fail closed");
    assert_eq!(error.code, a3s_oci_sdk::ErrorCode::PermissionDenied);
    assert!(error.message.contains("invalid identity count"));
}

#[test]
fn ordered_resource_rules_can_only_narrow_the_oci_inventory() {
    let access = policy(serde_json::json!({
        "devices": [
            {"allow": true, "type": "a", "access": "rwm"},
            {"allow": false, "type": "c", "major": 10, "minor": 229, "access": "wm"}
        ]
    }));
    let boundary = DeviceAccessBoundary::for_oci_nodes(
        [
            (DeviceAccessKind::Character, 1, 3),
            (DeviceAccessKind::Character, 10, 229),
        ],
        Some(access),
    )
    .expect("bounded OCI device policy");

    assert!(evaluate_boundary(
        &boundary,
        request(DeviceAccessKind::Character, 10, 229, "r"),
    ));
    assert!(!evaluate_boundary(
        &boundary,
        request(DeviceAccessKind::Character, 10, 229, "w"),
    ));
    assert!(!evaluate_boundary(
        &boundary,
        request(DeviceAccessKind::Character, 10, 229, "m"),
    ));
    assert!(!evaluate_boundary(
        &boundary,
        request(DeviceAccessKind::Character, 10, 230, "r"),
    ));
}

#[test]
fn ordered_resource_rules_cannot_remove_normative_default_device_access() {
    let access = policy(serde_json::json!({
        "devices": [{"allow": false, "type": "a", "access": "rwm"}]
    }));
    let boundary = DeviceAccessBoundary::for_oci_nodes(
        crate::OCI_LINUX_DEFAULT_DEVICE_NODES
            .map(|device| (DeviceAccessKind::Character, device.major, device.minor)),
        Some(access),
    )
    .expect("bounded OCI default-device policy");

    for device in crate::OCI_LINUX_DEFAULT_DEVICE_NODES {
        assert!(evaluate_boundary(
            &boundary,
            request(
                DeviceAccessKind::Character,
                device.major,
                device.minor,
                "rwm",
            ),
        ));
    }
    assert!(evaluate_boundary(
        &boundary,
        request(DeviceAccessKind::Character, 5, 2, "rwm"),
    ));
    assert!(evaluate_boundary(
        &boundary,
        request(DeviceAccessKind::Character, 136, 42, "rw"),
    ));
}

#[test]
fn containerd_default_policy_supports_major_and_minor_wildcards() {
    let policy = policy(serde_json::json!({
        "devices": [
            {"allow": false, "access": "rwm"},
            {"allow": true, "type": "c", "major": 1, "minor": 3, "access": "rwm"},
            {"allow": true, "type": "c", "major": 136, "access": "rwm"},
            {"allow": true, "type": "c", "major": 5, "minor": 2, "access": "rwm"}
        ]
    }));

    assert!(evaluate(
        &policy,
        request(DeviceAccessKind::Character, 1, 3, "rwm")
    ));
    assert!(evaluate(
        &policy,
        request(DeviceAccessKind::Character, 136, 42, "rw")
    ));
    assert!(evaluate(
        &policy,
        request(DeviceAccessKind::Character, 5, 2, "m")
    ));
    assert!(!evaluate(
        &policy,
        request(DeviceAccessKind::Character, 1, 4, "r")
    ));
    assert!(!evaluate(
        &policy,
        request(DeviceAccessKind::Block, 136, 42, "r")
    ));
}

#[test]
fn ordered_rules_add_and_remove_access_subsets() {
    let policy = policy(serde_json::json!({
        "devices": [
            {"allow": false, "access": "rwm"},
            {"allow": true, "type": "c", "major": 1, "access": "rw"},
            {"allow": false, "type": "c", "major": 1, "minor": 3, "access": "w"},
            {"allow": true, "type": "c", "major": 1, "minor": 3, "access": "m"}
        ]
    }));

    assert!(evaluate(
        &policy,
        request(DeviceAccessKind::Character, 1, 3, "r")
    ));
    assert!(!evaluate(
        &policy,
        request(DeviceAccessKind::Character, 1, 3, "w")
    ));
    assert!(evaluate(
        &policy,
        request(DeviceAccessKind::Character, 1, 3, "m")
    ));
    assert!(!evaluate(
        &policy,
        request(DeviceAccessKind::Character, 1, 3, "rw")
    ));
    assert!(evaluate(
        &policy,
        request(DeviceAccessKind::Character, 1, 5, "rw")
    ));
}

#[test]
fn all_device_rules_reset_the_accumulated_policy_in_list_order() {
    let policy = policy(serde_json::json!({
        "devices": [
            {"allow": false, "access": "rwm"},
            {"allow": true, "type": "c", "major": 1, "minor": 3, "access": "r"},
            {"allow": true, "type": "a", "major": 999, "minor": 999, "access": "m"},
            {"allow": false, "type": "b", "major": 8, "minor": 0, "access": "w"}
        ]
    }));

    assert!(evaluate(
        &policy,
        request(DeviceAccessKind::Character, 222, 7, "rwm")
    ));
    assert!(evaluate(
        &policy,
        request(DeviceAccessKind::Block, 8, 0, "r")
    ));
    assert!(!evaluate(
        &policy,
        request(DeviceAccessKind::Block, 8, 0, "w")
    ));
}

#[test]
fn supports_full_u32_device_numbers_without_signed_truncation() {
    let policy = policy(serde_json::json!({
        "devices": [
            {"allow": false, "access": "rwm"},
            {"allow": true, "type": "b", "major": 4294967295_u64, "minor": 4294967295_u64, "access": "r"}
        ]
    }));

    assert!(evaluate(
        &policy,
        request(DeviceAccessKind::Block, u32::MAX, u32::MAX, "r")
    ));
    assert!(!evaluate(
        &policy,
        request(DeviceAccessKind::Block, u32::MAX, u32::MAX - 1, "r")
    ));
}

#[test]
fn validates_rule_shapes_and_access_values() {
    for (value, expected) in [
        (
            serde_json::json!({"devices": [{"allow": true, "type": "p", "access": "r"}]}),
            "FIFO nodes",
        ),
        (
            serde_json::json!({"devices": [{"allow": true, "type": "u", "access": "r"}]}),
            "use `c`",
        ),
        (
            serde_json::json!({"devices": [{"allow": true, "type": "c", "major": -1, "access": "r"}]}),
            "non-negative u32",
        ),
        (
            serde_json::json!({"devices": [{"allow": true, "type": "c", "access": "rx"}]}),
            "only `r`, `w`, and `m`",
        ),
    ] {
        let resources: LinuxResources = serde_json::from_value(value).expect("decode resources");
        let error =
            DeviceAccessPolicy::from_oci(resources.devices().as_deref().expect("device rules"))
                .expect_err("invalid policy");
        assert!(error.message.contains(expected), "{error}");
    }
}

#[test]
fn omitted_and_empty_access_entries_are_ordered_no_ops() {
    let resources: LinuxResources = serde_json::from_value(serde_json::json!({
        "devices": [
            {"allow": true, "type": "c", "major": 1, "minor": 3},
            {"allow": false, "type": "b", "major": 8, "minor": 0, "access": ""}
        ]
    }))
    .expect("decode no-op device rules");
    assert!(
        DeviceAccessPolicy::from_oci(resources.devices().as_deref().expect("device rules"))
            .expect("OCI permits omitted and empty access masks")
            .is_none()
    );

    let policy = policy(serde_json::json!({
        "devices": [
            {"allow": false, "access": "rwm"},
            {"allow": true, "type": "c", "major": 1, "minor": 3},
            {"allow": true, "type": "c", "major": 1, "minor": 3, "access": "r"},
            {"allow": false, "type": "c", "major": 1, "minor": 3, "access": ""}
        ]
    }));
    assert!(evaluate(
        &policy,
        request(DeviceAccessKind::Character, 1, 3, "r")
    ));
    assert!(!evaluate(
        &policy,
        request(DeviceAccessKind::Character, 1, 3, "w")
    ));
}

#[test]
fn exact_rootless_policy_requires_the_bounded_six_device_rules() {
    let rootless_policy = policy(serde_json::json!({
        "devices": [
            {"allow": false, "access": "rwm"},
            {"allow": true, "type": "c", "major": 1, "minor": 3, "access": "rwm"},
            {"allow": true, "type": "c", "major": 1, "minor": 5, "access": "rwm"},
            {"allow": true, "type": "c", "major": 1, "minor": 7, "access": "rwm"},
            {"allow": true, "type": "c", "major": 1, "minor": 8, "access": "rwm"},
            {"allow": true, "type": "c", "major": 1, "minor": 9, "access": "rwm"},
            {"allow": true, "type": "c", "major": 5, "minor": 0, "access": "rwm"}
        ]
    }));
    let expected = [
        (DeviceAccessKind::Character, 1, 3),
        (DeviceAccessKind::Character, 1, 5),
        (DeviceAccessKind::Character, 1, 7),
        (DeviceAccessKind::Character, 1, 8),
        (DeviceAccessKind::Character, 1, 9),
        (DeviceAccessKind::Character, 5, 0),
    ];

    assert!(rootless_policy.is_exact_rootless_allowlist(&expected));

    let broader = policy(serde_json::json!({
        "devices": [
            {"allow": false, "access": "rwm"},
            {"allow": true, "type": "c", "major": 1, "access": "rwm"}
        ]
    }));
    assert!(!broader.is_exact_rootless_allowlist(&expected));
}

fn run_program(program: &[BpfInsn], request: AccessRequest) -> u32 {
    let mut registers = [0_u64; 11];
    let access_type = u32::from(request.access) << 16
        | match request.kind {
            DeviceAccessKind::Block => BPF_DEVCG_DEV_BLOCK,
            DeviceAccessKind::Character => BPF_DEVCG_DEV_CHAR,
            DeviceAccessKind::All => panic!("all is not an access request kind"),
        };
    let mut pc = 0_usize;
    while pc < program.len() {
        let instruction = program[pc];
        let dst = usize::from(instruction.regs & 0x0f);
        let src = usize::from(instruction.regs >> 4);
        let next = pc + 1;
        match u32::from(instruction.code) {
            code if code == libc::BPF_LDX | libc::BPF_W | libc::BPF_MEM => {
                assert_eq!(src, usize::from(BPF_REG_1));
                registers[dst] = u64::from(match instruction.off {
                    0 => access_type,
                    4 => request.major,
                    8 => request.minor,
                    offset => panic!("unexpected context offset {offset}"),
                });
                pc = next;
            }
            code if code == BPF_ALU64 | BPF_MOV | libc::BPF_K => {
                registers[dst] = instruction.imm as u32 as u64;
                pc = next;
            }
            code if code == BPF_ALU64 | BPF_MOV | libc::BPF_X => {
                registers[dst] = registers[src];
                pc = next;
            }
            code if code == libc::BPF_ALU | BPF_AND | libc::BPF_K => {
                registers[dst] = u64::from((registers[dst] as u32) & instruction.imm as u32);
                pc = next;
            }
            code if code == libc::BPF_ALU | BPF_AND | libc::BPF_X => {
                registers[dst] = u64::from((registers[dst] as u32) & registers[src] as u32);
                pc = next;
            }
            code if code == libc::BPF_ALU | BPF_OR | libc::BPF_K => {
                registers[dst] = u64::from((registers[dst] as u32) | instruction.imm as u32);
                pc = next;
            }
            code if code == libc::BPF_ALU | BPF_RSH | libc::BPF_K => {
                registers[dst] = u64::from((registers[dst] as u32) >> instruction.imm);
                pc = next;
            }
            code if code == libc::BPF_JMP | BPF_JNE | libc::BPF_K => {
                pc = if registers[dst] as u32 != instruction.imm as u32 {
                    jump_target(pc, instruction.off)
                } else {
                    next
                };
            }
            code if code == libc::BPF_JMP | BPF_JNE | libc::BPF_X => {
                pc = if registers[dst] as u32 != registers[src] as u32 {
                    jump_target(pc, instruction.off)
                } else {
                    next
                };
            }
            code if code == libc::BPF_JMP | BPF_EXIT => {
                return registers[usize::from(BPF_REG_0)] as u32;
            }
            code => panic!("unsupported test BPF opcode {code:#x}"),
        }
    }
    panic!("device BPF program did not exit")
}

fn jump_target(pc: usize, offset: i16) -> usize {
    usize::try_from(pc as isize + 1 + isize::from(offset)).expect("valid forward jump")
}
