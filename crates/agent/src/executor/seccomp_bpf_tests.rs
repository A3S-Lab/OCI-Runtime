use a3s_oci_sdk::oci_spec::runtime::Linux;
use seccompiler::{sock_filter, BpfProgram};
use serde_json::json;

use super::seccomp::SeccompPlan;

const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
const AUDIT_ARCH_ARM: u32 = 0x4000_0028;
const AARCH64_CLONE: u32 = 220;
const ARM_CLONE: u32 = 120;
const CLONE_NAMESPACE_MASK: u64 = 2_114_060_288;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_ALU_AND_K: u16 = 0x54;
const BPF_JMP_JA: u16 = 0x05;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_JMP_JGT_K: u16 = 0x25;
const BPF_JMP_JGE_K: u16 = 0x35;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;

#[test]
fn compiled_arm_clone_condition_allows_process_creation_without_namespaces() {
    let plan = plan(json!({
        "defaultAction": "SCMP_ACT_ERRNO",
        "defaultErrnoRet": 1,
        "architectures": ["SCMP_ARCH_ARM", "SCMP_ARCH_AARCH64"],
        "syscalls": [{
            "names": ["clone"],
            "action": "SCMP_ACT_ALLOW",
            "args": [{
                "index": 0,
                "value": CLONE_NAMESPACE_MASK,
                "valueTwo": 0,
                "op": "SCMP_CMP_MASKED_EQ"
            }]
        }]
    }))
    .expect("runtime-tools compatible ARM clone policy");
    let filters = plan.compiled_filters().expect("compile seccomp filters");

    assert_all_filters_allow(
        &filters,
        AUDIT_ARCH_AARCH64,
        AARCH64_CLONE,
        [libc::SIGCHLD as u64, 0, 0, 0, 0, 0],
    );
    assert_all_filters_allow(
        &filters,
        AUDIT_ARCH_ARM,
        ARM_CLONE,
        [libc::SIGCHLD as u64, 0, 0, 0, 0, 0],
    );

    assert_one_filter_returns(
        &filters,
        AUDIT_ARCH_AARCH64,
        AARCH64_CLONE,
        [CLONE_NAMESPACE_MASK | libc::SIGCHLD as u64, 0, 0, 0, 0, 0],
        libc::SECCOMP_RET_ERRNO | 1,
    );
    assert_one_filter_returns(
        &filters,
        AUDIT_ARCH_ARM,
        ARM_CLONE,
        [CLONE_NAMESPACE_MASK | libc::SIGCHLD as u64, 0, 0, 0, 0, 0],
        libc::SECCOMP_RET_ERRNO | 1,
    );
}

fn plan(seccomp: serde_json::Value) -> a3s_oci_sdk::Result<SeccompPlan> {
    let linux: Linux =
        serde_json::from_value(json!({"seccomp": seccomp})).expect("valid Linux seccomp fixture");
    SeccompPlan::from_linux(Some(&linux))
}

fn assert_all_filters_allow(
    filters: &[BpfProgram],
    architecture: u32,
    syscall: u32,
    arguments: [u64; 6],
) {
    for (index, filter) in filters.iter().enumerate() {
        assert_eq!(
            evaluate_bpf(filter, architecture, syscall, arguments),
            libc::SECCOMP_RET_ALLOW,
            "filter {index} rejected an allowed syscall"
        );
    }
}

fn assert_one_filter_returns(
    filters: &[BpfProgram],
    architecture: u32,
    syscall: u32,
    arguments: [u64; 6],
    expected: u32,
) {
    assert!(
        filters
            .iter()
            .any(|filter| evaluate_bpf(filter, architecture, syscall, arguments) == expected),
        "no filter returned the expected action {expected:#x}"
    );
}

fn evaluate_bpf(
    program: &[sock_filter],
    architecture: u32,
    syscall: u32,
    arguments: [u64; 6],
) -> u32 {
    let mut accumulator = 0_u32;
    let mut index = 0_usize;
    loop {
        let instruction = program.get(index).expect("BPF program terminated");
        match instruction.code {
            BPF_LD_W_ABS => {
                accumulator = seccomp_data_word(instruction.k, architecture, syscall, &arguments);
                index += 1;
            }
            BPF_ALU_AND_K => {
                accumulator &= instruction.k;
                index += 1;
            }
            BPF_JMP_JA => index += instruction.k as usize + 1,
            BPF_JMP_JEQ_K | BPF_JMP_JGT_K | BPF_JMP_JGE_K => {
                let matched = match instruction.code {
                    BPF_JMP_JEQ_K => accumulator == instruction.k,
                    BPF_JMP_JGT_K => accumulator > instruction.k,
                    BPF_JMP_JGE_K => accumulator >= instruction.k,
                    _ => unreachable!(),
                };
                index += usize::from(if matched {
                    instruction.jt
                } else {
                    instruction.jf
                }) + 1;
            }
            BPF_RET_K => return instruction.k,
            code => panic!("unexpected BPF opcode {code:#x}"),
        }
    }
}

fn seccomp_data_word(offset: u32, architecture: u32, syscall: u32, arguments: &[u64; 6]) -> u32 {
    match offset {
        SECCOMP_DATA_NR_OFFSET => syscall,
        SECCOMP_DATA_ARCH_OFFSET => architecture,
        8 | 12 => 0,
        offset if (SECCOMP_DATA_ARGS_OFFSET..SECCOMP_DATA_ARGS_OFFSET + 48).contains(&offset) => {
            let relative = offset - SECCOMP_DATA_ARGS_OFFSET;
            let argument = arguments[(relative / 8) as usize];
            match relative % 8 {
                0 => argument as u32,
                4 => (argument >> 32) as u32,
                byte => panic!("unaligned seccomp argument offset {byte}"),
            }
        }
        offset => panic!("unexpected seccomp_data offset {offset}"),
    }
}
