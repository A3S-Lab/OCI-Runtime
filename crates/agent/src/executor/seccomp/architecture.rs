use std::collections::BTreeSet;

use a3s_oci_sdk::oci_spec::runtime::Arch;
use a3s_oci_sdk::{Error, ErrorCode, Result};
use seccompiler::{sock_filter, BpfProgram, TargetArch};
use serde::{Deserialize, Serialize};

const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
const AUDIT_ARCH_ARM: u32 = 0x4000_0028;
const AUDIT_ARCH_I386: u32 = 0x4000_0003;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const MAX_BPF_INSTRUCTIONS: usize = 4_096;

const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;

/// One syscall ABI understood by the shared Linux seccomp executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SeccompArchitecture {
    Aarch64,
    Arm,
    X86,
    X86_64,
    X32,
}

impl SeccompArchitecture {
    pub(super) fn native() -> Result<Self> {
        match std::env::consts::ARCH {
            "aarch64" => Ok(Self::Aarch64),
            "x86_64" => Ok(Self::X86_64),
            architecture => Err(unsupported(
                "linux.seccomp.architectures",
                format!("seccomp is not implemented for architecture `{architecture}`"),
            )),
        }
    }

    pub(super) const fn compiler_target(self) -> TargetArch {
        match self {
            Self::Aarch64 | Self::Arm => TargetArch::aarch64,
            Self::X86 | Self::X86_64 | Self::X32 => TargetArch::x86_64,
        }
    }

    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Aarch64 => "aarch64",
            Self::Arm => "arm",
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::X32 => "x32",
        }
    }

    const fn audit_value(self) -> u32 {
        match self {
            Self::Aarch64 => AUDIT_ARCH_AARCH64,
            Self::Arm => AUDIT_ARCH_ARM,
            Self::X86 => AUDIT_ARCH_I386,
            Self::X86_64 | Self::X32 => AUDIT_ARCH_X86_64,
        }
    }

    const fn compiler_audit_value(self) -> u32 {
        match self {
            Self::Aarch64 | Self::Arm => AUDIT_ARCH_AARCH64,
            Self::X86 | Self::X86_64 | Self::X32 => AUDIT_ARCH_X86_64,
        }
    }
}

/// Resolve the native ABI plus every explicitly requested compatibility ABI.
pub(super) fn plan_architectures(
    architectures: Option<&[Arch]>,
) -> Result<(SeccompArchitecture, Vec<SeccompArchitecture>)> {
    let native = SeccompArchitecture::native()?;
    let mut selected = BTreeSet::from([native]);
    for (index, architecture) in architectures.unwrap_or_default().iter().enumerate() {
        let architecture = match architecture {
            Arch::ScmpArchNative => native,
            Arch::ScmpArchAarch64 => SeccompArchitecture::Aarch64,
            Arch::ScmpArchArm => SeccompArchitecture::Arm,
            Arch::ScmpArchX86 => SeccompArchitecture::X86,
            Arch::ScmpArchX86_64 => SeccompArchitecture::X86_64,
            Arch::ScmpArchX32 => SeccompArchitecture::X32,
            architecture => {
                return Err(unsupported(
                    &format!("linux.seccomp.architectures[{index}]"),
                    format!("seccomp architecture `{architecture:?}` is not implemented"),
                ));
            }
        };
        selected.insert(architecture);
    }
    Ok((native, selected.into_iter().collect()))
}

/// Put compatibility ABI filters first so native installation syscalls cannot
/// be restricted before all non-native filters have been attached.
pub(super) fn installation_order(
    architectures: &[SeccompArchitecture],
    native: SeccompArchitecture,
) -> impl Iterator<Item = SeccompArchitecture> + '_ {
    architectures
        .iter()
        .copied()
        .filter(move |architecture| *architecture != native)
        .chain(std::iter::once(native))
}

/// Compile the first, fail-closed program that admits only selected syscall
/// ABIs. X32 shares the x86_64 audit token and is distinguished by syscall bit.
pub(super) fn compile_architecture_gate(architectures: &[SeccompArchitecture]) -> BpfProgram {
    let selected = architectures.iter().copied().collect::<BTreeSet<_>>();
    let mut program = vec![statement(
        BPF_LD | BPF_W | BPF_ABS,
        SECCOMP_DATA_ARCH_OFFSET,
    )];

    if selected.contains(&SeccompArchitecture::Aarch64) {
        append_simple_allow(&mut program, AUDIT_ARCH_AARCH64);
    }
    if selected.contains(&SeccompArchitecture::Arm) {
        append_simple_allow(&mut program, AUDIT_ARCH_ARM);
    }
    if selected.contains(&SeccompArchitecture::X86) {
        append_simple_allow(&mut program, AUDIT_ARCH_I386);
    }

    let x86_64 = selected.contains(&SeccompArchitecture::X86_64);
    let x32 = selected.contains(&SeccompArchitecture::X32);
    match (x86_64, x32) {
        (true, true) => append_simple_allow(&mut program, AUDIT_ARCH_X86_64),
        (true, false) => {
            program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 4));
            program.push(statement(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
            // Linux and libseccomp treat the invalid -1 syscall as native x86_64.
            program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, u32::MAX, 1, 0));
            program.push(jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 1, 0));
            program.push(allow());
        }
        (false, true) => {
            program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 4));
            program.push(statement(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
            program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, u32::MAX, 2, 0));
            program.push(jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1));
            program.push(allow());
        }
        (false, false) => {}
    }
    program.push(kill_process());
    program
}

/// Replace seccompiler's single-architecture kill prefix with an ABI scope.
/// The architecture gate remains responsible for killing unselected ABIs;
/// each policy program returns ALLOW when another selected ABI is executing.
pub(super) fn scope_compiled_filter(
    mut compiled: BpfProgram,
    architecture: SeccompArchitecture,
) -> Result<BpfProgram> {
    let expected_prefix = [
        statement(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET),
        jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            architecture.compiler_audit_value(),
            1,
            0,
        ),
        kill_process(),
    ];
    if compiled.len() <= expected_prefix.len()
        || compiled[..expected_prefix.len()] != expected_prefix
    {
        return Err(seccomp_error(
            ErrorCode::Internal,
            "seccompiler emitted an unexpected architecture validation prefix",
        ));
    }
    let body = compiled.split_off(expected_prefix.len());
    let mut scoped = architecture_scope(architecture);
    scoped.extend(body);
    if scoped.len() > MAX_BPF_INSTRUCTIONS {
        return Err(seccomp_error(
            ErrorCode::ResourceExhausted,
            format!(
                "scoped seccomp filter requires {} BPF instructions; maximum is {MAX_BPF_INSTRUCTIONS}",
                scoped.len()
            ),
        ));
    }
    Ok(scoped)
}

fn architecture_scope(architecture: SeccompArchitecture) -> BpfProgram {
    let mut program = vec![
        statement(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET),
        jump(BPF_JMP | BPF_JEQ | BPF_K, architecture.audit_value(), 1, 0),
        allow(),
    ];
    match architecture {
        SeccompArchitecture::Aarch64 | SeccompArchitecture::Arm | SeccompArchitecture::X86 => {}
        SeccompArchitecture::X86_64 => {
            program.extend([
                statement(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET),
                jump(BPF_JMP | BPF_JEQ | BPF_K, u32::MAX, 2, 0),
                jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1),
                allow(),
            ]);
        }
        SeccompArchitecture::X32 => {
            program.extend([
                statement(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET),
                jump(BPF_JMP | BPF_JEQ | BPF_K, u32::MAX, 1, 0),
                jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 1, 0),
                allow(),
            ]);
        }
    }
    program
}

fn append_simple_allow(program: &mut BpfProgram, audit_architecture: u32) {
    program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, audit_architecture, 0, 1));
    program.push(allow());
}

const fn statement(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

const fn allow() -> sock_filter {
    statement(BPF_RET | BPF_K, libc::SECCOMP_RET_ALLOW)
}

const fn kill_process() -> sock_filter {
    statement(BPF_RET | BPF_K, libc::SECCOMP_RET_KILL_PROCESS)
}

fn unsupported(field: &str, reason: impl Into<String>) -> Error {
    Error::new(
        ErrorCode::Unsupported,
        format!("{field}: {}", reason.into()),
    )
    .for_operation("plan-seccomp")
}

fn seccomp_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("plan-seccomp")
}

#[cfg(test)]
mod tests {
    use super::{
        allow, compile_architecture_gate, jump, kill_process, scope_compiled_filter, statement,
        SeccompArchitecture, AUDIT_ARCH_AARCH64, AUDIT_ARCH_ARM, AUDIT_ARCH_I386,
        AUDIT_ARCH_X86_64, BPF_ABS, BPF_JEQ, BPF_JGE, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W,
        SECCOMP_DATA_ARCH_OFFSET, SECCOMP_DATA_NR_OFFSET, X32_SYSCALL_BIT,
    };

    const ERRNO_ONE: u32 = libc::SECCOMP_RET_ERRNO | 1;

    #[test]
    fn architecture_gate_distinguishes_x86_64_and_x32() {
        let x86_64 = compile_architecture_gate(&[SeccompArchitecture::X86_64]);
        assert_eq!(
            evaluate(&x86_64, AUDIT_ARCH_X86_64, 0),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate(&x86_64, AUDIT_ARCH_X86_64, u32::MAX),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate(&x86_64, AUDIT_ARCH_X86_64, X32_SYSCALL_BIT),
            libc::SECCOMP_RET_KILL_PROCESS
        );

        let x32 = compile_architecture_gate(&[SeccompArchitecture::X32]);
        assert_eq!(
            evaluate(&x32, AUDIT_ARCH_X86_64, X32_SYSCALL_BIT),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate(&x32, AUDIT_ARCH_X86_64, 0),
            libc::SECCOMP_RET_KILL_PROCESS
        );
        assert_eq!(
            evaluate(&x32, AUDIT_ARCH_X86_64, u32::MAX),
            libc::SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn architecture_gate_accepts_every_selected_audit_abi() {
        let program = compile_architecture_gate(&[
            SeccompArchitecture::Aarch64,
            SeccompArchitecture::Arm,
            SeccompArchitecture::X86,
            SeccompArchitecture::X86_64,
            SeccompArchitecture::X32,
        ]);
        assert_eq!(
            evaluate(&program, AUDIT_ARCH_AARCH64, 0),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate(&program, AUDIT_ARCH_ARM, 0),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate(&program, AUDIT_ARCH_I386, 0),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate(&program, AUDIT_ARCH_X86_64, 0),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate(&program, AUDIT_ARCH_X86_64, X32_SYSCALL_BIT),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(evaluate(&program, 0, 0), libc::SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn scoped_filters_allow_other_abis_and_enforce_their_own() {
        let raw = raw_compiler_program(AUDIT_ARCH_X86_64, ERRNO_ONE);
        let x86_64 = scope_compiled_filter(raw.clone(), SeccompArchitecture::X86_64)
            .expect("scope x86_64 filter");
        assert_eq!(evaluate(&x86_64, AUDIT_ARCH_X86_64, 0), ERRNO_ONE);
        assert_eq!(
            evaluate(&x86_64, AUDIT_ARCH_X86_64, X32_SYSCALL_BIT),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate(&x86_64, AUDIT_ARCH_I386, 0),
            libc::SECCOMP_RET_ALLOW
        );

        let x86 = scope_compiled_filter(
            raw_compiler_program(AUDIT_ARCH_X86_64, ERRNO_ONE),
            SeccompArchitecture::X86,
        )
        .expect("scope x86 filter");
        assert_eq!(evaluate(&x86, AUDIT_ARCH_I386, 0), ERRNO_ONE);
        assert_eq!(
            evaluate(&x86, AUDIT_ARCH_X86_64, 0),
            libc::SECCOMP_RET_ALLOW
        );

        let arm = scope_compiled_filter(
            raw_compiler_program(AUDIT_ARCH_AARCH64, ERRNO_ONE),
            SeccompArchitecture::Arm,
        )
        .expect("scope ARM filter");
        assert_eq!(evaluate(&arm, AUDIT_ARCH_ARM, 0), ERRNO_ONE);
        assert_eq!(
            evaluate(&arm, AUDIT_ARCH_AARCH64, 0),
            libc::SECCOMP_RET_ALLOW
        );

        let x32 = scope_compiled_filter(raw, SeccompArchitecture::X32).expect("scope x32 filter");
        assert_eq!(
            evaluate(&x32, AUDIT_ARCH_X86_64, 0),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate(&x32, AUDIT_ARCH_X86_64, X32_SYSCALL_BIT),
            ERRNO_ONE
        );
    }

    #[test]
    fn altered_compiler_prefix_fails_closed() {
        let mut raw = raw_compiler_program(AUDIT_ARCH_X86_64, ERRNO_ONE);
        raw[1].jt = 0;
        let error = scope_compiled_filter(raw, SeccompArchitecture::X86_64)
            .expect_err("unexpected compiler output must be rejected");
        assert_eq!(error.code, a3s_oci_sdk::ErrorCode::Internal);
    }

    fn raw_compiler_program(audit_architecture: u32, action: u32) -> seccompiler::BpfProgram {
        vec![
            statement(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET),
            jump(BPF_JMP | BPF_JEQ | BPF_K, audit_architecture, 1, 0),
            kill_process(),
            statement(BPF_RET | BPF_K, action),
        ]
    }

    fn evaluate(program: &[seccompiler::sock_filter], architecture: u32, syscall: u32) -> u32 {
        let mut accumulator = 0_u32;
        let mut index = 0_usize;
        loop {
            let instruction = program.get(index).expect("BPF program terminated");
            match instruction.code {
                code if code == BPF_LD | BPF_W | BPF_ABS => {
                    accumulator = match instruction.k {
                        SECCOMP_DATA_NR_OFFSET => syscall,
                        SECCOMP_DATA_ARCH_OFFSET => architecture,
                        offset => panic!("unexpected seccomp_data offset {offset}"),
                    };
                    index += 1;
                }
                code if code == BPF_JMP | BPF_JEQ | BPF_K => {
                    let offset = if accumulator == instruction.k {
                        instruction.jt
                    } else {
                        instruction.jf
                    };
                    index += usize::from(offset) + 1;
                }
                code if code == BPF_JMP | BPF_JGE | BPF_K => {
                    let offset = if accumulator >= instruction.k {
                        instruction.jt
                    } else {
                        instruction.jf
                    };
                    index += usize::from(offset) + 1;
                }
                code if code == BPF_RET | BPF_K => return instruction.k,
                code => panic!("unexpected BPF opcode {code:#x}"),
            }
        }
    }

    #[test]
    fn helper_instruction_constants_match_expected_encodings() {
        assert_eq!(allow().code, BPF_RET | BPF_K);
    }
}
