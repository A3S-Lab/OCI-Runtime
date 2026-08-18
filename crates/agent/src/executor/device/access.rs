use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use a3s_oci_sdk::oci_spec::runtime::{LinuxDeviceCgroup, LinuxDeviceType};
use a3s_oci_sdk::{Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};

use super::{device_error, invalid, unsupported};

const MAX_DEVICE_ACCESS_RULES: usize = 512;
const ALL_ACCESS: u8 = (BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE | BPF_DEVCG_ACC_MKNOD) as u8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DeviceAccessPolicy {
    rules: Vec<DeviceAccessRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeviceAccessRule {
    allow: bool,
    kind: DeviceAccessKind,
    major: Option<u32>,
    minor: Option<u32>,
    access: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum DeviceAccessKind {
    All,
    Block,
    Character,
}

#[derive(Debug)]
pub(in crate::executor) struct LoadedDeviceProgram(OwnedFd);

impl DeviceAccessPolicy {
    pub(super) fn from_oci(rules: &[LinuxDeviceCgroup]) -> Result<Option<Self>> {
        if rules.is_empty() {
            return Ok(None);
        }
        if rules.len() > MAX_DEVICE_ACCESS_RULES {
            return Err(invalid(format!(
                "linux.resources.devices contains {} entries; maximum is {MAX_DEVICE_ACCESS_RULES}",
                rules.len()
            )));
        }
        let rules = rules
            .iter()
            .enumerate()
            .map(|(index, rule)| DeviceAccessRule::from_oci(index, rule))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .filter(|rule| rule.access != 0)
            .collect::<Vec<_>>();
        if rules.is_empty() {
            return Ok(None);
        }
        let policy = Self { rules };
        policy.validate()?;
        Ok(Some(policy))
    }

    pub(super) fn load(&self) -> Result<OwnedFd> {
        self.validate()?;
        load_cgroup_device_program_fd(&self.build_program()?)
    }

    pub(super) fn load_for_rootless_helper(&self) -> Result<LoadedDeviceProgram> {
        self.validate()?;
        load_cgroup_device_program_fd(&self.build_program()?).map(LoadedDeviceProgram)
    }

    pub(super) fn is_exact_rootless_allowlist(
        &self,
        devices: &[(DeviceAccessKind, u32, u32)],
    ) -> bool {
        let Some((reset, grants)) = self.rules.split_first() else {
            return false;
        };
        if reset.allow
            || reset.kind != DeviceAccessKind::All
            || reset.major.is_some()
            || reset.minor.is_some()
            || reset.access != ALL_ACCESS
            || grants.len() != devices.len()
        {
            return false;
        }

        let mut remaining = devices.to_vec();
        for grant in grants {
            if !grant.allow
                || grant.kind == DeviceAccessKind::All
                || grant.access == 0
                || grant.access & !ALL_ACCESS != 0
            {
                return false;
            }
            let (Some(major), Some(minor)) = (grant.major, grant.minor) else {
                return false;
            };
            let Some(index) = remaining
                .iter()
                .position(|expected| *expected == (grant.kind, major, minor))
            else {
                return false;
            };
            remaining.swap_remove(index);
        }
        remaining.is_empty()
    }

    fn validate(&self) -> Result<()> {
        if self.rules.is_empty() || self.rules.len() > MAX_DEVICE_ACCESS_RULES {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                "serialized device policy has an invalid rule count",
            ));
        }
        if self.rules.iter().any(|rule| {
            rule.access == 0
                || rule.access & !ALL_ACCESS != 0
                || (rule.kind == DeviceAccessKind::All
                    && (rule.major.is_some() || rule.minor.is_some()))
        }) {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                "serialized device policy contains an invalid access rule",
            ));
        }
        Ok(())
    }

    fn build_program(&self) -> Result<Vec<BpfInsn>> {
        let mut program = vec![
            mov64_imm(BPF_REG_0, 0),
            ldx_mem(libc::BPF_W, BPF_REG_2, BPF_REG_1, 0),
            alu32_imm(BPF_AND, BPF_REG_2, 0xFFFF),
            ldx_mem(libc::BPF_W, BPF_REG_3, BPF_REG_1, 0),
            alu32_imm(BPF_RSH, BPF_REG_3, 16),
            ldx_mem(libc::BPF_W, BPF_REG_4, BPF_REG_1, 4),
            ldx_mem(libc::BPF_W, BPF_REG_5, BPF_REG_1, 8),
        ];

        for rule in &self.rules {
            let mut mismatch_jumps = Vec::with_capacity(3);
            match rule.kind {
                DeviceAccessKind::All => {}
                DeviceAccessKind::Block => mismatch_jumps.push(push_jne_imm(
                    &mut program,
                    BPF_REG_2,
                    BPF_DEVCG_DEV_BLOCK as i32,
                )),
                DeviceAccessKind::Character => mismatch_jumps.push(push_jne_imm(
                    &mut program,
                    BPF_REG_2,
                    BPF_DEVCG_DEV_CHAR as i32,
                )),
            }
            if let Some(major) = rule.major {
                mismatch_jumps.push(push_jne_imm(&mut program, BPF_REG_4, u32_as_i32(major)));
            }
            if let Some(minor) = rule.minor {
                mismatch_jumps.push(push_jne_imm(&mut program, BPF_REG_5, u32_as_i32(minor)));
            }

            if rule.kind == DeviceAccessKind::All {
                // The v1 devices controller treats `a` as a policy reset and
                // ignores the remaining match fields and access subset.
                program.push(mov64_imm(
                    BPF_REG_0,
                    if rule.allow { i32::from(ALL_ACCESS) } else { 0 },
                ));
            } else if rule.allow {
                program.push(alu32_imm(BPF_OR, BPF_REG_0, i32::from(rule.access)));
            } else {
                program.push(alu32_imm(
                    BPF_AND,
                    BPF_REG_0,
                    i32::from(ALL_ACCESS & !rule.access),
                ));
            }

            let next_rule = program.len();
            for jump_index in mismatch_jumps {
                patch_jump(&mut program, jump_index, next_rule)?;
            }
        }

        // A device operation may request more than one of r/w/m. It succeeds
        // only when the ordered policy retained every requested permission.
        program.push(mov64_reg(BPF_REG_1, BPF_REG_3));
        program.push(alu32_reg(BPF_AND, BPF_REG_1, BPF_REG_0));
        let reject_jump = push_jne_reg(&mut program, BPF_REG_1, BPF_REG_3);
        program.push(mov64_imm(BPF_REG_0, 1));
        program.push(exit_insn());
        let reject = program.len();
        program.push(mov64_imm(BPF_REG_0, 0));
        program.push(exit_insn());
        patch_jump(&mut program, reject_jump, reject)?;

        Ok(program)
    }
}

impl DeviceAccessRule {
    fn from_oci(index: usize, rule: &LinuxDeviceCgroup) -> Result<Self> {
        let field = format!("linux.resources.devices[{index}]");
        let kind = match rule.typ() {
            None | Some(LinuxDeviceType::A) => DeviceAccessKind::All,
            Some(LinuxDeviceType::B) => DeviceAccessKind::Block,
            Some(LinuxDeviceType::C) => DeviceAccessKind::Character,
            Some(LinuxDeviceType::U) => {
                return Err(unsupported(
                    &format!("{field}.type"),
                    "device cgroup rules use `c` for character devices",
                ));
            }
            Some(LinuxDeviceType::P) => {
                return Err(unsupported(
                    &format!("{field}.type"),
                    "FIFO nodes are not governed by the Linux devices controller",
                ));
            }
        };
        let major = parse_device_number(&format!("{field}.major"), rule.major())?;
        let minor = parse_device_number(&format!("{field}.minor"), rule.minor())?;
        let access =
            parse_device_access_mask(&format!("{field}.access"), rule.access().as_deref())?;

        Ok(Self {
            allow: rule.allow(),
            kind,
            major: (kind != DeviceAccessKind::All).then_some(major).flatten(),
            minor: (kind != DeviceAccessKind::All).then_some(minor).flatten(),
            access,
        })
    }
}

impl LoadedDeviceProgram {
    pub(in crate::executor) fn attach_to_fd(&self, cgroup: RawFd) -> Result<()> {
        attach_cgroup_device_program_fd(cgroup, &self.0, None)
    }

    pub(in crate::executor) fn replace_on_fd(
        &self,
        cgroup: RawFd,
        replaced: &LoadedDeviceProgram,
    ) -> Result<()> {
        attach_cgroup_device_program_fd(cgroup, &self.0, Some(&replaced.0))
    }

    pub(in crate::executor) fn detach_from_fd(&self, cgroup: RawFd) -> Result<()> {
        detach_cgroup_device_program_fd(cgroup, &self.0)
    }
}

pub(super) fn attach_loaded_cgroup_device_program(
    cgroup_path: &Path,
    loaded: &OwnedFd,
) -> Result<()> {
    attach_cgroup_device_program(cgroup_path, loaded, None)
}

pub(super) fn replace_loaded_cgroup_device_program(
    cgroup_path: &Path,
    loaded: &OwnedFd,
    replaced: &OwnedFd,
) -> Result<()> {
    attach_cgroup_device_program(cgroup_path, loaded, Some(replaced))
}

pub(super) fn detach_loaded_cgroup_device_program(
    cgroup_path: &Path,
    attached: &OwnedFd,
) -> Result<()> {
    let cgroup = open_cgroup_descriptor(cgroup_path)?;
    detach_cgroup_device_program_fd(cgroup.as_raw_fd(), attached).map_err(|error| {
        Error::new(
            error.code,
            format!(
                "failed to detach cgroup device BPF program from {}: {}",
                cgroup_path.display(),
                error.message
            ),
        )
        .for_operation("enforce-container-devices")
        .retryable(error.retryable)
    })
}

fn parse_device_number(field: &str, value: Option<i64>) -> Result<Option<u32>> {
    value
        .map(|value| {
            u32::try_from(value)
                .map_err(|_| invalid(format!("{field} must be a non-negative u32 when present")))
        })
        .transpose()
}

fn parse_device_access_mask(field: &str, value: Option<&str>) -> Result<u8> {
    let Some(value) = value else {
        return Ok(0);
    };
    let mut mask = 0_u8;
    for access in value.chars() {
        match access {
            'r' => mask |= BPF_DEVCG_ACC_READ as u8,
            'w' => mask |= BPF_DEVCG_ACC_WRITE as u8,
            'm' => mask |= BPF_DEVCG_ACC_MKNOD as u8,
            _ => {
                return Err(invalid(format!(
                    "{field} must contain only `r`, `w`, and `m`"
                )));
            }
        }
    }
    Ok(mask)
}

fn attach_cgroup_device_program(
    cgroup_path: &Path,
    loaded: &OwnedFd,
    replaced: Option<&OwnedFd>,
) -> Result<()> {
    let cgroup = open_cgroup_descriptor(cgroup_path)?;
    attach_cgroup_device_program_fd(cgroup.as_raw_fd(), loaded, replaced).map_err(|error| {
        Error::new(
            error.code,
            format!(
                "failed to attach cgroup device BPF program to {}: {}",
                cgroup_path.display(),
                error.message
            ),
        )
        .for_operation("enforce-container-devices")
        .retryable(error.retryable)
    })
}

fn attach_cgroup_device_program_fd(
    cgroup: RawFd,
    loaded: &OwnedFd,
    replaced: Option<&OwnedFd>,
) -> Result<()> {
    let mut attr = BpfProgAttachAttr {
        target_fd: cgroup as u32,
        attach_bpf_fd: loaded.as_raw_fd() as u32,
        attach_type: BPF_CGROUP_DEVICE,
        attach_flags: BPF_F_ALLOW_MULTI | if replaced.is_some() { BPF_F_REPLACE } else { 0 },
        replace_bpf_fd: replaced.map_or(0, |program| program.as_raw_fd() as u32),
    };
    // SAFETY: the cgroup and program descriptors are live owned fds and the
    // attribute struct matches the kernel layout for BPF_PROG_ATTACH.
    let attached = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_ATTACH,
            &mut attr as *mut _ as *mut libc::c_void,
            size_of::<BpfProgAttachAttr>(),
        )
    };
    if attached != 0 {
        return Err(bpf_last_os_error(
            "failed to attach cgroup device BPF program",
        ));
    }
    Ok(())
}

fn detach_cgroup_device_program_fd(cgroup: RawFd, attached: &OwnedFd) -> Result<()> {
    let mut attr = BpfProgAttachAttr {
        target_fd: cgroup as u32,
        attach_bpf_fd: attached.as_raw_fd() as u32,
        attach_type: BPF_CGROUP_DEVICE,
        attach_flags: 0,
        replace_bpf_fd: 0,
    };
    // SAFETY: the cgroup and program descriptors are live owned fds and the
    // attribute struct matches the kernel layout for BPF_PROG_DETACH.
    let detached = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_DETACH,
            &mut attr as *mut _ as *mut libc::c_void,
            size_of::<BpfProgAttachAttr>(),
        )
    };
    if detached != 0 {
        return Err(bpf_last_os_error(
            "failed to detach cgroup device BPF program",
        ));
    }
    Ok(())
}

fn load_cgroup_device_program_fd(program: &[BpfInsn]) -> Result<OwnedFd> {
    let insn_cnt = u32::try_from(program.len()).map_err(|error| {
        device_error(
            ErrorCode::ResourceExhausted,
            format!("cgroup device BPF program exceeds the kernel instruction limit: {error}"),
        )
    })?;
    let license = c"GPL";
    let mut log = Vec::new();
    let mut with_log = false;
    loop {
        let mut attr = BpfProgLoadAttr {
            prog_type: BPF_PROG_TYPE_CGROUP_DEVICE,
            insn_cnt,
            insns: program.as_ptr() as u64,
            license: license.as_ptr() as u64,
            log_level: if with_log { 1 } else { 0 },
            log_size: log.len() as u32,
            log_buf: if with_log { log.as_mut_ptr() as u64 } else { 0 },
            kern_version: 0,
            prog_flags: 0,
            prog_name: [0; 16],
            prog_ifindex: 0,
            expected_attach_type: BPF_CGROUP_DEVICE,
        };
        // SAFETY: the attribute struct is fully initialized and the program
        // and license pointers stay live for the duration of the syscall.
        let loaded = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_PROG_LOAD,
                &mut attr as *mut _ as *mut libc::c_void,
                size_of::<BpfProgLoadAttr>(),
            )
        };
        if loaded >= 0 {
            let fd = i32::try_from(loaded).map_err(|error| {
                device_error(
                    ErrorCode::Internal,
                    format!("BPF_PROG_LOAD returned an invalid descriptor: {error}"),
                )
            })?;
            // SAFETY: `fd` is a fresh owned descriptor returned by BPF_PROG_LOAD.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }

        let error = io::Error::last_os_error();
        if !with_log {
            bump_memlock_limit();
            log.resize(16 * 1024, 0);
            with_log = true;
            continue;
        }
        if error.raw_os_error() == Some(libc::ENOSPC) && log.len() < MAX_BPF_LOG_BYTES {
            let next = (log.len().max(16 * 1024) * 2).min(MAX_BPF_LOG_BYTES);
            log.resize(next, 0);
            continue;
        }
        return Err(bpf_load_failure(error, &log));
    }
}

fn open_cgroup_descriptor(path: &Path) -> Result<OwnedFd> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to open cgroup directory {}: {error}",
                    path.display()
                ),
            )
        })?;
    let raw = file.into_raw_fd();
    // SAFETY: `raw` is a live owned descriptor from OpenOptions.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn bump_memlock_limit() {
    let mut current = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: the pointed-to structure is valid and owned by this function.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &current) } == 0 {
        return;
    }
    // SAFETY: the pointed-to structure is valid and owned by this function.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut current) } != 0 {
        return;
    }
    current.rlim_cur = current.rlim_max;
    // SAFETY: the pointed-to structure is valid and owned by this function.
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &current) };
}

fn bpf_load_failure(error: io::Error, log: &[u8]) -> Error {
    let message = if let Some(verifier_log) = verifier_log(log) {
        format!("failed to load cgroup device BPF program: {error}: {verifier_log}")
    } else {
        format!("failed to load cgroup device BPF program: {error}")
    };
    device_error(bpf_error_code(&error), message)
}

fn bpf_last_os_error(message: impl Into<String>) -> Error {
    let error = io::Error::last_os_error();
    device_error(
        bpf_error_code(&error),
        format!("{}: {error}", message.into()),
    )
}

fn bpf_error_code(error: &io::Error) -> ErrorCode {
    match error.raw_os_error() {
        Some(code) if code == libc::EPERM || code == libc::EACCES => ErrorCode::PermissionDenied,
        Some(code) if code == libc::ENOMEM => ErrorCode::ResourceExhausted,
        Some(code)
            if code == libc::EINVAL
                || code == libc::EOPNOTSUPP
                || code == libc::ENOSYS
                || code == libc::ENOTSUP =>
        {
            ErrorCode::Unsupported
        }
        _ => ErrorCode::FailedPrecondition,
    }
}

fn verifier_log(log: &[u8]) -> Option<String> {
    let end = log.iter().rposition(|byte| *byte != 0)?;
    let log = String::from_utf8_lossy(&log[..=end]).trim().to_string();
    (!log.is_empty()).then_some(log)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct BpfInsn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

#[repr(C)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

#[repr(C)]
struct BpfProgAttachAttr {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
    replace_bpf_fd: u32,
}

const BPF_ALU64: u32 = 0x07;
const BPF_MOV: u32 = 0xb0;
const BPF_AND: u32 = 0x50;
const BPF_OR: u32 = 0x40;
const BPF_RSH: u32 = 0x70;
const BPF_JNE: u32 = 0x50;
const BPF_EXIT: u32 = 0x90;
const BPF_REG_0: u8 = 0;
const BPF_REG_1: u8 = 1;
const BPF_REG_2: u8 = 2;
const BPF_REG_3: u8 = 3;
const BPF_REG_4: u8 = 4;
const BPF_REG_5: u8 = 5;
const BPF_PROG_LOAD: u32 = 5;
const BPF_PROG_ATTACH: u32 = 8;
const BPF_PROG_DETACH: u32 = 9;
const BPF_F_ALLOW_MULTI: u32 = 1 << 1;
const BPF_F_REPLACE: u32 = 1 << 2;
const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 15;
const BPF_CGROUP_DEVICE: u32 = 6;
const BPF_DEVCG_ACC_MKNOD: u32 = 1;
const BPF_DEVCG_ACC_READ: u32 = 2;
const BPF_DEVCG_ACC_WRITE: u32 = 4;
const BPF_DEVCG_DEV_BLOCK: u32 = 1;
const BPF_DEVCG_DEV_CHAR: u32 = 2;
const MAX_BPF_LOG_BYTES: usize = 64 * 1024;

fn ldx_mem(size: u32, dst: u8, src: u8, off: i16) -> BpfInsn {
    BpfInsn {
        code: (libc::BPF_LDX | size | libc::BPF_MEM) as u8,
        regs: pack_regs(dst, src),
        off,
        imm: 0,
    }
}

fn alu32_imm(op: u32, dst: u8, imm: i32) -> BpfInsn {
    BpfInsn {
        code: (libc::BPF_ALU | op | libc::BPF_K) as u8,
        regs: pack_regs(dst, 0),
        off: 0,
        imm,
    }
}

fn alu32_reg(op: u32, dst: u8, src: u8) -> BpfInsn {
    BpfInsn {
        code: (libc::BPF_ALU | op | libc::BPF_X) as u8,
        regs: pack_regs(dst, src),
        off: 0,
        imm: 0,
    }
}

fn mov64_reg(dst: u8, src: u8) -> BpfInsn {
    BpfInsn {
        code: (BPF_ALU64 | BPF_MOV | libc::BPF_X) as u8,
        regs: pack_regs(dst, src),
        off: 0,
        imm: 0,
    }
}

fn mov64_imm(dst: u8, imm: i32) -> BpfInsn {
    BpfInsn {
        code: (BPF_ALU64 | BPF_MOV | libc::BPF_K) as u8,
        regs: pack_regs(dst, 0),
        off: 0,
        imm,
    }
}

fn push_jne_imm(program: &mut Vec<BpfInsn>, dst: u8, imm: i32) -> usize {
    let index = program.len();
    program.push(BpfInsn {
        code: (libc::BPF_JMP | BPF_JNE | libc::BPF_K) as u8,
        regs: pack_regs(dst, 0),
        off: 0,
        imm,
    });
    index
}

fn push_jne_reg(program: &mut Vec<BpfInsn>, dst: u8, src: u8) -> usize {
    let index = program.len();
    program.push(BpfInsn {
        code: (libc::BPF_JMP | BPF_JNE | libc::BPF_X) as u8,
        regs: pack_regs(dst, src),
        off: 0,
        imm: 0,
    });
    index
}

fn patch_jump(program: &mut [BpfInsn], jump_index: usize, target: usize) -> Result<()> {
    let jump = program.get_mut(jump_index).ok_or_else(|| {
        device_error(
            ErrorCode::Internal,
            "cgroup device BPF program lost a patch target",
        )
    })?;
    let offset = target as isize - jump_index as isize - 1;
    jump.off = i16::try_from(offset).map_err(|error| {
        device_error(
            ErrorCode::ResourceExhausted,
            format!("cgroup device BPF program exceeds jump limits: {error}"),
        )
    })?;
    Ok(())
}

fn exit_insn() -> BpfInsn {
    BpfInsn {
        code: (libc::BPF_JMP | BPF_EXIT) as u8,
        regs: 0,
        off: 0,
        imm: 0,
    }
}

fn pack_regs(dst: u8, src: u8) -> u8 {
    (dst & 0x0f) | ((src & 0x0f) << 4)
}

fn u32_as_i32(value: u32) -> i32 {
    i32::from_ne_bytes(value.to_ne_bytes())
}

#[cfg(test)]
mod tests;
