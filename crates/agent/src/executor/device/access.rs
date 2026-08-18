use std::collections::BTreeSet;
use std::os::fd::OwnedFd;
use std::path::Path;

use a3s_oci_sdk::oci_spec::runtime::{LinuxDeviceCgroup, LinuxDeviceType};
use a3s_oci_sdk::{ErrorCode, Result};
use serde::{Deserialize, Serialize};

use super::{device_error, invalid, unsupported};

mod kernel;

pub(in crate::executor) use kernel::LoadedDeviceProgram;

const MAX_DEVICE_ACCESS_RULES: usize = 512;
// DevicePlan admits 256 explicit OCI entries and then supplies the six
// normative defaults. PTMX and the Unix98 PTY slave family are represented
// separately because their nodes are created dynamically.
const MAX_DEVICE_ACCESS_IDENTITIES: usize = 256 + 6 + 2;
const ALL_ACCESS: u8 = (BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE | BPF_DEVCG_ACC_MKNOD) as u8;
const OCI_PTMX_MAJOR: u32 = 5;
const OCI_PTMX_MINOR: u32 = 2;
const UNIX98_PTY_SLAVE_MAJOR: u32 = 136;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DeviceAccessPolicy {
    rules: Vec<DeviceAccessRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DeviceAccessBoundary {
    identities: Vec<DeviceAccessIdentity>,
    policy: Option<DeviceAccessPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct DeviceAccessIdentity {
    kind: DeviceAccessKind,
    major: u32,
    minor: Option<u32>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum DeviceAccessKind {
    All,
    Block,
    Character,
}

impl DeviceAccessBoundary {
    pub(super) fn for_oci_nodes(
        nodes: impl IntoIterator<Item = (DeviceAccessKind, u32, u32)>,
        policy: Option<DeviceAccessPolicy>,
    ) -> Result<Self> {
        let mut identities = nodes
            .into_iter()
            .map(|(kind, major, minor)| DeviceAccessIdentity {
                kind,
                major,
                minor: Some(minor),
            })
            .collect::<BTreeSet<_>>();
        identities.insert(DeviceAccessIdentity {
            kind: DeviceAccessKind::Character,
            major: OCI_PTMX_MAJOR,
            minor: Some(OCI_PTMX_MINOR),
        });
        identities.insert(DeviceAccessIdentity {
            kind: DeviceAccessKind::Character,
            major: UNIX98_PTY_SLAVE_MAJOR,
            minor: None,
        });
        let boundary = Self {
            identities: identities.into_iter().collect(),
            policy,
        };
        boundary.validate()?;
        Ok(boundary)
    }

    pub(super) fn load(&self) -> Result<OwnedFd> {
        self.validate()?;
        kernel::load_cgroup_device_program(&self.build_program()?)
    }

    pub(super) fn load_for_rootless_helper(&self) -> Result<LoadedDeviceProgram> {
        self.validate()?;
        LoadedDeviceProgram::load(&self.build_program()?)
    }

    fn validate(&self) -> Result<()> {
        if self.identities.is_empty() || self.identities.len() > MAX_DEVICE_ACCESS_IDENTITIES {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                "OCI device inventory has an invalid identity count",
            ));
        }
        if self
            .identities
            .iter()
            .any(|identity| identity.kind == DeviceAccessKind::All)
        {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                "OCI device inventory contains a wildcard device type",
            ));
        }
        if let Some(policy) = &self.policy {
            policy.validate()?;
        }
        Ok(())
    }

    fn build_program(&self) -> Result<Vec<BpfInsn>> {
        let mut program = device_program_prelude(0);
        for identity in &self.identities {
            append_inventory_identity(&mut program, *identity)?;
        }

        // Preserve the immutable OCI inventory mask in a callee-saved BPF
        // register while evaluating the mutable ordered cgroup rules. The
        // final mask is their intersection, so an allow-all update can never
        // expose a device outside linux.devices or the normative defaults.
        program.push(mov64_reg(BPF_REG_6, BPF_REG_0));
        program.push(mov64_imm(
            BPF_REG_0,
            if self.policy.is_some() {
                0
            } else {
                i32::from(ALL_ACCESS)
            },
        ));
        if let Some(policy) = &self.policy {
            append_ordered_rules(&mut program, &policy.rules)?;
        }
        program.push(alu32_reg(BPF_AND, BPF_REG_0, BPF_REG_6));
        finish_device_program(&mut program)?;
        Ok(program)
    }
}

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

    #[cfg(test)]
    fn build_program(&self) -> Result<Vec<BpfInsn>> {
        let mut program = device_program_prelude(0);
        append_ordered_rules(&mut program, &self.rules)?;
        finish_device_program(&mut program)?;
        Ok(program)
    }
}

fn device_program_prelude(initial_access: u8) -> Vec<BpfInsn> {
    vec![
        mov64_imm(BPF_REG_0, i32::from(initial_access)),
        ldx_mem(libc::BPF_W, BPF_REG_2, BPF_REG_1, 0),
        alu32_imm(BPF_AND, BPF_REG_2, 0xFFFF),
        ldx_mem(libc::BPF_W, BPF_REG_3, BPF_REG_1, 0),
        alu32_imm(BPF_RSH, BPF_REG_3, 16),
        ldx_mem(libc::BPF_W, BPF_REG_4, BPF_REG_1, 4),
        ldx_mem(libc::BPF_W, BPF_REG_5, BPF_REG_1, 8),
    ]
}

fn append_ordered_rules(program: &mut Vec<BpfInsn>, rules: &[DeviceAccessRule]) -> Result<()> {
    for rule in rules {
        let mut mismatch_jumps = Vec::with_capacity(3);
        match rule.kind {
            DeviceAccessKind::All => {}
            DeviceAccessKind::Block => {
                mismatch_jumps.push(push_jne_imm(program, BPF_REG_2, BPF_DEVCG_DEV_BLOCK as i32))
            }
            DeviceAccessKind::Character => {
                mismatch_jumps.push(push_jne_imm(program, BPF_REG_2, BPF_DEVCG_DEV_CHAR as i32))
            }
        }
        if let Some(major) = rule.major {
            mismatch_jumps.push(push_jne_imm(program, BPF_REG_4, u32_as_i32(major)));
        }
        if let Some(minor) = rule.minor {
            mismatch_jumps.push(push_jne_imm(program, BPF_REG_5, u32_as_i32(minor)));
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
            patch_jump(program, jump_index, next_rule)?;
        }
    }
    Ok(())
}

fn append_inventory_identity(
    program: &mut Vec<BpfInsn>,
    identity: DeviceAccessIdentity,
) -> Result<()> {
    let expected_kind = match identity.kind {
        DeviceAccessKind::Block => BPF_DEVCG_DEV_BLOCK,
        DeviceAccessKind::Character => BPF_DEVCG_DEV_CHAR,
        DeviceAccessKind::All => {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                "OCI device inventory contains a wildcard device type",
            ));
        }
    };
    let mut mismatch_jumps = vec![
        push_jne_imm(program, BPF_REG_2, expected_kind as i32),
        push_jne_imm(program, BPF_REG_4, u32_as_i32(identity.major)),
    ];
    if let Some(minor) = identity.minor {
        mismatch_jumps.push(push_jne_imm(program, BPF_REG_5, u32_as_i32(minor)));
    }
    program.push(alu32_imm(BPF_OR, BPF_REG_0, i32::from(ALL_ACCESS)));
    let next_identity = program.len();
    for jump_index in mismatch_jumps {
        patch_jump(program, jump_index, next_identity)?;
    }
    Ok(())
}

fn finish_device_program(program: &mut Vec<BpfInsn>) -> Result<()> {
    // A device operation may request more than one of r/w/m. It succeeds only
    // when every boundary and ordered-policy layer retained every bit.
    program.push(mov64_reg(BPF_REG_1, BPF_REG_3));
    program.push(alu32_reg(BPF_AND, BPF_REG_1, BPF_REG_0));
    let reject_jump = push_jne_reg(program, BPF_REG_1, BPF_REG_3);
    program.push(mov64_imm(BPF_REG_0, 1));
    program.push(exit_insn());
    let reject = program.len();
    program.push(mov64_imm(BPF_REG_0, 0));
    program.push(exit_insn());
    patch_jump(program, reject_jump, reject)
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

pub(super) fn attach_loaded_cgroup_device_program(
    cgroup_path: &Path,
    loaded: &OwnedFd,
) -> Result<()> {
    kernel::attach_loaded_cgroup_device_program(cgroup_path, loaded)
}

pub(super) fn replace_loaded_cgroup_device_program(
    cgroup_path: &Path,
    loaded: &OwnedFd,
    replaced: &OwnedFd,
) -> Result<()> {
    kernel::replace_loaded_cgroup_device_program(cgroup_path, loaded, replaced)
}

pub(super) fn detach_loaded_cgroup_device_program(
    cgroup_path: &Path,
    attached: &OwnedFd,
) -> Result<()> {
    kernel::detach_loaded_cgroup_device_program(cgroup_path, attached)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct BpfInsn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
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
const BPF_REG_6: u8 = 6;
const BPF_DEVCG_ACC_MKNOD: u32 = 1;
const BPF_DEVCG_ACC_READ: u32 = 2;
const BPF_DEVCG_ACC_WRITE: u32 = 4;
const BPF_DEVCG_DEV_BLOCK: u32 = 1;
const BPF_DEVCG_DEV_CHAR: u32 = 2;

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
