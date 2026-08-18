use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::BpfInsn;
use crate::executor::device::device_error;

#[derive(Debug)]
pub(in crate::executor) struct LoadedDeviceProgram(OwnedFd);

impl LoadedDeviceProgram {
    pub(super) fn load(program: &[BpfInsn]) -> Result<Self> {
        load_cgroup_device_program(program).map(Self)
    }

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

pub(super) fn load_cgroup_device_program(program: &[BpfInsn]) -> Result<OwnedFd> {
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

const BPF_PROG_LOAD: u32 = 5;
const BPF_PROG_ATTACH: u32 = 8;
const BPF_PROG_DETACH: u32 = 9;
const BPF_F_ALLOW_MULTI: u32 = 1 << 1;
const BPF_F_REPLACE: u32 = 1 << 2;
const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 15;
const BPF_CGROUP_DEVICE: u32 = 6;
const MAX_BPF_LOG_BYTES: usize = 64 * 1024;
