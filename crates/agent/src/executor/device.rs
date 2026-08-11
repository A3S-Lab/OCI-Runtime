use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::{Linux, LinuxDevice, LinuxDeviceCgroup, LinuxDeviceType};
use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::mount::MountPlan;
use super::namespace::NamespacePlan;

const MAX_DEVICES: usize = 256;
const MAX_SCANNED_ROOTFS_ENTRIES: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DevicePlan {
    nodes: Vec<DeviceNode>,
    enforce_allowlist: bool,
}

#[derive(Debug)]
pub(super) struct PreparedDeviceSources {
    mounts: Option<Vec<OwnedFd>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DeviceNode {
    path: PathBuf,
    kind: DeviceKind,
    major: u32,
    minor: u32,
    mode: u32,
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DeviceKind {
    Block,
    Character,
    Fifo,
}

impl DevicePlan {
    pub(super) fn from_linux(linux: Option<&Linux>, mounts: &[MountPlan]) -> Result<Self> {
        let Some(linux) = linux else {
            return Ok(Self {
                nodes: Vec::new(),
                enforce_allowlist: false,
            });
        };
        let devices = linux.devices().as_deref().unwrap_or_default();
        let rules = linux
            .resources()
            .as_ref()
            .and_then(|resources| resources.devices().as_deref())
            .unwrap_or_default();
        if devices.len() > MAX_DEVICES {
            return Err(invalid(format!(
                "linux.devices contains {} entries; maximum is {MAX_DEVICES}",
                devices.len()
            )));
        }
        let nodes = devices
            .iter()
            .enumerate()
            .map(|(index, device)| DeviceNode::from_oci(index, device))
            .collect::<Result<Vec<_>>>()?;
        let mut unique_paths = BTreeSet::new();
        let mut unique_numbers = BTreeSet::new();
        for node in &nodes {
            if !unique_paths.insert(node.path.clone()) {
                return Err(invalid(format!(
                    "linux.devices contains duplicate path {}",
                    node.path.display()
                )));
            }
            if !unique_numbers.insert((node.kind, node.major, node.minor)) {
                return Err(invalid(format!(
                    "linux.devices contains duplicate {} {}:{}",
                    node.kind.description(),
                    node.major,
                    node.minor
                )));
            }
        }
        validate_device_policy(&nodes, Some(rules))?;
        let enforce_allowlist = !nodes.is_empty() || !rules.is_empty();
        if enforce_allowlist {
            validate_bind_mounts_are_nodev(mounts)?;
        }
        Ok(Self {
            nodes,
            enforce_allowlist,
        })
    }

    pub(super) fn validate_rootfs(&self, rootfs: &Path) -> Result<()> {
        if !self.enforce_allowlist {
            return Ok(());
        }
        let allowed = self
            .nodes
            .iter()
            .map(|node| node.path.clone())
            .collect::<BTreeSet<_>>();
        let mut pending = vec![rootfs.to_path_buf()];
        let mut visited = 0_usize;
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory).map_err(|error| {
                device_error(
                    ErrorCode::InvalidArgument,
                    format!(
                        "failed to scan rootfs device nodes in {}: {error}",
                        directory.display()
                    ),
                )
            })? {
                let entry = entry.map_err(|error| {
                    device_error(
                        ErrorCode::InvalidArgument,
                        format!("failed to inspect a rootfs entry: {error}"),
                    )
                })?;
                let entry_path = entry.path();
                visited = visited.checked_add(1).ok_or_else(|| {
                    device_error(ErrorCode::ResourceExhausted, "rootfs entry count overflow")
                })?;
                if visited > MAX_SCANNED_ROOTFS_ENTRIES {
                    return Err(device_error(
                        ErrorCode::ResourceExhausted,
                        format!("rootfs device scan exceeds {MAX_SCANNED_ROOTFS_ENTRIES} entries"),
                    ));
                }
                let metadata = fs::symlink_metadata(&entry_path).map_err(|error| {
                    device_error(
                        ErrorCode::InvalidArgument,
                        format!(
                            "failed to inspect rootfs entry {}: {error}",
                            entry_path.display()
                        ),
                    )
                })?;
                let file_type = metadata.file_type();
                if file_type.is_dir() {
                    pending.push(entry_path);
                } else if file_type.is_char_device() || file_type.is_block_device() {
                    let relative = entry_path.strip_prefix(rootfs).map_err(|_| {
                        device_error(
                            ErrorCode::PermissionDenied,
                            "rootfs device scan escaped the retained root",
                        )
                    })?;
                    let container_path = Path::new("/").join(relative);
                    if !allowed.contains(&container_path) {
                        return Err(device_error(
                            ErrorCode::PermissionDenied,
                            format!(
                                "rootfs contains device node outside the OCI allowlist: {}",
                                container_path.display()
                            ),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn prepare_sources(
        &self,
        namespaces: &NamespacePlan,
        runtime_directory: &Path,
    ) -> Result<PreparedDeviceSources> {
        if !namespaces.has_user() {
            return Ok(PreparedDeviceSources { mounts: None });
        }
        if !namespaces.new_user() && !self.nodes.is_empty() {
            return Err(unsupported(
                "linux.devices",
                "devices in a joined user namespace require externally prepared mount sources",
            ));
        }
        if self.nodes.is_empty() {
            return Ok(PreparedDeviceSources {
                mounts: Some(Vec::new()),
            });
        }

        let directory = runtime_directory.join("devices");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&directory).map_err(|error| {
            device_error(
                ErrorCode::Conflict,
                format!(
                    "failed to create private device source directory {}: {error}",
                    directory.display()
                ),
            )
        })?;

        let prepared = self
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| node.prepare_source(index, &directory, namespaces))
            .collect::<Result<Vec<_>>>();
        match prepared {
            Ok(mounts) => Ok(PreparedDeviceSources {
                mounts: Some(mounts),
            }),
            Err(error) => {
                let _ = fs::remove_dir_all(&directory);
                Err(error)
            }
        }
    }

    pub(super) fn bind_prepared_sources(
        &self,
        rootfs: &Path,
        prepared: &PreparedDeviceSources,
    ) -> Result<()> {
        let Some(mounts) = prepared.mounts.as_ref() else {
            return Ok(());
        };
        if mounts.len() != self.nodes.len() {
            return Err(device_error(
                ErrorCode::Internal,
                "prepared device source count does not match the OCI device plan",
            ));
        }
        for (node, source) in self.nodes.iter().zip(mounts) {
            node.bind_source(rootfs, source)?;
        }
        Ok(())
    }

    pub(super) fn create_all(&self) -> Result<()> {
        for node in &self.nodes {
            node.create()?;
        }
        Ok(())
    }

    pub(super) const fn uses_prepared_sources(prepared: &PreparedDeviceSources) -> bool {
        prepared.mounts.is_some()
    }

    pub(super) fn requires_setup(&self) -> bool {
        self.enforce_allowlist
    }

    pub(super) fn install_cgroup_device_filter(&self, cgroup_path: &Path) -> Result<()> {
        if !self.enforce_allowlist {
            return Ok(());
        }
        let program = build_cgroup_device_program(&self.nodes)?;
        attach_cgroup_device_program(cgroup_path, &program)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.nodes.len()
    }
}

impl DeviceNode {
    fn from_oci(index: usize, device: &LinuxDevice) -> Result<Self> {
        let path = normalize_device_path(index, device.path())?;
        let kind = DeviceKind::from_oci(index, device.typ())?;
        let major = u32::try_from(device.major()).map_err(|_| {
            invalid(format!(
                "linux.devices[{index}].major must be a non-negative u32"
            ))
        })?;
        let minor = u32::try_from(device.minor()).map_err(|_| {
            invalid(format!(
                "linux.devices[{index}].minor must be a non-negative u32"
            ))
        })?;
        let mode = device.file_mode().unwrap_or(0o666);
        if mode > 0o7777 {
            return Err(invalid(format!(
                "linux.devices[{index}].fileMode exceeds POSIX permission and special bits"
            )));
        }
        Ok(Self {
            path,
            kind,
            major,
            minor,
            mode,
            uid: device.uid().unwrap_or(0),
            gid: device.gid().unwrap_or(0),
        })
    }

    fn prepare_source(
        &self,
        index: usize,
        directory: &Path,
        namespaces: &NamespacePlan,
    ) -> Result<OwnedFd> {
        let host_uid = namespaces.host_uid(self.uid).ok_or_else(|| {
            invalid(format!(
                "linux.devices[{index}].uid {} is not covered by linux.uidMappings",
                self.uid
            ))
        })?;
        let host_gid = namespaces.host_gid(self.gid).ok_or_else(|| {
            invalid(format!(
                "linux.devices[{index}].gid {} is not covered by linux.gidMappings",
                self.gid
            ))
        })?;
        let path = directory.join(format!("device-{index:04}"));
        let path_cstring = path_cstring(&path, "prepared device source")?;
        let file_type = self.file_type();
        let device = libc::makedev(self.major, self.minor);
        // SAFETY: the path is a live NUL-terminated string in an exclusive
        // runtime directory and the mode and device numbers were validated.
        if unsafe { libc::mknod(path_cstring.as_ptr(), file_type | self.mode, device) } != 0 {
            return Err(last_os_error(format!(
                "precreate OCI device source for {}",
                self.path.display()
            )));
        }
        // SAFETY: the source path remains live and is still owned exclusively
        // by this create operation.
        if unsafe { libc::chown(path_cstring.as_ptr(), host_uid, host_gid) } != 0 {
            return Err(last_os_error(format!(
                "set mapped ownership on OCI device source for {}",
                self.path.display()
            )));
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(self.mode)).map_err(|error| {
            device_error(
                ErrorCode::PermissionDenied,
                format!(
                    "failed to set mode on OCI device source for {}: {error}",
                    self.path.display()
                ),
            )
        })?;
        self.verify_at(&path, host_uid, host_gid)?;
        clone_device_mount(&path)
    }

    fn bind_source(&self, rootfs: &Path, source: &OwnedFd) -> Result<()> {
        let canonical_rootfs = rootfs.canonicalize().map_err(|error| {
            invalid(format!(
                "failed to resolve the container rootfs while binding {}: {error}",
                self.path.display()
            ))
        })?;
        let relative = self.path.strip_prefix("/").map_err(|error| {
            device_error(
                ErrorCode::Internal,
                format!("invalid normalized OCI device path: {error}"),
            )
        })?;
        let target = canonical_rootfs.join(relative);
        let parent = target.parent().ok_or_else(|| {
            device_error(
                ErrorCode::Internal,
                format!("OCI device path has no parent: {}", target.display()),
            )
        })?;
        let canonical_parent = parent.canonicalize().map_err(|error| {
            invalid(format!(
                "failed to resolve OCI device parent {}: {error}",
                parent.display()
            ))
        })?;
        if canonical_parent != canonical_rootfs && !canonical_parent.starts_with(&canonical_rootfs)
        {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                format!(
                    "OCI device path escapes the container rootfs: {}",
                    self.path.display()
                ),
            ));
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&target)
            .map_err(|error| {
                invalid(format!(
                    "failed to create OCI device bind target {}: {error}",
                    self.path.display()
                ))
            })?;

        attach_device_mount(source, &target, &self.path)?;
        self.verify_at(&target, self.uid, self.gid)
    }

    fn create(&self) -> Result<()> {
        let parent = self.path.parent().ok_or_else(|| {
            invalid(format!(
                "device path has no parent: {}",
                self.path.display()
            ))
        })?;
        let metadata = fs::symlink_metadata(parent).map_err(|error| {
            device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "device parent directory {} is unavailable after mounts: {error}",
                    parent.display()
                ),
            )
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(device_error(
                ErrorCode::PermissionDenied,
                format!(
                    "device parent is not a real directory: {}",
                    parent.display()
                ),
            ));
        }
        let path =
            std::ffi::CString::new(self.path.as_os_str().as_encoded_bytes()).map_err(|error| {
                invalid(format!(
                    "device path {} contains NUL: {error}",
                    self.path.display()
                ))
            })?;
        let file_type = self.file_type();
        let device = libc::makedev(self.major, self.minor);
        // SAFETY: the path is a live NUL-terminated string and the mode and
        // device numbers were fully validated.
        if unsafe { libc::mknod(path.as_ptr(), file_type | self.mode, device) } != 0 {
            return Err(last_os_error(format!(
                "create OCI device {}",
                self.path.display()
            )));
        }
        // SAFETY: the device path is still a live NUL-terminated string.
        if unsafe { libc::chown(path.as_ptr(), self.uid, self.gid) } != 0 {
            return Err(last_os_error(format!(
                "set ownership on OCI device {}",
                self.path.display()
            )));
        }
        fs::set_permissions(&self.path, fs::Permissions::from_mode(self.mode)).map_err(
            |error| {
                device_error(
                    ErrorCode::PermissionDenied,
                    format!(
                        "failed to set mode on OCI device {}: {error}",
                        self.path.display()
                    ),
                )
            },
        )?;
        self.verify_at(&self.path, self.uid, self.gid)
    }

    const fn file_type(&self) -> libc::mode_t {
        match self.kind {
            DeviceKind::Block => libc::S_IFBLK,
            DeviceKind::Character => libc::S_IFCHR,
            DeviceKind::Fifo => libc::S_IFIFO,
        }
    }

    fn verify_at(&self, path: &Path, uid: u32, gid: u32) -> Result<()> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to verify OCI device {}: {error}",
                    self.path.display()
                ),
            )
        })?;
        let file_type_matches = match self.kind {
            DeviceKind::Block => metadata.file_type().is_block_device(),
            DeviceKind::Character => metadata.file_type().is_char_device(),
            DeviceKind::Fifo => metadata.file_type().is_fifo(),
        };
        if !file_type_matches
            || libc::major(metadata.rdev()) != self.major
            || libc::minor(metadata.rdev()) != self.minor
            || metadata.mode() & 0o7777 != self.mode
            || metadata.uid() != uid
            || metadata.gid() != gid
        {
            return Err(device_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "OCI device {} differs after enforcement",
                    self.path.display()
                ),
            ));
        }
        Ok(())
    }
}

impl DeviceKind {
    fn from_oci(index: usize, kind: LinuxDeviceType) -> Result<Self> {
        match kind {
            LinuxDeviceType::B => Ok(Self::Block),
            LinuxDeviceType::C | LinuxDeviceType::U => Ok(Self::Character),
            LinuxDeviceType::P => Ok(Self::Fifo),
            LinuxDeviceType::A => Err(invalid(format!(
                "linux.devices[{index}].type cannot create the wildcard device type"
            ))),
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Block => "block device",
            Self::Character => "character device",
            Self::Fifo => "FIFO",
        }
    }
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
const BPF_JNE: u32 = 0x50;
const BPF_EXIT: u32 = 0x90;
const BPF_REG_0: u8 = 0;
const BPF_REG_1: u8 = 1;
const BPF_REG_2: u8 = 2;
const BPF_REG_4: u8 = 4;
const BPF_REG_5: u8 = 5;
const BPF_PROG_LOAD: u32 = 5;
const BPF_PROG_ATTACH: u32 = 8;
const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 15;
const BPF_CGROUP_DEVICE: u32 = 6;
const BPF_DEVCG_DEV_BLOCK: u32 = 1;
const BPF_DEVCG_DEV_CHAR: u32 = 2;
const MAX_BPF_LOG_BYTES: usize = 64 * 1024;

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

fn build_cgroup_device_program(nodes: &[DeviceNode]) -> Result<Vec<BpfInsn>> {
    let allow_rules = nodes
        .iter()
        .filter_map(|node| match node.kind {
            DeviceKind::Block => Some((BPF_DEVCG_DEV_BLOCK, node.major, node.minor)),
            DeviceKind::Character => Some((BPF_DEVCG_DEV_CHAR, node.major, node.minor)),
            DeviceKind::Fifo => None,
        })
        .collect::<Vec<_>>();

    if allow_rules.is_empty() {
        return Ok(vec![mov64_imm(BPF_REG_0, 0), exit_insn()]);
    }

    let mut program = vec![
        ldx_mem(libc::BPF_W, BPF_REG_2, BPF_REG_1, 0),
        alu32_imm(BPF_AND, BPF_REG_2, 0xFFFF),
        ldx_mem(libc::BPF_W, BPF_REG_4, BPF_REG_1, 4),
        ldx_mem(libc::BPF_W, BPF_REG_5, BPF_REG_1, 8),
    ];
    let mut rule_starts = Vec::with_capacity(allow_rules.len());
    let mut mismatch_jumps = Vec::with_capacity(allow_rules.len());

    for (device_type, major, minor) in allow_rules {
        rule_starts.push(program.len());
        let mut rule_jumps = Vec::with_capacity(3);
        rule_jumps.push(push_jne_imm(&mut program, BPF_REG_2, device_type as i32));
        rule_jumps.push(push_jne_imm(&mut program, BPF_REG_4, major as i32));
        rule_jumps.push(push_jne_imm(&mut program, BPF_REG_5, minor as i32));
        program.push(mov64_imm(BPF_REG_0, 1));
        program.push(exit_insn());
        mismatch_jumps.push(rule_jumps);
    }

    let reject_start = program.len();
    program.push(mov64_imm(BPF_REG_0, 0));
    program.push(exit_insn());

    for (rule_index, rule_jumps) in mismatch_jumps.iter().enumerate() {
        let target = rule_starts
            .get(rule_index + 1)
            .copied()
            .unwrap_or(reject_start);
        for &jump_index in rule_jumps {
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
        }
    }

    Ok(program)
}

fn attach_cgroup_device_program(cgroup_path: &Path, program: &[BpfInsn]) -> Result<()> {
    let loaded = load_cgroup_device_program(program)?;
    let cgroup = open_cgroup_descriptor(cgroup_path)?;
    let mut attr = BpfProgAttachAttr {
        target_fd: cgroup.as_raw_fd() as u32,
        attach_bpf_fd: loaded.as_raw_fd() as u32,
        attach_type: BPF_CGROUP_DEVICE,
        attach_flags: 0,
        replace_bpf_fd: 0,
    };
    // SAFETY: the cgroup and program descriptors are live owned fds and the
    // attribute struct matches the kernel layout for BPF_PROG_ATTACH.
    let attached = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_ATTACH,
            &mut attr as *mut _ as *mut libc::c_void,
            std::mem::size_of::<BpfProgAttachAttr>(),
        )
    };
    if attached != 0 {
        return Err(bpf_last_os_error(format!(
            "failed to attach cgroup device BPF program to {}",
            cgroup_path.display()
        )));
    }
    Ok(())
}

fn load_cgroup_device_program(program: &[BpfInsn]) -> Result<OwnedFd> {
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
                std::mem::size_of::<BpfProgLoadAttr>(),
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
    if log.is_empty() {
        None
    } else {
        Some(log)
    }
}

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

fn mov64_imm(dst: u8, imm: i32) -> BpfInsn {
    BpfInsn {
        code: (BPF_ALU64 | BPF_MOV | libc::BPF_K) as u8,
        regs: pack_regs(dst, 0),
        off: 0,
        imm,
    }
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

fn validate_device_policy(nodes: &[DeviceNode], rules: Option<&[LinuxDeviceCgroup]>) -> Result<()> {
    let rules = rules.unwrap_or_default();
    if nodes.is_empty() && rules.is_empty() {
        return Ok(());
    }
    let Some(default_deny) = rules.first() else {
        return Err(unsupported(
            "linux.resources.devices",
            "explicit devices require a default-deny policy",
        ));
    };
    if default_deny.allow()
        || default_deny.typ().is_some()
        || default_deny.major().is_some()
        || default_deny.minor().is_some()
        || default_deny.access().as_deref() != Some("rwm")
    {
        return Err(unsupported(
            "linux.resources.devices[0]",
            "the supported policy starts with deny-all rwm",
        ));
    }
    if rules.len() != nodes.len() + 1 {
        return Err(unsupported(
            "linux.resources.devices",
            "the allow rules must exactly match the created device nodes",
        ));
    }
    for (index, (node, rule)) in nodes.iter().zip(&rules[1..]).enumerate() {
        let expected_type = match node.kind {
            DeviceKind::Block => LinuxDeviceType::B,
            DeviceKind::Character => LinuxDeviceType::C,
            DeviceKind::Fifo => LinuxDeviceType::P,
        };
        if !rule.allow()
            || rule.typ() != Some(expected_type)
            || rule.major() != Some(i64::from(node.major))
            || rule.minor() != Some(i64::from(node.minor))
            || rule.access().as_deref() != Some("rwm")
        {
            return Err(unsupported(
                &format!("linux.resources.devices[{}]", index + 1),
                "the rule must allow rwm for the matching created device",
            ));
        }
    }
    Ok(())
}

fn validate_bind_mounts_are_nodev(mounts: &[MountPlan]) -> Result<()> {
    if let Some(mount) = mounts
        .iter()
        .find(|mount| mount.bind && mount.flags & libc::MS_NODEV == 0)
    {
        Err(unsupported(
            &format!("mounts[{}].options", mount.index),
            "bind mounts must use nodev when an OCI device allowlist is active",
        ))
    } else {
        Ok(())
    }
}

fn clone_device_mount(path: &Path) -> Result<OwnedFd> {
    let path = path_cstring(path, "prepared device source")?;
    // SAFETY: the path is NUL-terminated and open_tree does not retain it.
    // OPEN_TREE_CLONE returns a detached mount owned by the returned fd.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(last_os_error("clone prepared OCI device source mount"));
    }
    let descriptor = libc::c_int::try_from(descriptor).map_err(|error| {
        device_error(
            ErrorCode::Internal,
            format!("open_tree returned an invalid device mount descriptor: {error}"),
        )
    })?;
    // SAFETY: `descriptor` is a fresh owned descriptor returned by open_tree.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn attach_device_mount(source: &OwnedFd, target: &Path, container_path: &Path) -> Result<()> {
    let target_descriptor = open_path_descriptor(target)?;
    let empty = c"";
    let flags = libc::MOVE_MOUNT_F_EMPTY_PATH | libc::MOVE_MOUNT_T_EMPTY_PATH;
    // SAFETY: both descriptors are live detached/source and target mount
    // references, both empty paths are NUL-terminated, and the EMPTY_PATH
    // flags select the descriptors directly.
    let moved = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            source.as_raw_fd(),
            empty.as_ptr(),
            target_descriptor.as_raw_fd(),
            empty.as_ptr(),
            flags,
        )
    };
    if moved != 0 {
        return Err(last_os_error(format!(
            "attach prepared OCI device {}",
            container_path.display()
        )));
    }

    let target = path_cstring(target, "OCI device bind target")?;
    let null = std::ptr::null::<libc::c_char>();
    let null_data = std::ptr::null::<libc::c_void>();
    // SAFETY: the bind target was created and mounted by this operation.
    if unsafe {
        libc::mount(
            null,
            target.as_ptr(),
            null,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NOEXEC,
            null_data,
        )
    } != 0
    {
        return Err(last_os_error(format!(
            "apply safe bind flags to OCI device {}",
            container_path.display()
        )));
    }
    Ok(())
}

fn open_path_descriptor(path: &Path) -> Result<OwnedFd> {
    let path = path_cstring(path, "OCI device bind target")?;
    // SAFETY: the target is NUL-terminated and open does not retain it.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(last_os_error("retain OCI device bind target"));
    }
    // SAFETY: `descriptor` is a fresh owned descriptor returned by open.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn path_cstring(path: &Path, label: &str) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|error| {
        invalid(format!(
            "{label} path {} contains NUL: {error}",
            path.display()
        ))
    })
}

fn normalize_device_path(index: usize, path: &Path) -> Result<PathBuf> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid(format!("linux.devices[{index}].path is not valid UTF-8")))?;
    if value.is_empty()
        || value.len() > 4_096
        || !value.starts_with('/')
        || value.ends_with('/')
        || value.as_bytes().contains(&0)
        || value.contains('\\')
        || value
            .trim_start_matches('/')
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(invalid(format!(
            "linux.devices[{index}].path must be a normalized absolute Linux path"
        )));
    }
    Ok(PathBuf::from(value))
}

fn invalid(message: impl Into<String>) -> Error {
    device_error(ErrorCode::InvalidArgument, message)
}

fn unsupported(field: &str, reason: &str) -> Error {
    device_error(ErrorCode::Unsupported, format!("{field}: {reason}"))
}

fn last_os_error(operation: impl Into<String>) -> Error {
    device_error(
        ErrorCode::PermissionDenied,
        format!(
            "failed to {}: {}",
            operation.into(),
            io::Error::last_os_error()
        ),
    )
}

fn device_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("configure-container-devices")
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::oci_spec::runtime::Linux;
    use a3s_oci_sdk::ErrorCode;

    use super::{build_cgroup_device_program, DeviceKind, DeviceNode, DevicePlan};
    use crate::executor::mount;
    use crate::executor::namespace::NamespacePlan;

    #[test]
    fn plans_the_exact_a3s_box_device_allowlist() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/a3s-box/config.json"))
                .expect("decode fixture");
        let linux: Linux =
            serde_json::from_value(config["linux"].clone()).expect("decode Linux config");
        let namespaces =
            NamespacePlan::from_linux(Some(&linux), 0, 0, &[]).expect("namespace plan");
        let mounts = mount::plan_all(
            serde_json::from_value::<Vec<a3s_oci_sdk::oci_spec::runtime::Mount>>(
                config["mounts"].clone(),
            )
            .expect("decode mounts")
            .as_slice()
            .into(),
            &namespaces,
        )
        .expect("mount plan");
        let plan = DevicePlan::from_linux(Some(&linux), &mounts).expect("device plan");
        assert_eq!(plan.len(), 6);
    }

    #[test]
    fn deny_only_device_policy_still_requires_rootfs_enforcement() {
        let linux: Linux = serde_json::from_value(serde_json::json!({
            "resources": {
                "devices": [{"allow": false, "access": "rwm"}]
            }
        }))
        .expect("decode deny-only device policy");
        let plan = DevicePlan::from_linux(Some(&linux), &[]).expect("device plan");
        assert!(plan.requires_setup());
        assert_eq!(plan.len(), 0);
    }

    #[test]
    fn rejects_device_allowlist_rules_that_do_not_match_the_created_nodes() {
        let mut config: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/a3s-box/config.json"))
                .expect("decode fixture");
        let linux: Linux =
            serde_json::from_value(config["linux"].clone()).expect("decode Linux config");
        let namespaces =
            NamespacePlan::from_linux(Some(&linux), 0, 0, &[]).expect("namespace plan");
        let mounts = mount::plan_all(
            serde_json::from_value::<Vec<a3s_oci_sdk::oci_spec::runtime::Mount>>(
                config["mounts"].clone(),
            )
            .expect("decode mounts")
            .as_slice()
            .into(),
            &namespaces,
        )
        .expect("mount plan");

        config["linux"]["resources"]["devices"][2]["minor"] = serde_json::json!(6);
        let mutated_linux: Linux =
            serde_json::from_value(config["linux"].clone()).expect("decode mutated Linux config");
        let error = DevicePlan::from_linux(Some(&mutated_linux), &mounts)
            .expect_err("mismatched allowlist must fail");
        assert_eq!(error.code, ErrorCode::Unsupported);
        assert!(error.message.contains("matching created device"));
    }

    #[test]
    fn builds_cgroup_device_bpf_for_block_and_char_devices_only() {
        let nodes = vec![
            DeviceNode {
                path: std::path::PathBuf::from("/dev/ttyS0"),
                kind: DeviceKind::Character,
                major: 4,
                minor: 64,
                mode: 0o660,
                uid: 0,
                gid: 0,
            },
            DeviceNode {
                path: std::path::PathBuf::from("/dev/loop0"),
                kind: DeviceKind::Block,
                major: 7,
                minor: 0,
                mode: 0o660,
                uid: 0,
                gid: 0,
            },
            DeviceNode {
                path: std::path::PathBuf::from("/tmp/fifo"),
                kind: DeviceKind::Fifo,
                major: 0,
                minor: 0,
                mode: 0o600,
                uid: 0,
                gid: 0,
            },
        ];
        let program = build_cgroup_device_program(&nodes).expect("device BPF program");
        assert_eq!(program.len(), 16);
        assert_eq!(
            program[0].code,
            (libc::BPF_LDX | libc::BPF_W | libc::BPF_MEM) as u8
        );
        assert_eq!(program[1].imm, 0xFFFF);
        assert_eq!(program[4].imm, 2);
        assert_eq!(program[4].off, 4);
        assert_eq!(program[9].imm, 1);
        assert_eq!(program[9].off, 4);
        assert_eq!(program[14].imm, 0);
        assert_eq!(program[15].code, (libc::BPF_JMP | super::BPF_EXIT) as u8);
    }

    #[test]
    fn fifo_only_device_plans_fall_back_to_reject_all() {
        let nodes = vec![DeviceNode {
            path: std::path::PathBuf::from("/tmp/fifo"),
            kind: DeviceKind::Fifo,
            major: 0,
            minor: 0,
            mode: 0o600,
            uid: 0,
            gid: 0,
        }];
        let program = build_cgroup_device_program(&nodes).expect("device BPF program");
        assert_eq!(program.len(), 2);
        assert_eq!(program[0].imm, 0);
        assert_eq!(program[1].code, (libc::BPF_JMP | super::BPF_EXIT) as u8);
    }
}
