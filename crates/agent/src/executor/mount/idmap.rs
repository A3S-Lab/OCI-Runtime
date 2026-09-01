use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::{File, Metadata};
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;

use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::attributes::{
    MountAttr, MOUNT_ATTR_ATIME, MOUNT_ATTR_NOATIME, MOUNT_ATTR_NODEV, MOUNT_ATTR_NODIRATIME,
    MOUNT_ATTR_NOEXEC, MOUNT_ATTR_NOSUID, MOUNT_ATTR_NOSYMFOLLOW, MOUNT_ATTR_RDONLY,
    MOUNT_ATTR_STRICTATIME,
};
use super::{path_cstring, BindSourceResolver, MountPlan, MountTargetKind, ResolvedBindSource};
use crate::executor::namespace::IdmapNamespaceHandles;

#[derive(Debug, Default)]
pub(in crate::executor) struct DetachedMountSources {
    sources: BTreeMap<usize, DetachedMountSource>,
    namespaces: IdmapNamespaceHandles,
    ordered_idmap_control: Option<UnixStream>,
}

#[derive(Debug)]
struct DetachedMountSource {
    descriptor: OwnedFd,
    kind: MountTargetKind,
}

impl DetachedMountSources {
    pub(in crate::executor) fn prepare(
        plans: &[MountPlan],
        source_resolver: &BindSourceResolver<'_>,
        namespaces: IdmapNamespaceHandles,
    ) -> Result<Self> {
        let mut sources = BTreeMap::new();
        for plan in plans {
            if plan.ordered_source.is_some() {
                // Resolve this source after its preceding mount has been
                // applied to the effective rootfs. Preparing it now would pin
                // the pre-mount placeholder instead of the ordered source.
                continue;
            }
            if plan.idmap.is_none() && !plan.detached_bind {
                continue;
            }
            let (detached, kind) = if plan.bind {
                let source = plan.source.as_deref().ok_or_else(|| {
                    apply_error(
                        ErrorCode::InvalidArgument,
                        plan.index,
                        "detached bind mount is missing its source",
                    )
                })?;
                let source = match source_resolver.resolve(plan.index, source)? {
                    Some(source) => source,
                    None if plan.idmap.is_none() && plan.detached_bind => {
                        // A source produced by an earlier mount in this
                        // plan does not exist until namespace entry. Keep
                        // it on the existing in-namespace path; only an
                        // already-existing foreign source needs parent
                        // user-namespace preparation.
                        continue;
                    }
                    None => {
                        return Err(apply_error(
                            ErrorCode::InvalidArgument,
                            plan.index,
                            "detached bind mount source does not exist",
                        ));
                    }
                };
                let kind = source.kind();
                (
                    clone_resolved_mount(plan.index, &source, plan.flags & libc::MS_REC != 0)?,
                    kind,
                )
            } else {
                (create_filesystem_mount(plan)?, MountTargetKind::Directory)
            };
            if let Some(idmap) = &plan.idmap {
                apply_idmap_attribute(
                    plan.index,
                    &detached,
                    namespaces.namespace_fd(idmap)?,
                    idmap.recursive,
                )?;
            }
            if plan.detached_bind {
                apply_detached_bind_attributes(plan, &detached)?;
            }
            if sources
                .insert(
                    plan.index,
                    DetachedMountSource {
                        descriptor: detached,
                        kind,
                    },
                )
                .is_some()
            {
                return Err(apply_error(
                    ErrorCode::Internal,
                    plan.index,
                    "duplicate detached mount source",
                ));
            }
        }
        Ok(Self {
            sources,
            namespaces,
            ordered_idmap_control: None,
        })
    }

    pub(in crate::executor) fn set_ordered_idmap_control(
        &mut self,
        control: UnixStream,
    ) -> Result<()> {
        if self.ordered_idmap_control.replace(control).is_some() {
            return Err(Error::new(
                ErrorCode::Conflict,
                "ordered ID-mapped mount control was already configured",
            )
            .for_operation("prepare-container-mounts"));
        }
        Ok(())
    }

    pub(in crate::executor) fn prepare_ordered(
        &mut self,
        plan: &MountPlan,
        source: &ResolvedBindSource,
    ) -> Result<()> {
        if plan.ordered_source.is_none() || (plan.idmap.is_none() && !plan.detached_bind) {
            return Err(apply_error(
                ErrorCode::Internal,
                plan.index,
                "ordered detached bind preparation was requested for an incompatible mount",
            ));
        }
        if self.sources.contains_key(&plan.index) {
            return Err(apply_error(
                ErrorCode::Internal,
                plan.index,
                "duplicate ordered detached mount source",
            ));
        }
        let detached = clone_resolved_mount(plan.index, source, plan.flags & libc::MS_REC != 0)?;
        if let Some(idmap) = &plan.idmap {
            let namespace = self.namespaces.namespace_fd(idmap)?;
            if let Some(control) = self.ordered_idmap_control.as_mut() {
                crate::executor::control::request_ordered_idmap(
                    control,
                    plan.index,
                    detached.as_raw_fd(),
                    namespace,
                )?;
            } else {
                apply_idmap_attribute(plan.index, &detached, namespace, idmap.recursive)?;
            }
        }
        if plan.detached_bind {
            apply_detached_bind_attributes(plan, &detached)?;
        }
        self.sources.insert(
            plan.index,
            DetachedMountSource {
                descriptor: detached,
                kind: source.kind(),
            },
        );
        Ok(())
    }

    pub(in crate::executor) fn contains(&self, index: usize) -> bool {
        self.sources.contains_key(&index)
    }

    pub(in crate::executor) fn source_kind(&self, index: usize) -> Option<MountTargetKind> {
        self.sources.get(&index).map(|source| source.kind)
    }

    pub(in crate::executor) fn open_destination(
        &self,
        index: usize,
        target: &CStr,
    ) -> Result<OwnedFd> {
        if !self.sources.contains_key(&index) {
            return Err(apply_error(
                ErrorCode::FailedPrecondition,
                index,
                "detached mount source was not prepared",
            ));
        }
        open_path(index, target, "retain the detached mount destination")
    }

    pub(in crate::executor) fn attach(
        &mut self,
        index: usize,
        destination: &OwnedFd,
    ) -> Result<()> {
        let source = self.sources.remove(&index).ok_or_else(|| {
            apply_error(
                ErrorCode::FailedPrecondition,
                index,
                "detached mount source is missing or was already attached",
            )
        })?;
        move_mount(index, &source.descriptor, destination)
    }

    pub(in crate::executor) fn ensure_consumed(&self) -> Result<()> {
        if self.sources.is_empty() {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "detached mount sources were not attached for mount indexes {:?}",
                    self.sources.keys().collect::<Vec<_>>()
                ),
            )
            .for_operation("prepare-container-mounts"))
        }
    }
}

pub(in crate::executor) fn apply_ordered_idmap_from_parent(
    plan: &MountPlan,
    mount: &OwnedFd,
    user_namespace: &OwnedFd,
) -> Result<()> {
    if plan.ordered_source.is_none() {
        return Err(apply_error(
            ErrorCode::PermissionDenied,
            plan.index,
            "parent ID-map request does not identify an ordered mount source",
        ));
    }
    let idmap = plan.idmap.as_ref().ok_or_else(|| {
        apply_error(
            ErrorCode::PermissionDenied,
            plan.index,
            "parent ID-map request does not identify an ID-mapped mount",
        )
    })?;
    // SAFETY: F_GETFL only inspects descriptor flags.
    let mount_flags = unsafe { libc::fcntl(mount.as_raw_fd(), libc::F_GETFL) };
    if mount_flags < 0 || mount_flags & libc::O_PATH != libc::O_PATH {
        return Err(apply_error(
            ErrorCode::PermissionDenied,
            plan.index,
            "parent ID-map request did not carry an O_PATH mount descriptor",
        ));
    }
    // SAFETY: NS_GET_NSTYPE reads namespace metadata from a live descriptor
    // and does not require a third ioctl argument.
    let namespace_type = unsafe { libc::ioctl(user_namespace.as_raw_fd(), libc::NS_GET_NSTYPE) };
    if namespace_type < 0 {
        return Err(apply_error(
            ErrorCode::PermissionDenied,
            plan.index,
            format!(
                "parent ID-map request carried an invalid user namespace descriptor: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    if namespace_type != libc::CLONE_NEWUSER {
        return Err(apply_error(
            ErrorCode::PermissionDenied,
            plan.index,
            format!(
                "parent ID-map request carried namespace type {namespace_type:#x}, expected a \
                 user namespace"
            ),
        ));
    }
    apply_idmap_attribute(
        plan.index,
        mount,
        user_namespace.as_raw_fd(),
        idmap.recursive,
    )
}

pub(super) fn attach_descriptor_bind(
    index: usize,
    source: &ResolvedBindSource,
    target: &CStr,
    recursive: bool,
) -> Result<bool> {
    if !source.is_descriptor_confined() {
        return Ok(false);
    }
    let attachment = (|| {
        let source = clone_resolved_mount(index, source, recursive)?;
        let destination = open_path(index, target, "retain the descriptor bind destination")?;
        move_mount(index, &source, &destination)
    })();
    match attachment {
        Ok(()) => Ok(true),
        // Some shared filesystems expose stable O_PATH descriptors but reject
        // OPEN_TREE_CLONE. The caller may use the retained path only when it
        // immediately proves that the resulting bind has this descriptor's
        // exact identity.
        Err(error) if error.code == ErrorCode::Unsupported => Ok(false),
        Err(error) => Err(error),
    }
}

pub(super) fn verify_legacy_descriptor_bind(
    index: usize,
    source: &ResolvedBindSource,
    target: &CStr,
) -> Result<()> {
    let Some(expected) = source.descriptor.as_ref() else {
        return Ok(());
    };
    let observed = match open_path(index, target, "inspect the legacy bind destination") {
        Ok(observed) => observed,
        Err(error) => {
            return Err(reject_legacy_descriptor_bind(
                index,
                target,
                format!("failed to retain the attached bind destination: {error}"),
            ));
        }
    };
    let observed = File::from(observed);
    let expected_metadata = expected.metadata().map_err(|error| {
        reject_legacy_descriptor_bind(
            index,
            target,
            format!("failed to inspect the retained bind source: {error}"),
        )
    })?;
    let observed_metadata = observed.metadata().map_err(|error| {
        reject_legacy_descriptor_bind(
            index,
            target,
            format!("failed to inspect the attached bind destination: {error}"),
        )
    })?;
    if same_bind_identity(&expected_metadata, &observed_metadata) {
        Ok(())
    } else {
        let expected_kind = expected_metadata.mode() & libc::S_IFMT;
        let observed_kind = observed_metadata.mode() & libc::S_IFMT;
        Err(reject_legacy_descriptor_bind(
            index,
            target,
            format!(
                "legacy bind source identity changed: expected dev={} ino={} mode={expected_kind:#o} \
                 rdev={}, found dev={} ino={} mode={observed_kind:#o} rdev={}",
                expected_metadata.dev(),
                expected_metadata.ino(),
                expected_metadata.rdev(),
                observed_metadata.dev(),
                observed_metadata.ino(),
                observed_metadata.rdev(),
            ),
        ))
    }
}

fn same_bind_identity(expected: &Metadata, observed: &Metadata) -> bool {
    expected.dev() == observed.dev()
        && expected.ino() == observed.ino()
        && (expected.mode() & libc::S_IFMT) == (observed.mode() & libc::S_IFMT)
        && expected.rdev() == observed.rdev()
}

fn create_filesystem_mount(plan: &MountPlan) -> Result<OwnedFd> {
    let filesystem_type = plan.filesystem_type.as_deref().ok_or_else(|| {
        apply_error(
            ErrorCode::InvalidArgument,
            plan.index,
            "ID-mapped filesystem mount is missing its type",
        )
    })?;
    let filesystem_type = CString::new(filesystem_type.as_bytes()).map_err(|error| {
        apply_error(
            ErrorCode::InvalidArgument,
            plan.index,
            format!("filesystem type contains a NUL byte: {error}"),
        )
    })?;
    // SAFETY: filesystem_type is NUL-terminated and fsopen does not retain
    // the pointer.
    let context = unsafe {
        libc::syscall(
            libc::SYS_fsopen,
            filesystem_type.as_ptr(),
            libc::FSOPEN_CLOEXEC,
        )
    };
    let context = owned_syscall_fd(plan.index, "open filesystem context with fsopen", context)?;

    if let Some(source) = plan.source.as_deref() {
        let source = source.to_str().ok_or_else(|| {
            apply_error(
                ErrorCode::InvalidArgument,
                plan.index,
                "ID-mapped filesystem source is not valid UTF-8",
            )
        })?;
        let filesystem_name = filesystem_type.to_str().map_err(|error| {
            apply_error(
                ErrorCode::Internal,
                plan.index,
                format!("validated filesystem type is not UTF-8: {error}"),
            )
        })?;
        if !matches!(source, "none" | "") && source != filesystem_name {
            configure_filesystem(
                plan.index,
                &context,
                libc::FSCONFIG_SET_STRING,
                Some("source"),
                Some(source),
            )?;
        }
    }
    for option in &plan.data {
        match option.split_once('=') {
            Some((key, value)) if !key.is_empty() => configure_filesystem(
                plan.index,
                &context,
                libc::FSCONFIG_SET_STRING,
                Some(key),
                Some(value),
            )?,
            None => configure_filesystem(
                plan.index,
                &context,
                libc::FSCONFIG_SET_FLAG,
                Some(option),
                None,
            )?,
            Some(_) => {
                return Err(apply_error(
                    ErrorCode::InvalidArgument,
                    plan.index,
                    format!("filesystem option `{option}` has an empty key"),
                ));
            }
        }
    }
    configure_filesystem(plan.index, &context, libc::FSCONFIG_CMD_CREATE, None, None)?;
    let mount_attributes = filesystem_mount_attributes(plan.index, plan.flags)?;
    // SAFETY: context is a live fsopen descriptor. fsmount creates and returns
    // a detached mount descriptor.
    let mount = unsafe {
        libc::syscall(
            libc::SYS_fsmount,
            context.as_raw_fd(),
            libc::FSMOUNT_CLOEXEC,
            mount_attributes,
        )
    };
    owned_syscall_fd(plan.index, "create detached filesystem with fsmount", mount)
}

fn configure_filesystem(
    index: usize,
    context: &OwnedFd,
    command: libc::c_uint,
    key: Option<&str>,
    value: Option<&str>,
) -> Result<()> {
    let key = key
        .map(|key| {
            CString::new(key.as_bytes()).map_err(|error| {
                apply_error(
                    ErrorCode::InvalidArgument,
                    index,
                    format!("filesystem option key contains a NUL byte: {error}"),
                )
            })
        })
        .transpose()?;
    let value = value
        .map(|value| {
            CString::new(value.as_bytes()).map_err(|error| {
                apply_error(
                    ErrorCode::InvalidArgument,
                    index,
                    format!("filesystem option value contains a NUL byte: {error}"),
                )
            })
        })
        .transpose()?;
    // SAFETY: context is live, key and any value are NUL-terminated, and
    // fsconfig does not retain either pointer.
    let configured = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            context.as_raw_fd(),
            command,
            key.as_ref().map_or(std::ptr::null(), |key| key.as_ptr()),
            value
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            0,
        )
    };
    if configured == 0 {
        Ok(())
    } else {
        Err(syscall_error(
            index,
            "configure detached ID-mapped filesystem",
            io::Error::last_os_error(),
        ))
    }
}

fn filesystem_mount_attributes(index: usize, flags: libc::c_ulong) -> Result<u32> {
    let supported = libc::MS_RDONLY
        | libc::MS_NOSUID
        | libc::MS_NODEV
        | libc::MS_NOEXEC
        | libc::MS_NOATIME
        | libc::MS_NODIRATIME
        | libc::MS_RELATIME
        | libc::MS_STRICTATIME
        | libc::MS_NOSYMFOLLOW;
    let unsupported = flags & !supported;
    if unsupported != 0 {
        return Err(apply_error(
            ErrorCode::Unsupported,
            index,
            format!(
                "ID-mapped filesystem mount flags {unsupported:#x} cannot be represented by \
                 fsmount"
            ),
        ));
    }
    let mut attributes = 0_u64;
    for (mount_flag, attribute) in [
        (libc::MS_RDONLY, libc::MOUNT_ATTR_RDONLY),
        (libc::MS_NOSUID, libc::MOUNT_ATTR_NOSUID),
        (libc::MS_NODEV, libc::MOUNT_ATTR_NODEV),
        (libc::MS_NOEXEC, libc::MOUNT_ATTR_NOEXEC),
        (libc::MS_NODIRATIME, libc::MOUNT_ATTR_NODIRATIME),
        (libc::MS_NOSYMFOLLOW, libc::MOUNT_ATTR_NOSYMFOLLOW),
    ] {
        if flags & mount_flag != 0 {
            attributes |= attribute;
        }
    }
    if flags & libc::MS_NOATIME != 0 {
        attributes |= libc::MOUNT_ATTR_NOATIME;
    } else if flags & libc::MS_STRICTATIME != 0 {
        attributes |= libc::MOUNT_ATTR_STRICTATIME;
    }
    u32::try_from(attributes).map_err(|error| {
        apply_error(
            ErrorCode::Internal,
            index,
            format!("fsmount attributes do not fit the kernel ABI: {error}"),
        )
    })
}

fn owned_syscall_fd(index: usize, action: &str, descriptor: libc::c_long) -> Result<OwnedFd> {
    if descriptor < 0 {
        return Err(syscall_error(index, action, io::Error::last_os_error()));
    }
    let descriptor = libc::c_int::try_from(descriptor).map_err(|error| {
        apply_error(
            ErrorCode::Internal,
            index,
            format!("{action} returned an invalid descriptor: {error}"),
        )
    })?;
    // SAFETY: descriptor is a newly owned successful syscall result.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn clone_resolved_mount(
    index: usize,
    source: &ResolvedBindSource,
    recursive: bool,
) -> Result<OwnedFd> {
    if let Some(descriptor) = source.descriptor.as_ref() {
        return clone_mount_from_descriptor(index, descriptor, recursive);
    }
    let source = path_cstring(index, "source", source.path())?;
    clone_mount_from_path(index, &source, recursive)
}

fn clone_mount_from_path(index: usize, source: &CString, recursive: bool) -> Result<OwnedFd> {
    let mut flags = libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC;
    if recursive {
        flags |= open_tree_flag(index, libc::AT_RECURSIVE, "AT_RECURSIVE")?;
    }
    // SAFETY: source is NUL-terminated and open_tree does not retain its
    // pointer. OPEN_TREE_CLONE returns a detached mount.
    let descriptor =
        unsafe { libc::syscall(libc::SYS_open_tree, libc::AT_FDCWD, source.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(syscall_error(
            index,
            "clone the bind source with open_tree",
            io::Error::last_os_error(),
        ));
    }
    let descriptor = libc::c_int::try_from(descriptor).map_err(|error| {
        apply_error(
            ErrorCode::Internal,
            index,
            format!("open_tree returned an invalid descriptor: {error}"),
        )
    })?;
    // SAFETY: descriptor is a newly owned successful open_tree result.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn clone_mount_from_descriptor(index: usize, source: &File, recursive: bool) -> Result<OwnedFd> {
    let mut flags = libc::OPEN_TREE_CLONE
        | libc::OPEN_TREE_CLOEXEC
        | open_tree_flag(index, libc::AT_EMPTY_PATH, "AT_EMPTY_PATH")?;
    if recursive {
        flags |= open_tree_flag(index, libc::AT_RECURSIVE, "AT_RECURSIVE")?;
    }
    // SAFETY: source is a live O_PATH descriptor, the empty pathname is
    // NUL-terminated, and AT_EMPTY_PATH selects that exact descriptor.
    let descriptor =
        unsafe { libc::syscall(libc::SYS_open_tree, source.as_raw_fd(), c"".as_ptr(), flags) };
    owned_syscall_fd(
        index,
        "clone the descriptor-confined bind source with open_tree",
        descriptor,
    )
}

fn open_tree_flag(index: usize, flag: libc::c_int, name: &str) -> Result<u32> {
    u32::try_from(flag).map_err(|error| {
        apply_error(
            ErrorCode::Internal,
            index,
            format!("{name} does not fit the open_tree flags ABI: {error}"),
        )
    })
}

fn move_mount(index: usize, source: &OwnedFd, destination: &OwnedFd) -> Result<()> {
    let empty_path = c"";
    let flags = libc::MOVE_MOUNT_F_EMPTY_PATH | libc::MOVE_MOUNT_T_EMPTY_PATH;
    // SAFETY: both descriptors are live, both paths are empty NUL-terminated
    // strings selected by the EMPTY_PATH flags, and move_mount retains none.
    let moved = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            source.as_raw_fd(),
            empty_path.as_ptr(),
            destination.as_raw_fd(),
            empty_path.as_ptr(),
            flags,
        )
    };
    if moved == 0 {
        Ok(())
    } else {
        Err(syscall_error(
            index,
            "attach the detached mount",
            io::Error::last_os_error(),
        ))
    }
}

fn reject_legacy_descriptor_bind(index: usize, target: &CStr, reason: String) -> Error {
    // SAFETY: target is a live NUL-terminated pathname. MNT_DETACH removes
    // only the just-created private bind layer and retains neither pointer nor
    // mount reference after returning.
    if unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) } == 0 {
        apply_error(ErrorCode::PermissionDenied, index, reason)
    } else {
        apply_error(
            ErrorCode::Internal,
            index,
            format!(
                "{reason}; failed to detach the rejected legacy bind: {}",
                io::Error::last_os_error()
            ),
        )
    }
}

fn apply_idmap_attribute(
    index: usize,
    mount: &OwnedFd,
    user_namespace: libc::c_int,
    recursive: bool,
) -> Result<()> {
    let userns_fd = u64::try_from(user_namespace).map_err(|error| {
        apply_error(
            ErrorCode::Internal,
            index,
            format!("ID-mapping namespace descriptor is invalid: {error}"),
        )
    })?;
    let attributes = MountAttr {
        attr_set: libc::MOUNT_ATTR_IDMAP,
        attr_clr: 0,
        propagation: 0,
        userns_fd,
    };
    apply_mount_attributes(
        index,
        mount,
        attributes,
        recursive,
        "apply MOUNT_ATTR_IDMAP",
    )
}

fn apply_detached_bind_attributes(plan: &MountPlan, mount: &OwnedFd) -> Result<()> {
    let (attr_set, attr_clr) = bind_mount_attributes(plan.flags);
    let attributes = MountAttr {
        attr_set,
        attr_clr,
        propagation: 0,
        userns_fd: 0,
    };
    apply_mount_attributes(
        plan.index,
        mount,
        attributes,
        false,
        "apply detached bind attributes",
    )?;
    if let Some(recursive) = plan.recursive_attributes {
        apply_mount_attributes(
            plan.index,
            mount,
            MountAttr {
                attr_set: recursive.attr_set,
                attr_clr: recursive.attr_clr,
                propagation: 0,
                userns_fd: 0,
            },
            true,
            "apply detached recursive bind attributes",
        )?;
    }
    Ok(())
}

fn bind_mount_attributes(flags: libc::c_ulong) -> (u64, u64) {
    let mut attr_set = 0;
    let mut attr_clr = 0;
    for (mount_flag, attribute) in [
        (libc::MS_RDONLY, MOUNT_ATTR_RDONLY),
        (libc::MS_NOSUID, MOUNT_ATTR_NOSUID),
        (libc::MS_NODEV, MOUNT_ATTR_NODEV),
        (libc::MS_NOEXEC, MOUNT_ATTR_NOEXEC),
        (libc::MS_NODIRATIME, MOUNT_ATTR_NODIRATIME),
        (libc::MS_NOSYMFOLLOW, MOUNT_ATTR_NOSYMFOLLOW),
    ] {
        if flags & mount_flag != 0 {
            attr_set |= attribute;
        }
    }
    if flags & libc::MS_NOATIME != 0 {
        attr_set |= MOUNT_ATTR_NOATIME;
        attr_clr |= MOUNT_ATTR_ATIME;
    } else if flags & libc::MS_STRICTATIME != 0 {
        attr_set |= MOUNT_ATTR_STRICTATIME;
        attr_clr |= MOUNT_ATTR_ATIME;
    }
    (attr_set, attr_clr)
}

fn apply_mount_attributes(
    index: usize,
    mount: &OwnedFd,
    attributes: MountAttr,
    recursive: bool,
    action: &str,
) -> Result<()> {
    let empty_path = c"";
    let mut flags = libc::AT_EMPTY_PATH;
    if recursive {
        flags |= libc::AT_RECURSIVE;
    }
    // SAFETY: mount remains live, empty_path is NUL-terminated, and
    // attributes is the complete version-0 mount_attr layout.
    let applied = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            mount.as_raw_fd(),
            empty_path.as_ptr(),
            flags,
            &attributes as *const MountAttr,
            size_of::<MountAttr>(),
        )
    };
    if applied == 0 {
        Ok(())
    } else {
        Err(syscall_error(index, action, io::Error::last_os_error()))
    }
}

fn open_path(index: usize, target: &CStr, action: &str) -> Result<OwnedFd> {
    // SAFETY: target is NUL-terminated and open does not retain the pointer.
    let descriptor = unsafe {
        libc::open(
            target.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(syscall_error(index, action, io::Error::last_os_error()));
    }
    // SAFETY: descriptor is a newly owned successful open result.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn syscall_error(index: usize, action: &str, error: io::Error) -> Error {
    let code = classify_errno(error.raw_os_error());
    apply_error(
        code,
        index,
        format!("{action} failed for detached mount: {error}"),
    )
}

fn classify_errno(errno: Option<i32>) -> ErrorCode {
    match errno {
        Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL | libc::ENODEV) => {
            ErrorCode::Unsupported
        }
        Some(libc::EACCES | libc::EPERM) => ErrorCode::PermissionDenied,
        _ => ErrorCode::Internal,
    }
}

fn apply_error(code: ErrorCode, index: usize, message: impl Into<String>) -> Error {
    Error::new(code, format!("mounts[{index}]: {}", message.into()))
        .for_operation("prepare-container-mounts")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;

    use a3s_oci_sdk::ErrorCode;

    use super::{
        apply_ordered_idmap_from_parent, bind_mount_attributes, classify_errno,
        filesystem_mount_attributes, same_bind_identity, BindSourceResolver, DetachedMountSources,
    };
    use crate::executor::mount::MountPlan;
    use crate::executor::namespace::{IdMapping, IdmapNamespaceHandles, IdmapPlan};

    #[test]
    fn idmapped_mount_syscall_errors_have_stable_types() {
        for errno in [libc::ENOSYS, libc::EOPNOTSUPP, libc::EINVAL] {
            assert_eq!(classify_errno(Some(errno)), ErrorCode::Unsupported);
        }
        for errno in [libc::EACCES, libc::EPERM] {
            assert_eq!(classify_errno(Some(errno)), ErrorCode::PermissionDenied);
        }
        assert_eq!(classify_errno(Some(libc::EIO)), ErrorCode::Internal);
    }

    #[test]
    fn legacy_bind_verification_requires_the_retained_inode_identity() {
        let temporary = tempfile::tempdir().expect("temporary bind sources");
        let retained = temporary.path().join("retained");
        let alias = temporary.path().join("alias");
        let replacement = temporary.path().join("replacement");
        fs::write(&retained, b"retained").expect("retained source");
        fs::hard_link(&retained, &alias).expect("same-inode alias");
        fs::write(&replacement, b"replacement").expect("replacement source");

        let retained = fs::metadata(retained).expect("retained metadata");
        let alias = fs::metadata(alias).expect("alias metadata");
        let replacement = fs::metadata(replacement).expect("replacement metadata");
        assert!(same_bind_identity(&retained, &alias));
        assert!(!same_bind_identity(&retained, &replacement));
    }

    #[test]
    fn detached_filesystem_flags_are_converted_without_silent_loss() {
        let attributes = filesystem_mount_attributes(
            7,
            libc::MS_RDONLY
                | libc::MS_NOSUID
                | libc::MS_NODEV
                | libc::MS_NOEXEC
                | libc::MS_NOATIME
                | libc::MS_NODIRATIME
                | libc::MS_NOSYMFOLLOW,
        )
        .expect("representable fsmount flags");
        assert_eq!(
            u64::from(attributes),
            libc::MOUNT_ATTR_RDONLY
                | libc::MOUNT_ATTR_NOSUID
                | libc::MOUNT_ATTR_NODEV
                | libc::MOUNT_ATTR_NOEXEC
                | libc::MOUNT_ATTR_NOATIME
                | libc::MOUNT_ATTR_NODIRATIME
                | libc::MOUNT_ATTR_NOSYMFOLLOW
        );

        let error = filesystem_mount_attributes(7, libc::MS_SYNCHRONOUS)
            .expect_err("unrepresentable fsmount flag");
        assert_eq!(error.code, ErrorCode::Unsupported);
        assert!(error.message.contains("cannot be represented"));
    }

    #[test]
    fn detached_bind_flags_preserve_requested_security_attributes() {
        let (attr_set, attr_clr) = bind_mount_attributes(
            libc::MS_RDONLY
                | libc::MS_NOSUID
                | libc::MS_NODEV
                | libc::MS_NOEXEC
                | libc::MS_NOATIME
                | libc::MS_NODIRATIME
                | libc::MS_NOSYMFOLLOW,
        );
        assert_eq!(
            attr_set,
            libc::MOUNT_ATTR_RDONLY
                | libc::MOUNT_ATTR_NOSUID
                | libc::MOUNT_ATTR_NODEV
                | libc::MOUNT_ATTR_NOEXEC
                | libc::MOUNT_ATTR_NOATIME
                | libc::MOUNT_ATTR_NODIRATIME
                | libc::MOUNT_ATTR_NOSYMFOLLOW
        );
        assert_eq!(attr_clr, libc::MOUNT_ATTR__ATIME);
    }

    #[test]
    fn defers_readonly_bind_sources_created_by_earlier_mounts() {
        let bundle = tempfile::tempdir().expect("temporary bundle");
        let plan = MountPlan {
            index: 7,
            destination: PathBuf::from("/generated-readonly"),
            source: Some(PathBuf::from("rootfs/generated-source")),
            filesystem_type: Some("none".into()),
            flags: libc::MS_BIND | libc::MS_REC | libc::MS_RDONLY,
            bind: true,
            remount_bind: true,
            detached_bind: true,
            propagation: None,
            recursive_attributes: None,
            idmap: None,
            data: Vec::new(),
            ordered_source: Some(PathBuf::from("generated-source")),
            oci_cgroup_source: false,
            oci_cgroup_destination: false,
            oci_readonly_option: false,
        };

        let resolver = BindSourceResolver::new(bundle.path(), None);
        let sources =
            DetachedMountSources::prepare(&[plan], &resolver, IdmapNamespaceHandles::default())
                .expect("deferred generated bind source");

        assert!(!sources.contains(7));
    }

    #[test]
    fn defers_idmapped_bind_sources_created_by_earlier_mounts() {
        let bundle = tempfile::tempdir().expect("temporary bundle");
        let plan = ordered_idmap_plan();

        let resolver = BindSourceResolver::new(bundle.path(), None);
        let sources =
            DetachedMountSources::prepare(&[plan], &resolver, IdmapNamespaceHandles::default())
                .expect("deferred generated ID-mapped bind source");

        assert!(!sources.contains(8));
    }

    #[test]
    fn parent_ordered_idmap_rejects_untrusted_plan_and_descriptor_shapes() {
        let mount: OwnedFd = fs::File::open("/dev/null")
            .expect("ordinary descriptor fixture")
            .into();
        let user_namespace: OwnedFd = fs::File::open("/proc/self/ns/user")
            .expect("user namespace fixture")
            .into();

        let mut unordered = ordered_idmap_plan();
        unordered.ordered_source = None;
        let error = apply_ordered_idmap_from_parent(&unordered, &mount, &user_namespace)
            .expect_err("unordered mount request must fail");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert!(error.message.contains("ordered mount source"));

        let mut unmapped = ordered_idmap_plan();
        unmapped.idmap = None;
        let error = apply_ordered_idmap_from_parent(&unmapped, &mount, &user_namespace)
            .expect_err("unmapped mount request must fail");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert!(error.message.contains("ID-mapped mount"));

        let error = apply_ordered_idmap_from_parent(&ordered_idmap_plan(), &mount, &user_namespace)
            .expect_err("ordinary descriptor must fail");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert!(error.message.contains("O_PATH mount descriptor"));

        let mount: OwnedFd = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open("/dev/null")
            .expect("O_PATH descriptor fixture")
            .into();
        let not_namespace: OwnedFd = fs::File::open("/dev/null")
            .expect("non-namespace descriptor fixture")
            .into();
        let error = apply_ordered_idmap_from_parent(&ordered_idmap_plan(), &mount, &not_namespace)
            .expect_err("non-namespace descriptor must fail");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert!(error.message.contains("namespace descriptor"));
    }

    fn ordered_idmap_plan() -> MountPlan {
        let mappings = vec![IdMapping {
            container_id: 0,
            host_id: 1000,
            size: 1,
        }];
        MountPlan {
            index: 8,
            destination: PathBuf::from("/generated-idmap"),
            source: Some(PathBuf::from("rootfs/generated-source")),
            filesystem_type: Some("none".into()),
            flags: libc::MS_BIND | libc::MS_REC,
            bind: true,
            remount_bind: false,
            detached_bind: false,
            propagation: None,
            recursive_attributes: None,
            idmap: Some(IdmapPlan::dedicated(false, mappings.clone(), mappings)),
            data: Vec::new(),
            ordered_source: Some(PathBuf::from("generated-source")),
            oci_cgroup_source: false,
            oci_cgroup_destination: false,
            oci_readonly_option: false,
        }
    }
}
