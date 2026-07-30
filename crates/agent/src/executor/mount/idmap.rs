use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::attributes::{
    MountAttr, MOUNT_ATTR_ATIME, MOUNT_ATTR_NOATIME, MOUNT_ATTR_NODEV, MOUNT_ATTR_NODIRATIME,
    MOUNT_ATTR_NOEXEC, MOUNT_ATTR_NOSUID, MOUNT_ATTR_NOSYMFOLLOW, MOUNT_ATTR_RDONLY,
    MOUNT_ATTR_STRICTATIME,
};
use super::{path_cstring, resolve_bind_source_path, MountPlan};
use crate::executor::namespace::IdmapNamespaceHandles;

#[derive(Debug, Default)]
pub(in crate::executor) struct DetachedMountSources {
    sources: BTreeMap<usize, OwnedFd>,
}

impl DetachedMountSources {
    pub(in crate::executor) fn prepare(
        plans: &[MountPlan],
        bundle_directory: &Path,
        namespaces: &IdmapNamespaceHandles,
    ) -> Result<Self> {
        let mut sources = BTreeMap::new();
        for plan in plans {
            if plan.idmap.is_none() && !plan.detached_bind {
                continue;
            }
            let detached = if plan.bind {
                let source = plan.source.as_deref().ok_or_else(|| {
                    apply_error(
                        ErrorCode::InvalidArgument,
                        plan.index,
                        "detached bind mount is missing its source",
                    )
                })?;
                let source = resolve_bind_source_path(plan.index, bundle_directory, source)?;
                let source = path_cstring(plan.index, "source", &source)?;
                clone_mount(plan.index, &source, plan.flags & libc::MS_REC != 0)?
            } else {
                create_filesystem_mount(plan)?
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
            if sources.insert(plan.index, detached).is_some() {
                return Err(apply_error(
                    ErrorCode::Internal,
                    plan.index,
                    "duplicate detached mount source",
                ));
            }
        }
        Ok(Self { sources })
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
        let empty_path = c"";
        let flags = libc::MOVE_MOUNT_F_EMPTY_PATH | libc::MOVE_MOUNT_T_EMPTY_PATH;
        // SAFETY: both descriptors are live, both paths are empty
        // NUL-terminated strings selected by the EMPTY_PATH flags, and
        // move_mount does not retain either pointer.
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

fn clone_mount(index: usize, source: &CString, recursive: bool) -> Result<OwnedFd> {
    let mut flags = libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC;
    if recursive {
        flags |= u32::try_from(libc::AT_RECURSIVE).expect("AT_RECURSIVE fits open_tree flags");
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
    use a3s_oci_sdk::ErrorCode;

    use super::{bind_mount_attributes, classify_errno, filesystem_mount_attributes};

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
}
