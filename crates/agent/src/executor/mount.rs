use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::Mount;
use a3s_oci_sdk::{Error, ErrorCode, Result};

const MAX_MOUNTS: usize = 1_024;
const MAX_MOUNT_STRING_BYTES: usize = 64 * 1_024;
const MAX_MOUNT_OPTIONS: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MountPlan {
    pub(super) index: usize,
    pub(super) destination: PathBuf,
    pub(super) source: Option<PathBuf>,
    pub(super) filesystem_type: Option<String>,
    pub(super) flags: libc::c_ulong,
    pub(super) bind: bool,
    pub(super) remount_bind: bool,
    pub(super) propagation: Option<libc::c_ulong>,
    pub(super) data: Vec<String>,
}

pub(super) fn plan_all(mounts: Option<&[Mount]>) -> Result<Vec<MountPlan>> {
    let mounts = mounts.unwrap_or_default();
    if mounts.len() > MAX_MOUNTS {
        return Err(invalid(format!(
            "mounts contains {} entries; maximum is {MAX_MOUNTS}",
            mounts.len()
        )));
    }
    mounts
        .iter()
        .enumerate()
        .map(|(index, mount)| MountPlan::new(index, mount))
        .collect()
}

pub(super) fn apply_all(plans: &[MountPlan], bundle_directory: &Path, rootfs: &Path) -> Result<()> {
    for plan in plans {
        plan.apply(bundle_directory, rootfs)?;
    }
    Ok(())
}

impl MountPlan {
    fn new(index: usize, mount: &Mount) -> Result<Self> {
        if mount.uid_mappings().is_some() || mount.gid_mappings().is_some() {
            return Err(unsupported(
                index,
                "uidMappings/gidMappings",
                "idmapped mounts are not implemented",
            ));
        }
        let destination = normalize_destination(index, mount.destination())?;
        if destination == Path::new("/") {
            return Err(unsupported(
                index,
                "destination",
                "replacing the container root with an additional mount is not implemented",
            ));
        }
        let source = mount
            .source()
            .as_ref()
            .map(|source| {
                validate_path(index, "source", source)?;
                Ok(source.clone())
            })
            .transpose()?;
        let filesystem_type = mount
            .typ()
            .as_deref()
            .map(|value| validate_string(index, "type", value))
            .transpose()?;

        let mut flags = 0;
        let mut bind = false;
        let mut remount_bind = false;
        let mut propagation = None;
        let mut data = Vec::new();
        let options = mount.options().as_deref().unwrap_or_default();
        if options.len() > MAX_MOUNT_OPTIONS {
            return Err(invalid(format!(
                "mounts[{index}].options contains {} entries; maximum is {MAX_MOUNT_OPTIONS}",
                options.len()
            )));
        }
        for option in options {
            validate_option(index, option)?;
            match option.as_str() {
                "defaults" => {}
                "ro" => set_flag(&mut flags, libc::MS_RDONLY, true, &mut remount_bind),
                "rw" => set_flag(&mut flags, libc::MS_RDONLY, false, &mut remount_bind),
                "suid" => set_flag(&mut flags, libc::MS_NOSUID, false, &mut remount_bind),
                "nosuid" => set_flag(&mut flags, libc::MS_NOSUID, true, &mut remount_bind),
                "dev" => set_flag(&mut flags, libc::MS_NODEV, false, &mut remount_bind),
                "nodev" => set_flag(&mut flags, libc::MS_NODEV, true, &mut remount_bind),
                "exec" => set_flag(&mut flags, libc::MS_NOEXEC, false, &mut remount_bind),
                "noexec" => set_flag(&mut flags, libc::MS_NOEXEC, true, &mut remount_bind),
                "sync" => set_flag(&mut flags, libc::MS_SYNCHRONOUS, true, &mut remount_bind),
                "async" => set_flag(&mut flags, libc::MS_SYNCHRONOUS, false, &mut remount_bind),
                "dirsync" => set_flag(&mut flags, libc::MS_DIRSYNC, true, &mut remount_bind),
                "remount" => flags |= libc::MS_REMOUNT,
                "mand" => set_flag(&mut flags, libc::MS_MANDLOCK, true, &mut remount_bind),
                "nomand" => set_flag(&mut flags, libc::MS_MANDLOCK, false, &mut remount_bind),
                "atime" => set_flag(&mut flags, libc::MS_NOATIME, false, &mut remount_bind),
                "noatime" => set_flag(&mut flags, libc::MS_NOATIME, true, &mut remount_bind),
                "diratime" => {
                    set_flag(&mut flags, libc::MS_NODIRATIME, false, &mut remount_bind);
                }
                "nodiratime" => {
                    set_flag(&mut flags, libc::MS_NODIRATIME, true, &mut remount_bind);
                }
                "relatime" => set_flag(&mut flags, libc::MS_RELATIME, true, &mut remount_bind),
                "norelatime" => {
                    set_flag(&mut flags, libc::MS_RELATIME, false, &mut remount_bind);
                }
                "strictatime" => {
                    set_flag(&mut flags, libc::MS_STRICTATIME, true, &mut remount_bind);
                }
                "nostrictatime" => {
                    set_flag(&mut flags, libc::MS_STRICTATIME, false, &mut remount_bind);
                }
                "lazytime" => set_flag(&mut flags, libc::MS_LAZYTIME, true, &mut remount_bind),
                "nolazytime" => {
                    set_flag(&mut flags, libc::MS_LAZYTIME, false, &mut remount_bind);
                }
                "iversion" => set_flag(&mut flags, libc::MS_I_VERSION, true, &mut remount_bind),
                "noiversion" => {
                    set_flag(&mut flags, libc::MS_I_VERSION, false, &mut remount_bind);
                }
                "silent" => set_flag(&mut flags, libc::MS_SILENT, true, &mut remount_bind),
                "loud" => set_flag(&mut flags, libc::MS_SILENT, false, &mut remount_bind),
                "nosymfollow" => {
                    set_flag(&mut flags, libc::MS_NOSYMFOLLOW, true, &mut remount_bind);
                }
                "symfollow" => {
                    set_flag(&mut flags, libc::MS_NOSYMFOLLOW, false, &mut remount_bind);
                }
                "bind" => {
                    bind = true;
                    flags |= libc::MS_BIND;
                    flags &= !libc::MS_REC;
                }
                "rbind" => {
                    bind = true;
                    flags |= libc::MS_BIND | libc::MS_REC;
                }
                "private" => set_propagation(index, &mut propagation, libc::MS_PRIVATE)?,
                "rprivate" => {
                    set_propagation(index, &mut propagation, libc::MS_PRIVATE | libc::MS_REC)?;
                }
                "shared" => set_propagation(index, &mut propagation, libc::MS_SHARED)?,
                "rshared" => {
                    set_propagation(index, &mut propagation, libc::MS_SHARED | libc::MS_REC)?;
                }
                "slave" => set_propagation(index, &mut propagation, libc::MS_SLAVE)?,
                "rslave" => {
                    set_propagation(index, &mut propagation, libc::MS_SLAVE | libc::MS_REC)?;
                }
                "unbindable" => {
                    set_propagation(index, &mut propagation, libc::MS_UNBINDABLE)?;
                }
                "runbindable" => {
                    set_propagation(index, &mut propagation, libc::MS_UNBINDABLE | libc::MS_REC)?
                }
                "idmap" | "ridmap" => {
                    return Err(unsupported(
                        index,
                        "options",
                        "idmapped mounts are not implemented",
                    ));
                }
                "tmpcopyup" => {
                    return Err(unsupported(
                        index,
                        "options",
                        "tmpfs copy-up is not implemented",
                    ));
                }
                "ratime" | "rdev" | "rdiratime" | "rexec" | "rnoatime" | "rnodiratime"
                | "rnoexec" | "rnorelatime" | "rnostrictatime" | "rnosuid" | "rnosymfollow"
                | "rrelatime" | "rro" | "rrw" | "rstrictatime" | "rsuid" | "rsymfollow" => {
                    return Err(unsupported(
                        index,
                        "options",
                        "recursive mount attributes require mount_setattr support",
                    ));
                }
                "move" => {
                    return Err(unsupported(
                        index,
                        "options",
                        "moving an existing mount is not implemented",
                    ));
                }
                _ => data.push(option.clone()),
            }
        }
        let data_bytes = data.iter().try_fold(0_usize, |bytes, option| {
            bytes.checked_add(option.len().saturating_add(1))
        });
        if data_bytes.is_none_or(|bytes| bytes > MAX_MOUNT_STRING_BYTES) {
            return Err(invalid(format!(
                "mounts[{index}].options filesystem data exceeds {MAX_MOUNT_STRING_BYTES} bytes"
            )));
        }
        if bind && source.is_none() {
            return Err(invalid(format!(
                "mounts[{index}].source is required for bind and rbind mounts"
            )));
        }
        if !bind && flags & libc::MS_REMOUNT == 0 && filesystem_type.is_none() {
            return Err(unsupported(
                index,
                "type",
                "filesystem auto-detection is not implemented",
            ));
        }

        Ok(Self {
            index,
            destination,
            source,
            filesystem_type,
            flags,
            bind,
            remount_bind,
            propagation,
            data,
        })
    }

    fn apply(&self, bundle_directory: &Path, rootfs: &Path) -> Result<()> {
        let target = resolve_target(self.index, rootfs, &self.destination)?;
        let source = self
            .source
            .as_deref()
            .map(|source| {
                if self.bind {
                    resolve_bind_source(self.index, bundle_directory, source)
                } else {
                    path_cstring(self.index, "source", source)
                }
            })
            .transpose()?;
        let filesystem_type = self
            .filesystem_type
            .as_deref()
            .map(|value| string_cstring(self.index, "type", value))
            .transpose()?;
        let data = if self.data.is_empty() {
            None
        } else {
            Some(string_cstring(self.index, "options", &self.data.join(","))?)
        };

        mount_call(
            self.index,
            source.as_ref(),
            &target,
            if self.bind {
                None
            } else {
                filesystem_type.as_ref()
            },
            self.flags,
            data.as_ref(),
            "apply",
        )?;
        if self.bind && self.remount_bind {
            let remount_flags = (self.flags & !(libc::MS_REC | libc::MS_REMOUNT))
                | libc::MS_BIND
                | libc::MS_REMOUNT;
            mount_call(
                self.index,
                None,
                &target,
                None,
                remount_flags,
                None,
                "remount bind attributes for",
            )?;
        }
        if let Some(propagation) = self.propagation {
            mount_call(
                self.index,
                None,
                &target,
                None,
                propagation,
                None,
                "apply propagation to",
            )?;
        }
        Ok(())
    }
}

fn set_flag(
    flags: &mut libc::c_ulong,
    flag: libc::c_ulong,
    enabled: bool,
    remount_bind: &mut bool,
) {
    if enabled {
        *flags |= flag;
    } else {
        *flags &= !flag;
    }
    *remount_bind = true;
}

fn set_propagation(
    index: usize,
    propagation: &mut Option<libc::c_ulong>,
    value: libc::c_ulong,
) -> Result<()> {
    if propagation.replace(value).is_some() {
        Err(invalid(format!(
            "mounts[{index}].options contains multiple propagation modes"
        )))
    } else {
        Ok(())
    }
}

fn normalize_destination(index: usize, path: &Path) -> Result<PathBuf> {
    let value = validate_path(index, "destination", path)?;
    let mut normalized = PathBuf::from("/");
    for component in value.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                normalized.pop();
            }
            component => normalized.push(component),
        }
    }
    Ok(normalized)
}

fn validate_path(index: usize, field: &str, path: &Path) -> Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid(format!("mounts[{index}].{field} is not valid UTF-8")))?;
    validate_string(index, field, value)
}

fn validate_string(index: usize, field: &str, value: &str) -> Result<String> {
    if value.is_empty() || value.len() > MAX_MOUNT_STRING_BYTES || value.as_bytes().contains(&0) {
        Err(invalid(format!(
            "mounts[{index}].{field} must contain 1..={MAX_MOUNT_STRING_BYTES} bytes and no NUL"
        )))
    } else {
        Ok(value.to_string())
    }
}

fn validate_option(index: usize, option: &str) -> Result<()> {
    validate_string(index, "options", option)?;
    if option.contains(',') {
        Err(invalid(format!(
            "mounts[{index}].options entries must not contain comma separators"
        )))
    } else {
        Ok(())
    }
}

fn resolve_target(index: usize, rootfs: &Path, destination: &Path) -> Result<CString> {
    let relative = destination
        .strip_prefix("/")
        .map_err(|error| internal(format!("invalid normalized mount destination: {error}")))?;
    let target = rootfs.join(relative).canonicalize().map_err(|error| {
        invalid(format!(
            "mounts[{index}].destination must already exist inside the rootfs: {error}"
        ))
    })?;
    if target == rootfs || !target.starts_with(rootfs) {
        return Err(permission_denied(format!(
            "mounts[{index}].destination escapes the container rootfs"
        )));
    }
    path_cstring(index, "destination", &target)
}

fn resolve_bind_source(index: usize, bundle_directory: &Path, source: &Path) -> Result<CString> {
    let source = if source.is_absolute() {
        source.to_path_buf()
    } else {
        bundle_directory.join(source)
    };
    let source = source.canonicalize().map_err(|error| {
        invalid(format!(
            "mounts[{index}].source does not resolve in the runtime namespace: {error}"
        ))
    })?;
    path_cstring(index, "source", &source)
}

fn path_cstring(index: usize, field: &str, path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|error| {
        invalid(format!(
            "mounts[{index}].{field} contains a NUL byte: {error}"
        ))
    })
}

fn string_cstring(index: usize, field: &str, value: &str) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|error| {
        invalid(format!(
            "mounts[{index}].{field} contains a NUL byte: {error}"
        ))
    })
}

fn mount_call(
    index: usize,
    source: Option<&CString>,
    target: &CString,
    filesystem_type: Option<&CString>,
    flags: libc::c_ulong,
    data: Option<&CString>,
    action: &str,
) -> Result<()> {
    // SAFETY: every non-null pointer references a live NUL-terminated buffer
    // for the duration of the syscall.
    if unsafe {
        libc::mount(
            source.map_or(std::ptr::null(), |value| value.as_ptr()),
            target.as_ptr(),
            filesystem_type.map_or(std::ptr::null(), |value| value.as_ptr()),
            flags,
            data.map_or(std::ptr::null(), |value| value.as_ptr().cast()),
        )
    } != 0
    {
        Err(internal(format!(
            "{action} mounts[{index}] failed: {}",
            io::Error::last_os_error()
        )))
    } else {
        Ok(())
    }
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message).for_operation("plan-container-mounts")
}

fn unsupported(index: usize, field: &str, reason: &str) -> Error {
    Error::new(
        ErrorCode::Unsupported,
        format!("mounts[{index}].{field}: {reason}"),
    )
    .for_operation("plan-container-mounts")
}

fn permission_denied(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::PermissionDenied, message).for_operation("prepare-container-mounts")
}

fn internal(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::Internal, message).for_operation("prepare-container-mounts")
}
