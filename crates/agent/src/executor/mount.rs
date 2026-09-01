mod attributes;
mod default_filesystem;
mod idmap;
mod scope;
mod target;

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::Mount;
use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::namespace::{collect_mappings, IdmapPlan, NamespacePlan};
use super::PinnedBundleDirectory;
use crate::vm_attachment::UtilityVmStorageSources;

pub(super) use default_filesystem::DefaultFilesystemPlan;
pub(super) use idmap::{apply_ordered_idmap_from_parent, DetachedMountSources};
pub(super) use scope::{validate_bundle_scoped_sources, validate_bundle_source_syntax};

const MAX_MOUNTS: usize = 1_024;
const MAX_MOUNT_STRING_BYTES: usize = 64 * 1_024;
const MAX_MOUNT_OPTIONS: usize = 4_096;

#[cfg(test)]
pub(super) use attributes::{
    MOUNT_ATTR_ATIME, MOUNT_ATTR_NOATIME, MOUNT_ATTR_NODEV, MOUNT_ATTR_NODIRATIME,
    MOUNT_ATTR_NOEXEC, MOUNT_ATTR_NOSUID, MOUNT_ATTR_NOSYMFOLLOW, MOUNT_ATTR_RDONLY,
    MOUNT_ATTR_STRICTATIME,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MountPlan {
    pub(super) index: usize,
    pub(super) destination: PathBuf,
    pub(super) source: Option<PathBuf>,
    pub(super) filesystem_type: Option<String>,
    pub(super) flags: libc::c_ulong,
    pub(super) bind: bool,
    pub(super) remount_bind: bool,
    pub(super) detached_bind: bool,
    pub(super) propagation: Option<libc::c_ulong>,
    pub(super) recursive_attributes: Option<attributes::RecursiveMountAttributes>,
    pub(super) idmap: Option<IdmapPlan>,
    pub(super) data: Vec<String>,
    pub(super) ordered_source: Option<PathBuf>,
    oci_cgroup_source: bool,
    oci_cgroup_destination: bool,
    oci_readonly_option: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MountTargetKind {
    Directory,
    File,
}

pub(super) struct BindSourceResolver<'a> {
    bundle_directory: &'a Path,
    pinned_bundle: Option<&'a PinnedBundleDirectory>,
}

#[derive(Debug)]
pub(super) struct ResolvedBindSource {
    path: PathBuf,
    mount_path: PathBuf,
    descriptor: Option<File>,
    kind: MountTargetKind,
}

impl<'a> BindSourceResolver<'a> {
    pub(super) const fn new(
        bundle_directory: &'a Path,
        pinned_bundle: Option<&'a PinnedBundleDirectory>,
    ) -> Self {
        Self {
            bundle_directory,
            pinned_bundle,
        }
    }

    pub(super) fn resolve(
        &self,
        index: usize,
        source: &Path,
    ) -> Result<Option<ResolvedBindSource>> {
        if let Some(bundle) = self.pinned_bundle {
            let mount_path = bind_source_candidate_path(self.bundle_directory, source);
            let descriptor = bundle.open_relative(
                source,
                libc::O_PATH,
                false,
                &format!("mounts[{index}].source"),
                "prepare-container-mounts",
            )?;
            return descriptor
                .map(|descriptor| {
                    ResolvedBindSource::from_descriptor(index, mount_path, descriptor)
                })
                .transpose();
        }
        let candidate = bind_source_candidate_path(self.bundle_directory, source);
        let path = match candidate.canonicalize() {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(invalid(format!(
                    "mounts[{index}].source does not resolve in the runtime namespace: {error}"
                )));
            }
        };
        let kind = if path.is_dir() {
            MountTargetKind::Directory
        } else {
            MountTargetKind::File
        };
        Ok(Some(ResolvedBindSource {
            mount_path: path.clone(),
            path,
            descriptor: None,
            kind,
        }))
    }

    pub(super) fn resolve_required(
        &self,
        index: usize,
        source: &Path,
    ) -> Result<ResolvedBindSource> {
        self.resolve(index, source)?.ok_or_else(|| {
            invalid(format!(
                "mounts[{index}].source does not exist in the runtime namespace: {}",
                bind_source_candidate_path(self.bundle_directory, source).display()
            ))
        })
    }

    pub(super) fn resolve_ordered_source(
        &self,
        index: usize,
        effective_rootfs: &Path,
        relative_source: &Path,
    ) -> Result<ResolvedBindSource> {
        if relative_source.as_os_str().is_empty()
            || relative_source.is_absolute()
            || relative_source
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(permission_denied(format!(
                "mounts[{index}].source has an invalid ordered rootfs projection: {}",
                relative_source.display()
            )));
        }
        let rootfs = File::open(effective_rootfs).map_err(|error| {
            permission_denied(format!(
                "failed to retain the effective rootfs for mounts[{index}].source: {error}"
            ))
        })?;
        if !rootfs
            .metadata()
            .map_err(|error| {
                permission_denied(format!(
                    "failed to inspect the effective rootfs for mounts[{index}].source: {error}"
                ))
            })?
            .is_dir()
        {
            return Err(permission_denied(format!(
                "effective rootfs for mounts[{index}].source is not a directory"
            )));
        }
        let relative = path_cstring(index, "source", relative_source)?;
        let mut how = std::mem::MaybeUninit::<libc::open_how>::zeroed();
        // SAFETY: zero is valid for every field of open_how.
        let how = unsafe { how.assume_init_mut() };
        how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
        how.resolve =
            libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_SYMLINKS;
        // SAFETY: rootfs and the pathname are live, and how is initialized for
        // the exact kernel ABI size.
        let descriptor = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                rootfs.as_raw_fd(),
                relative.as_ptr(),
                how as *const libc::open_how,
                std::mem::size_of::<libc::open_how>(),
            )
        };
        if descriptor < 0 {
            return Err(permission_denied(format!(
                "failed to open ordered descriptor-confined mounts[{index}].source {}: {}",
                relative_source.display(),
                io::Error::last_os_error()
            )));
        }
        let descriptor = libc::c_int::try_from(descriptor).map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("openat2 returned an invalid mounts[{index}].source descriptor: {error}"),
            )
            .for_operation("prepare-container-mounts")
        })?;
        // SAFETY: openat2 returned this fresh descriptor exactly once.
        let descriptor = unsafe { File::from_raw_fd(descriptor) };
        ResolvedBindSource::from_descriptor(
            index,
            effective_rootfs.join(relative_source),
            descriptor,
        )
    }
}

impl ResolvedBindSource {
    fn from_descriptor(index: usize, mount_path: PathBuf, descriptor: File) -> Result<Self> {
        let metadata = descriptor.metadata().map_err(|error| {
            permission_denied(format!(
                "failed to inspect descriptor-confined mounts[{index}].source: {error}"
            ))
        })?;
        let kind = if metadata.is_dir() {
            MountTargetKind::Directory
        } else {
            MountTargetKind::File
        };
        Ok(Self {
            path: PathBuf::from(format!("/proc/self/fd/{}", descriptor.as_raw_fd())),
            mount_path,
            descriptor: Some(descriptor),
            kind,
        })
    }

    pub(super) const fn kind(&self) -> MountTargetKind {
        self.kind
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) const fn is_descriptor_confined(&self) -> bool {
        self.descriptor.is_some()
    }

    fn cstring(&self, index: usize) -> Result<CString> {
        let source = path_cstring(index, "source", &self.mount_path)?;
        debug_assert!(self
            .descriptor
            .as_ref()
            .is_none_or(|descriptor| descriptor.as_raw_fd() >= 0));
        Ok(source)
    }
}

pub(super) fn plan_all(
    mounts: Option<&[Mount]>,
    namespaces: &NamespacePlan,
) -> Result<Vec<MountPlan>> {
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
        .map(|(index, mount)| MountPlan::new(index, mount, namespaces))
        .collect()
}

pub(super) fn mark_ordered_bind_sources(
    plans: &mut [MountPlan],
    bundle_directory: &Path,
    rootfs: &Path,
) {
    for plan in plans {
        if !plan.bind {
            continue;
        }
        let Some(source) = plan.source.as_deref() else {
            continue;
        };
        let source = bind_source_candidate_path(bundle_directory, source);
        let Ok(relative) = source.strip_prefix(rootfs) else {
            continue;
        };
        if relative.as_os_str().is_empty() {
            continue;
        }
        // Resolve every rootfs-internal source when its mount entry is
        // applied. This preserves list order for both caller mounts and early
        // synthesized filesystems such as /proc and /sys, while sources that
        // are unaffected by an earlier mount retain the same identity.
        plan.ordered_source = Some(relative.to_path_buf());
    }
}

pub(super) fn rewrite_vm_storage_sources(
    plans: &mut [MountPlan],
    sources: &UtilityVmStorageSources,
) -> Result<()> {
    for source in sources.as_slice() {
        let plan = plans.get_mut(source.mount_index()).ok_or_else(|| {
            permission_denied(format!(
                "VM storage source references missing OCI mount index {}",
                source.mount_index()
            ))
        })?;
        if plan.index != source.mount_index()
            || plan.source.as_deref() != Some(Path::new(source.configured_source()))
        {
            return Err(permission_denied(format!(
                "VM storage source for OCI mount index {} differs from its immutable configuration",
                source.mount_index()
            )));
        }
        if plan.bind || plan.filesystem_type.as_deref() != Some("ext4") {
            return Err(permission_denied(format!(
                "VM storage source for OCI mount index {} requires a non-bind ext4 mount",
                source.mount_index()
            )));
        }
        plan.source = Some(PathBuf::from(source.guest_source()));
    }
    Ok(())
}

pub(super) fn validate_control_workload_cgroup_mount(plans: &[MountPlan]) -> Result<()> {
    let mut cgroup_mounts = plans
        .iter()
        .filter(|plan| plan.filesystem_type.as_deref() == Some("cgroup2"));
    let Some(mount) = cgroup_mounts.next() else {
        return Err(invalid(
            "control/workload cgroup layout requires a read-only cgroup2 mount at /sys/fs/cgroup",
        ));
    };
    if cgroup_mounts.next().is_some()
        || mount.destination != Path::new("/sys/fs/cgroup")
        || !mount.is_effectively_readonly()
    {
        return Err(invalid(
            "control/workload cgroup layout requires exactly one read-only cgroup2 mount at /sys/fs/cgroup",
        ));
    }
    Ok(())
}

pub(super) fn apply_all(
    plans: &[MountPlan],
    rootfs: &Path,
    detached_sources: &mut DetachedMountSources,
    source_resolver: &BindSourceResolver<'_>,
) -> Result<()> {
    for plan in plans {
        plan.apply(rootfs, detached_sources, source_resolver)?;
    }
    detached_sources.ensure_consumed()
}

impl MountPlan {
    fn is_effectively_readonly(&self) -> bool {
        self.recursive_attributes.map_or_else(
            || self.flags & libc::MS_RDONLY != 0,
            |attributes| {
                if attributes.attr_set & attributes::MOUNT_ATTR_RDONLY != 0 {
                    true
                } else if attributes.attr_clr & attributes::MOUNT_ATTR_RDONLY != 0 {
                    false
                } else {
                    self.flags & libc::MS_RDONLY != 0
                }
            },
        )
    }

    fn new(index: usize, mount: &Mount, namespaces: &NamespacePlan) -> Result<Self> {
        let uid_mappings_specified = mount.uid_mappings().is_some();
        let gid_mappings_specified = mount.gid_mappings().is_some();
        if uid_mappings_specified != gid_mappings_specified {
            return Err(invalid(format!(
                "mounts[{index}].uidMappings and gidMappings must be specified together"
            )));
        }
        let explicit_id_mappings = if uid_mappings_specified {
            let uid_mappings = collect_mappings(
                &format!("mounts[{index}].uidMappings"),
                mount.uid_mappings().as_deref(),
            )?;
            let gid_mappings = collect_mappings(
                &format!("mounts[{index}].gidMappings"),
                mount.gid_mappings().as_deref(),
            )?;
            if uid_mappings.is_empty() || gid_mappings.is_empty() {
                return Err(invalid(format!(
                    "mounts[{index}].uidMappings and gidMappings must both contain mappings"
                )));
            }
            Some((uid_mappings, gid_mappings))
        } else {
            None
        };
        let oci_cgroup_destination =
            mount.destination().as_os_str().as_bytes() == b"/sys/fs/cgroup";
        let destination = normalize_destination(index, mount.destination())?;
        if destination == Path::new("/") {
            return Err(unsupported(
                index,
                "destination",
                "replacing the container root with an additional mount is not implemented",
            ));
        }
        let mut source = mount
            .source()
            .as_ref()
            .map(|source| {
                validate_path(index, "source", source)?;
                Ok(source.clone())
            })
            .transpose()?;
        let oci_cgroup_source = source
            .as_ref()
            .is_some_and(|source| source.as_os_str().as_bytes() == b"cgroup");
        let mut filesystem_type = mount
            .typ()
            .as_deref()
            .map(|value| validate_string(index, "type", value))
            .transpose()?;
        normalize_unified_cgroup_mount(index, &mut source, &mut filesystem_type)?;

        let mut flags = 0;
        let mut bind = false;
        let mut remount_bind = false;
        let mut detached_bind_compatible = true;
        let mut propagation = None;
        let mut recursive_attributes = None;
        let mut idmap_recursive = None;
        let mut data = Vec::new();
        let options = mount.options().as_deref().unwrap_or_default();
        let oci_readonly_option = options.iter().any(|option| option == "ro");
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
                "rw" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_RDONLY, false, &mut remount_bind);
                }
                "suid" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_NOSUID, false, &mut remount_bind);
                }
                "nosuid" => set_flag(&mut flags, libc::MS_NOSUID, true, &mut remount_bind),
                "dev" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_NODEV, false, &mut remount_bind);
                }
                "nodev" => set_flag(&mut flags, libc::MS_NODEV, true, &mut remount_bind),
                "exec" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_NOEXEC, false, &mut remount_bind);
                }
                "noexec" => set_flag(&mut flags, libc::MS_NOEXEC, true, &mut remount_bind),
                "sync" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_SYNCHRONOUS, true, &mut remount_bind);
                }
                "async" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_SYNCHRONOUS, false, &mut remount_bind);
                }
                "dirsync" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_DIRSYNC, true, &mut remount_bind);
                }
                "remount" => {
                    detached_bind_compatible = false;
                    flags |= libc::MS_REMOUNT;
                }
                "mand" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_MANDLOCK, true, &mut remount_bind);
                }
                "nomand" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_MANDLOCK, false, &mut remount_bind);
                }
                "atime" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_NOATIME, false, &mut remount_bind);
                }
                "noatime" => set_flag(&mut flags, libc::MS_NOATIME, true, &mut remount_bind),
                "diratime" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_NODIRATIME, false, &mut remount_bind);
                }
                "nodiratime" => {
                    set_flag(&mut flags, libc::MS_NODIRATIME, true, &mut remount_bind);
                }
                "relatime" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_RELATIME, true, &mut remount_bind);
                }
                "norelatime" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_RELATIME, false, &mut remount_bind);
                }
                "strictatime" => {
                    set_flag(&mut flags, libc::MS_STRICTATIME, true, &mut remount_bind);
                }
                "nostrictatime" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_STRICTATIME, false, &mut remount_bind);
                }
                "lazytime" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_LAZYTIME, true, &mut remount_bind);
                }
                "nolazytime" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_LAZYTIME, false, &mut remount_bind);
                }
                "iversion" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_I_VERSION, true, &mut remount_bind);
                }
                "noiversion" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_I_VERSION, false, &mut remount_bind);
                }
                "silent" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_SILENT, true, &mut remount_bind);
                }
                "loud" => {
                    detached_bind_compatible = false;
                    set_flag(&mut flags, libc::MS_SILENT, false, &mut remount_bind);
                }
                "nosymfollow" => {
                    set_flag(&mut flags, libc::MS_NOSYMFOLLOW, true, &mut remount_bind);
                }
                "symfollow" => {
                    detached_bind_compatible = false;
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
                "idmap" => set_idmap_mode(index, &mut idmap_recursive, false)?,
                "ridmap" => set_idmap_mode(index, &mut idmap_recursive, true)?,
                "tmpcopyup" => {
                    return Err(unsupported(
                        index,
                        "options",
                        "tmpfs copy-up is not implemented",
                    ));
                }
                option if attributes::record_option(&mut recursive_attributes, option) => {}
                "move" => {
                    return Err(unsupported(
                        index,
                        "options",
                        "moving an existing mount is not implemented",
                    ));
                }
                _ => {
                    detached_bind_compatible = false;
                    data.push(option.clone());
                }
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
        let idmap = match (explicit_id_mappings, idmap_recursive) {
            (Some((uid_mappings, gid_mappings)), recursive) => Some(IdmapPlan::dedicated(
                recursive.unwrap_or(false),
                uid_mappings,
                gid_mappings,
            )),
            (None, Some(recursive)) if namespaces.new_user() => Some(IdmapPlan::container(
                recursive,
                namespaces.uid_mappings(),
                namespaces.gid_mappings(),
            )),
            (None, Some(_)) => {
                return Err(invalid(format!(
                    "mounts[{index}].options requires paired mount mappings or a newly created \
                     container user namespace for idmap/ridmap"
                )));
            }
            (None, None) => None,
        };
        let requests_readonly = flags & libc::MS_RDONLY != 0
            || recursive_attributes
                .is_some_and(|attributes| attributes.attr_set & attributes::MOUNT_ATTR_RDONLY != 0);
        let detached_bind =
            namespaces.new_user() && bind && requests_readonly && detached_bind_compatible;
        // An explicit bind remount applies the requested attributes in the
        // first mount(2) call. Only ordinary bind creation needs the follow-up
        // remount used to apply VFS attributes.
        let remount_bind = remount_bind && flags & libc::MS_REMOUNT == 0;
        Ok(Self {
            index,
            destination,
            source,
            filesystem_type,
            flags,
            bind,
            remount_bind,
            detached_bind,
            propagation,
            recursive_attributes,
            idmap,
            data,
            ordered_source: None,
            oci_cgroup_source,
            oci_cgroup_destination,
            oci_readonly_option,
        })
    }

    pub(super) fn requests_cgroup_ownership(&self) -> bool {
        self.oci_cgroup_source
            && self.oci_cgroup_destination
            && !self.oci_readonly_option
            && self.filesystem_type.as_deref() == Some("cgroup2")
    }

    pub(super) fn prepare_target(&self, rootfs: &Path, kind: MountTargetKind) -> Result<PathBuf> {
        target::prepare(self, rootfs, kind)
    }

    fn apply(
        &self,
        rootfs: &Path,
        detached_sources: &mut DetachedMountSources,
        source_resolver: &BindSourceResolver<'_>,
    ) -> Result<()> {
        let ordered_bind_source = self
            .ordered_source
            .as_deref()
            .map(|relative_source| {
                source_resolver.resolve_ordered_source(self.index, rootfs, relative_source)
            })
            .transpose()?;
        if let Some(source) = ordered_bind_source.as_ref() {
            if self.idmap.is_some() || self.detached_bind {
                detached_sources.prepare_ordered(self, source)?;
            }
        }
        let detached_bind = self.detached_bind && detached_sources.contains(self.index);
        let uses_detached_source = self.idmap.is_some() || detached_bind;
        let bind_source = if self.bind && !uses_detached_source {
            Some(match ordered_bind_source {
                Some(source) => source,
                None => source_resolver.resolve_required(
                    self.index,
                    self.source.as_deref().ok_or_else(|| {
                        invalid(format!(
                            "mounts[{}].source is required for a bind mount",
                            self.index
                        ))
                    })?,
                )?,
            })
        } else {
            None
        };
        let target_kind = bind_source.as_ref().map_or_else(
            || {
                detached_sources
                    .source_kind(self.index)
                    .unwrap_or(MountTargetKind::Directory)
            },
            ResolvedBindSource::kind,
        );
        let target = self.prepare_target(rootfs, target_kind)?;
        let target = path_cstring(self.index, "destination", &target)?;
        let detached_destination = uses_detached_source
            .then(|| detached_sources.open_destination(self.index, &target))
            .transpose()?;
        let source = if uses_detached_source {
            None
        } else if let Some(source) = bind_source.as_ref() {
            Some(source.cstring(self.index)?)
        } else {
            self.source
                .as_deref()
                .map(|source| path_cstring(self.index, "source", source))
                .transpose()?
        };
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

        let descriptor_bind_attached = if let Some(source) = bind_source.as_ref() {
            idmap::attach_descriptor_bind(
                self.index,
                source,
                &target,
                self.flags & libc::MS_REC != 0,
            )?
        } else {
            false
        };

        if let Some(destination) = detached_destination.as_ref() {
            detached_sources.attach(self.index, destination)?;
        } else if !descriptor_bind_attached {
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
            if let Some(source) = bind_source.as_ref() {
                idmap::verify_legacy_descriptor_bind(self.index, source, &target)?;
            }
        }
        if self.bind && self.remount_bind && !detached_bind {
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
        if !detached_bind {
            if let Some(attributes) = self.recursive_attributes {
                attributes::apply(self.index, &target, attributes)?;
            }
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

fn normalize_unified_cgroup_mount(
    index: usize,
    source: &mut Option<PathBuf>,
    filesystem_type: &mut Option<String>,
) -> Result<()> {
    if filesystem_type.as_deref() != Some("cgroup") {
        return Ok(());
    }
    if source
        .as_deref()
        .is_some_and(|source| source != Path::new("cgroup"))
    {
        return Err(unsupported(
            index,
            "source",
            "legacy cgroup mounts must use source `cgroup` for cgroup v2 normalization",
        ));
    }
    *source = Some(PathBuf::from("cgroup2"));
    *filesystem_type = Some("cgroup2".to_string());
    Ok(())
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

fn set_idmap_mode(index: usize, idmap_recursive: &mut Option<bool>, recursive: bool) -> Result<()> {
    if idmap_recursive.replace(recursive).is_some() {
        Err(invalid(format!(
            "mounts[{index}].options contains multiple idmap/ridmap modes"
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

fn bind_source_candidate_path(bundle_directory: &Path, source: &Path) -> PathBuf {
    if source.is_absolute() {
        source.to_path_buf()
    } else {
        bundle_directory.join(source)
    }
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
