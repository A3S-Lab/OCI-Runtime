use std::path::{Path, PathBuf};

use a3s_oci_sdk::Result;

use super::{BindSourceResolver, DetachedMountSources, MountPlan};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplyPhase {
    BeforeConfigured,
    AfterConfigured,
}

#[derive(Debug, Clone, Copy)]
struct Definition {
    destination: &'static str,
    source: &'static str,
    filesystem_type: &'static str,
    flags: libc::c_ulong,
    data: &'static [&'static str],
    phase: ApplyPhase,
    requires_owned_network_namespace: bool,
}

const DEFINITIONS: [Definition; 4] = [
    Definition {
        destination: "/proc",
        source: "proc",
        filesystem_type: "proc",
        flags: libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
        data: &[],
        phase: ApplyPhase::BeforeConfigured,
        requires_owned_network_namespace: false,
    },
    Definition {
        destination: "/sys",
        source: "sysfs",
        filesystem_type: "sysfs",
        flags: libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
        data: &[],
        phase: ApplyPhase::BeforeConfigured,
        requires_owned_network_namespace: true,
    },
    Definition {
        destination: "/dev/pts",
        source: "devpts",
        filesystem_type: "devpts",
        flags: libc::MS_NOSUID | libc::MS_NOEXEC,
        data: &["newinstance", "ptmxmode=0666", "mode=0620"],
        phase: ApplyPhase::AfterConfigured,
        requires_owned_network_namespace: false,
    },
    Definition {
        destination: "/dev/shm",
        source: "shm",
        filesystem_type: "tmpfs",
        flags: libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
        data: &["mode=1777"],
        phase: ApplyPhase::AfterConfigured,
        requires_owned_network_namespace: false,
    },
];

/// Linux ABI filesystems synthesized only when the OCI mount list omits them.
///
/// `/proc` and eligible `/sys` mounts are installed before caller entries so
/// configured child mounts such as `/sys/fs/cgroup` remain visible.
/// `/dev/pts` and `/dev/shm` are installed after caller entries so a configured
/// `/dev` parent cannot hide them. Exact caller destinations are never
/// replaced. A non-initial user namespace may receive `/sys` only when it also
/// owns a new network namespace; Linux rejects a fresh sysfs mount otherwise,
/// and exposing the inherited host sysfs would cross the isolation boundary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(in crate::executor) struct DefaultFilesystemPlan {
    early: Vec<MountPlan>,
    late: Vec<MountPlan>,
}

impl DefaultFilesystemPlan {
    pub(in crate::executor) fn from_configured(
        configured: &[MountPlan],
        new_mount_namespace: bool,
        sysfs_mount_allowed: bool,
        devpts_gid: u32,
    ) -> Self {
        if !new_mount_namespace {
            return Self::default();
        }

        let mut plan = Self::default();
        for (ordinal, definition) in DEFINITIONS.iter().enumerate() {
            if definition.requires_owned_network_namespace && !sysfs_mount_allowed {
                continue;
            }
            if configured
                .iter()
                .any(|mount| mount.destination == Path::new(definition.destination))
            {
                continue;
            }
            let mount = default_mount(configured.len() + ordinal, definition, devpts_gid);
            match definition.phase {
                ApplyPhase::BeforeConfigured => plan.early.push(mount),
                ApplyPhase::AfterConfigured => plan.late.push(mount),
            }
        }
        plan
    }

    pub(in crate::executor) fn apply_early(
        &self,
        rootfs: &Path,
        detached_sources: &mut DetachedMountSources,
        source_resolver: &BindSourceResolver<'_>,
    ) -> Result<()> {
        apply(&self.early, rootfs, detached_sources, source_resolver)
    }

    pub(in crate::executor) fn apply_late(
        &self,
        rootfs: &Path,
        detached_sources: &mut DetachedMountSources,
        source_resolver: &BindSourceResolver<'_>,
    ) -> Result<()> {
        apply(&self.late, rootfs, detached_sources, source_resolver)
    }

    #[cfg(test)]
    pub(in crate::executor) fn early_destinations(&self) -> Vec<&Path> {
        self.early
            .iter()
            .map(|mount| mount.destination.as_path())
            .collect()
    }

    #[cfg(test)]
    pub(in crate::executor) fn late_destinations(&self) -> Vec<&Path> {
        self.late
            .iter()
            .map(|mount| mount.destination.as_path())
            .collect()
    }

    #[cfg(test)]
    pub(in crate::executor) fn is_empty(&self) -> bool {
        self.early.is_empty() && self.late.is_empty()
    }

    #[cfg(test)]
    pub(in crate::executor) fn data_for(&self, destination: &Path) -> Option<&[String]> {
        self.early
            .iter()
            .chain(&self.late)
            .find(|mount| mount.destination == destination)
            .map(|mount| mount.data.as_slice())
    }
}

fn default_mount(index: usize, definition: &Definition, devpts_gid: u32) -> MountPlan {
    let mut data = definition
        .data
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if definition.destination == "/dev/pts" {
        data.push(format!("gid={devpts_gid}"));
    }
    MountPlan {
        index,
        destination: PathBuf::from(definition.destination),
        source: Some(PathBuf::from(definition.source)),
        filesystem_type: Some(definition.filesystem_type.to_string()),
        flags: definition.flags,
        bind: false,
        remount_bind: false,
        detached_bind: false,
        propagation: None,
        recursive_attributes: None,
        idmap: None,
        data,
        oci_cgroup_source: false,
        oci_cgroup_destination: false,
        oci_readonly_option: false,
    }
}

fn apply(
    mounts: &[MountPlan],
    rootfs: &Path,
    detached_sources: &mut DetachedMountSources,
    source_resolver: &BindSourceResolver<'_>,
) -> Result<()> {
    for mount in mounts {
        mount.apply(rootfs, detached_sources, source_resolver)?;
    }
    Ok(())
}
