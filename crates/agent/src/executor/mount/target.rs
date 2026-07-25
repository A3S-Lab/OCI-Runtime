use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::Result;

use super::{internal, invalid, permission_denied, resolve_bind_source_path, MountPlan};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MountTargetKind {
    Directory,
    File,
}

pub(super) fn prepare(plan: &MountPlan, bundle_directory: &Path, rootfs: &Path) -> Result<PathBuf> {
    let kind = if plan.bind {
        let source = plan.source.as_deref().ok_or_else(|| {
            invalid(format!(
                "mounts[{}].source is required for bind and rbind mounts",
                plan.index
            ))
        })?;
        let source = resolve_bind_source_path(plan.index, bundle_directory, source)?;
        if source.is_dir() {
            MountTargetKind::Directory
        } else {
            MountTargetKind::File
        }
    } else {
        MountTargetKind::Directory
    };
    ensure(plan.index, rootfs, &plan.destination, kind)
}

fn ensure(
    index: usize,
    rootfs: &Path,
    destination: &Path,
    kind: MountTargetKind,
) -> Result<PathBuf> {
    let relative = destination
        .strip_prefix("/")
        .map_err(|error| internal(format!("invalid normalized mount destination: {error}")))?;
    let canonical_rootfs = rootfs.canonicalize().map_err(|error| {
        invalid(format!(
            "failed to resolve the container rootfs while preparing mounts[{index}]: {error}"
        ))
    })?;
    let target = canonical_rootfs.join(relative);
    match fs::symlink_metadata(&target) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {
            verify_creation_parent(index, &canonical_rootfs, &target)?;
            match kind {
                MountTargetKind::Directory => fs::create_dir_all(&target).map_err(|error| {
                    invalid(format!(
                        "failed to create mounts[{index}].destination directory: {error}"
                    ))
                })?,
                MountTargetKind::File => create_file_target(index, &target)?,
            }
        }
        Err(error) => {
            return Err(invalid(format!(
                "failed to inspect mounts[{index}].destination: {error}"
            )));
        }
    }
    let target = target.canonicalize().map_err(|error| {
        invalid(format!(
            "failed to resolve mounts[{index}].destination after target creation: {error}"
        ))
    })?;
    if target == canonical_rootfs || !target.starts_with(&canonical_rootfs) {
        return Err(permission_denied(format!(
            "mounts[{index}].destination escapes the container rootfs"
        )));
    }
    let metadata = fs::metadata(&target).map_err(|error| {
        invalid(format!(
            "failed to inspect mounts[{index}].destination after target creation: {error}"
        ))
    })?;
    if matches!(kind, MountTargetKind::Directory) && !metadata.is_dir() {
        return Err(invalid(format!(
            "mounts[{index}].destination must be a directory for this mount"
        )));
    }
    if matches!(kind, MountTargetKind::File) && metadata.is_dir() {
        return Err(invalid(format!(
            "mounts[{index}].destination must not be a directory for a non-directory bind source"
        )));
    }
    Ok(target)
}

fn create_file_target(index: usize, target: &Path) -> Result<()> {
    let parent = target.parent().ok_or_else(|| {
        internal(format!(
            "mounts[{index}].destination does not have a parent directory"
        ))
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        invalid(format!(
            "failed to create mounts[{index}].destination parent: {error}"
        ))
    })?;
    match OpenOptions::new().write(true).create_new(true).open(target) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(invalid(format!(
            "failed to create mounts[{index}].destination file: {error}"
        ))),
    }
}

fn verify_creation_parent(index: usize, rootfs: &Path, target: &Path) -> Result<()> {
    let mut ancestor = target.parent().ok_or_else(|| {
        internal(format!(
            "mounts[{index}].destination does not have a parent directory"
        ))
    })?;
    loop {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => {
                let resolved = ancestor.canonicalize().map_err(|error| {
                    invalid(format!(
                        "failed to resolve mounts[{index}].destination parent: {error}"
                    ))
                })?;
                if resolved != rootfs && !resolved.starts_with(rootfs) {
                    return Err(permission_denied(format!(
                        "mounts[{index}].destination creation escapes the container rootfs"
                    )));
                }
                if !resolved.is_dir() {
                    return Err(invalid(format!(
                        "mounts[{index}].destination parent is not a directory"
                    )));
                }
                return Ok(());
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                ancestor = ancestor.parent().ok_or_else(|| {
                    internal(format!(
                        "failed to find an existing parent for mounts[{index}].destination"
                    ))
                })?;
            }
            Err(error) => {
                return Err(invalid(format!(
                    "failed to inspect mounts[{index}].destination parent: {error}"
                )));
            }
        }
    }
}
