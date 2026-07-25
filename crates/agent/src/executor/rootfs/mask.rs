use std::cell::Cell;
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{ErrorCode, Result};

use super::{last_os_error, mount_raw, remount_readonly, rootfs_error, verify_readonly};

const MASK_DIRECTORY_DATA: &[u8] = b"nr_blocks=1,nr_inodes=2,mode=000\0";
const MASK_SOURCE_DATA: &[u8] = b"size=4k,nr_inodes=2,mode=0700\0";
const MASK_SOURCE_FILE: &str = "source";
const MASK_SOURCE_PREFIX: &str = ".a3s-oci-mask-source-";

pub(super) struct MaskSource {
    file: File,
    mount_directory: PathBuf,
    source_path: PathBuf,
    cleaned: Cell<bool>,
}

impl MaskSource {
    pub(super) fn open(rootfs: &Path) -> Result<Self> {
        // SAFETY: `getpid` has no preconditions.
        let process_id = unsafe { libc::getpid() };
        if process_id <= 0 {
            return Err(rootfs_error(
                ErrorCode::Internal,
                "failed to obtain a positive init PID for the masked-file source",
            ));
        }
        let mount_directory = rootfs.join(format!("{MASK_SOURCE_PREFIX}{process_id}"));
        fs::create_dir(&mount_directory).map_err(|error| {
            rootfs_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to create private masked-file mount {}: {error}",
                    mount_directory.display()
                ),
            )
        })?;
        if let Err(error) = mount_raw(
            Some(Path::new("tmpfs")),
            &mount_directory,
            Some(Path::new("tmpfs")),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            Some(MASK_SOURCE_DATA),
            "mount private masked-file source",
        ) {
            let _ = fs::remove_dir(&mount_directory);
            return Err(error);
        }
        let source_path = mount_directory.join(MASK_SOURCE_FILE);
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&source_path)
        {
            Ok(file) => file,
            Err(error) => {
                let _ = unmount_path(&mount_directory);
                let _ = fs::remove_dir(&mount_directory);
                return Err(rootfs_error(
                    ErrorCode::Internal,
                    format!("failed to create the private masked-file source: {error}"),
                ));
            }
        };
        let source = Self {
            file,
            mount_directory,
            source_path,
            cleaned: Cell::new(false),
        };
        if let Err(error) = verify_mask_source(&source.file) {
            return match source.cleanup() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(rootfs_error(
                    error.code,
                    format!("{error}; masked-file source cleanup also failed: {cleanup}"),
                )),
            };
        }
        Ok(source)
    }

    fn cleanup(&self) -> Result<()> {
        if self.cleaned.get() {
            return Ok(());
        }
        let mut failures = Vec::new();
        if let Err(error) = fs::remove_file(&self.source_path) {
            if error.kind() != ErrorKind::NotFound {
                failures.push(format!("unlink {}: {error}", self.source_path.display()));
            }
        }
        if let Err(error) = unmount_path(&self.mount_directory) {
            failures.push(format!(
                "detach {}: {error}",
                self.mount_directory.display()
            ));
        }
        if let Err(error) = fs::remove_dir(&self.mount_directory) {
            if error.kind() != ErrorKind::NotFound {
                failures.push(format!(
                    "remove {}: {error}",
                    self.mount_directory.display()
                ));
            }
        }
        if failures.is_empty() {
            self.cleaned.set(true);
            Ok(())
        } else {
            Err(rootfs_error(
                ErrorCode::Internal,
                format!(
                    "private masked-file source cleanup failed: {}",
                    failures.join("; ")
                ),
            ))
        }
    }
}

impl Drop for MaskSource {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub(super) fn apply(paths: &[PathBuf], source: &MaskSource) -> Result<()> {
    let mask_result = paths.iter().try_for_each(|path| mask_path(path, source));
    let cleanup_result = source.cleanup();
    match (mask_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(rootfs_error(
            error.code,
            format!("{error}; masked-file source cleanup also failed: {cleanup}"),
        )),
    }
}

fn mask_path(path: &Path, source: &MaskSource) -> Result<()> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(rootfs_error(
                ErrorCode::Internal,
                format!(
                    "failed to inspect masked container path {}: {error}",
                    path.display()
                ),
            ));
        }
    };
    if metadata.is_dir() {
        mount_raw(
            Some(Path::new("tmpfs")),
            path,
            Some(Path::new("tmpfs")),
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            Some(MASK_DIRECTORY_DATA),
            "mask container directory",
        )?;
        verify_readonly(path, "masked container directory")?;
        return Ok(());
    }

    mount_raw(
        Some(&source.source_path),
        path,
        None,
        libc::MS_BIND,
        None,
        "mask container file with an empty private source",
    )?;
    remount_readonly(path, "remount masked container file read-only")?;
    verify_masked_file(path, source)
}

fn verify_mask_source(file: &File) -> Result<()> {
    let metadata = file.metadata().map_err(|error| {
        rootfs_error(
            ErrorCode::FailedPrecondition,
            format!("failed to inspect the private masked-file source: {error}"),
        )
    })?;
    if !metadata.is_file() || metadata.len() != 0 {
        return Err(rootfs_error(
            ErrorCode::FailedPrecondition,
            "the private masked-file source is not an empty regular file",
        ));
    }
    Ok(())
}

fn verify_masked_file(path: &Path, source: &MaskSource) -> Result<()> {
    let metadata = fs::metadata(path).map_err(|error| {
        rootfs_error(
            ErrorCode::Internal,
            format!(
                "failed to verify masked container file {}: {error}",
                path.display()
            ),
        )
    })?;
    let source_metadata = source.file.metadata().map_err(|error| {
        rootfs_error(
            ErrorCode::Internal,
            format!("failed to re-inspect the masked-file source: {error}"),
        )
    })?;
    if !metadata.is_file()
        || metadata.len() != 0
        || metadata.dev() != source_metadata.dev()
        || metadata.ino() != source_metadata.ino()
    {
        return Err(rootfs_error(
            ErrorCode::Internal,
            format!(
                "masked container file {} is not backed by the private empty source",
                path.display()
            ),
        ));
    }
    verify_readonly(path, "masked container file")
}

fn unmount_path(path: &Path) -> Result<()> {
    let path = super::path_cstring(path)?;
    // SAFETY: `path` is a live NUL-terminated pathname.
    if unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) } != 0 {
        Err(last_os_error("detach the private masked-file source"))
    } else {
        Ok(())
    }
}
