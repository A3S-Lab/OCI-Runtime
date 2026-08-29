use std::fs::OpenOptions;
use std::mem::zeroed;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use a3s_oci_sdk::{Error, ErrorCode, Result};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE,
};

const MAX_BOOTSTRAP_LOG_BYTES: u64 = 64 * 1024;
const BOOTSTRAP_MOUNT_POINTS: &[&str] = &["dev", "newroot", "proc", "sys"];
const BOOTSTRAP_LOGS: &[&str] = &[
    "guest-init.stderr.log",
    "guest-init.stdout.log",
    "init-rust.log",
    "init.krun.log",
    "init.trace.log",
];

/// Validate the bounded host-visible state left by the Windows init bootstrap.
///
/// A new root may be empty. After the driver creates `dev` or a VM exits, the
/// root may contain only the fixed empty mount points and bounded plain-text
/// logs below. None of these paths is executed or accepted as caller state.
pub(crate) async fn validate_whpx_bootstrap_root(path: &Path) -> Result<()> {
    let mut entries = tokio::fs::read_dir(path).await.map_err(|error| {
        bootstrap_error(format!(
            "failed to inspect WHPX bootstrap root {}: {error}",
            path.display()
        ))
    })?;

    while let Some(entry) = entries.next_entry().await.map_err(|error| {
        bootstrap_error(format!(
            "failed to enumerate WHPX bootstrap root {}: {error}",
            path.display()
        ))
    })? {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(bootstrap_error(format!(
                "WHPX bootstrap root contains a non-Unicode entry: {}",
                entry.path().display()
            )));
        };
        let entry_path = entry.path();
        let metadata = tokio::fs::symlink_metadata(&entry_path)
            .await
            .map_err(|error| {
                bootstrap_error(format!(
                    "failed to inspect WHPX bootstrap entry {}: {error}",
                    entry_path.display()
                ))
            })?;

        if BOOTSTRAP_MOUNT_POINTS.contains(&name) {
            validate_empty_mount_point(&entry_path, &metadata).await?;
        } else if BOOTSTRAP_LOGS.contains(&name) {
            validate_bootstrap_log(&entry_path)?;
        } else {
            return Err(bootstrap_error(format!(
                "WHPX bootstrap root contains an unexpected entry: {}",
                entry_path.display()
            )));
        }
    }

    Ok(())
}

async fn validate_empty_mount_point(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(bootstrap_error(format!(
            "WHPX bootstrap mount point is not a plain directory: {}",
            path.display()
        )));
    }

    let mut entries = tokio::fs::read_dir(path).await.map_err(|error| {
        bootstrap_error(format!(
            "failed to inspect WHPX bootstrap mount point {}: {error}",
            path.display()
        ))
    })?;
    if entries
        .next_entry()
        .await
        .map_err(|error| {
            bootstrap_error(format!(
                "failed to enumerate WHPX bootstrap mount point {}: {error}",
                path.display()
            ))
        })?
        .is_some()
    {
        return Err(bootstrap_error(format!(
            "WHPX bootstrap mount point must be empty before VM launch: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_bootstrap_log(path: &Path) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            bootstrap_error(format!(
                "failed to open WHPX bootstrap log {}: {error}",
                path.display()
            ))
        })?;
    // SAFETY: `file` retains a live handle and `information` is writable for
    // the fixed-size structure populated by GetFileInformationByHandle.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(bootstrap_error(format!(
            "failed to inspect WHPX bootstrap log handle {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    if information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || information.nNumberOfLinks != 1
    {
        return Err(bootstrap_error(format!(
            "WHPX bootstrap log is not a plain file: {}",
            path.display()
        )));
    }
    let length = (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow);
    if length > MAX_BOOTSTRAP_LOG_BYTES {
        return Err(bootstrap_error(format!(
            "WHPX bootstrap log exceeds {MAX_BOOTSTRAP_LOG_BYTES} bytes: {} has {} bytes",
            path.display(),
            length
        )));
    }
    Ok(())
}

fn bootstrap_error(message: String) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message).for_operation("open-whpx-driver-candidate")
}

#[cfg(test)]
mod tests {
    use super::{
        validate_whpx_bootstrap_root, BOOTSTRAP_LOGS, BOOTSTRAP_MOUNT_POINTS,
        MAX_BOOTSTRAP_LOG_BYTES,
    };

    #[tokio::test]
    async fn accepts_empty_and_exact_post_boot_layouts() {
        let temporary = tempfile::tempdir().expect("temporary bootstrap root");
        validate_whpx_bootstrap_root(temporary.path())
            .await
            .expect("empty bootstrap root");

        for directory in BOOTSTRAP_MOUNT_POINTS {
            std::fs::create_dir(temporary.path().join(directory)).expect("bootstrap mount point");
        }
        for log in BOOTSTRAP_LOGS {
            std::fs::write(temporary.path().join(log), b"bounded init evidence")
                .expect("bootstrap log");
        }

        validate_whpx_bootstrap_root(temporary.path())
            .await
            .expect("exact post-boot layout");
    }

    #[tokio::test]
    async fn rejects_unknown_bootstrap_entries() {
        let temporary = tempfile::tempdir().expect("temporary bootstrap root");
        std::fs::write(temporary.path().join("unowned"), b"caller data").expect("unknown entry");

        let error = validate_whpx_bootstrap_root(temporary.path())
            .await
            .expect_err("unknown entry must fail");

        assert!(error.message.contains("unexpected entry"));
    }

    #[tokio::test]
    async fn rejects_nonempty_bootstrap_mount_points() {
        let temporary = tempfile::tempdir().expect("temporary bootstrap root");
        let dev = temporary.path().join("dev");
        std::fs::create_dir(&dev).expect("dev mount point");
        std::fs::write(dev.join("unexpected"), b"device").expect("mount point entry");

        let error = validate_whpx_bootstrap_root(temporary.path())
            .await
            .expect_err("nonempty mount point must fail");

        assert!(error.message.contains("must be empty"));
    }

    #[tokio::test]
    async fn rejects_oversized_bootstrap_logs() {
        let temporary = tempfile::tempdir().expect("temporary bootstrap root");
        let log = temporary.path().join("init.krun.log");
        let file = std::fs::File::create(&log).expect("bootstrap log");
        file.set_len(MAX_BOOTSTRAP_LOG_BYTES + 1)
            .expect("oversized bootstrap log");

        let error = validate_whpx_bootstrap_root(temporary.path())
            .await
            .expect_err("oversized log must fail");

        assert!(error.message.contains("exceeds"));
    }

    #[tokio::test]
    async fn rejects_hard_linked_bootstrap_logs() {
        let temporary = tempfile::tempdir().expect("temporary bootstrap root");
        let external_directory = tempfile::tempdir().expect("external temporary root");
        let external = external_directory.path().join("external.log");
        std::fs::write(&external, b"external data").expect("external fixture");
        std::fs::hard_link(&external, temporary.path().join("init.krun.log"))
            .expect("hard-linked bootstrap log");

        let error = validate_whpx_bootstrap_root(temporary.path())
            .await
            .expect_err("hard-linked log must fail");

        assert!(error.message.contains("not a plain file"));
    }
}
