use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use a3s_oci_sdk::OciBundle;
use tokio::io::AsyncReadExt;

pub(super) const MARKER_NAME: &str = ".a3s-oci-native-smoke";
pub(super) const MARKER_CONTENTS: &[u8] = b"a3s-oci-native-v1\n";
const MAX_MARKER_BYTES: u64 = 1_024;

pub(super) async fn canonical_directory(path: &Path, description: &str) -> Result<PathBuf, String> {
    let canonical = tokio::fs::canonicalize(path).await.map_err(|error| {
        format!(
            "failed to resolve {description} {}: {error}",
            path.display()
        )
    })?;
    let metadata = tokio::fs::symlink_metadata(&canonical)
        .await
        .map_err(|error| {
            format!(
                "failed to inspect {description} {}: {error}",
                canonical.display()
            )
        })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{description} must be a real directory: {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

pub(super) async fn fixed_rootfs(bundle: &OciBundle) -> Result<PathBuf, String> {
    let root = bundle
        .spec()
        .root()
        .as_ref()
        .ok_or_else(|| "native smoke bundle has no root filesystem".to_string())?;
    if root.path() != Path::new("rootfs") || root.readonly().unwrap_or(false) {
        return Err(
            "native smoke bundle must use writable normalized relative root.path `rootfs`".into(),
        );
    }
    let rootfs =
        canonical_directory(&bundle.directory().join(root.path()), "container rootfs").await?;
    if rootfs == bundle.directory() || !rootfs.starts_with(bundle.directory()) {
        return Err(format!(
            "container rootfs escapes native smoke bundle {}: {}",
            bundle.directory().display(),
            rootfs.display()
        ));
    }
    Ok(rootfs)
}

pub(super) async fn create_private_directory(path: &Path) -> Result<(), String> {
    let mut builder = tokio::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).await.map_err(|error| {
        format!(
            "failed to create private native smoke directory {}: {error}",
            path.display()
        )
    })
}

pub(super) async fn path_exists(path: &Path) -> Result<bool, String> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("failed to inspect {}: {error}", path.display())),
    }
}

pub(super) async fn read_marker(path: &Path) -> Result<Vec<u8>, String> {
    let file = tokio::fs::File::open(path).await.map_err(|error| {
        format!(
            "failed to open native smoke marker {}: {error}",
            path.display()
        )
    })?;
    let metadata = file.metadata().await.map_err(|error| {
        format!(
            "failed to inspect native smoke marker {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_file() || metadata.len() > MAX_MARKER_BYTES {
        return Err(format!(
            "native smoke marker must be a regular file no larger than {MAX_MARKER_BYTES} bytes"
        ));
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_MARKER_BYTES + 1)
        .read_to_end(&mut contents)
        .await
        .map_err(|error| {
            format!(
                "failed to read native smoke marker {}: {error}",
                path.display()
            )
        })?;
    if contents.len() as u64 > MAX_MARKER_BYTES {
        return Err("native smoke marker exceeded its bounded size while reading".into());
    }
    Ok(contents)
}

pub(super) async fn remove_marker(path: &Path) -> Result<(), String> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to remove native smoke marker {}: {error}",
            path.display()
        )),
    }
}

pub(super) fn unique_nonce() -> Result<String, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before the Unix epoch: {error}"))?
        .as_nanos();
    Ok(format!("{}-{nanos}", std::process::id()))
}
