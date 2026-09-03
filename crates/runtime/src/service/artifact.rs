use std::path::Path;

use a3s_oci_sdk::{
    CheckpointArtifactPath, CheckpointDigest, Error, ErrorCode, Result, RuntimeArtifact,
};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt as _;
use tokio::sync::OnceCell;

static CURRENT_ARTIFACT: OnceCell<RuntimeArtifact> = OnceCell::const_new();

pub(super) async fn current() -> Result<RuntimeArtifact> {
    CURRENT_ARTIFACT.get_or_try_init(load).await.cloned()
}

/// Verify one checkpoint artifact at the Host trust boundary.
///
/// Drivers must perform the same validation before consuming an artifact, but
/// the Host cannot make an immutable reference from driver-reported evidence
/// without independently checking the file that will be retained or restored.
/// The opened handle is used for the complete read so a rename after the
/// initial path check cannot redirect the hash to a different path.
pub(super) async fn verify_checkpoint_artifact(
    artifact_path: &CheckpointArtifactPath,
    expected_digest: &CheckpointDigest,
    expected_size: u64,
    operation: &'static str,
) -> Result<()> {
    if expected_size == 0 {
        return Err(Error::new(
            ErrorCode::FailedPrecondition,
            "checkpoint artifact size must be greater than zero",
        )
        .for_operation(operation));
    }

    let path = artifact_path.as_path();
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        checkpoint_artifact_io_error("inspect checkpoint artifact", path, operation, error)
    })?;
    if !is_plain_file(&metadata) {
        return Err(checkpoint_artifact_contract_error(
            operation,
            format!(
                "checkpoint artifact is not a regular nonsymlink file: {}",
                path.display()
            ),
        ));
    }

    let mut file = open_readonly_nofollow(path).await.map_err(|error| {
        checkpoint_artifact_io_error("open checkpoint artifact", path, operation, error)
    })?;
    let opened = file.metadata().await.map_err(|error| {
        checkpoint_artifact_io_error("inspect opened checkpoint artifact", path, operation, error)
    })?;
    if !is_plain_file(&opened) {
        return Err(checkpoint_artifact_contract_error(
            operation,
            format!(
                "opened checkpoint artifact is not a regular nonsymlink file: {}",
                path.display()
            ),
        ));
    }
    if !same_file_identity(&metadata, &opened) {
        return Err(checkpoint_artifact_contract_error(
            operation,
            format!(
                "checkpoint artifact was replaced while it was being opened: {}",
                path.display()
            ),
        ));
    }
    if opened.len() != expected_size {
        return Err(checkpoint_artifact_contract_error(
            operation,
            format!(
                "checkpoint artifact size {} differs from expected size {}",
                opened.len(),
                expected_size
            ),
        ));
    }

    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await.map_err(|error| {
            checkpoint_artifact_io_error("read checkpoint artifact", path, operation, error)
        })?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|error| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    format!("checkpoint artifact read size does not fit u64: {error}"),
                )
                .for_operation(operation)
            })?)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "checkpoint artifact read size overflowed u64",
                )
                .for_operation(operation)
            })?;
        if total > expected_size {
            return Err(checkpoint_artifact_contract_error(
                operation,
                format!("checkpoint artifact grew beyond expected size {expected_size}"),
            ));
        }
        hasher.update(&buffer[..read]);
    }

    let final_metadata = file.metadata().await.map_err(|error| {
        checkpoint_artifact_io_error(
            "inspect checkpoint artifact after hashing",
            path,
            operation,
            error,
        )
    })?;
    if !is_plain_file(&final_metadata) || final_metadata.len() != expected_size {
        return Err(checkpoint_artifact_contract_error(
            operation,
            "checkpoint artifact changed size or file type while it was hashed".to_string(),
        ));
    }
    if total != expected_size {
        return Err(checkpoint_artifact_contract_error(
            operation,
            format!("checkpoint artifact contained {total} bytes, expected {expected_size}"),
        ));
    }

    let actual_digest =
        CheckpointDigest::new(format!("sha256:{:x}", hasher.finalize())).map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!(
                    "failed to construct checkpoint artifact digest: {}",
                    error.message
                ),
            )
            .for_operation(operation)
        })?;
    if &actual_digest != expected_digest {
        return Err(checkpoint_artifact_contract_error(
            operation,
            format!(
                "checkpoint artifact digest {} differs from expected {}",
                actual_digest, expected_digest
            ),
        ));
    }
    Ok(())
}

async fn open_readonly_nofollow(path: &Path) -> std::io::Result<tokio::fs::File> {
    #[cfg(unix)]
    {
        let mut options = tokio::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        options.open(path).await
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        let mut options = tokio::fs::OpenOptions::new();
        options
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        options.open(path).await
    }

    #[cfg(not(any(unix, windows)))]
    {
        tokio::fs::File::open(path).await
    }
}

fn is_plain_file(metadata: &std::fs::Metadata) -> bool {
    metadata.is_file() && !metadata.file_type().is_symlink() && !is_reparse_point(metadata)
}

fn same_file_identity(_left: &std::fs::Metadata, _right: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        _left.dev() == _right.dev() && _left.ino() == _right.ino()
    }

    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn checkpoint_artifact_contract_error(operation: &'static str, message: String) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message).for_operation(operation)
}

fn checkpoint_artifact_io_error(
    action: &str,
    path: &Path,
    operation: &'static str,
    error: std::io::Error,
) -> Error {
    let code = match error.kind() {
        std::io::ErrorKind::NotFound => ErrorCode::NotFound,
        std::io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        std::io::ErrorKind::AlreadyExists => ErrorCode::AlreadyExists,
        _ => ErrorCode::Unavailable,
    };
    Error::new(
        code,
        format!("failed to {action} {}: {error}", path.display()),
    )
    .for_operation(operation)
    .retryable(matches!(
        error.kind(),
        std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
    ))
}

async fn load() -> Result<RuntimeArtifact> {
    let executable = std::env::current_exe().map_err(|error| {
        artifact_error(format!(
            "failed to resolve the current runtime executable: {error}"
        ))
    })?;
    let digest = digest_file(&executable).await?;
    RuntimeArtifact::new(
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        digest,
        option_env!("A3S_OCI_GIT_REVISION").map(str::to_string),
    )
    .map_err(|error| {
        artifact_error(format!(
            "current runtime executable identity is invalid: {}",
            error.message
        ))
    })
}

async fn digest_file(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path).await.map_err(|error| {
        artifact_error(format!(
            "failed to open current runtime executable {}: {error}",
            path.display()
        ))
    })?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await.map_err(|error| {
            artifact_error(format!(
                "failed to read current runtime executable {}: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn artifact_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::Unavailable, message)
        .for_operation("features")
        .retryable(true)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    #[tokio::test]
    async fn catalog_identity_matches_the_exact_host_test_executable() {
        let artifact = super::current().await.expect("runtime artifact identity");
        let executable = std::env::current_exe().expect("current test executable");
        let bytes = tokio::fs::read(executable)
            .await
            .expect("read current test executable");

        assert_eq!(artifact.name(), env!("CARGO_PKG_NAME"));
        assert_eq!(artifact.version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(
            artifact.digest(),
            format!("sha256:{:x}", Sha256::digest(bytes))
        );
    }
}
