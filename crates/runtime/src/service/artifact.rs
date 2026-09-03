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
    // Reject an obviously invalid path early so callers receive a stable
    // contract error.  The metadata is also compared with the opened handle
    // below, but it is never used for reading artifact contents.
    let path_metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        checkpoint_artifact_io_error("inspect checkpoint artifact", path, operation, error)
    })?;
    if !is_plain_file(&path_metadata) {
        return Err(checkpoint_artifact_contract_error(
            operation,
            format!(
                "checkpoint artifact is not a regular nonsymlink file: {}",
                path.display()
            ),
        ));
    }

    // Windows metadata does not expose a stable file identity through the
    // stable Rust API.  Capture one from a no-follow handle before opening
    // the handle that will be consumed, so a delete/recreate between the two
    // opens is detected without relying on path metadata alone.
    #[cfg(windows)]
    let path_identity = {
        let identity_file = open_readonly_nofollow(path).await.map_err(|error| {
            checkpoint_artifact_io_error(
                "open checkpoint artifact for identity",
                path,
                operation,
                error,
            )
        })?;
        let identity_metadata = identity_file.metadata().await.map_err(|error| {
            checkpoint_artifact_io_error(
                "inspect checkpoint artifact identity handle",
                path,
                operation,
                error,
            )
        })?;
        if !is_plain_file(&identity_metadata) {
            return Err(checkpoint_artifact_contract_error(
                operation,
                format!(
                    "checkpoint artifact identity handle is not a regular nonsymlink file: {}",
                    path.display()
                ),
            ));
        }
        file_identity(&identity_file, path, operation)?
    };

    // Validate the handle that will actually be consumed.  A path-based
    // metadata check can become stale between inspection and open (including
    // a delete/recreate or reparse-point substitution).  The platform
    // no-follow flags make the opened object the trust anchor; all subsequent
    // metadata and hashing operations stay on that handle.
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
    #[cfg(unix)]
    if !same_file_identity(&path_metadata, &opened) {
        return Err(checkpoint_artifact_contract_error(
            operation,
            format!(
                "checkpoint artifact was replaced while it was being opened: {}",
                path.display()
            ),
        ));
    }
    #[cfg(windows)]
    if file_identity(&file, path, operation)? != path_identity {
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
                "checkpoint artifact digest {actual_digest} differs from expected {expected_digest}"
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

#[cfg(unix)]
fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    volume_serial_number: u32,
    file_index: u64,
}

#[cfg(windows)]
fn file_identity(
    file: &tokio::fs::File,
    path: &Path,
    operation: &'static str,
) -> Result<FileIdentity> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: the file owns a valid handle for the duration of the call and
    // the output pointer refers to writable storage of the exact structure.
    let succeeded =
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) };
    if succeeded == 0 {
        return Err(Error::new(
            ErrorCode::Unavailable,
            format!(
                "failed to obtain checkpoint artifact identity {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ),
        )
        .for_operation(operation)
        .retryable(true));
    }
    // SAFETY: GetFileInformationByHandle returned success and initialized the
    // complete BY_HANDLE_FILE_INFORMATION structure.
    let information = unsafe { information.assume_init() };
    Ok(FileIdentity {
        volume_serial_number: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
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
    use std::path::PathBuf;

    use a3s_oci_sdk::{CheckpointArtifactPath, CheckpointDigest, ErrorCode};
    use sha2::{Digest, Sha256};

    fn artifact_path(path: PathBuf) -> CheckpointArtifactPath {
        CheckpointArtifactPath::new(path).expect("valid checkpoint artifact path")
    }

    fn digest(bytes: &[u8]) -> CheckpointDigest {
        CheckpointDigest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
            .expect("valid checkpoint digest")
    }

    #[tokio::test]
    async fn verifier_accepts_the_exact_regular_file_contents() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("checkpoint.bin");
        let bytes = b"checkpoint payload";
        tokio::fs::write(&path, bytes)
            .await
            .expect("write checkpoint artifact");

        super::verify_checkpoint_artifact(
            &artifact_path(path),
            &digest(bytes),
            bytes.len() as u64,
            "test",
        )
        .await
        .expect("regular artifact must verify");
    }

    #[tokio::test]
    async fn verifier_rejects_size_and_digest_mismatches_without_retry() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("checkpoint.bin");
        let bytes = b"checkpoint payload";
        tokio::fs::write(&path, bytes)
            .await
            .expect("write checkpoint artifact");
        let wrapped = artifact_path(path);

        let size_error = super::verify_checkpoint_artifact(
            &wrapped,
            &digest(bytes),
            bytes.len() as u64 + 1,
            "test",
        )
        .await
        .expect_err("wrong artifact size must fail");
        assert_eq!(size_error.code, ErrorCode::FailedPrecondition);
        assert!(!size_error.retryable);

        let digest_error = super::verify_checkpoint_artifact(
            &wrapped,
            &digest(b"different payload"),
            bytes.len() as u64,
            "test",
        )
        .await
        .expect_err("wrong artifact digest must fail");
        assert_eq!(digest_error.code, ErrorCode::FailedPrecondition);
        assert!(!digest_error.retryable);
    }

    #[tokio::test]
    async fn verifier_rejects_empty_and_directory_artifacts() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let empty = temporary.path().join("empty.bin");
        tokio::fs::write(&empty, [])
            .await
            .expect("write empty artifact");
        let empty_error =
            super::verify_checkpoint_artifact(&artifact_path(empty), &digest(&[]), 0, "test")
                .await
                .expect_err("empty artifact must fail");
        assert_eq!(empty_error.code, ErrorCode::FailedPrecondition);

        let directory = temporary.path().join("directory");
        tokio::fs::create_dir(&directory)
            .await
            .expect("create artifact directory");
        let directory_error = super::verify_checkpoint_artifact(
            &artifact_path(directory),
            &digest(b"directory"),
            9,
            "test",
        )
        .await
        .expect_err("directory artifact must fail");
        assert_eq!(directory_error.code, ErrorCode::FailedPrecondition);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn verifier_rejects_a_symlink_artifact() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let target = temporary.path().join("target.bin");
        let link = temporary.path().join("link.bin");
        let bytes = b"checkpoint payload";
        tokio::fs::write(&target, bytes)
            .await
            .expect("write target artifact");
        symlink(&target, &link).expect("create artifact symlink");

        let error = super::verify_checkpoint_artifact(
            &artifact_path(link),
            &digest(bytes),
            bytes.len() as u64,
            "test",
        )
        .await
        .expect_err("symlink artifact must fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_file_identity_distinguishes_distinct_open_files() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let first_path = temporary.path().join("first.bin");
        let second_path = temporary.path().join("second.bin");
        tokio::fs::write(&first_path, b"first")
            .await
            .expect("write first artifact");
        tokio::fs::write(&second_path, b"second")
            .await
            .expect("write second artifact");
        let first = tokio::fs::File::open(&first_path)
            .await
            .expect("open first artifact");
        let second = tokio::fs::File::open(&second_path)
            .await
            .expect("open second artifact");

        assert_ne!(
            super::file_identity(&first, &first_path, "test").expect("first identity"),
            super::file_identity(&second, &second_path, "test").expect("second identity")
        );
    }

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
