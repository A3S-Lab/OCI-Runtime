use std::path::{Path, PathBuf};

use a3s_oci_sdk::{CheckpointArtifactPath, CheckpointReference, Error, ErrorCode, Result};
use containerd_shim_protos::protobuf::well_known_types::any::Any;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PACKAGE_SCHEMA_V1: &str = "a3s.oci.containerd-checkpoint.v1";
const ARTIFACT_FILE_NAME: &str = "a3s-oci-checkpoint-v1.bin";
const MANIFEST_FILE_NAME: &str = "a3s-oci-checkpoint-v1.json";
const RUNC_CHECKPOINT_OPTIONS_NAME: &str = "containerd.runc.v1.CheckpointOptions";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_OPTIONS_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckpointDestination {
    directory: PathBuf,
    artifact_path: CheckpointArtifactPath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckpointPackage {
    artifact_path: CheckpointArtifactPath,
    reference: CheckpointReference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckpointManifest {
    schema_version: String,
    artifact: String,
    reference: CheckpointReference,
}

impl CheckpointDestination {
    pub(crate) async fn open(path: &str) -> Result<Self> {
        let directory = canonical_directory(path).await?;
        let artifact_path = CheckpointArtifactPath::new(directory.join(ARTIFACT_FILE_NAME))?;
        Ok(Self {
            directory,
            artifact_path,
        })
    }

    pub(crate) fn artifact_path(&self) -> &CheckpointArtifactPath {
        &self.artifact_path
    }

    pub(crate) async fn committed(&self) -> Result<Option<CheckpointPackage>> {
        let Some(manifest) = load_manifest(&self.directory).await? else {
            return Ok(None);
        };
        validate_artifact(&self.artifact_path, &manifest.reference).await?;
        Ok(Some(CheckpointPackage {
            artifact_path: self.artifact_path.clone(),
            reference: manifest.reference,
        }))
    }

    pub(crate) async fn commit(&self, reference: CheckpointReference) -> Result<()> {
        let manifest = CheckpointManifest {
            schema_version: PACKAGE_SCHEMA_V1.to_string(),
            artifact: ARTIFACT_FILE_NAME.to_string(),
            reference,
        };
        manifest.validate()?;
        validate_artifact(&self.artifact_path, &manifest.reference).await?;
        if let Some(existing) = load_manifest(&self.directory).await? {
            return require_same_manifest(&existing, &manifest);
        }

        let mut encoded = serde_json::to_vec_pretty(&manifest).map_err(|error| {
            package_error(
                ErrorCode::Internal,
                format!("failed to encode checkpoint package manifest: {error}"),
            )
        })?;
        encoded.push(b'\n');
        let pending = pending_path(&self.directory)?;
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let mut file = options
            .open(&pending)
            .await
            .map_err(|error| package_io("create pending checkpoint manifest", &pending, error))?;
        if let Err(error) = file.write_all(&encoded).await {
            drop(file);
            let _ = tokio::fs::remove_file(&pending).await;
            return Err(package_io(
                "write pending checkpoint manifest",
                &pending,
                error,
            ));
        }
        if let Err(error) = file.sync_all().await {
            drop(file);
            let _ = tokio::fs::remove_file(&pending).await;
            return Err(package_io(
                "sync pending checkpoint manifest",
                &pending,
                error,
            ));
        }
        drop(file);

        if let Some(existing) = load_manifest(&self.directory).await? {
            let _ = tokio::fs::remove_file(&pending).await;
            return require_same_manifest(&existing, &manifest);
        }
        let manifest_path = self.directory.join(MANIFEST_FILE_NAME);
        match tokio::fs::hard_link(&pending, &manifest_path).await {
            Ok(()) => {
                tokio::fs::remove_file(&pending).await.map_err(|error| {
                    package_io("remove linked pending checkpoint manifest", &pending, error)
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = tokio::fs::remove_file(&pending).await;
                let existing = load_manifest(&self.directory).await?.ok_or_else(|| {
                    package_error(
                        ErrorCode::Conflict,
                        "checkpoint manifest appeared during commit but could not be loaded",
                    )
                })?;
                return require_same_manifest(&existing, &manifest);
            }
            Err(error) => {
                let _ = tokio::fs::remove_file(&pending).await;
                return Err(package_io(
                    "publish checkpoint package manifest",
                    &manifest_path,
                    error,
                ));
            }
        }
        sync_directory(self.directory.clone()).await
    }
}

impl CheckpointPackage {
    pub(crate) async fn load(path: &str) -> Result<Self> {
        let destination = CheckpointDestination::open(path).await?;
        destination.committed().await?.ok_or_else(|| {
            package_error(
                ErrorCode::NotFound,
                format!(
                    "checkpoint package {} has no {MANIFEST_FILE_NAME}",
                    destination.directory.display()
                ),
            )
        })
    }

    pub(crate) fn artifact_path(&self) -> &CheckpointArtifactPath {
        &self.artifact_path
    }

    pub(crate) fn reference(&self) -> &CheckpointReference {
        &self.reference
    }
}

impl CheckpointManifest {
    fn validate(&self) -> Result<()> {
        if self.schema_version != PACKAGE_SCHEMA_V1 || self.artifact != ARTIFACT_FILE_NAME {
            return Err(package_error(
                ErrorCode::InvalidArgument,
                format!(
                    "checkpoint package must use schema {PACKAGE_SCHEMA_V1} and artifact {ARTIFACT_FILE_NAME}"
                ),
            ));
        }
        Ok(())
    }
}

pub(crate) fn validate_checkpoint_options(options: Option<&Any>, path: &str) -> Result<()> {
    let Some(options) = options else {
        return Ok(());
    };
    if options.type_url.rsplit('/').next() != Some(RUNC_CHECKPOINT_OPTIONS_NAME) {
        return Err(package_error(
            ErrorCode::Unsupported,
            format!(
                "unsupported containerd checkpoint options type {}; expected {RUNC_CHECKPOINT_OPTIONS_NAME}",
                options.type_url
            ),
        ));
    }
    if options.value.len() > MAX_OPTIONS_BYTES {
        return Err(package_error(
            ErrorCode::ResourceExhausted,
            format!("containerd checkpoint options exceed {MAX_OPTIONS_BYTES} bytes"),
        ));
    }

    let mut cursor = 0;
    let mut image_path = None;
    while cursor < options.value.len() {
        let key = read_varint(&options.value, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 0x07;
        if field == 0 {
            return Err(invalid_options("checkpoint options contain field zero"));
        }
        match field {
            1..=5 => {
                require_wire(wire, 0, field)?;
                if read_varint(&options.value, &mut cursor)? != 0 {
                    return Err(unsupported_option(field));
                }
            }
            6 => {
                require_wire(wire, 2, field)?;
                let _ = read_bytes(&options.value, &mut cursor)?;
                return Err(unsupported_option(field));
            }
            7 | 9 => {
                require_wire(wire, 2, field)?;
                if !read_bytes(&options.value, &mut cursor)?.is_empty() {
                    return Err(unsupported_option(field));
                }
            }
            8 => {
                require_wire(wire, 2, field)?;
                if image_path.is_some() {
                    return Err(invalid_options(
                        "checkpoint options repeat the image_path field",
                    ));
                }
                let value = std::str::from_utf8(read_bytes(&options.value, &mut cursor)?)
                    .map_err(|_| invalid_options("checkpoint image_path is not valid UTF-8"))?;
                image_path = Some(value);
            }
            _ => {
                return Err(package_error(
                    ErrorCode::Unsupported,
                    format!("unsupported containerd checkpoint option field {field}"),
                ));
            }
        }
    }
    if image_path.is_some_and(|image_path| image_path != path) {
        return Err(invalid_options(
            "checkpoint options image_path differs from the Task request path",
        ));
    }
    Ok(())
}

async fn canonical_directory(path: &str) -> Result<PathBuf> {
    if path.is_empty() {
        return Err(package_error(
            ErrorCode::InvalidArgument,
            "containerd checkpoint path must not be empty",
        ));
    }
    let directory = tokio::fs::canonicalize(path)
        .await
        .map_err(|error| package_io("resolve checkpoint directory", Path::new(path), error))?;
    let metadata = tokio::fs::metadata(&directory)
        .await
        .map_err(|error| package_io("inspect checkpoint directory", &directory, error))?;
    if !metadata.is_dir() {
        return Err(package_error(
            ErrorCode::InvalidArgument,
            format!("checkpoint path {} is not a directory", directory.display()),
        ));
    }
    Ok(directory)
}

async fn load_manifest(directory: &Path) -> Result<Option<CheckpointManifest>> {
    let path = directory.join(MANIFEST_FILE_NAME);
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = match options.open(&path).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(package_io("open checkpoint manifest", &path, error)),
    };
    let metadata = file
        .metadata()
        .await
        .map_err(|error| package_io("inspect checkpoint manifest", &path, error))?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(package_error(
            ErrorCode::FailedPrecondition,
            format!(
                "checkpoint manifest {} must be a regular file of at most {MAX_MANIFEST_BYTES} bytes",
                path.display()
            ),
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| package_io("read checkpoint manifest", &path, error))?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(package_error(
            ErrorCode::FailedPrecondition,
            format!(
                "checkpoint manifest {} exceeds its size limit",
                path.display()
            ),
        ));
    }
    let manifest: CheckpointManifest = serde_json::from_slice(&bytes).map_err(|error| {
        package_error(
            ErrorCode::InvalidArgument,
            format!(
                "failed to decode checkpoint manifest {}: {error}",
                path.display()
            ),
        )
    })?;
    manifest.validate()?;
    Ok(Some(manifest))
}

async fn validate_artifact(
    artifact_path: &CheckpointArtifactPath,
    reference: &CheckpointReference,
) -> Result<()> {
    let path = artifact_path.as_path();
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .await
        .map_err(|error| package_io("open checkpoint artifact", path, error))?;
    let metadata = file
        .metadata()
        .await
        .map_err(|error| package_io("inspect checkpoint artifact", path, error))?;
    if !metadata.is_file() || metadata.len() != reference.artifact_size_bytes() {
        return Err(package_error(
            ErrorCode::FailedPrecondition,
            format!(
                "checkpoint artifact {} size differs from its immutable reference",
                path.display()
            ),
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|error| package_io("read checkpoint artifact", path, error))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let actual = format!("sha256:{:x}", digest.finalize());
    if actual != reference.artifact_digest().as_str() {
        return Err(package_error(
            ErrorCode::FailedPrecondition,
            format!(
                "checkpoint artifact {} digest differs from its immutable reference",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn require_same_manifest(
    existing: &CheckpointManifest,
    expected: &CheckpointManifest,
) -> Result<()> {
    if existing == expected {
        Ok(())
    } else {
        Err(package_error(
            ErrorCode::AlreadyExists,
            "checkpoint directory already contains a different A3S checkpoint package",
        ))
    }
}

fn pending_path(directory: &Path) -> Result<PathBuf> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|error| {
        package_error(
            ErrorCode::Unavailable,
            format!("failed to generate checkpoint manifest nonce: {error}"),
        )
    })?;
    Ok(directory.join(format!(
        ".{MANIFEST_FILE_NAME}.{}.pending",
        nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )))
}

async fn sync_directory(directory: PathBuf) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        std::fs::File::open(&directory)
            .and_then(|file| file.sync_all())
            .map_err(|error| package_io("sync checkpoint directory", &directory, error))
    })
    .await
    .map_err(|error| {
        package_error(
            ErrorCode::Internal,
            format!("checkpoint directory sync task failed: {error}"),
        )
    })?
}

fn read_varint(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes
            .get(*cursor)
            .ok_or_else(|| invalid_options("checkpoint options contain a truncated varint"))?;
        *cursor += 1;
        if shift == 63 && byte > 1 {
            return Err(invalid_options(
                "checkpoint options contain an overflowing varint",
            ));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(invalid_options(
        "checkpoint options contain an invalid varint",
    ))
}

fn read_bytes<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a [u8]> {
    let length = usize::try_from(read_varint(bytes, cursor)?).map_err(|_| {
        invalid_options("checkpoint options field length does not fit this platform")
    })?;
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| invalid_options("checkpoint options field length overflowed"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_options("checkpoint options contain a truncated field"))?;
    *cursor = end;
    Ok(value)
}

fn require_wire(actual: u64, expected: u64, field: u64) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(invalid_options(format!(
            "checkpoint option field {field} uses wire type {actual}, expected {expected}"
        )))
    }
}

fn unsupported_option(field: u64) -> Error {
    package_error(
        ErrorCode::Unsupported,
        format!("containerd checkpoint option field {field} has unsupported semantics"),
    )
}

fn invalid_options(message: impl Into<String>) -> Error {
    package_error(ErrorCode::InvalidArgument, message)
}

fn package_io(action: &str, path: &Path, error: std::io::Error) -> Error {
    let code = match error.kind() {
        std::io::ErrorKind::NotFound => ErrorCode::NotFound,
        std::io::ErrorKind::AlreadyExists => ErrorCode::AlreadyExists,
        std::io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        _ => ErrorCode::Unavailable,
    };
    package_error(
        code,
        format!("failed to {action} {}: {error}", path.display()),
    )
}

fn package_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("containerd-checkpoint-package")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(value: Vec<u8>) -> Any {
        Any {
            type_url: format!("types.containerd.io/{RUNC_CHECKPOINT_OPTIONS_NAME}"),
            value,
            ..Default::default()
        }
    }

    #[test]
    fn checkpoint_options_accept_only_neutral_runc_semantics() {
        validate_checkpoint_options(None, "/checkpoint").expect("missing options");
        validate_checkpoint_options(Some(&options(Vec::new())), "/checkpoint")
            .expect("default runc options");

        let path = b"/checkpoint";
        let mut image_path = vec![0x42, u8::try_from(path.len()).expect("path length")];
        image_path.extend_from_slice(path);
        validate_checkpoint_options(Some(&options(image_path)), "/checkpoint")
            .expect("matching image path");

        assert_eq!(
            validate_checkpoint_options(Some(&options(vec![0x08, 0x01])), "/checkpoint")
                .expect_err("exit=true is unsupported")
                .code,
            ErrorCode::Unsupported
        );
        assert_eq!(
            validate_checkpoint_options(
                Some(&options(vec![0x42, 0x05, b'o', b't'])),
                "/checkpoint"
            )
            .expect_err("truncated image path must fail")
            .code,
            ErrorCode::InvalidArgument
        );
    }
}
