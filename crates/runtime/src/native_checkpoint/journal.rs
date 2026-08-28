use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{
    canonical_json_bytes, CheckpointArtifactPath, CheckpointCompatibility, CheckpointDigest,
    ErrorCode, OperationId, Result,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::artifact::encode_token;
use super::{checkpoint_error, io_error};
use crate::DriverCheckpointResult;

mod restore;

pub(super) use restore::RestoreJournalRecord;

const STATE_DIRECTORY: &str = ".a3s-oci-native-checkpoint-v1";
const STATE_SCHEMA_V1: &str = "a3s.oci.native-checkpoint-state.v1";
const JOURNAL_SCHEMA_V1: &str = "a3s.oci.native-checkpoint-operation.v1";
const MARKER_FILE: &str = "schema.json";
const LOCK_FILE: &str = "lock";
const JOURNALS_DIRECTORY: &str = "operations";
const STAGING_DIRECTORY: &str = "staging";
const RESTORE_JOURNALS_DIRECTORY: &str = "restore-operations";
const RESTORE_STAGING_DIRECTORY: &str = "restore-staging";
const MAX_JOURNAL_BYTES: u64 = 256 * 1024;
const MAX_JOURNALS: usize = 4_096;

#[derive(Debug)]
pub(super) struct CheckpointJournalStore {
    operations: PathBuf,
    staging: PathBuf,
    restore_operations: PathBuf,
    restore_staging: PathBuf,
    _lock: File,
}

#[derive(Debug)]
pub(super) struct StageDirectory {
    images: PathBuf,
    work: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct JournalRecord {
    schema_version: String,
    operation_id: OperationId,
    request_digest: CheckpointDigest,
    artifact_path: CheckpointArtifactPath,
    pending_name: String,
    publication_token: String,
    outcome: JournalOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum JournalOutcome {
    Allocated,
    Prepared { result: JournalResult },
    Published { result: JournalResult },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct JournalResult {
    compatibility: CheckpointCompatibility,
    artifact_digest: CheckpointDigest,
    artifact_size_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateMarker {
    schema_version: String,
}

impl CheckpointJournalStore {
    pub(super) async fn open(runtime_parent: impl AsRef<Path>) -> Result<Self> {
        let runtime_parent = runtime_parent.as_ref().to_path_buf();
        tokio::task::spawn_blocking(move || Self::open_blocking(&runtime_parent))
            .await
            .map_err(|error| {
                checkpoint_error(
                    ErrorCode::Internal,
                    format!("checkpoint journal open task failed: {error}"),
                )
            })?
    }

    pub(super) async fn load(&self, operation_id: &OperationId) -> Result<Option<JournalRecord>> {
        let path = self.journal_path(operation_id);
        let expected = operation_id.clone();
        tokio::task::spawn_blocking(move || load_record(&path, &expected))
            .await
            .map_err(|error| {
                checkpoint_error(
                    ErrorCode::Internal,
                    format!("checkpoint journal read task failed: {error}"),
                )
            })?
    }

    pub(super) async fn store(&self, record: &JournalRecord) -> Result<()> {
        record.validate()?;
        let operations = self.operations.clone();
        let record = record.clone();
        tokio::task::spawn_blocking(move || store_record(&operations, &record))
            .await
            .map_err(|error| {
                checkpoint_error(
                    ErrorCode::Internal,
                    format!("checkpoint journal write task failed: {error}"),
                )
            })?
    }

    pub(super) async fn remove(&self, operation_id: &OperationId) -> Result<()> {
        let path = self.journal_path(operation_id);
        let operations = self.operations.clone();
        tokio::task::spawn_blocking(move || match std::fs::remove_file(&path) {
            Ok(()) => sync_directory(&operations, "sync checkpoint operation directory"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(
                "remove checkpoint operation journal",
                &path,
                error,
            )),
        })
        .await
        .map_err(|error| {
            checkpoint_error(
                ErrorCode::Internal,
                format!("checkpoint journal removal task failed: {error}"),
            )
        })?
    }

    pub(super) async fn create_stage(&self, operation_id: &OperationId) -> Result<StageDirectory> {
        let root = self.staging.join(stage_name(operation_id));
        let staging = self.staging.clone();
        tokio::task::spawn_blocking(move || {
            cleanup_stage_blocking(&staging, &root)?;
            create_private_directory(&root)?;
            let images = root.join("images");
            let work = root.join("work");
            if let Err(error) =
                create_private_directory(&images).and_then(|()| create_private_directory(&work))
            {
                let _ = std::fs::remove_dir_all(&root);
                return Err(error);
            }
            sync_directory(&staging, "sync checkpoint staging directory")?;
            Ok(StageDirectory { images, work })
        })
        .await
        .map_err(|error| {
            checkpoint_error(
                ErrorCode::Internal,
                format!("checkpoint stage creation task failed: {error}"),
            )
        })?
    }

    pub(super) async fn cleanup_stage(&self, operation_id: &OperationId) -> Result<()> {
        let root = self.staging.join(stage_name(operation_id));
        let staging = self.staging.clone();
        tokio::task::spawn_blocking(move || cleanup_stage_blocking(&staging, &root))
            .await
            .map_err(|error| {
                checkpoint_error(
                    ErrorCode::Internal,
                    format!("checkpoint stage cleanup task failed: {error}"),
                )
            })?
    }

    fn journal_path(&self, operation_id: &OperationId) -> PathBuf {
        self.operations
            .join(format!("{}.json", operation_hash(operation_id)))
    }

    fn open_blocking(runtime_parent: &Path) -> Result<Self> {
        let runtime_parent = std::fs::canonicalize(runtime_parent).map_err(|error| {
            io_error("resolve checkpoint runtime parent", runtime_parent, error)
        })?;
        let parent_metadata = std::fs::symlink_metadata(&runtime_parent).map_err(|error| {
            io_error("inspect checkpoint runtime parent", &runtime_parent, error)
        })?;
        if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
            return Err(checkpoint_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "checkpoint runtime parent is not a real directory: {}",
                    runtime_parent.display()
                ),
            ));
        }
        let root = runtime_parent.join(STATE_DIRECTORY);
        match create_private_directory(&root) {
            Ok(()) => {}
            Err(error) if error.code == ErrorCode::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        ensure_private_directory(&root)?;

        let lock_path = root.join(LOCK_FILE);
        let mut lock_options = OpenOptions::new();
        lock_options
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let lock = lock_options
            .open(&lock_path)
            .map_err(|error| io_error("open checkpoint state lock", &lock_path, error))?;
        ensure_private_file(&lock, &lock_path)?;
        FileExt::try_lock_exclusive(&lock).map_err(|error| {
            checkpoint_error(
                ErrorCode::Conflict,
                format!(
                    "another native checkpoint backend owns {}: {error}",
                    root.display()
                ),
            )
            .retryable(true)
        })?;
        initialize_marker(&root)?;

        let operations = root.join(JOURNALS_DIRECTORY);
        let staging = root.join(STAGING_DIRECTORY);
        let restore_operations = root.join(RESTORE_JOURNALS_DIRECTORY);
        let restore_staging = root.join(RESTORE_STAGING_DIRECTORY);
        for directory in [&operations, &staging, &restore_operations, &restore_staging] {
            match create_private_directory(directory) {
                Ok(()) => {}
                Err(error) if error.code == ErrorCode::AlreadyExists => {
                    ensure_private_directory(directory)?;
                }
                Err(error) => return Err(error),
            }
        }
        cleanup_all_stages(&staging)?;
        restore::reconcile_stages(&restore_operations, &restore_staging)?;
        Ok(Self {
            operations,
            staging,
            restore_operations,
            restore_staging,
            _lock: lock,
        })
    }
}

impl StageDirectory {
    pub(super) fn images(&self) -> &Path {
        &self.images
    }

    pub(super) fn work(&self) -> &Path {
        &self.work
    }

    #[cfg(test)]
    pub(super) fn root(&self) -> &Path {
        self.images
            .parent()
            .expect("checkpoint stage images always have a parent")
    }
}

impl JournalRecord {
    pub(super) fn allocated(
        operation_id: OperationId,
        request_digest: CheckpointDigest,
        artifact_path: CheckpointArtifactPath,
        publication_token: [u8; 32],
    ) -> Self {
        let pending_name = pending_name(&operation_id, &publication_token);
        Self {
            schema_version: JOURNAL_SCHEMA_V1.to_string(),
            operation_id,
            request_digest,
            artifact_path,
            pending_name,
            publication_token: encode_token(&publication_token),
            outcome: JournalOutcome::Allocated,
        }
    }

    pub(super) fn validate_request(
        &self,
        operation_id: &OperationId,
        request_digest: &CheckpointDigest,
        artifact_path: &CheckpointArtifactPath,
    ) -> Result<()> {
        self.validate()?;
        if &self.operation_id != operation_id
            || &self.request_digest != request_digest
            || &self.artifact_path != artifact_path
        {
            return Err(checkpoint_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "operation ID {operation_id} was already used for a different checkpoint request"
                ),
            ));
        }
        Ok(())
    }

    pub(super) fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub(super) fn artifact_path(&self) -> &CheckpointArtifactPath {
        &self.artifact_path
    }

    pub(super) fn pending_name(&self) -> &str {
        &self.pending_name
    }

    pub(super) fn publication_token(&self) -> Result<[u8; 32]> {
        decode_token(&self.publication_token)
    }

    pub(super) const fn outcome(&self) -> &JournalOutcome {
        &self.outcome
    }

    pub(super) fn mark_prepared(&mut self, result: JournalResult) {
        self.outcome = JournalOutcome::Prepared { result };
    }

    pub(super) fn mark_published(&mut self, result: JournalResult) {
        self.outcome = JournalOutcome::Published { result };
    }

    fn validate(&self) -> Result<()> {
        let token = decode_token(&self.publication_token)?;
        if self.schema_version != JOURNAL_SCHEMA_V1
            || self.pending_name != pending_name(&self.operation_id, &token)
        {
            return Err(checkpoint_error(
                ErrorCode::FailedPrecondition,
                "native checkpoint operation journal has invalid schema or pending identity",
            ));
        }
        match &self.outcome {
            JournalOutcome::Allocated => {}
            JournalOutcome::Prepared { result } | JournalOutcome::Published { result } => {
                result.validate()?;
            }
        }
        Ok(())
    }
}

impl JournalResult {
    pub(super) fn new(
        compatibility: CheckpointCompatibility,
        artifact_digest: CheckpointDigest,
        artifact_size_bytes: u64,
    ) -> Result<Self> {
        let result = Self {
            compatibility,
            artifact_digest,
            artifact_size_bytes,
        };
        result.validate()?;
        Ok(result)
    }

    pub(super) const fn compatibility(&self) -> &CheckpointCompatibility {
        &self.compatibility
    }

    pub(super) const fn artifact_digest(&self) -> &CheckpointDigest {
        &self.artifact_digest
    }

    pub(super) const fn artifact_size_bytes(&self) -> u64 {
        self.artifact_size_bytes
    }

    pub(super) fn driver_result(&self) -> Result<DriverCheckpointResult> {
        DriverCheckpointResult::new(
            self.compatibility.clone(),
            self.artifact_digest.clone(),
            self.artifact_size_bytes,
        )
    }

    fn validate(&self) -> Result<()> {
        self.driver_result().map(|_| ())
    }
}

pub(super) fn operation_hash(operation_id: &OperationId) -> String {
    format!("{:x}", Sha256::digest(operation_id.as_str().as_bytes()))
}

fn pending_name(operation_id: &OperationId, token: &[u8; 32]) -> String {
    format!(
        ".a3s-oci-checkpoint-{}-{}.pending",
        operation_hash(operation_id),
        encode_token(token)
    )
}

fn stage_name(operation_id: &OperationId) -> String {
    format!("stage-{}", operation_hash(operation_id))
}

fn load_record(path: &Path, expected: &OperationId) -> Result<Option<JournalRecord>> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error("open checkpoint operation journal", path, error)),
    };
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect checkpoint operation journal", path, error))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_JOURNAL_BYTES {
        return Err(checkpoint_error(
            ErrorCode::FailedPrecondition,
            format!(
                "checkpoint operation journal must be a regular file of 1 through {MAX_JOURNAL_BYTES} bytes: {}",
                path.display()
            ),
        ));
    }
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|error| io_error("read checkpoint operation journal", path, error))?;
    if encoded.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(checkpoint_error(
            ErrorCode::ResourceExhausted,
            format!(
                "checkpoint operation journal exceeds its bound: {}",
                path.display()
            ),
        ));
    }
    let record: JournalRecord = serde_json::from_slice(&encoded).map_err(|error| {
        checkpoint_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to decode checkpoint operation journal {}: {error}",
                path.display()
            ),
        )
    })?;
    record.validate()?;
    if record.operation_id() != expected {
        return Err(checkpoint_error(
            ErrorCode::FailedPrecondition,
            format!(
                "checkpoint operation journal filename does not match {}",
                expected
            ),
        ));
    }
    Ok(Some(record))
}

fn store_record(directory: &Path, record: &JournalRecord) -> Result<()> {
    if !directory
        .join(format!("{}.json", operation_hash(record.operation_id())))
        .exists()
        && std::fs::read_dir(directory)
            .map_err(|error| io_error("list checkpoint operation journals", directory, error))?
            .take(MAX_JOURNALS + 1)
            .count()
            >= MAX_JOURNALS
    {
        return Err(checkpoint_error(
            ErrorCode::ResourceExhausted,
            format!("native checkpoint operation journal reached {MAX_JOURNALS} entries"),
        ));
    }
    let encoded = canonical_json_bytes(record).map_err(|error| {
        checkpoint_error(
            ErrorCode::Internal,
            format!("failed to encode checkpoint operation journal: {error}"),
        )
    })?;
    if encoded.is_empty() || encoded.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(checkpoint_error(
            ErrorCode::ResourceExhausted,
            "encoded checkpoint operation journal exceeds its bound",
        ));
    }
    let mut nonce = [0_u8; 8];
    getrandom::fill(&mut nonce).map_err(|error| {
        checkpoint_error(
            ErrorCode::Unavailable,
            format!("failed to generate checkpoint journal nonce: {error}"),
        )
    })?;
    let pending = directory.join(format!(
        ".journal-{}-{}.pending",
        operation_hash(record.operation_id()),
        nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ));
    let final_path = directory.join(format!("{}.json", operation_hash(record.operation_id())));
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(&pending)
        .map_err(|error| io_error("create pending checkpoint journal", &pending, error))?;
    let write_result = file.write_all(&encoded).and_then(|()| file.sync_all());
    if let Err(error) = write_result {
        drop(file);
        let _ = std::fs::remove_file(&pending);
        return Err(io_error(
            "write pending checkpoint journal",
            &pending,
            error,
        ));
    }
    drop(file);
    if let Err(error) = std::fs::rename(&pending, &final_path) {
        let _ = std::fs::remove_file(&pending);
        return Err(io_error(
            "commit checkpoint operation journal",
            &final_path,
            error,
        ));
    }
    sync_directory(directory, "sync checkpoint operation directory")
}

fn initialize_marker(root: &Path) -> Result<()> {
    let marker_path = root.join(MARKER_FILE);
    match std::fs::read(&marker_path) {
        Ok(encoded) => {
            let marker: StateMarker = serde_json::from_slice(&encoded).map_err(|error| {
                checkpoint_error(
                    ErrorCode::FailedPrecondition,
                    format!("failed to decode checkpoint state marker: {error}"),
                )
            })?;
            if marker.schema_version != STATE_SCHEMA_V1 {
                return Err(checkpoint_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "checkpoint state uses unsupported schema {}",
                        marker.schema_version
                    ),
                ));
            }
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(io_error(
                "read checkpoint state marker",
                &marker_path,
                error,
            ))
        }
    }
    for entry in std::fs::read_dir(root)
        .map_err(|error| io_error("list uninitialized checkpoint state", root, error))?
    {
        let name = entry
            .map_err(|error| io_error("read checkpoint state entry", root, error))?
            .file_name();
        if name != LOCK_FILE {
            return Err(checkpoint_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "uninitialized checkpoint state directory is not empty: {}",
                    root.display()
                ),
            ));
        }
    }
    let marker = StateMarker {
        schema_version: STATE_SCHEMA_V1.to_string(),
    };
    let encoded = canonical_json_bytes(&marker).map_err(|error| {
        checkpoint_error(
            ErrorCode::Internal,
            format!("failed to encode checkpoint state marker: {error}"),
        )
    })?;
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(&marker_path)
        .map_err(|error| io_error("create checkpoint state marker", &marker_path, error))?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error("write checkpoint state marker", &marker_path, error))?;
    sync_directory(root, "sync checkpoint state root")
}

fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|error| io_error("create private checkpoint directory", path, error))
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect private checkpoint directory", path, error))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(checkpoint_error(
            ErrorCode::PermissionDenied,
            format!(
                "checkpoint state directory must be real, owner-only, and owned by the runtime user: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn ensure_private_file(file: &File, path: &Path) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect checkpoint state file", path, error))?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(checkpoint_error(
            ErrorCode::PermissionDenied,
            format!(
                "checkpoint state file must be regular, owner-only, and owned by the runtime user: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn cleanup_all_stages(staging: &Path) -> Result<()> {
    for entry in std::fs::read_dir(staging)
        .map_err(|error| io_error("list checkpoint staging directory", staging, error))?
    {
        let entry =
            entry.map_err(|error| io_error("read checkpoint staging entry", staging, error))?;
        let name = entry.file_name().into_string().map_err(|_| {
            checkpoint_error(
                ErrorCode::FailedPrecondition,
                "checkpoint staging contains a non-UTF-8 entry",
            )
        })?;
        if !valid_stage_name(&name) {
            return Err(checkpoint_error(
                ErrorCode::FailedPrecondition,
                format!("checkpoint staging contains an unknown entry {name:?}"),
            ));
        }
        cleanup_stage_blocking(staging, &entry.path())?;
    }
    Ok(())
}

fn cleanup_stage_blocking(staging: &Path, root: &Path) -> Result<()> {
    if root.parent() != Some(staging)
        || root
            .file_name()
            .and_then(|name| name.to_str())
            .is_none_or(|name| !valid_stage_name(name))
    {
        return Err(checkpoint_error(
            ErrorCode::Internal,
            "refusing to clean a checkpoint stage outside the private staging root",
        ));
    }
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error("inspect checkpoint stage", root, error)),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(checkpoint_error(
            ErrorCode::FailedPrecondition,
            format!(
                "checkpoint stage is not a real directory: {}",
                root.display()
            ),
        ));
    }
    std::fs::remove_dir_all(root)
        .map_err(|error| io_error("remove checkpoint stage", root, error))?;
    sync_directory(staging, "sync checkpoint staging directory")
}

fn valid_stage_name(name: &str) -> bool {
    name.strip_prefix("stage-").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn sync_directory(directory: &Path, action: &str) -> Result<()> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| io_error(action, directory, error))
}

fn decode_token(encoded: &str) -> Result<[u8; 32]> {
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(checkpoint_error(
            ErrorCode::FailedPrecondition,
            "checkpoint publication token is not 32-byte lowercase hexadecimal",
        ));
    }
    let mut token = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| {
            checkpoint_error(
                ErrorCode::FailedPrecondition,
                "checkpoint publication token is not UTF-8 hexadecimal",
            )
        })?;
        token[index] = u8::from_str_radix(text, 16).map_err(|_| {
            checkpoint_error(
                ErrorCode::FailedPrecondition,
                "checkpoint publication token contains invalid hexadecimal",
            )
        })?;
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use a3s_oci_core::{DriverKind, HostPlatform, IsolationClass};
    use a3s_oci_sdk::{CheckpointFormat, RuntimeArtifact};
    use tempfile::tempdir;

    use super::*;

    fn digest(byte: char) -> CheckpointDigest {
        CheckpointDigest::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn journal(operation: &str, path: &Path) -> JournalRecord {
        JournalRecord::allocated(
            OperationId::new(operation).unwrap(),
            digest('1'),
            CheckpointArtifactPath::new(path.to_path_buf()).unwrap(),
            [7_u8; 32],
        )
    }

    fn result() -> JournalResult {
        JournalResult::new(
            CheckpointCompatibility::new(
                DriverKind::NativeLinux,
                IsolationClass::SharedHostKernel,
                HostPlatform::Linux,
                std::env::consts::ARCH,
                RuntimeArtifact::new("a3s-oci-runtime", "0.2.0", digest('2').to_string(), None)
                    .unwrap(),
                digest('3'),
                CheckpointFormat::new("native-linux-criu", 1).unwrap(),
            )
            .unwrap(),
            digest('4'),
            42,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn journal_reopens_every_durable_phase_exactly() {
        let temporary = tempdir().unwrap();
        let store = CheckpointJournalStore::open(temporary.path())
            .await
            .unwrap();
        let path = temporary.path().join("checkpoint.bin");
        let mut record = journal("journal-phases", &path);
        store.store(&record).await.unwrap();
        assert!(matches!(
            store
                .load(record.operation_id())
                .await
                .unwrap()
                .unwrap()
                .outcome(),
            JournalOutcome::Allocated
        ));
        record.mark_prepared(result());
        store.store(&record).await.unwrap();
        assert!(matches!(
            store
                .load(record.operation_id())
                .await
                .unwrap()
                .unwrap()
                .outcome(),
            JournalOutcome::Prepared { .. }
        ));
        record.mark_published(result());
        store.store(&record).await.unwrap();
        assert!(matches!(
            store
                .load(record.operation_id())
                .await
                .unwrap()
                .unwrap()
                .outcome(),
            JournalOutcome::Published { .. }
        ));
        store.remove(record.operation_id()).await.unwrap();
        assert!(store.load(record.operation_id()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn exclusive_state_lock_prevents_split_checkpoint_owners() {
        let temporary = tempdir().unwrap();
        let first = CheckpointJournalStore::open(temporary.path())
            .await
            .unwrap();
        let error = CheckpointJournalStore::open(temporary.path())
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
        drop(first);
        CheckpointJournalStore::open(temporary.path())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn abandoned_private_stage_is_removed_on_reopen() {
        let temporary = tempdir().unwrap();
        let store = CheckpointJournalStore::open(temporary.path())
            .await
            .unwrap();
        let operation = OperationId::new("abandoned-stage").unwrap();
        let stage = store.create_stage(&operation).await.unwrap();
        std::fs::write(stage.images().join("partial.img"), b"partial").unwrap();
        let stage_root = stage.root().to_path_buf();
        drop(store);
        let _reopened = CheckpointJournalStore::open(temporary.path())
            .await
            .unwrap();
        assert!(!stage_root.exists());
    }
}
