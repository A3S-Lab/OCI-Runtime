mod artifact;
mod journal;
mod publication;
mod restore;
mod tool;

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Weak};

use a3s_oci_agent::LinuxExecutor;
use a3s_oci_core::{DriverKind, HostPlatform, IsolationClass};
use a3s_oci_sdk::{
    canonical_json_bytes, CheckpointCompatibility, CheckpointDigest, CheckpointFormat, ContainerId,
    ContainerTarget, Error, ErrorCode, OperationId, Result, RuntimeArtifact,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

use crate::{DriverCheckpointRequest, DriverCheckpointResult};
use artifact::{ArtifactMetadata, BuiltArtifact, ExternalMountManifestEntry};
use journal::{CheckpointJournalStore, JournalOutcome, JournalRecord, JournalResult};
use publication::ArtifactDestination;
pub(super) use restore::NativeRestoreRecovery;
use tool::CriuTool;

const CHECKPOINT_FORMAT_NAME: &str = "native-linux-criu";
const CHECKPOINT_FORMAT_VERSION: u16 = 1;
const DRIVER_BUILD_SCHEMA_V1: &str = "a3s.oci.native-criu-driver-build.v1";

/// Explicit CRIU-backed native Linux checkpoint implementation.
#[derive(Debug)]
pub(super) struct NativeCriuCheckpoint {
    tool: CriuTool,
    journals: CheckpointJournalStore,
    driver_build_digest: CheckpointDigest,
    format: CheckpointFormat,
    operation_locks: Mutex<BTreeMap<OperationId, Weak<Mutex<()>>>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DriverBuildIdentity {
    schema_version: &'static str,
    package_version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_revision: Option<&'static str>,
    agent_executable_digest: CheckpointDigest,
    criu: tool::CriuIdentity,
    format_name: &'static str,
    format_version: u16,
    dump_options: Vec<String>,
    restore_options: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestFingerprint<'a> {
    schema_version: &'static str,
    context: &'a a3s_oci_sdk::OperationContext,
    source: &'a a3s_oci_sdk::ContainerRecord,
    artifact_path: &'a a3s_oci_sdk::CheckpointArtifactPath,
    runtime_artifact: &'a RuntimeArtifact,
}

impl NativeCriuCheckpoint {
    pub(super) async fn open(
        runtime_parent: impl AsRef<Path>,
        init_executable: impl AsRef<Path>,
        criu_executable: impl AsRef<Path>,
    ) -> Result<Self> {
        let init_digest = digest_regular_file(init_executable.as_ref()).await?;
        let tool = CriuTool::open(criu_executable).await?;
        let format = CheckpointFormat::new(CHECKPOINT_FORMAT_NAME, CHECKPOINT_FORMAT_VERSION)?;
        let identity = DriverBuildIdentity {
            schema_version: DRIVER_BUILD_SCHEMA_V1,
            package_version: env!("CARGO_PKG_VERSION"),
            source_revision: option_env!("A3S_OCI_GIT_REVISION"),
            agent_executable_digest: init_digest,
            criu: tool.identity(),
            format_name: CHECKPOINT_FORMAT_NAME,
            format_version: CHECKPOINT_FORMAT_VERSION,
            dump_options: CriuTool::dump_option_identity(),
            restore_options: CriuTool::restore_option_identity(),
        };
        let encoded = canonical_json_bytes(&identity).map_err(|error| {
            checkpoint_error(
                ErrorCode::Internal,
                format!("failed to encode native checkpoint build identity: {error}"),
            )
        })?;
        let driver_build_digest =
            CheckpointDigest::new(format!("sha256:{:x}", Sha256::digest(encoded)))?;
        let journals = CheckpointJournalStore::open(runtime_parent).await?;
        Ok(Self {
            tool,
            journals,
            driver_build_digest,
            format,
            operation_locks: Mutex::new(BTreeMap::new()),
        })
    }

    pub(super) fn tool_version(&self) -> &str {
        self.tool.version()
    }

    pub(super) fn tool_digest(&self) -> &CheckpointDigest {
        self.tool.digest()
    }

    pub(super) fn driver_build_digest(&self) -> &CheckpointDigest {
        &self.driver_build_digest
    }

    pub(super) fn format(&self) -> &CheckpointFormat {
        &self.format
    }

    pub(super) async fn checkpoint(
        &self,
        executor: &LinuxExecutor,
        request: DriverCheckpointRequest,
    ) -> Result<DriverCheckpointResult> {
        let operation_id = request.context.operation_id.clone();
        let operation_lock = self.operation_lock(&operation_id).await;
        let _guard = operation_lock.lock().await;
        let request_digest = request_digest(&request)?;
        if let Some(record) = self.journals.load(&operation_id).await? {
            record.validate_request(&operation_id, &request_digest, &request.artifact_path)?;
            match record.outcome().clone() {
                JournalOutcome::Published { result } => {
                    self.finish_published_cleanup(&record).await?;
                    return result.driver_result();
                }
                JournalOutcome::Prepared { result } => {
                    return self.finish_prepared(record, result).await;
                }
                JournalOutcome::Allocated => {
                    self.cleanup_allocated(&record).await?;
                    self.journals.remove(&operation_id).await?;
                }
            }
        }
        self.checkpoint_fresh(executor, request, request_digest)
            .await
    }

    pub(super) async fn acknowledge(&self, operation_id: &OperationId) -> Result<()> {
        let operation_lock = self.operation_lock(operation_id).await;
        let _guard = operation_lock.lock().await;
        if self.journals.load_restore(operation_id).await?.is_some() {
            self.cleanup_restore_operation(operation_id).await?;
        }
        let Some(record) = self.journals.load(operation_id).await? else {
            return Ok(());
        };
        self.cleanup_allocated(&record).await?;
        self.journals.cleanup_stage(operation_id).await?;
        self.journals.remove(operation_id).await
    }

    async fn checkpoint_fresh(
        &self,
        executor: &LinuxExecutor,
        request: DriverCheckpointRequest,
        request_digest: CheckpointDigest,
    ) -> Result<DriverCheckpointResult> {
        validate_source_record(&request.source)?;
        let destination = ArtifactDestination::open(&request.artifact_path).await?;
        destination.ensure_absent().await?;
        let expected_target = source_target(&request.source)?;
        let source = executor
            .checkpoint_source(
                &request.context,
                &expected_target,
                &request.source.config_digest,
            )
            .await?;
        if source.target() != &expected_target
            || *request.source.state.pid() != Some(source.init_pid())
        {
            return Err(checkpoint_error(
                ErrorCode::Conflict,
                "durable checkpoint source PID does not match the exact executor process",
            ));
        }
        let compatibility = CheckpointCompatibility::new(
            DriverKind::NativeLinux,
            IsolationClass::SharedHostKernel,
            HostPlatform::Linux,
            std::env::consts::ARCH,
            request.runtime_artifact.clone(),
            self.driver_build_digest.clone(),
            self.format.clone(),
        )?;
        let cgroup_path = source
            .cgroup_path()
            .to_str()
            .ok_or_else(|| {
                checkpoint_error(
                    ErrorCode::FailedPrecondition,
                    "checkpoint cgroup path is not valid UTF-8",
                )
            })?
            .to_string();
        let external_mounts = source
            .external_mounts()
            .map(|(name, mountpoint)| ExternalMountManifestEntry::new(name, mountpoint))
            .collect::<Result<Vec<_>>>()?;
        let metadata = ArtifactMetadata {
            source: expected_target.clone(),
            source_config_digest: CheckpointDigest::new(request.source.config_digest.clone())?,
            source_attachments_digest: CheckpointDigest::new(
                request.source.attachments_digest.clone().ok_or_else(|| {
                    checkpoint_error(
                        ErrorCode::FailedPrecondition,
                        "checkpoint source has no attachment-manifest digest",
                    )
                })?,
            )?,
            compatibility: compatibility.clone(),
            launcher_pid: source.launcher_pid(),
            checkpoint_root_pid: source.checkpoint_root_pid(),
            init_pid: source.init_pid(),
            cgroup_path: cgroup_path.clone(),
            criu: self.tool.identity(),
            dump_options: CriuTool::dump_options(
                &cgroup_path,
                external_mounts
                    .iter()
                    .map(|mount| (mount.name(), mount.mountpoint())),
            )?,
            external_mounts,
        };
        let operation_id = request.context.operation_id.clone();
        let stage = self.journals.create_stage(&operation_id).await?;
        let dump = self
            .tool
            .dump(&source, stage.images(), stage.work(), &request.context)
            .await;
        let rechecked = executor
            .checkpoint_source(
                &request.context,
                &expected_target,
                &request.source.config_digest,
            )
            .await;
        if let Err(mut error) = dump {
            if let Err(recheck) = rechecked {
                append_failure(&mut error, "source freezer recheck", &recheck);
            }
            if let Err(cleanup) = self.journals.cleanup_stage(&operation_id).await {
                append_failure(&mut error, "checkpoint stage cleanup", &cleanup);
            }
            return Err(error);
        }
        let rechecked = match rechecked {
            Ok(rechecked) => rechecked,
            Err(mut error) => {
                if let Err(cleanup) = self.journals.cleanup_stage(&operation_id).await {
                    append_failure(&mut error, "checkpoint stage cleanup", &cleanup);
                }
                return Err(error);
            }
        };
        if rechecked != source {
            let mut error = checkpoint_error(
                ErrorCode::Conflict,
                "native checkpoint source identity changed while CRIU produced the image",
            );
            if let Err(cleanup) = self.journals.cleanup_stage(&operation_id).await {
                append_failure(&mut error, "checkpoint stage cleanup", &cleanup);
            }
            return Err(error);
        }

        let mut publication_token = [0_u8; 32];
        if let Err(random_error) = getrandom::fill(&mut publication_token) {
            let mut error = checkpoint_error(
                ErrorCode::Unavailable,
                format!("failed to generate checkpoint publication token: {random_error}"),
            );
            if let Err(cleanup) = self.journals.cleanup_stage(&operation_id).await {
                append_failure(&mut error, "checkpoint stage cleanup", &cleanup);
            }
            return Err(error);
        }
        let mut record = JournalRecord::allocated(
            operation_id.clone(),
            request_digest,
            request.artifact_path.clone(),
            publication_token,
        );
        if let Err(mut error) = self.journals.store(&record).await {
            if let Err(cleanup) = self.journals.cleanup_stage(&operation_id).await {
                append_failure(&mut error, "checkpoint stage cleanup", &cleanup);
            }
            return Err(error);
        }
        let pending = match destination
            .create_pending(record.pending_name(), publication_token)
            .await
        {
            Ok(pending) => pending,
            Err(mut error) => {
                self.cleanup_fresh_metadata(&record, &mut error).await;
                return Err(error);
            }
        };
        let built = match artifact::build(
            pending,
            stage.images().to_path_buf(),
            metadata,
            publication_token,
        )
        .await
        {
            Ok(built) => built,
            Err(mut error) => {
                if let Err(cleanup) = destination
                    .remove_created_pending(record.pending_name())
                    .await
                {
                    append_failure(&mut error, "pending artifact cleanup", &cleanup);
                }
                self.cleanup_fresh_metadata(&record, &mut error).await;
                return Err(error);
            }
        };
        if built.manifest.compatibility() != &compatibility {
            let mut error = checkpoint_error(
                ErrorCode::Internal,
                "checkpoint artifact compatibility changed while packaging",
            );
            if let Err(cleanup) = destination
                .remove_created_pending(record.pending_name())
                .await
            {
                append_failure(&mut error, "pending artifact cleanup", &cleanup);
            }
            self.cleanup_fresh_metadata(&record, &mut error).await;
            return Err(error);
        }
        if let Err(mut error) = self.journals.cleanup_stage(&operation_id).await {
            if let Err(cleanup) = destination
                .remove_created_pending(record.pending_name())
                .await
            {
                append_failure(&mut error, "pending artifact cleanup", &cleanup);
            }
            if let Err(cleanup) = self.journals.remove(&operation_id).await {
                append_failure(&mut error, "checkpoint journal cleanup", &cleanup);
            }
            return Err(error);
        }
        let result = journal_result(&built)?;
        record.mark_prepared(result.clone());
        if let Err(mut error) = self.journals.store(&record).await {
            if let Err(cleanup) = destination
                .remove_created_pending(record.pending_name())
                .await
            {
                append_failure(&mut error, "pending artifact cleanup", &cleanup);
            }
            if let Err(cleanup) = self.journals.remove(&operation_id).await {
                append_failure(&mut error, "checkpoint journal cleanup", &cleanup);
            }
            return Err(error);
        }
        self.finish_prepared(record, result).await
    }

    async fn finish_prepared(
        &self,
        mut record: JournalRecord,
        result: JournalResult,
    ) -> Result<DriverCheckpointResult> {
        let destination = ArtifactDestination::open(record.artifact_path()).await?;
        let token = record.publication_token()?;
        let pending = destination.open_pending(record.pending_name()).await?;
        match pending {
            Some(pending) => {
                let built = artifact::validate(
                    pending,
                    result.artifact_digest().clone(),
                    result.artifact_size_bytes(),
                    token,
                )
                .await?;
                require_retained_compatibility(&built, &result)?;
                if let Err(mut error) = destination.publish(record.pending_name()).await {
                    if error.code == ErrorCode::AlreadyExists {
                        if let Err(cleanup) = destination
                            .remove_owned_pending(record.pending_name(), token)
                            .await
                        {
                            append_failure(&mut error, "pending artifact cleanup", &cleanup);
                        }
                        if let Err(cleanup) = self.journals.remove(record.operation_id()).await {
                            append_failure(&mut error, "checkpoint journal cleanup", &cleanup);
                        }
                    }
                    return Err(error);
                }
            }
            None => {
                let final_file = destination.open_final().await?.ok_or_else(|| {
                    checkpoint_error(
                        ErrorCode::Unavailable,
                        "prepared checkpoint lost both its retained pending file and published artifact",
                    )
                    .retryable(true)
                })?;
                let built = artifact::validate(
                    final_file,
                    result.artifact_digest().clone(),
                    result.artifact_size_bytes(),
                    token,
                )
                .await?;
                require_retained_compatibility(&built, &result)?;
            }
        }
        record.mark_published(result.clone());
        self.journals.store(&record).await?;
        destination
            .remove_owned_pending(record.pending_name(), token)
            .await?;
        result.driver_result()
    }

    async fn finish_published_cleanup(&self, record: &JournalRecord) -> Result<()> {
        let destination = match ArtifactDestination::open(record.artifact_path()).await {
            Ok(destination) => destination,
            Err(error) if error.code == ErrorCode::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        destination
            .remove_owned_pending(record.pending_name(), record.publication_token()?)
            .await
    }

    async fn cleanup_allocated(&self, record: &JournalRecord) -> Result<()> {
        let destination = match ArtifactDestination::open(record.artifact_path()).await {
            Ok(destination) => destination,
            Err(error) if error.code == ErrorCode::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        destination
            .remove_owned_pending(record.pending_name(), record.publication_token()?)
            .await
    }

    async fn cleanup_fresh_metadata(&self, record: &JournalRecord, error: &mut Error) {
        if let Err(cleanup) = self.journals.cleanup_stage(record.operation_id()).await {
            append_failure(error, "checkpoint stage cleanup", &cleanup);
        }
        if let Err(cleanup) = self.journals.remove(record.operation_id()).await {
            append_failure(error, "checkpoint journal cleanup", &cleanup);
        }
    }

    async fn operation_lock(&self, operation_id: &OperationId) -> Arc<Mutex<()>> {
        let mut locks = self.operation_locks.lock().await;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(operation_id).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(operation_id.clone(), Arc::downgrade(&lock));
        lock
    }
}

fn request_digest(request: &DriverCheckpointRequest) -> Result<CheckpointDigest> {
    let fingerprint = RequestFingerprint {
        schema_version: JOURNAL_REQUEST_SCHEMA_V1,
        context: &request.context,
        source: &request.source,
        artifact_path: &request.artifact_path,
        runtime_artifact: &request.runtime_artifact,
    };
    let encoded = canonical_json_bytes(&fingerprint).map_err(|error| {
        checkpoint_error(
            ErrorCode::Internal,
            format!("failed to encode checkpoint request fingerprint: {error}"),
        )
    })?;
    CheckpointDigest::new(format!("sha256:{:x}", Sha256::digest(encoded)))
}

const JOURNAL_REQUEST_SCHEMA_V1: &str = "a3s.oci.native-checkpoint-request.v1";

fn validate_source_record(source: &a3s_oci_sdk::ContainerRecord) -> Result<()> {
    if source.driver != DriverKind::NativeLinux
        || source.isolation != IsolationClass::SharedHostKernel
        || *source.state.status() != a3s_oci_sdk::oci_spec::runtime::ContainerState::Running
        || !source.is_paused()
        || source.generation.0 == 0
        || source.attachments_digest.is_none()
    {
        return Err(checkpoint_error(
            ErrorCode::FailedPrecondition,
            "native checkpoint requires a paused running native generation with exact attachment evidence",
        ));
    }
    CheckpointDigest::new(source.config_digest.clone())?;
    CheckpointDigest::new(source.attachments_digest.clone().unwrap_or_default())?;
    Ok(())
}

fn source_target(source: &a3s_oci_sdk::ContainerRecord) -> Result<ContainerTarget> {
    Ok(ContainerTarget::exact(
        ContainerId::new(source.state.id().to_string()).map_err(|error| {
            checkpoint_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "checkpoint source has an invalid container ID: {}",
                    error.message
                ),
            )
        })?,
        source.generation,
    ))
}

fn journal_result(built: &BuiltArtifact) -> Result<JournalResult> {
    JournalResult::new(
        built.manifest.compatibility().clone(),
        built.digest.clone(),
        built.size_bytes,
    )
}

fn require_retained_compatibility(built: &BuiltArtifact, result: &JournalResult) -> Result<()> {
    if built.manifest.compatibility() == result.compatibility() {
        Ok(())
    } else {
        Err(checkpoint_error(
            ErrorCode::FailedPrecondition,
            "checkpoint artifact compatibility differs from its retained operation journal",
        ))
    }
}

async fn digest_regular_file(path: &Path) -> Result<CheckpointDigest> {
    if !path.is_absolute() {
        return Err(checkpoint_error(
            ErrorCode::InvalidArgument,
            format!(
                "native checkpoint init executable path must be absolute: {}",
                path.display()
            ),
        ));
    }
    let canonical = tokio::fs::canonicalize(path)
        .await
        .map_err(|error| io_error("resolve checkpoint init executable", path, error))?;
    let mut options = tokio::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(&canonical)
        .await
        .map_err(|error| io_error("open checkpoint init executable", &canonical, error))?;
    let metadata = file
        .metadata()
        .await
        .map_err(|error| io_error("inspect checkpoint init executable", &canonical, error))?;
    if !metadata.is_file() {
        return Err(checkpoint_error(
            ErrorCode::FailedPrecondition,
            format!(
                "checkpoint init executable is not a regular file: {}",
                canonical.display()
            ),
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|error| io_error("hash checkpoint init executable", &canonical, error))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    CheckpointDigest::new(format!("sha256:{:x}", digest.finalize()))
}

fn append_failure(primary: &mut Error, label: &str, cleanup: &Error) {
    primary.message = format!("{}; {label} failed: {cleanup}", primary.message);
}

fn checkpoint_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("native-linux-checkpoint")
}

fn io_error(action: &str, path: &Path, error: io::Error) -> Error {
    let code = match error.kind() {
        io::ErrorKind::NotFound => ErrorCode::NotFound,
        io::ErrorKind::AlreadyExists => ErrorCode::AlreadyExists,
        io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        _ => ErrorCode::Unavailable,
    };
    checkpoint_error(
        code,
        format!("failed to {action} {}: {error}", path.display()),
    )
    .retryable(matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ))
}
