use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::{AgentCreateRequest, AgentState};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    canonical_json_bytes, CheckpointArtifactPath, CheckpointDigest, CheckpointReference,
    ContainerTarget, ErrorCode, OperationId, Result,
};
use serde::{Deserialize, Serialize};

use super::{
    checkpoint_error, cleanup_stage_blocking, create_private_directory, ensure_private_directory,
    ensure_private_file, io_error, operation_hash, stage_name, sync_directory,
    CheckpointJournalStore, StageDirectory, MAX_JOURNALS,
};
use crate::native_checkpoint::artifact::CheckpointArtifactManifest;

const RESTORE_JOURNAL_SCHEMA_V1: &str = "a3s.oci.native-restore-operation.v1";
const MAX_RESTORE_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::native_checkpoint) struct RestoreJournalRecord {
    schema_version: String,
    operation_id: OperationId,
    request_digest: CheckpointDigest,
    agent_request: AgentCreateRequest,
    artifact_path: CheckpointArtifactPath,
    reference: CheckpointReference,
    outcome: RestoreJournalOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "kebab-case", deny_unknown_fields)]
pub(in crate::native_checkpoint) enum RestoreJournalOutcome {
    Allocated,
    Prepared {
        manifest: CheckpointArtifactManifest,
    },
    Restored {
        manifest: CheckpointArtifactManifest,
        state: AgentState,
    },
}

impl CheckpointJournalStore {
    pub(in crate::native_checkpoint) async fn load_restore(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<RestoreJournalRecord>> {
        let path = self.restore_journal_path(operation_id);
        let expected = operation_id.clone();
        tokio::task::spawn_blocking(move || load_record(&path, Some(&expected)))
            .await
            .map_err(|error| {
                checkpoint_error(
                    ErrorCode::Internal,
                    format!("restore journal read task failed: {error}"),
                )
            })?
    }

    pub(in crate::native_checkpoint) async fn find_restore(
        &self,
        target: &ContainerTarget,
    ) -> Result<Option<RestoreJournalRecord>> {
        let directory = self.restore_operations.clone();
        let target = target.clone();
        tokio::task::spawn_blocking(move || find_record(&directory, &target))
            .await
            .map_err(|error| {
                checkpoint_error(
                    ErrorCode::Internal,
                    format!("restore journal lookup task failed: {error}"),
                )
            })?
    }

    pub(in crate::native_checkpoint) async fn store_restore(
        &self,
        record: &RestoreJournalRecord,
    ) -> Result<()> {
        record.validate()?;
        let directory = self.restore_operations.clone();
        let record = record.clone();
        tokio::task::spawn_blocking(move || store_record(&directory, &record))
            .await
            .map_err(|error| {
                checkpoint_error(
                    ErrorCode::Internal,
                    format!("restore journal write task failed: {error}"),
                )
            })?
    }

    pub(in crate::native_checkpoint) async fn remove_restore(
        &self,
        operation_id: &OperationId,
    ) -> Result<()> {
        let path = self.restore_journal_path(operation_id);
        let directory = self.restore_operations.clone();
        tokio::task::spawn_blocking(move || match std::fs::remove_file(&path) {
            Ok(()) => sync_directory(&directory, "sync restore operation directory"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error("remove restore operation journal", &path, error)),
        })
        .await
        .map_err(|error| {
            checkpoint_error(
                ErrorCode::Internal,
                format!("restore journal removal task failed: {error}"),
            )
        })?
    }

    pub(in crate::native_checkpoint) async fn create_restore_stage(
        &self,
        operation_id: &OperationId,
    ) -> Result<StageDirectory> {
        let root = self.restore_staging.join(stage_name(operation_id));
        let staging = self.restore_staging.clone();
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
            sync_directory(&staging, "sync restore staging directory")?;
            Ok(StageDirectory { images, work })
        })
        .await
        .map_err(|error| {
            checkpoint_error(
                ErrorCode::Internal,
                format!("restore stage creation task failed: {error}"),
            )
        })?
    }

    pub(in crate::native_checkpoint) async fn open_restore_stage(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<StageDirectory>> {
        let root = self.restore_staging.join(stage_name(operation_id));
        tokio::task::spawn_blocking(move || open_stage(&root))
            .await
            .map_err(|error| {
                checkpoint_error(
                    ErrorCode::Internal,
                    format!("restore stage open task failed: {error}"),
                )
            })?
    }

    pub(in crate::native_checkpoint) async fn cleanup_restore_stage(
        &self,
        operation_id: &OperationId,
    ) -> Result<()> {
        let root = self.restore_staging.join(stage_name(operation_id));
        let staging = self.restore_staging.clone();
        tokio::task::spawn_blocking(move || cleanup_stage_blocking(&staging, &root))
            .await
            .map_err(|error| {
                checkpoint_error(
                    ErrorCode::Internal,
                    format!("restore stage cleanup task failed: {error}"),
                )
            })?
    }

    fn restore_journal_path(&self, operation_id: &OperationId) -> PathBuf {
        self.restore_operations
            .join(format!("{}.json", operation_hash(operation_id)))
    }
}

impl RestoreJournalRecord {
    pub(in crate::native_checkpoint) fn allocated(
        request_digest: CheckpointDigest,
        agent_request: AgentCreateRequest,
        artifact_path: CheckpointArtifactPath,
        reference: CheckpointReference,
    ) -> Result<Self> {
        let record = Self {
            schema_version: RESTORE_JOURNAL_SCHEMA_V1.to_string(),
            operation_id: agent_request.context.operation_id.clone(),
            request_digest,
            agent_request,
            artifact_path,
            reference,
            outcome: RestoreJournalOutcome::Allocated,
        };
        record.validate()?;
        Ok(record)
    }

    pub(in crate::native_checkpoint) fn validate_request(
        &self,
        operation_id: &OperationId,
        request_digest: &CheckpointDigest,
        agent_request: &AgentCreateRequest,
        artifact_path: &CheckpointArtifactPath,
        reference: &CheckpointReference,
    ) -> Result<()> {
        self.validate()?;
        if &self.operation_id != operation_id
            || &self.request_digest != request_digest
            || &self.agent_request != agent_request
            || &self.artifact_path != artifact_path
            || &self.reference != reference
        {
            return Err(checkpoint_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "operation ID {operation_id} was already used for a different native restore request"
                ),
            ));
        }
        Ok(())
    }

    pub(in crate::native_checkpoint) fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub(in crate::native_checkpoint) fn target(&self) -> &ContainerTarget {
        &self.agent_request.target
    }

    pub(in crate::native_checkpoint) fn agent_request(&self) -> &AgentCreateRequest {
        &self.agent_request
    }

    pub(in crate::native_checkpoint) fn artifact_path(&self) -> &CheckpointArtifactPath {
        &self.artifact_path
    }

    pub(in crate::native_checkpoint) fn reference(&self) -> &CheckpointReference {
        &self.reference
    }

    pub(in crate::native_checkpoint) fn manifest(&self) -> Option<&CheckpointArtifactManifest> {
        match &self.outcome {
            RestoreJournalOutcome::Allocated => None,
            RestoreJournalOutcome::Prepared { manifest }
            | RestoreJournalOutcome::Restored { manifest, .. } => Some(manifest),
        }
    }

    pub(in crate::native_checkpoint) fn mark_prepared(
        &mut self,
        manifest: CheckpointArtifactManifest,
    ) {
        self.outcome = RestoreJournalOutcome::Prepared { manifest };
    }

    pub(in crate::native_checkpoint) fn mark_allocated(&mut self) {
        self.outcome = RestoreJournalOutcome::Allocated;
    }

    pub(in crate::native_checkpoint) fn mark_restored(
        &mut self,
        manifest: CheckpointArtifactManifest,
        state: AgentState,
    ) -> Result<()> {
        self.outcome = RestoreJournalOutcome::Restored { manifest, state };
        self.validate()
    }

    fn validate(&self) -> Result<()> {
        let bundle = self.agent_request.bundle.to_guest_bundle()?;
        if self.schema_version != RESTORE_JOURNAL_SCHEMA_V1
            || self.operation_id != self.agent_request.context.operation_id
            || self.agent_request.target.generation.is_none()
            || bundle.config_digest() != self.agent_request.bundle.config_digest()
            || self.agent_request.bundle.config_digest()
                != self.reference.source_config_digest().as_str()
        {
            return Err(checkpoint_error(
                ErrorCode::FailedPrecondition,
                "native restore operation journal has invalid schema, request, or configuration identity",
            ));
        }
        if let RestoreJournalOutcome::Restored { state, .. } = &self.outcome {
            if state.target() != &self.agent_request.target
                || state.config_digest() != self.agent_request.bundle.config_digest()
                || state.status() != ContainerState::Running
                || !state.paused()
                || state.pid().is_none_or(|pid| pid <= 0)
            {
                return Err(checkpoint_error(
                    ErrorCode::FailedPrecondition,
                    "native restore journal retained an invalid restored state",
                ));
            }
        }
        Ok(())
    }
}

pub(super) fn reconcile_stages(operations: &Path, staging: &Path) -> Result<()> {
    let mut retained = BTreeSet::new();
    for entry in bounded_entries(operations, "restore operation")? {
        let path = entry.path();
        let name = entry.file_name().into_string().map_err(|_| {
            checkpoint_error(
                ErrorCode::FailedPrecondition,
                "restore operation directory contains a non-UTF-8 entry",
            )
        })?;
        if is_pending_journal_name(&name) {
            let mut options = OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            let file = options
                .open(&path)
                .map_err(|error| io_error("open pending restore journal", &path, error))?;
            ensure_private_file(&file, &path)?;
            drop(file);
            std::fs::remove_file(&path)
                .map_err(|error| io_error("remove pending restore journal", &path, error))?;
            continue;
        }
        if !is_final_journal_name(&name) {
            return Err(checkpoint_error(
                ErrorCode::FailedPrecondition,
                format!("restore operation directory contains an unknown entry {name:?}"),
            ));
        }
        let record = load_record(&path, None)?.ok_or_else(|| {
            checkpoint_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "restore journal disappeared during startup: {}",
                    path.display()
                ),
            )
        })?;
        if record.manifest().is_some() {
            retained.insert(stage_name(record.operation_id()));
        }
    }
    sync_directory(operations, "sync restored operation directory")?;

    for entry in bounded_entries(staging, "restore staging")? {
        let name = entry.file_name().into_string().map_err(|_| {
            checkpoint_error(
                ErrorCode::FailedPrecondition,
                "restore staging contains a non-UTF-8 entry",
            )
        })?;
        if !super::valid_stage_name(&name) {
            return Err(checkpoint_error(
                ErrorCode::FailedPrecondition,
                format!("restore staging contains an unknown entry {name:?}"),
            ));
        }
        if retained.contains(&name) {
            let _ = open_stage(&entry.path())?;
        } else {
            cleanup_stage_blocking(staging, &entry.path())?;
        }
    }
    Ok(())
}

fn find_record(directory: &Path, target: &ContainerTarget) -> Result<Option<RestoreJournalRecord>> {
    let mut found = None;
    for entry in bounded_entries(directory, "restore operation")? {
        let name = entry.file_name().into_string().map_err(|_| {
            checkpoint_error(
                ErrorCode::FailedPrecondition,
                "restore operation directory contains a non-UTF-8 entry",
            )
        })?;
        if !is_final_journal_name(&name) {
            continue;
        }
        let path = entry.path();
        let record = load_record(&path, None)?.ok_or_else(|| {
            checkpoint_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "restore journal disappeared during lookup: {}",
                    path.display()
                ),
            )
        })?;
        if record.target() == target {
            if found.is_some() {
                return Err(checkpoint_error(
                    ErrorCode::Conflict,
                    format!("multiple native restore journals claim target {target:?}"),
                ));
            }
            found = Some(record);
        }
    }
    Ok(found)
}

fn load_record(
    path: &Path,
    expected: Option<&OperationId>,
) -> Result<Option<RestoreJournalRecord>> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error("open restore operation journal", path, error)),
    };
    ensure_private_file(&file, path)?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect restore operation journal", path, error))?;
    if metadata.len() == 0 || metadata.len() > MAX_RESTORE_JOURNAL_BYTES {
        return Err(checkpoint_error(
            ErrorCode::FailedPrecondition,
            format!(
                "restore operation journal must contain 1 through {MAX_RESTORE_JOURNAL_BYTES} bytes: {}",
                path.display()
            ),
        ));
    }
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_RESTORE_JOURNAL_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|error| io_error("read restore operation journal", path, error))?;
    if encoded.len() as u64 > MAX_RESTORE_JOURNAL_BYTES {
        return Err(checkpoint_error(
            ErrorCode::ResourceExhausted,
            format!(
                "restore operation journal exceeds its bound: {}",
                path.display()
            ),
        ));
    }
    let record: RestoreJournalRecord = serde_json::from_slice(&encoded).map_err(|error| {
        checkpoint_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to decode restore operation journal {}: {error}",
                path.display()
            ),
        )
    })?;
    record.validate()?;
    let expected_name = format!("{}.json", operation_hash(record.operation_id()));
    if expected.is_some_and(|expected| record.operation_id() != expected)
        || path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str())
    {
        return Err(checkpoint_error(
            ErrorCode::FailedPrecondition,
            format!(
                "restore operation journal filename does not match {}",
                record.operation_id()
            ),
        ));
    }
    Ok(Some(record))
}

fn store_record(directory: &Path, record: &RestoreJournalRecord) -> Result<()> {
    let final_path = directory.join(format!("{}.json", operation_hash(record.operation_id())));
    if !final_path.exists()
        && bounded_entries(directory, "restore operation")?.len() >= MAX_JOURNALS
    {
        return Err(checkpoint_error(
            ErrorCode::ResourceExhausted,
            format!("native restore operation journal reached {MAX_JOURNALS} entries"),
        ));
    }
    let encoded = canonical_json_bytes(record).map_err(|error| {
        checkpoint_error(
            ErrorCode::Internal,
            format!("failed to encode restore operation journal: {error}"),
        )
    })?;
    if encoded.is_empty() || encoded.len() as u64 > MAX_RESTORE_JOURNAL_BYTES {
        return Err(checkpoint_error(
            ErrorCode::ResourceExhausted,
            "encoded restore operation journal exceeds its bound",
        ));
    }
    let mut nonce = [0_u8; 8];
    getrandom::fill(&mut nonce).map_err(|error| {
        checkpoint_error(
            ErrorCode::Unavailable,
            format!("failed to generate restore journal nonce: {error}"),
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
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(&pending)
        .map_err(|error| io_error("create pending restore journal", &pending, error))?;
    if let Err(error) = file.write_all(&encoded).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(&pending);
        return Err(io_error("write pending restore journal", &pending, error));
    }
    drop(file);
    if let Err(error) = std::fs::rename(&pending, &final_path) {
        let _ = std::fs::remove_file(&pending);
        return Err(io_error(
            "commit restore operation journal",
            &final_path,
            error,
        ));
    }
    sync_directory(directory, "sync restore operation directory")
}

fn open_stage(root: &Path) -> Result<Option<StageDirectory>> {
    match std::fs::symlink_metadata(root) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(checkpoint_error(
                ErrorCode::PermissionDenied,
                format!("restore stage is not a real directory: {}", root.display()),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error("inspect restore stage", root, error)),
    }
    ensure_private_directory(root)?;
    let images = root.join("images");
    let work = root.join("work");
    ensure_private_directory(&images)?;
    ensure_private_directory(&work)?;
    Ok(Some(StageDirectory { images, work }))
}

fn bounded_entries(directory: &Path, label: &str) -> Result<Vec<std::fs::DirEntry>> {
    let mut entries = std::fs::read_dir(directory)
        .map_err(|error| io_error(&format!("list {label} directory"), directory, error))?
        .take(MAX_JOURNALS + 1)
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| io_error(&format!("read {label} directory"), directory, error))?;
    if entries.len() > MAX_JOURNALS {
        return Err(checkpoint_error(
            ErrorCode::ResourceExhausted,
            format!("{label} directory exceeds {MAX_JOURNALS} entries"),
        ));
    }
    entries.sort_by_key(std::fs::DirEntry::file_name);
    Ok(entries)
}

fn is_final_journal_name(name: &str) -> bool {
    name.strip_suffix(".json").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn is_pending_journal_name(name: &str) -> bool {
    name.starts_with(".journal-") && name.ends_with(".pending")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use a3s_oci_agent_protocol::{AgentBundle, GuestPath};
    use a3s_oci_core::{DriverKind, HostPlatform, IsolationClass};
    use a3s_oci_sdk::oci_spec::runtime::{ContainerState, StateBuilder};
    use a3s_oci_sdk::{
        CheckpointCompatibility, CheckpointFormat, ContainerId, ContainerRecord, CreateAttachments,
        Generation, OciBundle, OperationContext, ProcessIo, RuntimeArtifact,
        PAUSED_STATE_ANNOTATION,
    };
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    fn digest(symbol: char) -> CheckpointDigest {
        CheckpointDigest::new(format!("sha256:{}", symbol.to_string().repeat(64))).unwrap()
    }

    fn fixture(
        root: &Path,
    ) -> (
        AgentCreateRequest,
        CheckpointArtifactPath,
        CheckpointReference,
    ) {
        let bundle = OciBundle::from_json(
            root.join("bundle"),
            serde_json::to_string(&json!({
                "ociVersion": "1.3.0",
                "root": {"path": "rootfs"},
                "process": {
                    "cwd": "/",
                    "args": ["/bin/true"],
                    "user": {"uid": 0, "gid": 0}
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let io = ProcessIo::default();
        let attachments = CreateAttachments::from_bundle(&bundle, io.clone()).unwrap();
        let source = ContainerRecord {
            state: StateBuilder::default()
                .version("1.3.0")
                .id("restore-journal-source")
                .status(ContainerState::Running)
                .pid(4_242)
                .bundle(bundle.directory().to_path_buf())
                .annotations(HashMap::from([(
                    PAUSED_STATE_ANNOTATION.to_string(),
                    "true".to_string(),
                )]))
                .build()
                .unwrap(),
            generation: Generation(1),
            driver: DriverKind::NativeLinux,
            isolation: IsolationClass::SharedHostKernel,
            guest_session: None,
            network_enforcement: None,
            config_digest: bundle.config_digest().to_string(),
            attachments_digest: Some(attachments.digest().unwrap()),
        };
        let compatibility = CheckpointCompatibility::new(
            DriverKind::NativeLinux,
            IsolationClass::SharedHostKernel,
            HostPlatform::Linux,
            std::env::consts::ARCH,
            RuntimeArtifact::new("a3s-oci-runtime", "0.2.0", digest('2').to_string(), None)
                .unwrap(),
            digest('3'),
            CheckpointFormat::new("native-linux-criu", 1).unwrap(),
        )
        .unwrap();
        let reference =
            CheckpointReference::new(&source, compatibility, digest('4'), 4_096).unwrap();
        let context = OperationContext::new(OperationId::new("restore-journal-operation").unwrap());
        let request = AgentCreateRequest {
            context,
            target: ContainerTarget::exact(
                ContainerId::new("restore-journal-target").unwrap(),
                Generation(2),
            ),
            bundle: AgentBundle::new(&bundle, GuestPath::new("/run/a3s/restore-bundle").unwrap()),
            io,
        };
        let artifact = CheckpointArtifactPath::new(root.join("checkpoint.bin")).unwrap();
        (request, artifact, reference)
    }

    #[tokio::test]
    async fn allocated_restore_journal_reopens_and_rejects_request_drift() {
        let temporary = tempdir().unwrap();
        let (request, artifact, reference) = fixture(temporary.path());
        let store = CheckpointJournalStore::open(temporary.path())
            .await
            .unwrap();
        let record = RestoreJournalRecord::allocated(
            digest('1'),
            request.clone(),
            artifact.clone(),
            reference.clone(),
        )
        .unwrap();
        store.store_restore(&record).await.unwrap();
        assert_eq!(
            store.load_restore(record.operation_id()).await.unwrap(),
            Some(record.clone())
        );
        assert_eq!(
            store.find_restore(&request.target).await.unwrap(),
            Some(record.clone())
        );
        let mut changed = request.clone();
        changed.io.stdin = a3s_oci_sdk::IoMode::Pipe;
        let error = record
            .validate_request(
                record.operation_id(),
                &digest('1'),
                &changed,
                &artifact,
                &reference,
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        drop(store);

        let reopened = CheckpointJournalStore::open(temporary.path())
            .await
            .unwrap();
        assert_eq!(
            reopened.load_restore(record.operation_id()).await.unwrap(),
            Some(record)
        );
    }

    #[tokio::test]
    async fn allocated_restore_stage_is_removed_on_reopen() {
        let temporary = tempdir().unwrap();
        let (request, artifact, reference) = fixture(temporary.path());
        let store = CheckpointJournalStore::open(temporary.path())
            .await
            .unwrap();
        let record =
            RestoreJournalRecord::allocated(digest('1'), request, artifact, reference).unwrap();
        store.store_restore(&record).await.unwrap();
        let stage = store
            .create_restore_stage(record.operation_id())
            .await
            .unwrap();
        std::fs::write(stage.images().join("partial.img"), b"partial").unwrap();
        let root = stage.root().to_path_buf();
        drop(store);

        let _reopened = CheckpointJournalStore::open(temporary.path())
            .await
            .unwrap();
        assert!(!root.exists());
    }

    #[tokio::test]
    async fn prepared_restore_stage_survives_reopen_with_exact_images() {
        let temporary = tempdir().unwrap();
        let (request, artifact, reference) = fixture(temporary.path());
        let store = CheckpointJournalStore::open(temporary.path())
            .await
            .unwrap();
        let mut record =
            RestoreJournalRecord::allocated(digest('1'), request, artifact, reference).unwrap();
        let stage = store
            .create_restore_stage(record.operation_id())
            .await
            .unwrap();
        let (manifest, image) = crate::native_checkpoint::artifact::retained_manifest_fixture();
        std::fs::write(stage.images().join("inventory.img"), image).unwrap();
        record.mark_prepared(manifest.clone());
        store.store_restore(&record).await.unwrap();
        let root = stage.root().to_path_buf();
        drop(store);

        let reopened = CheckpointJournalStore::open(temporary.path())
            .await
            .unwrap();
        assert!(root.is_dir());
        let reopened_stage = reopened
            .open_restore_stage(record.operation_id())
            .await
            .unwrap()
            .unwrap();
        manifest
            .validate_retained_images(reopened_stage.images())
            .unwrap();
    }

    #[tokio::test]
    async fn restored_restore_stage_and_paused_state_survive_reopen() {
        let temporary = tempdir().unwrap();
        let (request, artifact, reference) = fixture(temporary.path());
        let store = CheckpointJournalStore::open(temporary.path())
            .await
            .unwrap();
        let mut record =
            RestoreJournalRecord::allocated(digest('1'), request.clone(), artifact, reference)
                .unwrap();
        let stage = store
            .create_restore_stage(record.operation_id())
            .await
            .unwrap();
        let (manifest, image) = crate::native_checkpoint::artifact::retained_manifest_fixture();
        std::fs::write(stage.images().join("inventory.img"), image).unwrap();
        let restored = AgentState::new_with_pause(
            request.target,
            ContainerState::Running,
            Some(7_777),
            request.bundle.config_digest(),
            true,
        )
        .unwrap();
        record.mark_restored(manifest.clone(), restored).unwrap();
        store.store_restore(&record).await.unwrap();
        let root = stage.root().to_path_buf();
        drop(store);

        let reopened = CheckpointJournalStore::open(temporary.path())
            .await
            .unwrap();
        assert!(root.is_dir());
        assert_eq!(
            reopened.load_restore(record.operation_id()).await.unwrap(),
            Some(record.clone())
        );
        let reopened_stage = reopened
            .open_restore_stage(record.operation_id())
            .await
            .unwrap()
            .unwrap();
        manifest
            .validate_retained_images(reopened_stage.images())
            .unwrap();
    }
}
