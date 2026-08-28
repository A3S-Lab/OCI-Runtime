use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{
    ContainerId, ContainerTarget, DeleteMode, Error, ErrorCode, IsolationRequest, OperationId,
    Result,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};

const JOURNAL_SCHEMA: &str = "a3s.oci.cli-lifecycle.v1";
const LOCK_FILE: &str = "lock";
const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct JournalSnapshot {
    schema_version: String,
    pub(super) revision: u64,
    pub(super) container_id: ContainerId,
    pub(super) next_incarnation: u64,
    pub(super) lifecycle: Option<LifecycleJournal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct LifecycleJournal {
    pub(super) incarnation: u64,
    pub(super) bundle_directory: PathBuf,
    pub(super) config_digest: String,
    pub(super) attachments_digest: String,
    pub(super) isolation: IsolationRequest,
    pub(super) pid_file: Option<PathBuf>,
    pub(super) create_operation_id: OperationId,
    pub(super) create_acknowledged: bool,
    pub(super) target: Option<ContainerTarget>,
    pub(super) next_operation_sequence: u64,
    pub(super) start_acknowledged: bool,
    pub(super) pending_start: Option<PendingOperation>,
    pub(super) pending_kill: Option<PendingKill>,
    pub(super) pending_delete: Option<PendingDelete>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PendingOperation {
    pub(super) sequence: u64,
    pub(super) operation_id: OperationId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PendingKill {
    pub(super) operation: PendingOperation,
    pub(super) signal: i32,
    pub(super) all: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PendingDelete {
    pub(super) operation: PendingOperation,
    pub(super) mode: DeleteMode,
}

pub(super) struct LockedJournal {
    directory: PathBuf,
    _lock: File,
    state: JournalSnapshot,
}

impl LockedJournal {
    pub(super) async fn open(
        state_root: PathBuf,
        container_id: ContainerId,
        create_directory: bool,
    ) -> Result<Self> {
        tokio::task::spawn_blocking(move || {
            open_locked_journal(&state_root, container_id, create_directory)
        })
        .await
        .map_err(join_error)?
    }

    pub(super) fn state(&self) -> &JournalSnapshot {
        &self.state
    }

    pub(super) fn state_mut(&mut self) -> &mut JournalSnapshot {
        &mut self.state
    }

    pub(super) async fn persist(self) -> Result<Self> {
        tokio::task::spawn_blocking(move || persist_locked_journal(self))
            .await
            .map_err(join_error)?
    }
}

impl JournalSnapshot {
    fn empty(container_id: ContainerId) -> Self {
        Self {
            schema_version: JOURNAL_SCHEMA.to_string(),
            revision: 0,
            container_id,
            next_incarnation: 1,
            lifecycle: None,
        }
    }

    fn validate(&self, expected_id: &ContainerId, expected_revision: u64) -> Result<()> {
        if self.schema_version != JOURNAL_SCHEMA {
            return Err(corrupt(format!(
                "unsupported lifecycle journal schema {:?}",
                self.schema_version
            )));
        }
        if &self.container_id != expected_id || self.revision != expected_revision {
            return Err(corrupt(
                "lifecycle journal identity or revision does not match its durable path",
            ));
        }
        if self.next_incarnation == 0 {
            return Err(corrupt("lifecycle journal next incarnation is zero"));
        }
        if let Some(lifecycle) = &self.lifecycle {
            lifecycle.validate(expected_id, self.next_incarnation)?;
        }
        Ok(())
    }
}

impl LifecycleJournal {
    fn validate(&self, expected_id: &ContainerId, next_incarnation: u64) -> Result<()> {
        if self.incarnation == 0 || self.incarnation >= next_incarnation {
            return Err(corrupt(
                "active lifecycle incarnation is outside the allocated journal range",
            ));
        }
        if !self.bundle_directory.is_absolute()
            || self
                .pid_file
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
        {
            return Err(corrupt(
                "lifecycle bundle and PID-file identities must be absolute",
            ));
        }
        validate_digest(&self.config_digest)?;
        validate_digest(&self.attachments_digest)?;
        if self.next_operation_sequence == 0 {
            return Err(corrupt("lifecycle operation sequence is zero"));
        }
        if self.create_acknowledged && self.target.is_none() {
            return Err(corrupt(
                "acknowledged create operation does not retain an exact target",
            ));
        }
        if self.start_acknowledged && self.pending_start.is_some() {
            return Err(corrupt(
                "acknowledged start operation also retains a pending retry",
            ));
        }
        if let Some(target) = &self.target {
            if &target.id != expected_id || target.generation.is_none() {
                return Err(corrupt(
                    "lifecycle target is not the journal container's exact generation",
                ));
            }
        }
        for operation in [
            self.pending_start.as_ref(),
            self.pending_kill.as_ref().map(|pending| &pending.operation),
            self.pending_delete
                .as_ref()
                .map(|pending| &pending.operation),
        ]
        .into_iter()
        .flatten()
        {
            if operation.sequence == 0 || operation.sequence >= self.next_operation_sequence {
                return Err(corrupt(
                    "pending operation sequence is outside the allocated journal range",
                ));
            }
        }
        Ok(())
    }
}

fn open_locked_journal(
    state_root: &Path,
    container_id: ContainerId,
    create_directory: bool,
) -> Result<LockedJournal> {
    ensure_secure_journal_platform()?;
    let state_root = validate_state_root(state_root)?;
    let directory = state_root.join(container_id.as_str());
    if create_directory {
        create_private_directory(&directory)?;
    } else if !directory.exists() {
        return Err(not_found(&container_id));
    }
    validate_private_directory(&directory, "container lifecycle journal directory")?;

    let lock_path = directory.join(LOCK_FILE);
    let lock = open_lock_file(&lock_path)?;
    FileExt::lock_exclusive(&lock).map_err(|error| {
        journal_io(
            format!("failed to lock lifecycle journal {}", lock_path.display()),
            error,
        )
    })?;
    validate_lock_file(&lock_path, &lock)?;

    let state = load_latest_snapshot(&directory, &container_id)?
        .unwrap_or_else(|| JournalSnapshot::empty(container_id));
    Ok(LockedJournal {
        directory,
        _lock: lock,
        state,
    })
}

#[cfg(unix)]
fn ensure_secure_journal_platform() -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn ensure_secure_journal_platform() -> Result<()> {
    Err(Error::new(
        ErrorCode::Unsupported,
        "the OCI CLI lifecycle journal requires Unix ownership and mode enforcement",
    )
    .for_operation("oci-cli-journal-open"))
}

fn persist_locked_journal(mut journal: LockedJournal) -> Result<LockedJournal> {
    let revision = journal
        .state
        .revision
        .checked_add(1)
        .ok_or_else(|| corrupt("lifecycle journal revision overflowed"))?;
    journal.state.revision = revision;
    journal
        .state
        .validate(&journal.state.container_id, revision)?;
    let encoded = serde_json::to_vec_pretty(&journal.state).map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("failed to encode lifecycle journal: {error}"),
        )
        .for_operation("oci-cli-journal-write")
    })?;
    if encoded.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            "encoded lifecycle journal exceeds its bounded snapshot size",
        )
        .for_operation("oci-cli-journal-write"));
    }

    let final_name = snapshot_name(revision);
    let final_path = journal.directory.join(&final_name);
    if final_path.exists() {
        return Err(corrupt(format!(
            "lifecycle journal revision already exists: {}",
            final_path.display()
        )));
    }
    let pending_path = unused_pending_path(&journal.directory, revision)?;
    let write_result = (|| -> Result<()> {
        let mut pending = create_private_file(&pending_path)?;
        pending.write_all(&encoded).map_err(|error| {
            journal_io(
                format!(
                    "failed to write lifecycle journal {}",
                    pending_path.display()
                ),
                error,
            )
        })?;
        pending.sync_all().map_err(|error| {
            journal_io(
                format!(
                    "failed to synchronize lifecycle journal {}",
                    pending_path.display()
                ),
                error,
            )
        })?;
        drop(pending);
        fs::rename(&pending_path, &final_path).map_err(|error| {
            journal_io(
                format!(
                    "failed to publish lifecycle journal {}",
                    final_path.display()
                ),
                error,
            )
        })?;
        sync_directory(&journal.directory)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = remove_regular_pending(&pending_path);
    }
    write_result?;
    remove_obsolete_snapshots(&journal.directory, revision);
    Ok(journal)
}

fn validate_state_root(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() || path.parent().is_none() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "OCI CLI state root must be a non-root absolute path: {}",
                path.display()
            ),
        )
        .for_operation("oci-cli-journal-open"));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        journal_io(
            format!("failed to inspect OCI CLI state root {}", path.display()),
            error,
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(permission(format!(
            "OCI CLI state root must not be a symbolic link: {}",
            path.display()
        )));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        journal_io(
            format!("failed to resolve OCI CLI state root {}", path.display()),
            error,
        )
    })?;
    #[cfg(unix)]
    if canonical != path {
        return Err(permission(format!(
            "OCI CLI state root must be canonical and contain no symbolic path components: {}",
            path.display()
        )));
    }
    validate_private_directory(&canonical, "OCI CLI state root")?;
    Ok(canonical)
}

fn create_private_directory(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    #[cfg(unix)]
    let result = {
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)
    };
    #[cfg(not(unix))]
    let result = fs::DirBuilder::new().create(path);
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(journal_io(
            format!(
                "failed to create container lifecycle journal directory {}",
                path.display()
            ),
            error,
        )),
    }
}

fn validate_private_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        journal_io(
            format!("failed to inspect {label} {}", path.display()),
            error,
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(permission(format!(
            "{label} must be a nonsymlink directory: {}",
            path.display()
        )));
    }
    validate_private_metadata(&metadata, path, label)
}

#[cfg(unix)]
fn validate_private_metadata(metadata: &fs::Metadata, path: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: geteuid has no arguments and cannot fail.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid || metadata.permissions().mode() & 0o077 != 0 {
        return Err(permission(format!(
            "{label} must be owned by the effective user and deny group/world access: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_private_metadata(metadata: &fs::Metadata, path: &Path, label: &str) -> Result<()> {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(permission(format!(
            "{label} must not be a Windows reparse point: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn validate_private_metadata(_metadata: &fs::Metadata, _path: &Path, _label: &str) -> Result<()> {
    Err(Error::new(
        ErrorCode::Unsupported,
        "OCI CLI journal security is unavailable on this platform",
    )
    .for_operation("oci-cli-journal-open"))
}

fn open_lock_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|error| {
        journal_io(
            format!("failed to open lifecycle journal lock {}", path.display()),
            error,
        )
    })
}

fn validate_lock_file(path: &Path, file: &File) -> Result<()> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        journal_io(
            format!(
                "failed to inspect lifecycle journal lock {}",
                path.display()
            ),
            error,
        )
    })?;
    let file_metadata = file.metadata().map_err(|error| {
        journal_io(
            format!("failed to inspect open lifecycle lock {}", path.display()),
            error,
        )
    })?;
    if path_metadata.file_type().is_symlink() || !file_metadata.is_file() {
        return Err(permission(format!(
            "lifecycle journal lock must be a nonsymlink regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino()
        {
            return Err(permission(format!(
                "lifecycle journal lock changed while it was opened: {}",
                path.display()
            )));
        }
    }
    validate_private_file_metadata(&file_metadata, path, "lifecycle journal lock")
}

fn load_latest_snapshot(
    directory: &Path,
    container_id: &ContainerId,
) -> Result<Option<JournalSnapshot>> {
    let entries = fs::read_dir(directory).map_err(|error| {
        journal_io(
            format!(
                "failed to enumerate lifecycle journal directory {}",
                directory.display()
            ),
            error,
        )
    })?;
    let mut latest: Option<JournalSnapshot> = None;
    let mut entry_count = 0usize;
    let mut pending = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            journal_io(
                format!(
                    "failed to enumerate lifecycle journal directory {}",
                    directory.display()
                ),
                error,
            )
        })?;
        entry_count = entry_count.saturating_add(1);
        if entry_count > MAX_DIRECTORY_ENTRIES {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                format!(
                    "lifecycle journal directory exceeds {MAX_DIRECTORY_ENTRIES} entries: {}",
                    directory.display()
                ),
            )
            .for_operation("oci-cli-journal-open"));
        }
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            corrupt(format!(
                "lifecycle journal contains a non-Unicode entry in {}",
                directory.display()
            ))
        })?;
        if name == LOCK_FILE {
            continue;
        }
        if is_pending_name(name) {
            validate_regular_path(&entry.path(), "pending lifecycle journal")?;
            pending.push(entry.path());
            continue;
        }
        let revision = snapshot_revision(name).ok_or_else(|| {
            corrupt(format!(
                "unexpected lifecycle journal entry {}",
                entry.path().display()
            ))
        })?;
        let snapshot = read_snapshot(&entry.path(), container_id, revision)?;
        if latest
            .as_ref()
            .is_none_or(|current| snapshot.revision > current.revision)
        {
            latest = Some(snapshot);
        }
    }
    for path in pending {
        let _ = remove_regular_pending(&path);
    }
    Ok(latest)
}

fn read_snapshot(
    path: &Path,
    container_id: &ContainerId,
    revision: u64,
) -> Result<JournalSnapshot> {
    validate_regular_path(path, "lifecycle journal snapshot")?;
    let mut file = File::open(path).map_err(|error| {
        journal_io(
            format!("failed to open lifecycle journal {}", path.display()),
            error,
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        journal_io(
            format!("failed to inspect lifecycle journal {}", path.display()),
            error,
        )
    })?;
    validate_private_file_metadata(&metadata, path, "lifecycle journal snapshot")?;
    if metadata.len() > MAX_SNAPSHOT_BYTES {
        return Err(corrupt(format!(
            "lifecycle journal exceeds {MAX_SNAPSHOT_BYTES} bytes: {}",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes).map_err(|error| {
        journal_io(
            format!("failed to read lifecycle journal {}", path.display()),
            error,
        )
    })?;
    let snapshot: JournalSnapshot = serde_json::from_slice(&bytes).map_err(|error| {
        corrupt(format!(
            "failed to decode lifecycle journal {}: {error}",
            path.display()
        ))
    })?;
    snapshot.validate(container_id, revision)?;
    Ok(snapshot)
}

fn validate_regular_path(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        journal_io(
            format!("failed to inspect {label} {}", path.display()),
            error,
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(permission(format!(
            "{label} must be a nonsymlink regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_file_metadata(metadata: &fs::Metadata, path: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: geteuid has no arguments and cannot fail.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid || metadata.permissions().mode() & 0o077 != 0 {
        return Err(permission(format!(
            "{label} must be owned by the effective user and deny group/world access: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file_metadata(
    _metadata: &fs::Metadata,
    _path: &Path,
    _label: &str,
) -> Result<()> {
    Ok(())
}

fn create_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|error| {
        journal_io(
            format!("failed to create lifecycle journal {}", path.display()),
            error,
        )
    })
}

fn unused_pending_path(directory: &Path, revision: u64) -> Result<PathBuf> {
    for attempt in 0..32u8 {
        let path = directory.join(format!(
            "journal-{revision:020}.pending-{}-{attempt:02}",
            std::process::id()
        ));
        if !path.exists() {
            return Ok(path);
        }
        remove_regular_pending(&path)?;
    }
    Err(Error::new(
        ErrorCode::ResourceExhausted,
        "could not allocate a lifecycle journal staging path",
    )
    .for_operation("oci-cli-journal-write"))
}

fn remove_regular_pending(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path).map_err(|error| {
                journal_io(
                    format!(
                        "failed to remove pending lifecycle journal {}",
                        path.display()
                    ),
                    error,
                )
            })
        }
        Ok(_) => Err(permission(format!(
            "pending lifecycle journal is not a regular file: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(journal_io(
            format!(
                "failed to inspect pending lifecycle journal {}",
                path.display()
            ),
            error,
        )),
    }
}

fn remove_obsolete_snapshots(directory: &Path, retained_revision: u64) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(revision) = snapshot_revision(name) else {
            continue;
        };
        if revision < retained_revision {
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            journal_io(
                format!(
                    "failed to synchronize lifecycle journal directory {}",
                    path.display()
                ),
                error,
            )
        })
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn snapshot_name(revision: u64) -> String {
    format!("journal-{revision:020}.json")
}

fn snapshot_revision(name: &str) -> Option<u64> {
    let value = name.strip_prefix("journal-")?.strip_suffix(".json")?;
    (value.len() == 20 && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

fn is_pending_name(name: &str) -> bool {
    let Some(value) = name.strip_prefix("journal-") else {
        return false;
    };
    let Some((revision, suffix)) = value.split_once(".pending-") else {
        return false;
    };
    revision.len() == 20
        && revision.bytes().all(|byte| byte.is_ascii_digit())
        && !suffix.is_empty()
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-')
}

fn validate_digest(value: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(corrupt("journal digest is not SHA-256"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(corrupt("journal digest is not lowercase SHA-256"));
    }
    Ok(())
}

fn not_found(id: &ContainerId) -> Error {
    Error::new(
        ErrorCode::NotFound,
        format!("container {id} has no OCI CLI lifecycle journal"),
    )
    .for_operation("oci-cli-journal-open")
}

fn permission(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::PermissionDenied, message).for_operation("oci-cli-journal-open")
}

fn corrupt(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::Internal, message).for_operation("oci-cli-journal-open")
}

fn journal_io(context: String, error: std::io::Error) -> Error {
    Error::new(ErrorCode::Internal, format!("{context}: {error}")).for_operation("oci-cli-journal")
}

fn join_error(error: tokio::task::JoinError) -> Error {
    Error::new(
        ErrorCode::Internal,
        format!("lifecycle journal worker failed: {error}"),
    )
    .for_operation("oci-cli-journal")
}
