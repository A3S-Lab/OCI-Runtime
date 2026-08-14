use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{
    ContainerId, DriverKind, Error, ErrorCode, ExitStatus, Generation, IsolationClass,
    ProcessRecord, Result, Signal, TerminalSize,
};
use serde::{Deserialize, Serialize};

use crate::adapter::TaskIdentity;
use crate::identity::IncarnationId;

mod create_intent;

pub(crate) use create_intent::{NewShimCreateIntent, ShimCreateIntent};

const METADATA_FILE_NAME: &str = "a3s-oci-shim-v1.json";
const INCARNATION_FILE_NAME: &str = "a3s-oci-shim-incarnation-v1";
const METADATA_SCHEMA_VERSION: u32 = 8;
const MIN_METADATA_SCHEMA_VERSION: u32 = 1;
const MAX_METADATA_BYTES: u64 = 1024 * 1024;
const MAX_INCARNATION_BYTES: u64 = 64;
const MAX_PENDING_STDIN_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ShimMetadata {
    schema_version: u32,
    namespace: String,
    task_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    incarnation: Option<String>,
    container_id: ContainerId,
    generation: Generation,
    driver: DriverKind,
    isolation: IsolationClass,
    bundle: PathBuf,
    stdin: String,
    stdout: String,
    stderr: String,
    terminal: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    stdin_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_stdin_write: Option<PendingStdinWrite>,
    #[serde(default, skip_serializing_if = "StdinCloseState::is_open")]
    stdin_close_state: StdinCloseState,
    #[serde(default, skip_serializing_if = "is_zero")]
    resize_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_resize: Option<PendingResize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_size: Option<TerminalSize>,
    #[serde(default, skip_serializing_if = "is_zero")]
    signal_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_signal: Option<PendingSignal>,
    #[serde(default, skip_serializing_if = "is_zero")]
    output_cursor: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    control_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_control: Option<PendingControlOperation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_update_digest: Option<String>,
    rootfs_mounted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit: Option<ExitStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exited_at_unix_nanos: Option<u128>,
    #[serde(default, skip_serializing_if = "is_zero")]
    exec_sequence: u64,
    execs: Vec<ExecMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecMetadata {
    pub(crate) exec_id: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) incarnation: u64,
    pub(crate) stage: ExecStage,
    pub(crate) process: Process,
    pub(crate) stdin: String,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) terminal: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) stdin_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) pending_stdin_write: Option<PendingStdinWrite>,
    #[serde(default, skip_serializing_if = "StdinCloseState::is_open")]
    pub(crate) stdin_close_state: StdinCloseState,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) resize_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) pending_resize: Option<PendingResize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) terminal_size: Option<TerminalSize>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) signal_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) pending_signal: Option<PendingSignal>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) output_cursor: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) record: Option<ProcessRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) exit: Option<ExitStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) exited_at_unix_nanos: Option<u128>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ExecStage {
    Added,
    Starting,
    Started,
    Exited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ControlOperationKind {
    Pause,
    Resume,
    Update,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingStdinWrite {
    sequence: u64,
    data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum StdinCloseState {
    #[default]
    Open,
    Closing,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingResize {
    sequence: u64,
    size: TerminalSize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingSignal {
    sequence: u64,
    signal: Signal,
    all: bool,
}

impl PendingSignal {
    pub(crate) fn new(sequence: u64, signal: i32, all: bool) -> Result<Self> {
        let operation = Self {
            sequence,
            signal: Signal::new(signal)?,
            all,
        };
        operation.validate()?;
        Ok(operation)
    }

    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) fn signal(&self) -> Signal {
        self.signal
    }

    pub(crate) fn all(&self) -> bool {
        self.all
    }

    fn validate(&self) -> Result<()> {
        if self.sequence == 0 {
            return Err(metadata_error(
                "pending containerd signal records sequence zero",
            ));
        }
        Signal::new(self.signal.get()).map(drop)
    }
}

impl PendingResize {
    pub(crate) fn new(sequence: u64, size: TerminalSize) -> Result<Self> {
        let resize = Self { sequence, size };
        resize.validate()?;
        Ok(resize)
    }

    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) fn size(&self) -> TerminalSize {
        self.size
    }

    fn validate(&self) -> Result<()> {
        if self.sequence == 0 {
            return Err(metadata_error(
                "pending containerd terminal resize records sequence zero",
            ));
        }
        validate_terminal_size(self.size, "pending containerd terminal resize")
    }
}

impl StdinCloseState {
    pub(crate) fn is_open(&self) -> bool {
        *self == Self::Open
    }
}

impl PendingStdinWrite {
    pub(crate) fn new(sequence: u64, data: Vec<u8>) -> Result<Self> {
        let write = Self { sequence, data };
        write.validate()?;
        Ok(write)
    }

    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }

    fn validate(&self) -> Result<()> {
        if self.sequence == 0 {
            return Err(metadata_error(
                "pending containerd stdin write records sequence zero",
            ));
        }
        if self.data.is_empty() {
            return Err(metadata_error(
                "pending containerd stdin write records an empty payload",
            ));
        }
        if self.data.len() > MAX_PENDING_STDIN_BYTES {
            return Err(metadata_error(format!(
                "pending containerd stdin write contains {} bytes, exceeding the {MAX_PENDING_STDIN_BYTES}-byte limit",
                self.data.len()
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingControlOperation {
    sequence: u64,
    kind: ControlOperationKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_digest: Option<String>,
}

impl PendingControlOperation {
    pub(crate) fn new(
        sequence: u64,
        kind: ControlOperationKind,
        request_digest: Option<String>,
    ) -> Result<Self> {
        let operation = Self {
            sequence,
            kind,
            request_digest,
        };
        operation.validate()?;
        Ok(operation)
    }

    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) fn kind(&self) -> ControlOperationKind {
        self.kind
    }

    pub(crate) fn request_digest(&self) -> Option<&str> {
        self.request_digest.as_deref()
    }

    fn validate(&self) -> Result<()> {
        if self.sequence == 0 {
            return Err(metadata_error(
                "pending containerd control operation records sequence zero",
            ));
        }
        match self.kind {
            ControlOperationKind::Pause | ControlOperationKind::Resume
                if self.request_digest.is_some() =>
            {
                Err(metadata_error(
                    "Pause and Resume control operations must not record a request digest",
                ))
            }
            ControlOperationKind::Update => validate_sha256_digest(
                self.request_digest.as_deref().ok_or_else(|| {
                    metadata_error("pending Update control operation omitted its request digest")
                })?,
                "pending Update request",
            ),
            ControlOperationKind::Pause | ControlOperationKind::Resume => Ok(()),
        }
    }
}

impl ExecMetadata {
    pub(crate) fn new(
        exec_id: String,
        process: Process,
        stdin: String,
        stdout: String,
        stderr: String,
        terminal: bool,
    ) -> Self {
        Self {
            exec_id,
            incarnation: 0,
            stage: ExecStage::Added,
            process,
            stdin,
            stdout,
            stderr,
            terminal,
            stdin_sequence: 0,
            pending_stdin_write: None,
            stdin_close_state: StdinCloseState::Open,
            resize_sequence: 0,
            pending_resize: None,
            terminal_size: None,
            signal_sequence: 0,
            pending_signal: None,
            output_cursor: 0,
            record: None,
            exit: None,
            exited_at_unix_nanos: None,
        }
    }
}

pub(crate) struct NewShimMetadata {
    pub(crate) identity: TaskIdentity,
    pub(crate) generation: Generation,
    pub(crate) driver: DriverKind,
    pub(crate) isolation: IsolationClass,
    pub(crate) bundle: PathBuf,
    pub(crate) stdin: String,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) terminal: bool,
    pub(crate) output_cursor: u64,
    pub(crate) rootfs_mounted: bool,
}

impl ShimMetadata {
    pub(crate) fn new(value: NewShimMetadata) -> Self {
        let TaskIdentity {
            namespace,
            task_id,
            incarnation,
            container_id,
        } = value.identity;
        Self {
            schema_version: METADATA_SCHEMA_VERSION,
            namespace,
            task_id,
            incarnation: incarnation.as_ref().map(|value| value.as_str().to_string()),
            container_id,
            generation: value.generation,
            driver: value.driver,
            isolation: value.isolation,
            bundle: value.bundle,
            stdin: value.stdin,
            stdout: value.stdout,
            stderr: value.stderr,
            terminal: value.terminal,
            stdin_sequence: 0,
            pending_stdin_write: None,
            stdin_close_state: StdinCloseState::Open,
            resize_sequence: 0,
            pending_resize: None,
            terminal_size: None,
            signal_sequence: 0,
            pending_signal: None,
            output_cursor: value.output_cursor,
            control_sequence: 0,
            pending_control: None,
            last_update_digest: None,
            rootfs_mounted: value.rootfs_mounted,
            exit: None,
            exited_at_unix_nanos: None,
            exec_sequence: 0,
            execs: Vec::new(),
        }
    }

    pub(crate) fn path(bundle: &Path) -> PathBuf {
        bundle.join(METADATA_FILE_NAME)
    }

    pub(crate) fn incarnation_path(bundle: &Path) -> PathBuf {
        bundle.join(INCARNATION_FILE_NAME)
    }

    pub(crate) fn load_or_create_incarnation(bundle: &Path) -> Result<IncarnationId> {
        let path = Self::incarnation_path(bundle);
        match open_private_read(&path) {
            Ok(file) => read_incarnation(file, &path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let incarnation = IncarnationId::generate()?;
                let temporary = bundle.join(format!(
                    ".{INCARNATION_FILE_NAME}.{}.tmp",
                    incarnation.as_str()
                ));
                let mut create = OpenOptions::new();
                create.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    create
                        .mode(0o600)
                        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
                }
                match create.open(&temporary) {
                    Ok(mut file) => {
                        if let Err(error) = file
                            .write_all(incarnation.as_str().as_bytes())
                            .and_then(|()| file.sync_all())
                        {
                            let _ = fs::remove_file(&temporary);
                            return Err(metadata_io(
                                "commit incarnation temporary",
                                &temporary,
                                error,
                            ));
                        }
                        match fs::hard_link(&temporary, &path) {
                            Ok(()) => {
                                let _ = fs::remove_file(&temporary);
                                sync_parent(&path)?;
                                Ok(incarnation)
                            }
                            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                                let _ = fs::remove_file(&temporary);
                                let file = open_private_read(&path).map_err(|error| {
                                    metadata_io("open raced incarnation", &path, error)
                                })?;
                                read_incarnation(file, &path)
                            }
                            Err(error) => {
                                let _ = fs::remove_file(&temporary);
                                Err(metadata_io("publish incarnation", &path, error))
                            }
                        }
                    }
                    Err(error) => Err(metadata_io(
                        "create incarnation temporary",
                        &temporary,
                        error,
                    )),
                }
            }
            Err(error) => Err(metadata_io("open incarnation", &path, error)),
        }
    }

    pub(crate) fn load(path: &Path) -> Result<Option<Self>> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(metadata_io("open", path, error)),
        };
        validate_metadata_file(&file, path)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_METADATA_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| metadata_io("read", path, error))?;
        if bytes.len() as u64 > MAX_METADATA_BYTES {
            return Err(metadata_error(format!(
                "shim metadata {} exceeds the {MAX_METADATA_BYTES}-byte limit",
                path.display()
            )));
        }
        let metadata: Self = serde_json::from_slice(&bytes).map_err(|error| {
            metadata_error(format!(
                "failed to decode shim metadata {}: {error}",
                path.display()
            ))
        })?;
        metadata.validate(path)?;
        Ok(Some(metadata))
    }

    pub(crate) fn store(&self) -> Result<()> {
        self.validate(&Self::path(&self.bundle))?;
        let encoded = serde_json::to_vec_pretty(self).map_err(|error| {
            metadata_error(format!(
                "failed to encode containerd shim metadata: {error}"
            ))
        })?;
        atomic_write(&Self::path(&self.bundle), &encoded)
    }

    pub(crate) fn remove(bundle: &Path) -> Result<()> {
        let path = Self::path(bundle);
        match fs::remove_file(&path) {
            Ok(()) => sync_parent(&path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(metadata_io("remove", &path, error)),
        }
    }

    pub(crate) fn identity(&self) -> Result<TaskIdentity> {
        let incarnation = self
            .incarnation
            .as_deref()
            .map(IncarnationId::new)
            .transpose()?;
        let identity = TaskIdentity::with_optional_incarnation(
            self.namespace.clone(),
            self.task_id.clone(),
            incarnation,
        )?;
        if identity.container_id != self.container_id {
            return Err(metadata_error(format!(
                "shim metadata identity resolves to {}, but records {}",
                identity.container_id.as_str(),
                self.container_id.as_str()
            )));
        }
        Ok(identity)
    }

    pub(crate) fn generation(&self) -> Generation {
        self.generation
    }

    pub(crate) fn driver(&self) -> DriverKind {
        self.driver
    }

    pub(crate) fn isolation(&self) -> IsolationClass {
        self.isolation
    }

    pub(crate) fn bundle(&self) -> &Path {
        &self.bundle
    }

    pub(crate) fn stdin(&self) -> &str {
        &self.stdin
    }

    pub(crate) fn stdout(&self) -> &str {
        &self.stdout
    }

    pub(crate) fn stderr(&self) -> &str {
        &self.stderr
    }

    pub(crate) fn terminal(&self) -> bool {
        self.terminal
    }

    pub(crate) fn output_cursor(&self) -> u64 {
        self.output_cursor
    }

    pub(crate) fn stdin_sequence(&self) -> u64 {
        self.stdin_sequence
    }

    pub(crate) fn pending_stdin_write(&self) -> Option<&PendingStdinWrite> {
        self.pending_stdin_write.as_ref()
    }

    pub(crate) fn stdin_close_state(&self) -> StdinCloseState {
        self.stdin_close_state
    }

    pub(crate) fn resize_sequence(&self) -> u64 {
        self.resize_sequence
    }

    pub(crate) fn pending_resize(&self) -> Option<&PendingResize> {
        self.pending_resize.as_ref()
    }

    pub(crate) fn terminal_size(&self) -> Option<TerminalSize> {
        self.terminal_size
    }

    pub(crate) fn signal_sequence(&self) -> u64 {
        self.signal_sequence
    }

    pub(crate) fn pending_signal(&self) -> Option<&PendingSignal> {
        self.pending_signal.as_ref()
    }

    pub(crate) fn control_sequence(&self) -> u64 {
        self.control_sequence
    }

    pub(crate) fn pending_control(&self) -> Option<&PendingControlOperation> {
        self.pending_control.as_ref()
    }

    pub(crate) fn last_update_digest(&self) -> Option<&str> {
        self.last_update_digest.as_deref()
    }

    pub(crate) fn rootfs_mounted(&self) -> bool {
        self.rootfs_mounted
    }

    pub(crate) fn exit(&self) -> Option<&ExitStatus> {
        self.exit.as_ref()
    }

    pub(crate) fn exited_at_unix_nanos(&self) -> Option<u128> {
        self.exited_at_unix_nanos
    }

    pub(crate) fn execs(&self) -> &[ExecMetadata] {
        &self.execs
    }

    pub(crate) fn exec_sequence(&self) -> u64 {
        self.exec_sequence
    }

    pub(crate) fn set_exit(&mut self, exit: Option<ExitStatus>, exited_at: Option<u128>) {
        self.exit = exit;
        self.exited_at_unix_nanos = exited_at;
    }

    pub(crate) fn set_execs(&mut self, execs: Vec<ExecMetadata>) {
        self.execs = execs;
    }

    pub(crate) fn set_exec_sequence(&mut self, sequence: u64) {
        self.exec_sequence = sequence;
    }

    pub(crate) fn set_control_state(
        &mut self,
        sequence: u64,
        pending: Option<PendingControlOperation>,
        last_update_digest: Option<String>,
    ) {
        self.control_sequence = sequence;
        self.pending_control = pending;
        self.last_update_digest = last_update_digest;
    }

    pub(crate) fn set_stdin_state(
        &mut self,
        sequence: u64,
        pending: Option<PendingStdinWrite>,
        close_state: StdinCloseState,
    ) {
        self.stdin_sequence = sequence;
        self.pending_stdin_write = pending;
        self.stdin_close_state = close_state;
    }

    pub(crate) fn set_resize_state(
        &mut self,
        sequence: u64,
        pending: Option<PendingResize>,
        terminal_size: Option<TerminalSize>,
    ) {
        self.resize_sequence = sequence;
        self.pending_resize = pending;
        self.terminal_size = terminal_size;
    }

    pub(crate) fn set_signal_state(&mut self, sequence: u64, pending: Option<PendingSignal>) {
        self.signal_sequence = sequence;
        self.pending_signal = pending;
    }

    fn validate(&self, path: &Path) -> Result<()> {
        if !(MIN_METADATA_SCHEMA_VERSION..=METADATA_SCHEMA_VERSION).contains(&self.schema_version) {
            return Err(metadata_error(format!(
                "unsupported shim metadata schema {} in {}; expected {MIN_METADATA_SCHEMA_VERSION} through {METADATA_SCHEMA_VERSION}",
                self.schema_version,
                path.display()
            )));
        }
        if self.generation.0 == 0 {
            return Err(metadata_error(format!(
                "shim metadata {} records generation zero",
                path.display()
            )));
        }
        if self.schema_version < 3
            && (self.control_sequence != 0
                || self.pending_control.is_some()
                || self.last_update_digest.is_some())
        {
            return Err(metadata_error(format!(
                "shim metadata schema {} cannot contain schema-v3 control state",
                self.schema_version
            )));
        }
        if self.schema_version < 4
            && (self.stdin_sequence != 0
                || self.pending_stdin_write.is_some()
                || self
                    .execs
                    .iter()
                    .any(|exec| exec.stdin_sequence != 0 || exec.pending_stdin_write.is_some()))
        {
            return Err(metadata_error(format!(
                "shim metadata schema {} cannot contain schema-v4 stdin state",
                self.schema_version
            )));
        }
        if self.schema_version < 5
            && (self.stdin_close_state != StdinCloseState::Open
                || self
                    .execs
                    .iter()
                    .any(|exec| exec.stdin_close_state != StdinCloseState::Open))
        {
            return Err(metadata_error(format!(
                "shim metadata schema {} cannot contain schema-v5 stdin close state",
                self.schema_version
            )));
        }
        if self.schema_version < 6
            && (self.resize_sequence != 0
                || self.pending_resize.is_some()
                || self.terminal_size.is_some()
                || self.execs.iter().any(|exec| {
                    exec.resize_sequence != 0
                        || exec.pending_resize.is_some()
                        || exec.terminal_size.is_some()
                }))
        {
            return Err(metadata_error(format!(
                "shim metadata schema {} cannot contain schema-v6 terminal resize state",
                self.schema_version
            )));
        }
        if self.schema_version < 7
            && (self.signal_sequence != 0
                || self.pending_signal.is_some()
                || self
                    .execs
                    .iter()
                    .any(|exec| exec.signal_sequence != 0 || exec.pending_signal.is_some()))
        {
            return Err(metadata_error(format!(
                "shim metadata schema {} cannot contain schema-v7 signal state",
                self.schema_version
            )));
        }
        if self.schema_version < 8
            && (self.exec_sequence != 0 || self.execs.iter().any(|exec| exec.incarnation != 0))
        {
            return Err(metadata_error(format!(
                "shim metadata schema {} cannot contain schema-v8 exec incarnation state",
                self.schema_version
            )));
        }
        validate_stdin_state(
            self.stdin_sequence,
            self.pending_stdin_write.as_ref(),
            self.stdin_close_state,
            "task",
        )?;
        validate_resize_state(
            self.resize_sequence,
            self.pending_resize.as_ref(),
            self.terminal_size,
            self.terminal,
            "task",
        )?;
        validate_signal_state(
            self.signal_sequence,
            self.pending_signal.as_ref(),
            true,
            "task",
        )?;
        if self.stdin.is_empty()
            && (self.stdin_sequence != 0
                || self.pending_stdin_write.is_some()
                || self.stdin_close_state != StdinCloseState::Open)
        {
            return Err(metadata_error(
                "task stdin journal state requires a configured stdin FIFO",
            ));
        }
        if let Some(pending) = &self.pending_control {
            pending.validate()?;
            if self.control_sequence.checked_add(1) != Some(pending.sequence) {
                return Err(metadata_error(format!(
                    "pending containerd control sequence {} does not follow completed sequence {}",
                    pending.sequence, self.control_sequence
                )));
            }
        }
        if let Some(digest) = &self.last_update_digest {
            if self.control_sequence == 0 {
                return Err(metadata_error(
                    "last completed Update request requires a nonzero control sequence",
                ));
            }
            validate_sha256_digest(digest, "last completed Update request")?;
        }
        if !self.bundle.is_absolute() {
            return Err(metadata_error(format!(
                "shim metadata {} records a non-absolute bundle {}",
                path.display(),
                self.bundle.display()
            )));
        }
        if self.bundle != path.parent().unwrap_or_else(|| Path::new("")) {
            return Err(metadata_error(format!(
                "shim metadata {} records a different bundle {}",
                path.display(),
                self.bundle.display()
            )));
        }
        self.identity()?;
        let mut previous = None;
        let mut exec_incarnations = BTreeSet::new();
        for exec in &self.execs {
            if exec.exec_id.is_empty() {
                return Err(metadata_error("shim metadata contains an empty exec ID"));
            }
            if previous
                .as_deref()
                .is_some_and(|value| value >= exec.exec_id.as_str())
            {
                return Err(metadata_error(
                    "shim metadata exec entries must be unique and sorted by exec ID",
                ));
            }
            if exec.incarnation > self.exec_sequence {
                return Err(metadata_error(format!(
                    "exec {} incarnation {} exceeds the allocated exec sequence {}",
                    exec.exec_id, exec.incarnation, self.exec_sequence
                )));
            }
            if exec.incarnation != 0 && !exec_incarnations.insert(exec.incarnation) {
                return Err(metadata_error(format!(
                    "exec incarnation {} is assigned to more than one current exec",
                    exec.incarnation
                )));
            }
            validate_stdin_state(
                exec.stdin_sequence,
                exec.pending_stdin_write.as_ref(),
                exec.stdin_close_state,
                &format!("exec {}", exec.exec_id),
            )?;
            validate_resize_state(
                exec.resize_sequence,
                exec.pending_resize.as_ref(),
                exec.terminal_size,
                exec.terminal,
                &format!("exec {}", exec.exec_id),
            )?;
            validate_signal_state(
                exec.signal_sequence,
                exec.pending_signal.as_ref(),
                false,
                &format!("exec {}", exec.exec_id),
            )?;
            if exec.stdin.is_empty()
                && (exec.stdin_sequence != 0
                    || exec.pending_stdin_write.is_some()
                    || exec.stdin_close_state != StdinCloseState::Open)
            {
                return Err(metadata_error(format!(
                    "exec {} stdin journal state requires a configured stdin FIFO",
                    exec.exec_id
                )));
            }
            previous = Some(exec.exec_id.clone());
        }
        Ok(())
    }
}

fn validate_stdin_state(
    completed_sequence: u64,
    pending: Option<&PendingStdinWrite>,
    close_state: StdinCloseState,
    context: &str,
) -> Result<()> {
    if close_state != StdinCloseState::Open && pending.is_some() {
        return Err(metadata_error(format!(
            "containerd {context} stdin cannot retain a pending write while it is {close_state:?}"
        )));
    }
    let Some(pending) = pending else {
        return Ok(());
    };
    pending.validate()?;
    if completed_sequence.checked_add(1) != Some(pending.sequence) {
        return Err(metadata_error(format!(
            "pending containerd {context} stdin sequence {} does not follow completed sequence {completed_sequence}",
            pending.sequence
        )));
    }
    Ok(())
}

fn validate_resize_state(
    completed_sequence: u64,
    pending: Option<&PendingResize>,
    terminal_size: Option<TerminalSize>,
    terminal: bool,
    context: &str,
) -> Result<()> {
    if !terminal && (completed_sequence != 0 || pending.is_some() || terminal_size.is_some()) {
        return Err(metadata_error(format!(
            "non-terminal containerd {context} cannot retain terminal resize state"
        )));
    }
    if let Some(size) = terminal_size {
        validate_terminal_size(size, &format!("containerd {context} terminal size"))?;
        if completed_sequence == 0 {
            return Err(metadata_error(format!(
                "containerd {context} terminal size requires a completed resize sequence"
            )));
        }
    }
    if let Some(pending) = pending {
        pending.validate()?;
        if completed_sequence.checked_add(1) != Some(pending.sequence) {
            return Err(metadata_error(format!(
                "pending containerd {context} resize sequence {} does not follow completed sequence {completed_sequence}",
                pending.sequence
            )));
        }
        if terminal_size == Some(pending.size) {
            return Err(metadata_error(format!(
                "pending containerd {context} resize repeats the completed terminal size"
            )));
        }
    }
    Ok(())
}

fn validate_terminal_size(size: TerminalSize, context: &str) -> Result<()> {
    if size.width == 0 || size.height == 0 {
        return Err(metadata_error(format!(
            "{context} records zero terminal width or height"
        )));
    }
    Ok(())
}

fn validate_signal_state(
    completed_sequence: u64,
    pending: Option<&PendingSignal>,
    allow_all: bool,
    context: &str,
) -> Result<()> {
    let Some(pending) = pending else {
        return Ok(());
    };
    pending.validate()?;
    if completed_sequence.checked_add(1) != Some(pending.sequence) {
        return Err(metadata_error(format!(
            "pending containerd {context} signal sequence {} does not follow completed sequence {completed_sequence}",
            pending.sequence
        )));
    }
    if pending.all && !allow_all {
        return Err(metadata_error(format!(
            "pending containerd {context} signal cannot request all processes"
        )));
    }
    Ok(())
}

const fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn validate_sha256_digest(digest: &str, context: &str) -> Result<()> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(metadata_error(format!(
            "{context} digest must use the sha256 prefix"
        )));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(metadata_error(format!(
            "{context} digest must contain 64 lowercase hexadecimal digits"
        )));
    }
    Ok(())
}

fn read_incarnation(mut file: File, path: &Path) -> Result<IncarnationId> {
    validate_private_file(&file, path, MAX_INCARNATION_BYTES)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_INCARNATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| metadata_io("read incarnation", path, error))?;
    if bytes.len() as u64 > MAX_INCARNATION_BYTES {
        return Err(metadata_error(format!(
            "containerd task incarnation {} exceeds the {MAX_INCARNATION_BYTES}-byte limit",
            path.display()
        )));
    }
    let value = String::from_utf8(bytes).map_err(|error| {
        metadata_error(format!(
            "containerd task incarnation {} is not UTF-8: {error}",
            path.display()
        ))
    })?;
    IncarnationId::new(value)
}

fn open_private_read(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn validate_metadata_file(file: &File, path: &Path) -> Result<()> {
    validate_private_file(file, path, MAX_METADATA_BYTES)
}

fn validate_private_file(file: &File, path: &Path, maximum_bytes: u64) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|error| metadata_io("inspect", path, error))?;
    if !metadata.file_type().is_file() {
        return Err(metadata_error(format!(
            "shim metadata {} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > maximum_bytes {
        return Err(metadata_error(format!(
            "shim metadata {} exceeds the {maximum_bytes}-byte limit",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid {
            return Err(metadata_error(format!(
                "shim metadata {} is owned by UID {}, expected effective UID {effective_uid}",
                path.display(),
                metadata.uid()
            )));
        }
        if metadata.mode() & 0o077 != 0 {
            return Err(metadata_error(format!(
                "shim metadata {} has unsafe mode {:04o}; group and other permissions must be zero",
                path.display(),
                metadata.mode() & 0o7777
            )));
        }
    }
    Ok(())
}

fn atomic_write(destination: &Path, encoded: &[u8]) -> Result<()> {
    let file_name = destination.file_name().ok_or_else(|| {
        metadata_error(format!(
            "shim metadata destination has no file name: {}",
            destination.display()
        ))
    })?;
    let temporary = destination.with_file_name(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = match options.open(&temporary) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_file(&temporary).map_err(|remove_error| {
                metadata_io("remove stale temporary", &temporary, remove_error)
            })?;
            options
                .open(&temporary)
                .map_err(|open_error| metadata_io("create temporary", &temporary, open_error))?
        }
        Err(error) => return Err(metadata_io("create temporary", &temporary, error)),
    };
    let result = file.write_all(encoded).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(metadata_io("write temporary", &temporary, error));
    }
    if let Err(error) = fs::rename(&temporary, destination) {
        let _ = fs::remove_file(&temporary);
        return Err(metadata_io("commit", destination, error));
    }
    sync_parent(destination)
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        metadata_error(format!(
            "shim metadata path has no parent: {}",
            path.display()
        ))
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| metadata_io("sync parent of", path, error))
}

fn metadata_io(operation: &str, path: &Path, error: io::Error) -> Error {
    Error::new(
        ErrorCode::Unavailable,
        format!(
            "failed to {operation} containerd shim metadata {}: {error}",
            path.display()
        ),
    )
    .for_operation("containerd-shim-metadata")
}

fn metadata_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message).for_operation("containerd-shim-metadata")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(bundle: &Path) -> ShimMetadata {
        ShimMetadata::new(NewShimMetadata {
            identity: TaskIdentity::new("k8s.io", "task-a").expect("identity"),
            generation: Generation(7),
            driver: DriverKind::NativeLinux,
            isolation: IsolationClass::SharedHostKernel,
            bundle: bundle.to_path_buf(),
            stdin: "stdin".to_string(),
            stdout: "stdout".to_string(),
            stderr: "stderr".to_string(),
            terminal: false,
            output_cursor: 0,
            rootfs_mounted: true,
        })
    }

    #[test]
    fn metadata_round_trip_is_atomic_and_identity_bound() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let expected = metadata(directory.path());
        expected.store().expect("store metadata");
        assert_eq!(
            ShimMetadata::load(&ShimMetadata::path(directory.path())).expect("load metadata"),
            Some(expected.clone())
        );
        assert_eq!(
            expected
                .identity()
                .expect("validated identity")
                .container_id,
            expected.container_id
        );
        assert!(directory
            .path()
            .read_dir()
            .expect("read directory")
            .all(|entry| !entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")));
    }

    #[test]
    fn schema_v1_metadata_defaults_task_and_exec_output_cursors_to_zero() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut expected = metadata(directory.path());
        let process: Process = serde_json::from_value(serde_json::json!({
            "terminal": true,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/sh"],
            "cwd": "/"
        }))
        .expect("OCI process");
        expected.set_execs(vec![ExecMetadata::new(
            "exec-a".to_string(),
            process,
            String::new(),
            "exec-out".to_string(),
            String::new(),
            true,
        )]);
        expected.store().expect("store current metadata");

        let path = ShimMetadata::path(directory.path());
        let mut document: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read metadata"))
                .expect("decode metadata document");
        document["schema_version"] = serde_json::json!(1);
        document
            .as_object_mut()
            .expect("metadata object")
            .remove("output_cursor");
        for field in ["control_sequence", "pending_control", "last_update_digest"] {
            document
                .as_object_mut()
                .expect("metadata object")
                .remove(field);
        }
        document["execs"][0]
            .as_object_mut()
            .expect("exec metadata object")
            .remove("output_cursor");
        fs::write(
            &path,
            serde_json::to_vec_pretty(&document).expect("encode schema-v1 metadata"),
        )
        .expect("replace metadata with schema-v1 document");

        let loaded = ShimMetadata::load(&path)
            .expect("load schema-v1 metadata")
            .expect("metadata exists");
        assert_eq!(loaded.schema_version, 1);
        assert_eq!(loaded.output_cursor(), 0);
        assert_eq!(loaded.execs()[0].output_cursor, 0);
        assert_eq!(loaded.control_sequence(), 0);
        assert_eq!(loaded.pending_control(), None);
        assert_eq!(loaded.last_update_digest(), None);
    }

    #[test]
    fn schema_v2_metadata_round_trip_preserves_task_and_exec_output_cursors() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut expected = metadata(directory.path());
        expected.output_cursor = 41;
        let process: Process = serde_json::from_value(serde_json::json!({
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/true"],
            "cwd": "/"
        }))
        .expect("OCI process");
        let mut exec = ExecMetadata::new(
            "exec-a".to_string(),
            process,
            String::new(),
            "exec-out".to_string(),
            "exec-err".to_string(),
            false,
        );
        exec.output_cursor = 73;
        expected.set_execs(vec![exec]);

        expected.store().expect("store current metadata");
        let path = ShimMetadata::path(directory.path());
        let mut document: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read metadata"))
                .expect("decode metadata document");
        document["schema_version"] = serde_json::json!(2);
        for field in ["control_sequence", "pending_control", "last_update_digest"] {
            document
                .as_object_mut()
                .expect("metadata object")
                .remove(field);
        }
        fs::write(
            &path,
            serde_json::to_vec_pretty(&document).expect("encode schema-v2 metadata"),
        )
        .expect("replace metadata with schema-v2 document");

        let loaded = ShimMetadata::load(&path)
            .expect("load schema-v2 metadata")
            .expect("metadata exists");

        assert_eq!(loaded.schema_version, 2);
        assert_eq!(loaded.output_cursor(), 41);
        assert_eq!(loaded.execs()[0].output_cursor, 73);
        assert_eq!(loaded.control_sequence(), 0);
        assert_eq!(loaded.pending_control(), None);
        assert_eq!(loaded.last_update_digest(), None);
    }

    #[test]
    fn schema_v3_metadata_round_trip_preserves_pending_control_state() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut expected = metadata(directory.path());
        expected.schema_version = 3;
        let last_update = format!("sha256:{}", "1".repeat(64));
        let pending_update = format!("sha256:{}", "2".repeat(64));
        expected.set_control_state(
            4,
            Some(
                PendingControlOperation::new(
                    5,
                    ControlOperationKind::Update,
                    Some(pending_update.clone()),
                )
                .expect("pending Update"),
            ),
            Some(last_update.clone()),
        );

        expected.store().expect("store schema-v3 metadata");
        let loaded = ShimMetadata::load(&ShimMetadata::path(directory.path()))
            .expect("load schema-v3 metadata")
            .expect("metadata exists");

        assert_eq!(loaded.schema_version, 3);
        assert_eq!(loaded.control_sequence(), 4);
        assert_eq!(loaded.pending_control(), expected.pending_control());
        assert_eq!(
            loaded
                .pending_control()
                .and_then(PendingControlOperation::request_digest),
            Some(pending_update.as_str())
        );
        assert_eq!(loaded.last_update_digest(), Some(last_update.as_str()));
        assert_eq!(loaded.stdin_sequence(), 0);
        assert_eq!(loaded.pending_stdin_write(), None);
    }

    #[test]
    fn schema_v4_metadata_round_trip_preserves_task_and_exec_stdin_state() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut expected = metadata(directory.path());
        expected.set_stdin_state(
            4,
            Some(PendingStdinWrite::new(5, b"task-pending".to_vec()).expect("task stdin")),
            StdinCloseState::Open,
        );
        let process: Process = serde_json::from_value(serde_json::json!({
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/cat"],
            "cwd": "/"
        }))
        .expect("OCI process");
        let mut exec = ExecMetadata::new(
            "exec-a".to_string(),
            process,
            "exec-in".to_string(),
            "exec-out".to_string(),
            String::new(),
            false,
        );
        exec.stdin_sequence = 8;
        exec.pending_stdin_write =
            Some(PendingStdinWrite::new(9, b"exec-pending".to_vec()).expect("exec stdin"));
        expected.set_execs(vec![exec]);
        expected.schema_version = 4;

        expected.store().expect("store schema-v4 metadata");
        let loaded = ShimMetadata::load(&ShimMetadata::path(directory.path()))
            .expect("load schema-v4 metadata")
            .expect("metadata exists");

        assert_eq!(loaded.schema_version, 4);
        assert_eq!(loaded.stdin_sequence(), 4);
        assert_eq!(loaded.pending_stdin_write(), expected.pending_stdin_write());
        assert_eq!(loaded.stdin_close_state(), StdinCloseState::Open);
        assert_eq!(loaded.execs()[0].stdin_sequence, 8);
        assert_eq!(
            loaded.execs()[0].pending_stdin_write,
            expected.execs()[0].pending_stdin_write
        );
        assert_eq!(loaded.execs()[0].stdin_close_state, StdinCloseState::Open);
    }

    #[test]
    fn schema_v5_metadata_round_trip_preserves_task_and_exec_stdin_close_state() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut expected = metadata(directory.path());
        expected.schema_version = 5;
        expected.set_stdin_state(4, None, StdinCloseState::Closing);
        let process: Process = serde_json::from_value(serde_json::json!({
            "terminal": true,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/sh"],
            "cwd": "/"
        }))
        .expect("OCI process");
        let mut exec = ExecMetadata::new(
            "exec-closed".to_string(),
            process,
            "exec-in".to_string(),
            "exec-out".to_string(),
            String::new(),
            true,
        );
        exec.stdin_sequence = 8;
        exec.stdin_close_state = StdinCloseState::Closed;
        expected.set_execs(vec![exec]);

        expected.store().expect("store schema-v5 metadata");
        let loaded = ShimMetadata::load(&ShimMetadata::path(directory.path()))
            .expect("load schema-v5 metadata")
            .expect("metadata exists");

        assert_eq!(loaded.schema_version, 5);
        assert_eq!(loaded.stdin_sequence(), 4);
        assert_eq!(loaded.stdin_close_state(), StdinCloseState::Closing);
        assert_eq!(loaded.execs()[0].stdin_sequence, 8);
        assert_eq!(loaded.execs()[0].stdin_close_state, StdinCloseState::Closed);
        assert_eq!(loaded.resize_sequence(), 0);
        assert_eq!(loaded.pending_resize(), None);
        assert_eq!(loaded.terminal_size(), None);
        assert_eq!(loaded.execs()[0].resize_sequence, 0);
        assert_eq!(loaded.execs()[0].pending_resize, None);
        assert_eq!(loaded.execs()[0].terminal_size, None);
        assert_eq!(loaded.signal_sequence(), 0);
        assert_eq!(loaded.pending_signal(), None);
        assert_eq!(loaded.execs()[0].signal_sequence, 0);
        assert_eq!(loaded.execs()[0].pending_signal, None);
    }

    #[test]
    fn schema_v6_metadata_round_trip_preserves_task_and_exec_resize_state() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut expected = metadata(directory.path());
        expected.schema_version = 6;
        expected.terminal = true;
        let task_size = TerminalSize {
            width: 120,
            height: 40,
        };
        let pending_task_size = TerminalSize {
            width: 132,
            height: 43,
        };
        expected.set_resize_state(
            3,
            Some(PendingResize::new(4, pending_task_size).expect("pending task resize")),
            Some(task_size),
        );
        let process: Process = serde_json::from_value(serde_json::json!({
            "terminal": true,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/sh"],
            "cwd": "/"
        }))
        .expect("OCI process");
        let mut exec = ExecMetadata::new(
            "exec-resize".to_string(),
            process,
            "exec-in".to_string(),
            "exec-out".to_string(),
            String::new(),
            true,
        );
        exec.resize_sequence = 8;
        exec.terminal_size = Some(TerminalSize {
            width: 91,
            height: 31,
        });
        exec.pending_resize = Some(
            PendingResize::new(
                9,
                TerminalSize {
                    width: 97,
                    height: 37,
                },
            )
            .expect("pending exec resize"),
        );
        expected.set_execs(vec![exec]);

        expected.store().expect("store schema-v6 metadata");
        let loaded = ShimMetadata::load(&ShimMetadata::path(directory.path()))
            .expect("load schema-v6 metadata")
            .expect("metadata exists");

        assert_eq!(loaded.schema_version, 6);
        assert_eq!(loaded.resize_sequence(), 3);
        assert_eq!(loaded.terminal_size(), Some(task_size));
        assert_eq!(loaded.pending_resize(), expected.pending_resize());
        assert_eq!(loaded.execs()[0].resize_sequence, 8);
        assert_eq!(
            loaded.execs()[0].terminal_size,
            Some(TerminalSize {
                width: 91,
                height: 31
            })
        );
        assert_eq!(
            loaded.execs()[0].pending_resize,
            expected.execs()[0].pending_resize
        );
        assert_eq!(loaded.signal_sequence(), 0);
        assert_eq!(loaded.pending_signal(), None);
        assert_eq!(loaded.execs()[0].signal_sequence, 0);
        assert_eq!(loaded.execs()[0].pending_signal, None);
    }

    #[test]
    fn schema_v7_metadata_round_trip_preserves_task_and_exec_signal_state() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut expected = metadata(directory.path());
        expected.schema_version = 7;
        expected.set_signal_state(
            3,
            Some(PendingSignal::new(4, libc::SIGTERM, true).expect("pending task signal")),
        );
        let process: Process = serde_json::from_value(serde_json::json!({
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/sh"],
            "cwd": "/"
        }))
        .expect("OCI process");
        let mut exec = ExecMetadata::new(
            "exec-signal".to_string(),
            process,
            String::new(),
            String::new(),
            String::new(),
            false,
        );
        exec.signal_sequence = 8;
        exec.pending_signal =
            Some(PendingSignal::new(9, libc::SIGUSR1, false).expect("pending exec signal"));
        expected.set_execs(vec![exec]);

        expected.store().expect("store schema-v7 metadata");
        let loaded = ShimMetadata::load(&ShimMetadata::path(directory.path()))
            .expect("load schema-v7 metadata")
            .expect("metadata exists");

        assert_eq!(loaded.schema_version, 7);
        assert_eq!(loaded.signal_sequence(), 3);
        assert_eq!(loaded.pending_signal(), expected.pending_signal());
        assert_eq!(loaded.execs()[0].signal_sequence, 8);
        assert_eq!(
            loaded.execs()[0].pending_signal,
            expected.execs()[0].pending_signal
        );
        assert_eq!(loaded.exec_sequence(), 0);
        assert_eq!(loaded.execs()[0].incarnation, 0);
    }

    #[test]
    fn schema_v8_metadata_preserves_exec_incarnations_after_deletion() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut expected = metadata(directory.path());
        expected.set_exec_sequence(3);
        let process: Process = serde_json::from_value(serde_json::json!({
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/true"],
            "cwd": "/"
        }))
        .expect("OCI process");
        let mut first = ExecMetadata::new(
            "exec-a".to_string(),
            process.clone(),
            String::new(),
            String::new(),
            String::new(),
            false,
        );
        first.incarnation = 1;
        let mut third = ExecMetadata::new(
            "exec-b".to_string(),
            process,
            String::new(),
            String::new(),
            String::new(),
            false,
        );
        third.incarnation = 3;
        expected.set_execs(vec![first, third]);

        expected.store().expect("store schema-v8 metadata");
        let mut loaded = ShimMetadata::load(&ShimMetadata::path(directory.path()))
            .expect("load schema-v8 metadata")
            .expect("metadata exists");
        assert_eq!(loaded.schema_version, 8);
        assert_eq!(loaded.exec_sequence(), 3);
        assert_eq!(loaded.execs()[0].incarnation, 1);
        assert_eq!(loaded.execs()[1].incarnation, 3);

        loaded.set_execs(Vec::new());
        loaded.store().expect("store deleted exec metadata");
        let deleted = ShimMetadata::load(&ShimMetadata::path(directory.path()))
            .expect("reload deleted exec metadata")
            .expect("metadata exists");
        assert!(deleted.execs().is_empty());
        assert_eq!(deleted.exec_sequence(), 3);
    }

    #[test]
    fn schema_v8_metadata_rejects_invalid_exec_incarnation_state() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let process: Process = serde_json::from_value(serde_json::json!({
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/true"],
            "cwd": "/"
        }))
        .expect("OCI process");

        let mut legacy = metadata(directory.path());
        legacy.schema_version = 7;
        legacy.set_exec_sequence(1);
        assert_eq!(
            legacy
                .store()
                .expect_err("schema-v7 exec sequence must fail")
                .code,
            ErrorCode::FailedPrecondition
        );

        let mut beyond_sequence = metadata(directory.path());
        beyond_sequence.set_exec_sequence(1);
        let mut exec = ExecMetadata::new(
            "exec-a".to_string(),
            process.clone(),
            String::new(),
            String::new(),
            String::new(),
            false,
        );
        exec.incarnation = 2;
        beyond_sequence.set_execs(vec![exec]);
        assert_eq!(
            beyond_sequence
                .store()
                .expect_err("exec incarnation beyond sequence must fail")
                .code,
            ErrorCode::FailedPrecondition
        );

        let mut duplicate = metadata(directory.path());
        duplicate.set_exec_sequence(1);
        let mut first = ExecMetadata::new(
            "exec-a".to_string(),
            process.clone(),
            String::new(),
            String::new(),
            String::new(),
            false,
        );
        first.incarnation = 1;
        let mut second = ExecMetadata::new(
            "exec-b".to_string(),
            process,
            String::new(),
            String::new(),
            String::new(),
            false,
        );
        second.incarnation = 1;
        duplicate.set_execs(vec![first, second]);
        assert_eq!(
            duplicate
                .store()
                .expect_err("duplicate exec incarnations must fail")
                .code,
            ErrorCode::FailedPrecondition
        );
    }

    #[test]
    fn schema_v3_metadata_rejects_invalid_control_state() {
        let directory = tempfile::tempdir().expect("temporary directory");

        let mut wrong_sequence = metadata(directory.path());
        wrong_sequence.set_control_state(
            4,
            Some(
                PendingControlOperation::new(6, ControlOperationKind::Pause, None)
                    .expect("pending Pause"),
            ),
            None,
        );
        assert_eq!(
            wrong_sequence
                .store()
                .expect_err("nonconsecutive pending sequence must fail")
                .code,
            ErrorCode::FailedPrecondition
        );

        let mut digest_without_sequence = metadata(directory.path());
        digest_without_sequence.set_control_state(
            0,
            None,
            Some(format!("sha256:{}", "3".repeat(64))),
        );
        assert_eq!(
            digest_without_sequence
                .store()
                .expect_err("completed Update digest without sequence must fail")
                .code,
            ErrorCode::FailedPrecondition
        );

        let mut legacy_with_control = metadata(directory.path());
        legacy_with_control.schema_version = 2;
        legacy_with_control.set_control_state(1, None, None);
        assert_eq!(
            legacy_with_control
                .store()
                .expect_err("schema-v2 control state must fail")
                .code,
            ErrorCode::FailedPrecondition
        );

        let mut legacy_with_stdin = metadata(directory.path());
        legacy_with_stdin.schema_version = 3;
        legacy_with_stdin.set_stdin_state(
            0,
            Some(PendingStdinWrite::new(1, b"pending".to_vec()).expect("pending stdin")),
            StdinCloseState::Open,
        );
        assert_eq!(
            legacy_with_stdin
                .store()
                .expect_err("schema-v3 stdin state must fail")
                .code,
            ErrorCode::FailedPrecondition
        );

        let mut legacy_with_close = metadata(directory.path());
        legacy_with_close.schema_version = 4;
        legacy_with_close.set_stdin_state(0, None, StdinCloseState::Closing);
        assert_eq!(
            legacy_with_close
                .store()
                .expect_err("schema-v4 stdin close state must fail")
                .code,
            ErrorCode::FailedPrecondition
        );

        let mut legacy_with_resize = metadata(directory.path());
        legacy_with_resize.terminal = true;
        legacy_with_resize.schema_version = 5;
        legacy_with_resize.set_resize_state(
            1,
            None,
            Some(TerminalSize {
                width: 80,
                height: 24,
            }),
        );
        assert_eq!(
            legacy_with_resize
                .store()
                .expect_err("schema-v5 resize state must fail")
                .code,
            ErrorCode::FailedPrecondition
        );

        let mut legacy_with_signal = metadata(directory.path());
        legacy_with_signal.schema_version = 6;
        legacy_with_signal.set_signal_state(
            0,
            Some(PendingSignal::new(1, libc::SIGTERM, false).expect("pending signal")),
        );
        assert_eq!(
            legacy_with_signal
                .store()
                .expect_err("schema-v6 signal state must fail")
                .code,
            ErrorCode::FailedPrecondition
        );

        let mut closing_with_pending = metadata(directory.path());
        closing_with_pending.set_stdin_state(
            0,
            Some(PendingStdinWrite::new(1, b"pending".to_vec()).expect("pending stdin")),
            StdinCloseState::Closing,
        );
        assert_eq!(
            closing_with_pending
                .store()
                .expect_err("closing stdin with a pending write must fail")
                .code,
            ErrorCode::FailedPrecondition
        );

        let mut skipped_sequence = metadata(directory.path());
        skipped_sequence.set_stdin_state(
            4,
            Some(PendingStdinWrite::new(6, b"pending".to_vec()).expect("pending stdin")),
            StdinCloseState::Open,
        );
        assert_eq!(
            skipped_sequence
                .store()
                .expect_err("nonconsecutive stdin sequence must fail")
                .code,
            ErrorCode::FailedPrecondition
        );

        assert_eq!(
            PendingStdinWrite::new(1, vec![0; MAX_PENDING_STDIN_BYTES + 1])
                .expect_err("oversized pending stdin must fail")
                .code,
            ErrorCode::FailedPrecondition
        );

        let mut nonterminal_resize = metadata(directory.path());
        nonterminal_resize.set_resize_state(
            0,
            Some(
                PendingResize::new(
                    1,
                    TerminalSize {
                        width: 80,
                        height: 24,
                    },
                )
                .expect("pending resize"),
            ),
            None,
        );
        assert_eq!(
            nonterminal_resize
                .store()
                .expect_err("non-terminal resize state must fail")
                .code,
            ErrorCode::FailedPrecondition
        );

        let mut repeated_resize = metadata(directory.path());
        repeated_resize.terminal = true;
        let repeated_size = TerminalSize {
            width: 120,
            height: 40,
        };
        repeated_resize.set_resize_state(
            4,
            Some(PendingResize::new(5, repeated_size).expect("pending resize")),
            Some(repeated_size),
        );
        assert_eq!(
            repeated_resize
                .store()
                .expect_err("pending resize must differ from completed size")
                .code,
            ErrorCode::FailedPrecondition
        );

        let mut skipped_resize = metadata(directory.path());
        skipped_resize.terminal = true;
        skipped_resize.set_resize_state(
            4,
            Some(
                PendingResize::new(
                    6,
                    TerminalSize {
                        width: 132,
                        height: 43,
                    },
                )
                .expect("pending resize"),
            ),
            None,
        );
        assert_eq!(
            skipped_resize
                .store()
                .expect_err("nonconsecutive resize sequence must fail")
                .code,
            ErrorCode::FailedPrecondition
        );

        assert_eq!(
            PendingResize::new(
                1,
                TerminalSize {
                    width: 0,
                    height: 24,
                },
            )
            .expect_err("zero-width pending resize must fail")
            .code,
            ErrorCode::FailedPrecondition
        );

        let mut skipped_signal = metadata(directory.path());
        skipped_signal.set_signal_state(
            4,
            Some(PendingSignal::new(6, libc::SIGTERM, false).expect("pending signal")),
        );
        assert_eq!(
            skipped_signal
                .store()
                .expect_err("nonconsecutive signal sequence must fail")
                .code,
            ErrorCode::FailedPrecondition
        );

        let mut exec_all = ExecMetadata::new(
            "exec-all".to_string(),
            serde_json::from_value(serde_json::json!({
                "terminal": false,
                "user": {"uid": 0, "gid": 0},
                "args": ["/bin/sh"],
                "cwd": "/"
            }))
            .expect("OCI process"),
            String::new(),
            String::new(),
            String::new(),
            false,
        );
        exec_all.pending_signal =
            Some(PendingSignal::new(1, libc::SIGTERM, true).expect("pending exec signal"));
        let mut invalid_exec_all = metadata(directory.path());
        invalid_exec_all.set_execs(vec![exec_all]);
        assert_eq!(
            invalid_exec_all
                .store()
                .expect_err("exec signal cannot target all processes")
                .code,
            ErrorCode::FailedPrecondition
        );

        assert_eq!(
            PendingSignal::new(0, libc::SIGTERM, false)
                .expect_err("zero signal sequence must fail")
                .code,
            ErrorCode::FailedPrecondition
        );
        assert_eq!(
            PendingSignal::new(1, 0, false)
                .expect_err("zero signal number must fail")
                .code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn task_incarnation_is_stable_within_one_bundle_and_distinct_across_bundles() {
        let first_bundle = tempfile::tempdir().expect("first bundle");
        let second_bundle = tempfile::tempdir().expect("second bundle");

        let first = ShimMetadata::load_or_create_incarnation(first_bundle.path())
            .expect("create first incarnation");
        let replay = ShimMetadata::load_or_create_incarnation(first_bundle.path())
            .expect("reload first incarnation");
        let second = ShimMetadata::load_or_create_incarnation(second_bundle.path())
            .expect("create second incarnation");

        assert_eq!(first, replay);
        assert_ne!(first, second);
        let path = ShimMetadata::incarnation_path(first_bundle.path());
        assert_eq!(
            fs::read_to_string(&path).expect("read incarnation"),
            first.as_str()
        );
        assert!(first_bundle
            .path()
            .read_dir()
            .expect("read bundle")
            .all(|entry| !entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")));
    }

    #[test]
    fn task_incarnation_rejects_corruption_symlinks_and_wide_permissions() {
        let directory = tempfile::tempdir().expect("bundle");
        let path = ShimMetadata::incarnation_path(directory.path());

        fs::write(&path, "not-an-incarnation").expect("write invalid incarnation");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("set private invalid incarnation permissions");
        }
        let error = ShimMetadata::load_or_create_incarnation(directory.path())
            .expect_err("invalid incarnation must fail closed");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        fs::remove_file(&path).expect("remove invalid incarnation");

        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};

            let target = directory.path().join("incarnation-target");
            fs::write(&target, "01".repeat(32)).expect("write symlink target");
            symlink(&target, &path).expect("create incarnation symlink");
            let error = ShimMetadata::load_or_create_incarnation(directory.path())
                .expect_err("incarnation symlink must fail closed");
            assert_eq!(error.code, ErrorCode::Unavailable);
            fs::remove_file(&path).expect("remove incarnation symlink");

            fs::write(&path, "02".repeat(32)).expect("write wide incarnation");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
                .expect("set wide incarnation permissions");
            let error = ShimMetadata::load_or_create_incarnation(directory.path())
                .expect_err("wide incarnation permissions must fail closed");
            assert_eq!(error.code, ErrorCode::FailedPrecondition);
        }
    }

    #[test]
    fn metadata_rejects_generation_and_identity_drift() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut value = metadata(directory.path());
        value.generation = Generation(0);
        assert_eq!(
            value.store().expect_err("generation zero must fail").code,
            ErrorCode::FailedPrecondition
        );

        let mut value = metadata(directory.path());
        value.container_id = ContainerId::new("changed").expect("container ID");
        assert_eq!(
            value.store().expect_err("identity drift must fail").code,
            ErrorCode::FailedPrecondition
        );
    }

    #[cfg(unix)]
    #[test]
    fn metadata_load_rejects_symlinks_oversized_files_and_wide_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = ShimMetadata::path(directory.path());
        let target = directory.path().join("target.json");
        fs::write(&target, b"{}").expect("write symlink target");
        symlink(&target, &path).expect("create metadata symlink");
        let error = ShimMetadata::load(&path).expect_err("metadata symlink must fail closed");
        assert!(matches!(
            error.code,
            ErrorCode::Unavailable | ErrorCode::FailedPrecondition
        ));

        fs::remove_file(&path).expect("remove metadata symlink");
        fs::write(&path, vec![b'x'; (MAX_METADATA_BYTES + 1) as usize])
            .expect("write oversized metadata");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("set private metadata mode");
        let error = ShimMetadata::load(&path).expect_err("oversized metadata must fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(error.message.contains("exceeds"));

        fs::write(
            &path,
            serde_json::to_vec(&metadata(directory.path())).expect("encode metadata"),
        )
        .expect("write metadata with wide permissions");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("set wide metadata mode");
        let error = ShimMetadata::load(&path).expect_err("wide metadata mode must fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(error.message.contains("unsafe mode"));
    }
}
