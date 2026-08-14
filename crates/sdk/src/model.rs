use std::collections::BTreeMap;
use std::path::PathBuf;

use a3s_oci_core::{DriverKind, IsolationClass, RuntimeFeatures};
use oci_spec::runtime::{Features, LinuxResources, Process, State};
use serde::{de, Deserialize, Deserializer, Serialize};

use crate::{
    AttachmentCapabilities, ContainerId, CreateAttachments, Error, ErrorCode, Generation,
    OciBundle, OperationId, ProcessId, Result, TrustDomainId,
};

/// Runtime operation advertised through feature discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeOperation {
    Features,
    Create,
    State,
    Start,
    Kill,
    Delete,
    Exec,
    Wait,
    List,
    Pause,
    Resume,
    Update,
    Processes,
    Stats,
    Events,
    ReadOutput,
    WriteStdin,
    CloseStdin,
    Resize,
    SignalProcess,
    WaitProcess,
    File,
    Filesystem,
    Checkpoint,
    Restore,
}

/// Standards-based and A3S-specific runtime capability inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInfo {
    /// OCI-standard feature report.
    pub oci: Features,
    /// Driver availability, readiness, and isolation evidence.
    pub drivers: RuntimeFeatures,
    /// Operations implemented by this exact service and driver set.
    pub operations: Vec<RuntimeOperation>,
    /// Versioned create-time attachment schemas and optional extensions.
    pub attachments: AttachmentCapabilities,
}

/// Explicit isolation requirement. Drivers may never silently weaken it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "kebab-case")]
pub enum IsolationRequest {
    /// One workload or pod owns a utility VM and its guest kernel.
    DedicatedVm,
    /// Containers in one caller-declared trust domain share a utility VM.
    SharedGuestKernel {
        /// Scope inside which guest-kernel sharing is allowed.
        trust_domain: TrustDomainId,
    },
    /// Containers share the native Linux host kernel.
    SharedHostKernel,
}

impl IsolationRequest {
    /// Effective isolation class requested by the caller.
    #[must_use]
    pub const fn class(&self) -> IsolationClass {
        match self {
            Self::DedicatedVm => IsolationClass::DedicatedVm,
            Self::SharedGuestKernel { .. } => IsolationClass::SharedGuestKernel,
            Self::SharedHostKernel => IsolationClass::SharedHostKernel,
        }
    }
}

/// Container ID plus an optional generation fence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerTarget {
    pub id: ContainerId,
    /// When present, stale requests against a reused ID must fail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<Generation>,
}

impl ContainerTarget {
    /// Target the current generation of a container ID.
    #[must_use]
    pub const fn current(id: ContainerId) -> Self {
        Self {
            id,
            generation: None,
        }
    }

    /// Target one exact durable generation.
    #[must_use]
    pub const fn exact(id: ContainerId, generation: Generation) -> Self {
        Self {
            id,
            generation: Some(generation),
        }
    }
}

/// Process inside one exact or current container generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessTarget {
    pub container: ContainerTarget,
    pub process_id: ProcessId,
}

/// Idempotency and deadline metadata for a mutating request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationContext {
    pub operation_id: OperationId,
    /// Absolute Unix time in milliseconds after which work must not begin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline_unix_ms: Option<u64>,
}

impl OperationContext {
    /// Construct an operation without a caller deadline.
    #[must_use]
    pub const fn new(operation_id: OperationId) -> Self {
        Self {
            operation_id,
            deadline_unix_ms: None,
        }
    }
}

/// File payload operation inside one exact container root filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileOp {
    /// Replace one regular file with the supplied base64 payload.
    Upload,
    /// Read one regular file and return its base64 payload.
    Download,
}

/// Generation-fenced file transfer request.
///
/// Uploads carry a stable operation context so an explicitly retried request
/// cannot append, duplicate, or redirect a partially acknowledged write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRequest {
    pub target: ContainerTarget,
    pub op: FileOp,
    /// Absolute path, home-relative path, or `~/` path inside the container.
    pub path: String,
    /// Base64-encoded upload payload. Downloads must omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Optional container account used for home expansion and new ownership.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Required for uploads and omitted for read-only downloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<OperationContext>,
}

/// Result of one generation-fenced file transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileResponse {
    pub target: ContainerTarget,
    /// Base64-encoded download payload. Upload responses omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    pub size: u64,
}

/// Metadata or mutation operation inside one exact container filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemOp {
    Stat,
    MakeDir,
    Move,
    ListDir,
    Remove,
}

impl FilesystemOp {
    /// Whether this operation changes the container filesystem.
    #[must_use]
    pub const fn is_mutating(self) -> bool {
        matches!(self, Self::MakeDir | Self::Move | Self::Remove)
    }
}

/// Generation-fenced filesystem metadata or mutation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemRequest {
    pub target: ContainerTarget,
    pub op: FilesystemOp,
    /// Source or primary path inside the container.
    pub path: String,
    /// Destination path required only by [`FilesystemOp::Move`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// Descendant depth for [`FilesystemOp::ListDir`]; zero means one level.
    #[serde(default)]
    pub depth: u32,
    /// Optional container account used for home expansion and new ownership.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Required for mutating operations and omitted for read-only operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<OperationContext>,
}

/// Portable file type returned by filesystem metadata operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemEntryKind {
    Unspecified,
    File,
    Directory,
}

/// Portable metadata for one entry inside a container filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemEntry {
    pub name: String,
    pub kind: FilesystemEntryKind,
    pub path: String,
    pub size: i64,
    pub mode: u32,
    pub permissions: String,
    pub owner: String,
    pub group: String,
    pub modified_seconds: i64,
    pub modified_nanos: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

/// Result of one generation-fenced filesystem operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemResponse {
    pub target: ContainerTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<FilesystemEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<FilesystemEntry>,
}

/// Host-side standard-I/O disposition for an OCI process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IoMode {
    Null,
    Inherit,
    Pipe,
    Capture,
    Terminal,
}

/// Initial terminal dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalSize {
    pub width: u16,
    pub height: u16,
}

/// I/O attachment requested for an init or exec process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIo {
    pub stdin: IoMode,
    pub stdout: IoMode,
    pub stderr: IoMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_size: Option<TerminalSize>,
}

impl Default for ProcessIo {
    fn default() -> Self {
        Self {
            stdin: IoMode::Null,
            stdout: IoMode::Capture,
            stderr: IoMode::Capture,
            terminal_size: None,
        }
    }
}

/// Positive Linux signal number delivered by a runtime driver or guest agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Signal(i32);

impl Signal {
    /// Validate a signal number. Platform-specific availability is checked later.
    pub fn new(number: i32) -> Result<Self> {
        if number <= 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "signal number must be positive",
            ));
        }
        Ok(Self(number))
    }

    /// Numeric signal value.
    #[must_use]
    pub const fn get(self) -> i32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Signal {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let number = i32::deserialize(deserializer)?;
        Self::new(number).map_err(de::Error::custom)
    }
}

/// OCI create operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateRequest {
    pub context: OperationContext,
    pub id: ContainerId,
    pub bundle: OciBundle,
    pub isolation: IsolationRequest,
    /// Complete versioned rootfs, mount, network, I/O, secret, and extension contract.
    pub attachments: CreateAttachments,
}

/// Client-side composition of the complete foreground OCI lifecycle.
///
/// `run` is deliberately not a runtime service or wire operation. The SDK
/// submits `create`, `start`, `wait`, and `delete` independently so every
/// mutation retains its normal durable replay identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRequest {
    /// Complete request used for the OCI create operation.
    pub create: CreateRequest,
    /// Stable context used for the OCI start operation.
    pub start_context: OperationContext,
    /// Stable context used for both normal and error-path forced cleanup.
    pub delete_context: OperationContext,
}

/// OCI query-state operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateRequest {
    pub target: ContainerTarget,
}

/// OCI start operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartRequest {
    pub context: OperationContext,
    pub target: ContainerTarget,
}

/// OCI kill operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillRequest {
    pub context: OperationContext,
    pub target: ContainerTarget,
    pub signal: Signal,
    /// Deliver the signal to every process in the container.
    pub all: bool,
}

/// Resource cleanup behavior for delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeleteMode {
    /// Enforce the OCI requirement that only a stopped container is deleted.
    StoppedOnly,
    /// Stop remaining processes and then delete runtime-owned resources.
    Force,
}

/// OCI delete operation plus an explicit force extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub context: OperationContext,
    pub target: ContainerTarget,
    pub mode: DeleteMode,
}

/// Execute an additional complete OCI process configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRequest {
    pub context: OperationContext,
    pub container: ContainerTarget,
    pub process_id: ProcessId,
    #[serde(with = "crate::process_serde")]
    pub process: Process,
    pub io: ProcessIo,
}

/// Generic idempotent container mutation used by pause and resume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerOperationRequest {
    pub context: OperationContext,
    pub target: ContainerTarget,
}

/// Wait for an init process to exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitRequest {
    pub target: ContainerTarget,
    /// Maximum wait duration. `None` waits without an SDK-imposed deadline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// List containers visible within this runtime service scope.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListRequest {
    /// Optional isolation-class filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isolation: Option<IsolationClass>,
}

/// Apply a complete OCI Linux resource update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateRequest {
    pub context: OperationContext,
    pub target: ContainerTarget,
    pub resources: LinuxResources,
}

/// Query processes inside a container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessesRequest {
    pub target: ContainerTarget,
}

/// Query one typed resource snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsRequest {
    pub target: ContainerTarget,
}

/// Poll ordered runtime events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsRequest {
    /// Optional container filter. A missing generation matches every retained
    /// generation of this ID; an exact generation matches only that instance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<ContainerTarget>,
    /// Exclusive global cursor. Use zero for the beginning of retained history.
    pub after_sequence: u64,
    /// Maximum matching events returned in this batch.
    pub limit: u32,
    /// Optional long-poll timeout. `None` performs an immediate poll.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_timeout_ms: Option<u64>,
}

/// Read captured stdout or stderr after an inclusive byte cursor.
///
/// Start with `after_sequence = 0`, then pass the last returned
/// [`OutputChunk::sequence`] to the next poll.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadOutputRequest {
    pub process: ProcessTarget,
    pub after_sequence: u64,
    pub max_bytes: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_timeout_ms: Option<u64>,
}

/// Write bytes to a process's standard input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteStdinRequest {
    pub context: OperationContext,
    pub process: ProcessTarget,
    pub data: Vec<u8>,
}

/// Close a process's standard input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseStdinRequest {
    pub context: OperationContext,
    pub process: ProcessTarget,
}

/// Resize a process terminal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResizeRequest {
    pub context: OperationContext,
    pub process: ProcessTarget,
    pub size: TerminalSize,
}

/// Signal an init or exec process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalProcessRequest {
    pub context: OperationContext,
    pub process: ProcessTarget,
    pub signal: Signal,
}

/// Wait for an init or exec process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitProcessRequest {
    pub process: ProcessTarget,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// Create a portable checkpoint using the selected driver's supported mechanism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointRequest {
    pub context: OperationContext,
    pub target: ContainerTarget,
    pub directory: PathBuf,
    pub leave_running: bool,
}

/// Restore a container from a previously created checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreRequest {
    pub context: OperationContext,
    pub id: ContainerId,
    pub bundle: OciBundle,
    pub checkpoint_directory: PathBuf,
    pub isolation: IsolationRequest,
    /// Complete versioned attachment contract for the restored generation.
    pub attachments: CreateAttachments,
}

/// Durable runtime state with generation and effective isolation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerRecord {
    pub state: State,
    pub generation: Generation,
    pub driver: DriverKind,
    pub isolation: IsolationClass,
    pub config_digest: String,
    /// Exact create-time attachment evidence. Legacy records created before
    /// attachment protocol v1 do not contain this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachments_digest: Option<String>,
}

/// OCI state annotation used to expose the runtime's freezer state without
/// inventing a non-standard OCI lifecycle status.
pub const PAUSED_STATE_ANNOTATION: &str = "dev.a3s.oci.runtime.paused";

/// Opt-in cgroup layout used by runtimes that embed a trusted control plane
/// beside an untrusted workload in one OCI container.
pub const CONTROL_WORKLOAD_CGROUP_LAYOUT_ANNOTATION: &str = "dev.a3s.oci.cgroup.layout";
/// Versioned value for [`CONTROL_WORKLOAD_CGROUP_LAYOUT_ANNOTATION`].
pub const CONTROL_WORKLOAD_CGROUP_LAYOUT_V1: &str = "control-workload-v1";
/// Extra outer-envelope memory reserved for the trusted control plane.
pub const CONTROL_CGROUP_MEMORY_HEADROOM_ANNOTATION: &str =
    "dev.a3s.oci.cgroup.control-memory-headroom-bytes";
/// Extra outer-envelope CPU quota reserved for the trusted control plane.
pub const CONTROL_CGROUP_CPU_HEADROOM_ANNOTATION: &str =
    "dev.a3s.oci.cgroup.control-cpu-headroom-micros";
/// Extra outer-envelope process capacity reserved for the trusted control plane.
pub const CONTROL_CGROUP_PIDS_HEADROOM_ANNOTATION: &str =
    "dev.a3s.oci.cgroup.control-pids-headroom";
/// Descriptor inherited by the trusted init for moving bootstrap processes.
pub const CONTROL_CGROUP_PROCS_FD: i32 = 6;
/// Descriptor inherited by the trusted init for joining user workload processes.
pub const WORKLOAD_CGROUP_PROCS_FD: i32 = 7;
/// Environment key identifying [`CONTROL_CGROUP_PROCS_FD`].
pub const CONTROL_CGROUP_PROCS_FD_ENV: &str = "A3S_CONTROL_CGROUP_PROCS_FD";
/// Environment key identifying [`WORKLOAD_CGROUP_PROCS_FD`].
pub const WORKLOAD_CGROUP_PROCS_FD_ENV: &str = "A3S_WORKLOAD_CGROUP_PROCS_FD";
/// Guest-visible child cgroup containing trusted control-plane processes.
pub const CONTROL_CGROUP_NAME: &str = "a3s-control";
/// Guest-visible child cgroup containing all user workload processes.
pub const WORKLOAD_CGROUP_NAME: &str = "a3s-workload";

impl ContainerRecord {
    /// Whether all processes in this exact container generation are frozen.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.state
            .annotations()
            .as_ref()
            .and_then(|annotations| annotations.get(PAUSED_STATE_ANNOTATION))
            .is_some_and(|value| value == "true")
    }
}

/// Runtime-visible init or exec process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessRecord {
    pub target: ProcessTarget,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub terminal: bool,
}

/// Terminal process result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExitStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    pub oom_killed: bool,
}

impl<'de> Deserialize<'de> for ExitStatus {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Fields {
            exit_code: Option<i32>,
            signal: Option<i32>,
            oom_killed: bool,
        }

        let fields = Fields::deserialize(deserializer)?;
        let status = Self {
            exit_code: fields.exit_code,
            signal: fields.signal,
            oom_killed: fields.oom_killed,
        };
        status.validate().map_err(de::Error::custom)?;
        Ok(status)
    }
}

impl ExitStatus {
    /// Construct a normal Linux process exit result.
    pub fn exited(exit_code: i32) -> Result<Self> {
        let status = Self {
            exit_code: Some(exit_code),
            signal: None,
            oom_killed: false,
        };
        status.validate()?;
        Ok(status)
    }

    /// Construct a Linux signal-termination result.
    pub fn signaled(signal: i32, oom_killed: bool) -> Result<Self> {
        let status = Self {
            exit_code: None,
            signal: Some(signal),
            oom_killed,
        };
        status.validate()?;
        Ok(status)
    }

    /// Validate the mutually exclusive terminal-result representation.
    pub fn validate(&self) -> Result<()> {
        match (self.exit_code, self.signal, self.oom_killed) {
            (Some(exit_code), None, false) if (0..=255).contains(&exit_code) => Ok(()),
            (None, Some(signal), _) if signal > 0 => Ok(()),
            _ => Err(Error::new(
                ErrorCode::InvalidArgument,
                "exit status must contain either an exit code in 0..=255 or a positive signal; \
                 oomKilled requires signal termination",
            )
            .for_operation("validate-exit-status")),
        }
    }
}

/// Captured process output stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

/// One globally ordered output frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputChunk {
    /// Inclusive cursor immediately after this frame.
    ///
    /// Data frames advance the cursor by `data.len()` bytes. An EOF frame has
    /// empty data and advances it by one logical position. This permits exact
    /// pagination through a partially returned driver frame.
    pub sequence: u64,
    /// Descriptor from which the frame was drained.
    pub stream: OutputStream,
    /// Raw output bytes. Non-EOF frames are never empty.
    pub data: Vec<u8>,
    /// Whether this is the final frame for `stream`.
    pub eof: bool,
}

/// CPU counters normalized across native and utility-VM drivers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuStats {
    pub usage_ns: u64,
    pub user_ns: u64,
    pub system_ns: u64,
    pub throttled_ns: u64,
}

/// Memory counters normalized across drivers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryStats {
    pub usage_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_bytes: Option<u64>,
}

/// Aggregate bytes read by the workload across all block devices.
pub const IO_READ_BYTES_METRIC: &str = "io.read_bytes";

/// Aggregate bytes written by the workload across all block devices.
pub const IO_WRITE_BYTES_METRIC: &str = "io.write_bytes";

/// Effective cgroup process limit, with [`u64::MAX`] representing `pids.max=max`.
pub const PIDS_LIMIT_METRIC: &str = "pids.limit";

/// Runtime resource snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerStats {
    pub target: ContainerTarget,
    pub timestamp_unix_ns: u64,
    pub cpu: CpuStats,
    pub memory: MemoryStats,
    pub process_count: u64,
    /// Driver-specific counters remain typed as named integer metrics.
    pub metrics: BTreeMap<String, u64>,
}

impl ContainerStats {
    /// Validate normalized counters returned by a runtime driver.
    pub fn validate(&self) -> Result<()> {
        if self.timestamp_unix_ns == 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "container stats timestamp must be a positive Unix nanosecond value",
            )
            .for_operation("validate-container-stats"));
        }
        let accounted = self
            .cpu
            .user_ns
            .checked_add(self.cpu.system_ns)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "container CPU user and system counters overflow",
                )
                .for_operation("validate-container-stats")
            })?;
        if accounted > self.cpu.usage_ns {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "container CPU user and system counters exceed total usage",
            )
            .for_operation("validate-container-stats"));
        }
        if self
            .memory
            .peak_bytes
            .is_some_and(|peak| peak < self.memory.usage_bytes)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "container memory peak is below current usage",
            )
            .for_operation("validate-container-stats"));
        }
        if let Some(name) = self.metrics.keys().find(|name| {
            name.is_empty()
                || name.len() > 256
                || name
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
        }) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("container metric name is invalid: {name:?}"),
            )
            .for_operation("validate-container-stats"));
        }
        Ok(())
    }
}

/// Ordered lifecycle or process event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeEventKind {
    ContainerCreating,
    ContainerCreated,
    ContainerStarted,
    ContainerStopped,
    ContainerDeleted,
    ContainerPaused,
    ContainerResumed,
    ResourcesUpdated,
    ProcessCreated,
    ProcessStarted,
    ProcessExited,
    OutputDropped,
    RuntimeWarning,
}

/// Ordered lifecycle or process event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    /// Nonzero global sequence assigned by the durable host journal.
    pub sequence: u64,
    /// Host commit timestamp in nanoseconds since the Unix epoch.
    pub timestamp_unix_ns: u64,
    /// Exact container generation that produced the event.
    pub container: ContainerTarget,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_id: Option<ProcessId>,
    pub kind: RuntimeEventKind,
    pub attributes: BTreeMap<String, String>,
}

/// One bounded event poll result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventBatch {
    pub events: Vec<RuntimeEvent>,
    /// Exclusive cursor for the next poll. This may advance past nonmatching
    /// events when a container filter is active.
    pub next_sequence: u64,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        ContainerId, ContainerStats, ContainerTarget, CpuStats, ExitStatus, Generation,
        MemoryStats, Signal,
    };

    #[test]
    fn signal_deserialization_cannot_bypass_validation() {
        assert_eq!(
            serde_json::from_str::<Signal>("9")
                .expect("positive signal")
                .get(),
            9
        );
        assert!(serde_json::from_str::<Signal>("0").is_err());
        assert!(serde_json::from_str::<Signal>("-9").is_err());
    }

    #[test]
    fn exit_status_requires_one_valid_terminal_outcome() {
        assert_eq!(
            ExitStatus::exited(42).expect("normal exit"),
            ExitStatus {
                exit_code: Some(42),
                signal: None,
                oom_killed: false,
            }
        );
        assert_eq!(
            ExitStatus::signaled(9, true).expect("signal exit"),
            ExitStatus {
                exit_code: None,
                signal: Some(9),
                oom_killed: true,
            }
        );
        for status in [
            ExitStatus {
                exit_code: None,
                signal: None,
                oom_killed: false,
            },
            ExitStatus {
                exit_code: Some(0),
                signal: Some(9),
                oom_killed: false,
            },
            ExitStatus {
                exit_code: Some(256),
                signal: None,
                oom_killed: false,
            },
            ExitStatus {
                exit_code: Some(1),
                signal: None,
                oom_killed: true,
            },
        ] {
            assert!(status.validate().is_err(), "{status:?} must be rejected");
        }
        assert!(serde_json::from_str::<ExitStatus>(
            r#"{"exit_code":0,"signal":9,"oom_killed":false}"#
        )
        .is_err());
    }

    #[test]
    fn container_stats_reject_inconsistent_normalized_counters() {
        let mut stats = ContainerStats {
            target: ContainerTarget::exact(
                ContainerId::new("stats-test").expect("container ID"),
                Generation(1),
            ),
            timestamp_unix_ns: 1,
            cpu: CpuStats {
                usage_ns: 30,
                user_ns: 10,
                system_ns: 20,
                throttled_ns: 0,
            },
            memory: MemoryStats {
                usage_bytes: 1_024,
                limit_bytes: Some(4_096),
                peak_bytes: Some(2_048),
            },
            process_count: 1,
            metrics: BTreeMap::from([("memory.events.oom_kill".to_string(), 0)]),
        };
        stats.validate().expect("valid stats");

        stats.cpu.system_ns = 21;
        assert!(stats.validate().is_err());
        stats.cpu.system_ns = 20;
        stats.memory.peak_bytes = Some(1_023);
        assert!(stats.validate().is_err());
        stats.memory.peak_bytes = Some(2_048);
        stats.metrics.insert("invalid metric".into(), 1);
        assert!(stats.validate().is_err());
    }
}
