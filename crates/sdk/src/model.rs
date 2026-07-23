use std::collections::BTreeMap;
use std::path::PathBuf;

use a3s_oci_core::{DriverKind, IsolationClass, RuntimeFeatures};
use oci_spec::runtime::{Features, LinuxResources, Process, State};
use serde::{de, Deserialize, Deserializer, Serialize};

use crate::{
    ContainerId, Error, ErrorCode, Generation, OciBundle, OperationId, ProcessId, Result,
    TrustDomainId,
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
    pub io: ProcessIo,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<ContainerTarget>,
    pub after_sequence: u64,
    pub limit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_timeout_ms: Option<u64>,
}

/// Read captured stdout or stderr after a sequence cursor.
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
    pub process: ProcessTarget,
    pub data: Vec<u8>,
}

/// Close a process's standard input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseStdinRequest {
    pub process: ProcessTarget,
}

/// Resize a process terminal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResizeRequest {
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
    pub io: ProcessIo,
}

/// Durable runtime state with generation and effective isolation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerRecord {
    pub state: State,
    pub generation: Generation,
    pub driver: DriverKind,
    pub isolation: IsolationClass,
    pub config_digest: String,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    pub oom_killed: bool,
}

/// Captured process output stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

/// One ordered output frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputChunk {
    pub sequence: u64,
    pub stream: OutputStream,
    pub data: Vec<u8>,
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
    pub sequence: u64,
    pub timestamp_unix_ns: u64,
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
    pub next_sequence: u64,
}

#[cfg(test)]
mod tests {
    use super::Signal;

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
}
