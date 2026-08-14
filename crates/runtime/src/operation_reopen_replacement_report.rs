use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultPoint, AgentTransportOperationStage,
    AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::oci_spec::runtime::LinuxResources;
use a3s_oci_sdk::{
    ContainerId, ContainerStats, DeleteMode, ErrorCode, ExitStatus, FileOp, FilesystemOp,
    Generation, OperationId, OutputChunk, ProcessId, ProcessRecord, TerminalSize,
};
use serde::{Deserialize, Serialize};

use crate::report::AgentVmSmokeReport;

/// Schema emitted by the real HVF non-Create reopen and owner-replacement diagnostic.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v3";

/// Delete schema with exact stopped-only journal and no-live-record evidence.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_DELETE_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v4";

/// Wait schema with durable init-exit cache and dispatch-free replay evidence.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_WAIT_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v5";

/// Exec schema with exact live-process rehydration and journal-rebind evidence.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_EXEC_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v6";

/// SignalProcess schema with exact live-process signal replay and marker evidence.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_SIGNAL_PROCESS_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v7";

/// WaitProcess schema with exact Exec-exit cache and replay evidence.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_WAIT_PROCESS_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v8";

/// Pause schema with exact freezer recovery and journal-rebind evidence.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_PAUSE_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v9";

/// Resume schema with paused setup reconstruction and journal-rebind evidence.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_RESUME_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v10";

/// Processes schema with exact rebuilt live-inventory evidence.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_PROCESSES_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v11";

/// Update schema with exact resource replay and replacement Stats evidence.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_UPDATE_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v12";

/// Stats schema with fresh-owner resource snapshot evidence.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_STATS_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v13";

/// ReadOutput schema with rebuilt captured-output evidence.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_READ_OUTPUT_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v14";

/// WriteStdin schema with committed-input replay in the replacement Exec.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_WRITE_STDIN_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v15";

/// CloseStdin schema with committed-EOF replay in the replacement Exec.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_CLOSE_STDIN_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v16";

/// Resize schema with committed terminal dimensions replayed in the replacement Exec.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_RESIZE_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v17";

/// File schema with a durable Host upload rebuilt in the replacement Guest.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_FILE_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v18";

/// Filesystem schema with a durable Host mkdir rebuilt in the replacement Guest.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_FILESYSTEM_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v19";

/// Start schema retained for compatibility with existing evidence.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_START_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v2";

/// Original State-only schema retained for compatibility with existing evidence.
pub const OCI_VM_OPERATION_REOPEN_REPLACEMENT_STATE_SCHEMA_VERSION: &str =
    "a3s.oci.oci-vm-operation-reopen-replacement.v1";

const QUALIFICATION_FAULT_OPERATION: &str = "oci-vm-transport-qualification-fault";

/// Retained evidence for one operation reissued through a replacement HVF owner.
///
/// Version 1 qualifies `state`, version 2 adds `start`, version 3 adds `kill`,
/// version 4 adds stopped-only `delete`, version 5 adds init `wait` with
/// durable terminal-cache evidence, version 6 adds live terminal `exec`
/// recovery, version 7 adds exact `signal-process` recovery, version 8 adds
/// non-init `wait-process` recovery, version 9 adds `pause` with durable
/// freezer-state recovery, and version 10 adds `resume` with exact paused
/// setup reconstruction, version 11 adds the exact `processes` inventory after
/// live init and Exec reconstruction, and version 12 adds exact `update`
/// resource replay with replacement Stats evidence, and version 13 adds a
/// fresh-owner `stats` query after committed Update reconstruction, version 14
/// adds rebuilt captured-output evidence, version 15 adds committed stdin-write
/// replay, version 16 adds committed stdin-close replay, and version 17 adds
/// committed terminal-resize replay, version 18 adds durable file-upload
/// reconstruction, and version 19 adds durable directory reconstruction.
/// Earlier operations continue to emit their compatible schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciVmOperationReopenReplacementReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the diagnostic was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of this exact recovery path.
    pub status: CapabilityStatus,
    /// Whether the host loaded and validated the submitted OCI bundle.
    pub bundle_loaded: bool,
    /// Operation interrupted at the selected point in the first VM session.
    pub requested_operation: AgentOperation,
    /// Exact signal selected by a Kill qualification or Delete setup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_signal: Option<i32>,
    /// Whether a Kill qualification or Delete setup targets every process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_all: Option<bool>,
    /// Cleanup mode selected by a Delete qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_mode: Option<DeleteMode>,
    /// Maximum init Wait duration used by a Wait qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_timeout_ms: Option<u64>,
    /// Maximum non-init WaitProcess duration used by a qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_process_timeout_ms: Option<u64>,
    /// Exact signal-derived exit result required from every Wait observation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_exit_status: Option<ExitStatus>,
    /// Exit result delivered by the first owner, when its response committed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_wait_exit_status: Option<ExitStatus>,
    /// Exit result returned by the first Wait call after Host reopen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_wait_exit_status: Option<ExitStatus>,
    /// Exit result returned by a later durable-cache replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_wait_exit_status: Option<ExitStatus>,
    /// Caller-selected non-init process ID used by an Exec qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_process_id: Option<ProcessId>,
    /// Terminal mode bound to the complete Exec request and recovered process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_terminal: Option<bool>,
    /// Exact positive Linux signal used by a SignalProcess qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_process_signal: Option<i32>,
    /// Exact bytes bound to a WriteStdin qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_stdin_data: Option<Vec<u8>>,
    /// Exact positive terminal dimensions bound to a Resize qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resize_size: Option<TerminalSize>,
    /// File transfer operation selected by a File qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_op: Option<FileOp>,
    /// Exact container path selected by a File qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    /// Exact base64 payload selected by an upload qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_data: Option<String>,
    /// Optional container account selected by a File qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_user: Option<String>,
    /// Filesystem operation selected by a Filesystem qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem_op: Option<FilesystemOp>,
    /// Exact primary path selected by a Filesystem qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem_path: Option<String>,
    /// Optional destination path selected by a Filesystem qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem_destination: Option<String>,
    /// Directory traversal depth selected by a Filesystem qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem_depth: Option<u32>,
    /// Optional container account selected by a Filesystem qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem_user: Option<String>,
    /// Inclusive captured-output cursor used by a ReadOutput qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_output_after_sequence: Option<u64>,
    /// Maximum captured payload used by a ReadOutput qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_output_max_bytes: Option<u32>,
    /// Long-poll timeout used by a ReadOutput qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_output_wait_timeout_ms: Option<u64>,
    /// Exact nonce-bound output required from both owners.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_output_chunks: Option<Vec<OutputChunk>>,
    /// Complete OCI Linux resource profile bound to an Update qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_resources: Option<LinuxResources>,
    /// Exact Host or Guest transport point used to force the owner handoff.
    pub requested_stage: AgentTransportOperationStage,
    /// Nonce bound to the armed qualification and retained Guest evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualification_operation_id: Option<OperationId>,
    /// Stable Create identity used to rebuild the pre-start process after reopen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_create_operation_id: Option<OperationId>,
    /// Stable Start identity used to rebuild a running process after reopen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_start_operation_id: Option<OperationId>,
    /// Stable Kill identity used to rebuild the stopped Guest tombstone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_kill_operation_id: Option<OperationId>,
    /// Stable Exec identity used to rebuild the signalable process after reopen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_exec_operation_id: Option<OperationId>,
    /// Stable SignalProcess identity used to terminate a WaitProcess target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_signal_process_operation_id: Option<OperationId>,
    /// Stable Pause identity used to prepare a Resume qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_pause_operation_id: Option<OperationId>,
    /// Stable Update identity used to establish a Stats resource baseline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_update_operation_id: Option<OperationId>,
    /// Container identity retained in durable host state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<ContainerId>,
    /// Negotiated protocol version observed at the injected point.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub negotiated_protocol: Option<u16>,
    /// Exact versioned point reached by the one-shot injector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injected_point: Option<String>,
    /// Number of times the selected point was crossed.
    pub fault_crossings: u32,
    /// Stable error class returned by the first operation or disconnect probe.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_operation_error_code: Option<ErrorCode>,
    /// Operation attached to the first operation or disconnect-probe error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_operation_error_operation: Option<String>,
    /// Whether the first-owner error explicitly allowed the operation to be reissued.
    pub first_operation_error_retryable: bool,
    /// Whether the first owner delivered the selected operation's complete response.
    pub first_operation_response_received: bool,
    /// Whether a follow-up request exposed a post-response disconnect.
    pub disconnect_probe_attempted: bool,
    /// Whether the first driver's completed response exactly matched the durable record.
    pub first_response_matches_durable_record: bool,
    /// Whether a delivered first Wait response matched the required exit result.
    #[serde(default)]
    pub first_response_matches_expected_exit: bool,
    /// Whether the interrupted operation left the exact durable record in `created`.
    pub durable_created_retained: bool,
    /// Whether a delivered mutating response left the exact durable record in `running`.
    #[serde(default)]
    pub durable_running_retained: bool,
    /// Whether the durable running record retained an applied freezer state.
    #[serde(default)]
    pub durable_paused_retained: bool,
    /// Whether a delivered Kill response left the exact durable record in `stopped`.
    #[serde(default)]
    pub durable_stopped_retained: bool,
    /// Whether the first owner retained no live container record.
    #[serde(default)]
    pub first_durable_records_empty: bool,
    /// Whether the Delete journal was still prepared before Host reopen.
    #[serde(default)]
    pub delete_journal_prepared_before_reopen: bool,
    /// Whether the Delete journal had already reached `SucceededEmpty` before reopen.
    #[serde(default)]
    pub delete_journal_succeeded_empty_before_reopen: bool,
    /// Whether the exact init exit result was durably cached before Host reopen.
    #[serde(default)]
    pub init_exit_cached_before_reopen: bool,
    /// Whether the Exec journal remained prepared before Host reopen.
    #[serde(default)]
    pub exec_journal_prepared_before_reopen: bool,
    /// Whether the Exec journal already held a completed process response.
    #[serde(default)]
    pub exec_journal_succeeded_before_reopen: bool,
    /// Whether the SignalProcess journal remained prepared before Host reopen.
    #[serde(default)]
    pub signal_process_journal_prepared_before_reopen: bool,
    /// Whether the SignalProcess journal had reached `SucceededEmpty` before reopen.
    #[serde(default)]
    pub signal_process_journal_succeeded_before_reopen: bool,
    /// Whether the WriteStdin journal remained prepared before Host reopen.
    #[serde(default)]
    pub write_stdin_journal_prepared_before_reopen: bool,
    /// Whether the WriteStdin journal had reached SucceededEmpty before reopen.
    #[serde(default)]
    pub write_stdin_journal_succeeded_before_reopen: bool,
    /// Whether the CloseStdin journal remained prepared before Host reopen.
    #[serde(default)]
    pub close_stdin_journal_prepared_before_reopen: bool,
    /// Whether the CloseStdin journal had reached SucceededEmpty before reopen.
    #[serde(default)]
    pub close_stdin_journal_succeeded_before_reopen: bool,
    /// Whether the Resize journal remained prepared before Host reopen.
    #[serde(default)]
    pub resize_journal_prepared_before_reopen: bool,
    /// Whether the Resize journal had reached SucceededEmpty before reopen.
    #[serde(default)]
    pub resize_journal_succeeded_before_reopen: bool,
    /// Whether the Pause journal remained prepared before Host reopen.
    #[serde(default)]
    pub pause_journal_prepared_before_reopen: bool,
    /// Whether the Pause journal already held a completed paused response.
    #[serde(default)]
    pub pause_journal_succeeded_before_reopen: bool,
    /// Whether the Resume journal remained prepared before Host reopen.
    #[serde(default)]
    pub resume_journal_prepared_before_reopen: bool,
    /// Whether the Resume journal already held a completed running response.
    #[serde(default)]
    pub resume_journal_succeeded_before_reopen: bool,
    /// Whether the Update journal remained prepared before Host reopen.
    #[serde(default)]
    pub update_journal_prepared_before_reopen: bool,
    /// Whether the Update journal already held a completed running response.
    #[serde(default)]
    pub update_journal_succeeded_before_reopen: bool,
    /// Whether the exact non-init exit result was durably cached before Host reopen.
    #[serde(default)]
    pub process_exit_cached_before_reopen: bool,
    /// Positive init PID retained from the first owner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_created_pid: Option<i32>,
    /// Positive Exec PID committed by the first owner, when its response arrived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_exec_pid: Option<u32>,
    /// Exact live inventory returned by the first Processes query, when delivered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_process_inventory: Option<Vec<ProcessRecord>>,
    /// Resource snapshot returned by the first Stats owner, when delivered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_stats_snapshot: Option<ContainerStats>,
    /// Captured chunks returned by the first ReadOutput owner, when delivered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_output_chunks: Option<Vec<OutputChunk>>,
    /// Generation retained before the first host service closed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation_before_reopen: Option<Generation>,
    /// Whether nonce-bound Guest console evidence passed exact validation.
    pub guest_evidence_verified: bool,
    /// Qualification nonce decoded independently from Guest console evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_evidence_operation_id: Option<OperationId>,
    /// Whether a new `HostRuntimeService` opened the same durable root.
    pub host_service_reopened: bool,
    /// Number of durable records accepted by the replacement driver's recovery hook.
    pub replacement_recovery_calls: u32,
    /// Whether recovery rebuilt the first owner's pre-start process in the fresh Guest.
    pub replacement_rehydrated_created_record: bool,
    /// Whether recovery also restarted that process before reopening a running record.
    #[serde(default)]
    pub replacement_rehydrated_running_record: bool,
    /// Whether recovery killed the replacement process before reopening a stopped record.
    #[serde(default)]
    pub replacement_rehydrated_stopped_record: bool,
    /// Whether recovery rebuilt the completed live Exec in the fresh Guest.
    #[serde(default)]
    pub replacement_rehydrated_exec_record: bool,
    /// Whether recovery reapplied an already-committed signal to the rebuilt Exec.
    #[serde(default)]
    pub replacement_rehydrated_signal_process: bool,
    /// Whether recovery replayed a committed stdin write into the rebuilt Exec.
    #[serde(default)]
    pub replacement_rehydrated_write_stdin: bool,
    /// Whether recovery replayed a committed stdin close into the rebuilt Exec.
    #[serde(default)]
    pub replacement_rehydrated_close_stdin: bool,
    /// Whether recovery replayed committed terminal dimensions into the rebuilt Exec.
    #[serde(default)]
    pub replacement_rehydrated_resize: bool,
    /// Whether recovery rebuilt a delivered upload and its Guest journal.
    #[serde(default)]
    pub replacement_rehydrated_file: bool,
    /// Whether recovery rebuilt a delivered mkdir and its Guest journal.
    #[serde(default)]
    pub replacement_rehydrated_filesystem: bool,
    /// Whether recovery reapplied an already-committed Pause to the rebuilt init.
    #[serde(default)]
    pub replacement_rehydrated_paused_record: bool,
    /// Whether recovery replayed the committed Resume after rebuilding Pause.
    #[serde(default)]
    pub replacement_rehydrated_resumed_record: bool,
    /// Whether recovery reapplied a committed Update to the fresh Guest.
    #[serde(default)]
    pub replacement_rehydrated_update: bool,
    /// Whether the selected operation completed through the replacement owner.
    pub operation_completed_after_reopen: bool,
    /// Generation returned by the replacement operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation_after_reopen: Option<Generation>,
    /// Positive init PID observed through the replacement Guest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement_created_pid: Option<i32>,
    /// Positive Exec PID returned by the replacement Guest and durable replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_exec_pid: Option<u32>,
    /// Exact live inventory returned by the replacement Processes query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_process_inventory: Option<Vec<ProcessRecord>>,
    /// Replacement resource snapshot retained as concrete Update effect evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_update_stats: Option<ContainerStats>,
    /// Resource snapshot returned by the replacement Stats owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_stats_snapshot: Option<ContainerStats>,
    /// Captured chunks returned by the replacement ReadOutput owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_output_chunks: Option<Vec<OutputChunk>>,
    /// Whether the replacement response exactly matched the recovered durable record.
    pub replacement_response_matches_durable_record: bool,
    /// Whether the replacement Wait response matched the required exit result.
    #[serde(default)]
    pub replacement_response_matches_expected_exit: bool,
    /// Whether the later cached Wait response matched the required exit result.
    #[serde(default)]
    pub cached_response_matches_expected_exit: bool,
    /// Whether the exact init exit result was durable after replacement Wait.
    #[serde(default)]
    pub init_exit_cached_after_reopen: bool,
    /// Whether the exact non-init exit result was durable after replacement WaitProcess.
    #[serde(default)]
    pub process_exit_cached_after_reopen: bool,
    /// Whether a delivered first Processes response was an exact live inventory.
    #[serde(default)]
    pub first_process_inventory_verified: bool,
    /// Whether the replacement Processes response was an exact rebuilt inventory.
    #[serde(default)]
    pub replacement_process_inventory_verified: bool,
    /// Whether logical process identities were rebound to the replacement PIDs.
    #[serde(default)]
    pub process_inventory_rebound: bool,
    /// Whether repeated replacement Stats proved the exact updated cgroup profile.
    #[serde(default)]
    pub replacement_update_effect_verified: bool,
    /// Whether a delivered first Stats response matched the configured profile.
    #[serde(default)]
    pub first_stats_verified: bool,
    /// Whether replacement Stats matched the rebuilt configured profile.
    #[serde(default)]
    pub replacement_stats_verified: bool,
    /// Whether a delivered first snapshot was replaced by fresh-owner evidence.
    #[serde(default)]
    pub stats_snapshot_rebound: bool,
    /// Whether a delivered first ReadOutput response matched the expected chunks.
    #[serde(default)]
    pub first_output_verified: bool,
    /// Whether replacement ReadOutput returned the exact rebuilt chunks.
    #[serde(default)]
    pub replacement_output_verified: bool,
    /// Whether replacement output was read from the rebuilt Exec process.
    #[serde(default)]
    pub output_response_rebound: bool,
    /// Whether a delivered first File response matched the exact upload.
    #[serde(default)]
    pub first_file_response_verified: bool,
    /// Whether the replacement File response matched the exact upload.
    #[serde(default)]
    pub replacement_file_response_verified: bool,
    /// Whether a repeated replacement upload returned the same durable Host response.
    #[serde(default)]
    pub file_response_replayed: bool,
    /// Whether a replacement download observed the exact uploaded bytes.
    #[serde(default)]
    pub replacement_file_effect_verified: bool,
    /// Whether a delivered first Filesystem response matched the exact mkdir.
    #[serde(default)]
    pub first_filesystem_response_verified: bool,
    /// Whether the replacement Filesystem response matched the exact mkdir.
    #[serde(default)]
    pub replacement_filesystem_response_verified: bool,
    /// Whether a repeated replacement mkdir returned the same durable Host response.
    #[serde(default)]
    pub filesystem_response_replayed: bool,
    /// Whether replacement Stat observed the exact created directory.
    #[serde(default)]
    pub replacement_filesystem_effect_verified: bool,
    /// Whether the exact durable generation was observed across the owner handoff.
    pub same_generation_reused: bool,
    /// Whether replacement recovery reused the original setup Create identity.
    pub setup_create_identity_reused: bool,
    /// Whether replacement recovery reused the original setup Start identity.
    #[serde(default)]
    pub setup_start_identity_reused: bool,
    /// Whether replacement recovery reused the original setup Kill identity.
    #[serde(default)]
    pub setup_kill_identity_reused: bool,
    /// Whether the interrupted operation reused its original identity in the fresh Guest.
    #[serde(default)]
    pub same_operation_id_reused: bool,
    /// Whether Create replay was rebound to the replacement process PID.
    #[serde(default)]
    pub setup_create_response_rebound: bool,
    /// Whether Start replay was rebound to the replacement process PID.
    #[serde(default)]
    pub setup_start_response_rebound: bool,
    /// Whether the completed Exec response was rebound to the replacement PID.
    #[serde(default)]
    pub exec_response_rebound: bool,
    /// Whether the completed Pause response was rebound to the replacement PID.
    #[serde(default)]
    pub pause_response_rebound: bool,
    /// Whether the completed Resume response was rebound to the replacement PID.
    #[serde(default)]
    pub resume_response_rebound: bool,
    /// Whether the completed Update response was rebound to the replacement PID.
    #[serde(default)]
    pub update_response_rebound: bool,
    /// Whether replacement dispatch reused the complete first-owner Exec request.
    #[serde(default)]
    pub exec_request_identity_reused: bool,
    /// Whether replacement dispatch reused the complete first-owner SignalProcess request.
    #[serde(default)]
    pub signal_process_request_identity_reused: bool,
    /// Whether replacement dispatch reused the complete first-owner WriteStdin request.
    #[serde(default)]
    pub write_stdin_request_identity_reused: bool,
    /// Whether replacement dispatch reused the complete first-owner CloseStdin request.
    #[serde(default)]
    pub close_stdin_request_identity_reused: bool,
    /// Whether replacement dispatch reused the complete first-owner Resize request.
    #[serde(default)]
    pub resize_request_identity_reused: bool,
    /// Whether replacement dispatch reused the complete first-owner File request.
    #[serde(default)]
    pub file_request_identity_reused: bool,
    /// Whether replacement dispatch reused the complete first-owner Filesystem request.
    #[serde(default)]
    pub filesystem_request_identity_reused: bool,
    /// Whether replacement dispatch reused the exact first-owner Pause request.
    #[serde(default)]
    pub pause_request_identity_reused: bool,
    /// Whether replacement dispatch reused the exact first-owner Resume request.
    #[serde(default)]
    pub resume_request_identity_reused: bool,
    /// Whether replacement dispatch reused the complete first-owner Update request.
    #[serde(default)]
    pub update_request_identity_reused: bool,
    /// Whether both Processes dispatches resolved the same exact container target.
    #[serde(default)]
    pub processes_request_target_reused: bool,
    /// Whether both Stats dispatches resolved the same exact container target.
    #[serde(default)]
    pub stats_request_target_reused: bool,
    /// Whether both ReadOutput dispatches reused the complete resolved request.
    #[serde(default)]
    pub read_output_request_identity_reused: bool,
    /// Whether replacement WaitProcess reused the exact resolved target and timeout.
    #[serde(default)]
    pub wait_process_request_identity_reused: bool,
    /// Whether the post-recovery operation replay avoided another driver dispatch.
    #[serde(default)]
    pub operation_replayed_without_driver_dispatch: bool,
    /// Whether a later Wait returned from cache without another driver dispatch.
    #[serde(default)]
    pub cached_wait_replayed_without_driver_dispatch: bool,
    /// Number of operation dispatches recorded by the first qualification driver.
    #[serde(default)]
    pub first_operation_dispatches: u32,
    /// Number of operation dispatches recorded by replacement, including recovery rebuilds.
    #[serde(default)]
    pub replacement_operation_dispatches: u32,
    /// Whether a stale exact generation was rejected before Host driver dispatch.
    #[serde(default)]
    pub host_stale_generation_rejected: bool,
    /// Whether a stale exact generation was rejected by the replacement Guest.
    #[serde(default)]
    pub guest_stale_generation_rejected: bool,
    /// Whether a changed Host retry was rejected before another Exec dispatch.
    #[serde(default)]
    pub host_changed_request_rejected: bool,
    /// Whether the replacement Guest rejected a changed request with the same operation ID.
    #[serde(default)]
    pub guest_changed_request_rejected: bool,
    /// Whether any first-owner workload marker was removed before replacement launch.
    #[serde(default)]
    pub marker_reset_before_replacement: bool,
    /// Whether the replacement workload produced the exact configured marker.
    #[serde(default)]
    pub replacement_workload_verified: bool,
    /// Whether a first Exec marker was absent when allowed or exactly nonce-bound when observed.
    #[serde(default)]
    pub first_exec_marker_verified: bool,
    /// Whether the first Exec marker was removed before replacement launch.
    #[serde(default)]
    pub exec_marker_reset_before_replacement: bool,
    /// Whether the replacement Exec wrote the exact nonce-bound marker.
    #[serde(default)]
    pub replacement_exec_marker_verified: bool,
    /// Whether first-owner signal-marker state matched the selected transport stage.
    #[serde(default)]
    pub first_signal_marker_verified: bool,
    /// Whether the first signal marker was removed before replacement launch.
    #[serde(default)]
    pub signal_marker_reset_before_replacement: bool,
    /// Whether the replacement Exec observed the exact nonce-bound signal.
    #[serde(default)]
    pub replacement_signal_marker_verified: bool,
    /// Whether first-owner stdin-effect marker state matched the transport stage.
    #[serde(default)]
    pub first_write_marker_verified: bool,
    /// Whether the first stdin-effect marker was removed before replacement launch.
    #[serde(default)]
    pub write_marker_reset_before_replacement: bool,
    /// Whether the replacement Exec consumed the exact nonce-bound stdin bytes.
    #[serde(default)]
    pub replacement_write_marker_verified: bool,
    /// Whether first-owner stdin-close marker state matched the transport stage.
    #[serde(default)]
    pub first_close_marker_verified: bool,
    /// Whether the first stdin-close marker was removed before replacement launch.
    #[serde(default)]
    pub close_marker_reset_before_replacement: bool,
    /// Whether the replacement Exec observed EOF and wrote the exact marker.
    #[serde(default)]
    pub replacement_close_marker_verified: bool,
    /// Whether first-owner terminal-size marker state matched the transport stage.
    #[serde(default)]
    pub first_resize_marker_verified: bool,
    /// Whether the first terminal-size marker was removed before replacement launch.
    #[serde(default)]
    pub resize_marker_reset_before_replacement: bool,
    /// Whether the replacement Exec observed and recorded the exact dimensions.
    #[serde(default)]
    pub replacement_resize_marker_verified: bool,
    /// Whether force delete completed through the replacement VM owner.
    pub force_delete_completed: bool,
    /// Whether stopped-only delete completed through the replacement VM owner.
    #[serde(default)]
    pub stopped_only_delete_completed: bool,
    /// Whether no durable container record remained after delete.
    pub durable_records_empty: bool,
    /// Whether the final Delete journal reached `SucceededEmpty` after reopen.
    #[serde(default)]
    pub delete_journal_succeeded_empty_after_reopen: bool,
    /// Whether the workload marker remained absent after complete cleanup.
    pub marker_absent_after_cleanup: bool,
    /// Whether the independent Exec marker remained absent after complete cleanup.
    #[serde(default)]
    pub exec_marker_absent_after_cleanup: bool,
    /// Whether the independent SignalProcess marker remained absent after cleanup.
    #[serde(default)]
    pub signal_marker_absent_after_cleanup: bool,
    /// Whether the independent WriteStdin effect marker remained absent after cleanup.
    #[serde(default)]
    pub write_marker_absent_after_cleanup: bool,
    /// Whether the independent CloseStdin effect marker remained absent after cleanup.
    #[serde(default)]
    pub close_marker_absent_after_cleanup: bool,
    /// Whether the independent Resize effect marker remained absent after cleanup.
    #[serde(default)]
    pub resize_marker_absent_after_cleanup: bool,
    /// Whether the uploaded qualification file was absent after explicit cleanup.
    #[serde(default)]
    pub file_effect_absent_after_cleanup: bool,
    /// Whether the qualification directory was absent after explicit cleanup.
    #[serde(default)]
    pub filesystem_effect_absent_after_cleanup: bool,
    /// Whether the first guest executor returned to its original runtime inventory.
    pub first_guest_runtime_clean: bool,
    /// Whether the replacement guest executor returned to the same inventory.
    pub replacement_guest_runtime_clean: bool,
    /// Whether endpoint, shim, and VM-worker identities prove two different owners.
    pub owners_distinct: bool,
    /// Whether the command removed its newly created qualification state root.
    pub state_root_removed: bool,
    /// First authenticated VM and host cleanup evidence.
    pub first_vm: AgentVmSmokeReport,
    /// Replacement authenticated VM and host cleanup evidence.
    pub replacement_vm: AgentVmSmokeReport,
    /// Diagnostic reason when the evidence was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl OciVmOperationReopenReplacementReport {
    pub(crate) fn initial_state(
        platform: HostPlatform,
        requested_stage: AgentTransportOperationStage,
    ) -> Self {
        Self {
            schema_version: OCI_VM_OPERATION_REOPEN_REPLACEMENT_STATE_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            bundle_loaded: false,
            requested_operation: AgentOperation::State,
            kill_signal: None,
            kill_all: None,
            delete_mode: None,
            wait_timeout_ms: None,
            wait_process_timeout_ms: None,
            expected_exit_status: None,
            first_wait_exit_status: None,
            replacement_wait_exit_status: None,
            cached_wait_exit_status: None,
            exec_process_id: None,
            exec_terminal: None,
            signal_process_signal: None,
            write_stdin_data: None,
            resize_size: None,
            file_op: None,
            file_path: None,
            file_data: None,
            file_user: None,
            filesystem_op: None,
            filesystem_path: None,
            filesystem_destination: None,
            filesystem_depth: None,
            filesystem_user: None,
            read_output_after_sequence: None,
            read_output_max_bytes: None,
            read_output_wait_timeout_ms: None,
            expected_output_chunks: None,
            update_resources: None,
            requested_stage,
            qualification_operation_id: None,
            setup_create_operation_id: None,
            setup_start_operation_id: None,
            setup_kill_operation_id: None,
            setup_exec_operation_id: None,
            setup_signal_process_operation_id: None,
            setup_pause_operation_id: None,
            setup_update_operation_id: None,
            container_id: None,
            negotiated_protocol: None,
            injected_point: None,
            fault_crossings: 0,
            first_operation_error_code: None,
            first_operation_error_operation: None,
            first_operation_error_retryable: false,
            first_operation_response_received: false,
            disconnect_probe_attempted: false,
            first_response_matches_durable_record: false,
            first_response_matches_expected_exit: false,
            durable_created_retained: false,
            durable_running_retained: false,
            durable_paused_retained: false,
            durable_stopped_retained: false,
            first_durable_records_empty: false,
            delete_journal_prepared_before_reopen: false,
            delete_journal_succeeded_empty_before_reopen: false,
            init_exit_cached_before_reopen: false,
            exec_journal_prepared_before_reopen: false,
            exec_journal_succeeded_before_reopen: false,
            signal_process_journal_prepared_before_reopen: false,
            signal_process_journal_succeeded_before_reopen: false,
            write_stdin_journal_prepared_before_reopen: false,
            write_stdin_journal_succeeded_before_reopen: false,
            close_stdin_journal_prepared_before_reopen: false,
            close_stdin_journal_succeeded_before_reopen: false,
            resize_journal_prepared_before_reopen: false,
            resize_journal_succeeded_before_reopen: false,
            pause_journal_prepared_before_reopen: false,
            pause_journal_succeeded_before_reopen: false,
            resume_journal_prepared_before_reopen: false,
            resume_journal_succeeded_before_reopen: false,
            update_journal_prepared_before_reopen: false,
            update_journal_succeeded_before_reopen: false,
            process_exit_cached_before_reopen: false,
            first_created_pid: None,
            first_exec_pid: None,
            first_process_inventory: None,
            first_stats_snapshot: None,
            first_output_chunks: None,
            generation_before_reopen: None,
            guest_evidence_verified: false,
            guest_evidence_operation_id: None,
            host_service_reopened: false,
            replacement_recovery_calls: 0,
            replacement_rehydrated_created_record: false,
            replacement_rehydrated_running_record: false,
            replacement_rehydrated_stopped_record: false,
            replacement_rehydrated_exec_record: false,
            replacement_rehydrated_signal_process: false,
            replacement_rehydrated_write_stdin: false,
            replacement_rehydrated_close_stdin: false,
            replacement_rehydrated_resize: false,
            replacement_rehydrated_file: false,
            replacement_rehydrated_filesystem: false,
            replacement_rehydrated_paused_record: false,
            replacement_rehydrated_resumed_record: false,
            replacement_rehydrated_update: false,
            operation_completed_after_reopen: false,
            generation_after_reopen: None,
            replacement_created_pid: None,
            replacement_exec_pid: None,
            replacement_process_inventory: None,
            replacement_update_stats: None,
            replacement_stats_snapshot: None,
            replacement_output_chunks: None,
            replacement_response_matches_durable_record: false,
            replacement_response_matches_expected_exit: false,
            cached_response_matches_expected_exit: false,
            init_exit_cached_after_reopen: false,
            process_exit_cached_after_reopen: false,
            first_process_inventory_verified: false,
            replacement_process_inventory_verified: false,
            process_inventory_rebound: false,
            replacement_update_effect_verified: false,
            first_stats_verified: false,
            replacement_stats_verified: false,
            stats_snapshot_rebound: false,
            first_output_verified: false,
            replacement_output_verified: false,
            output_response_rebound: false,
            first_file_response_verified: false,
            replacement_file_response_verified: false,
            file_response_replayed: false,
            replacement_file_effect_verified: false,
            first_filesystem_response_verified: false,
            replacement_filesystem_response_verified: false,
            filesystem_response_replayed: false,
            replacement_filesystem_effect_verified: false,
            same_generation_reused: false,
            setup_create_identity_reused: false,
            setup_start_identity_reused: false,
            setup_kill_identity_reused: false,
            same_operation_id_reused: false,
            setup_create_response_rebound: false,
            setup_start_response_rebound: false,
            exec_response_rebound: false,
            pause_response_rebound: false,
            resume_response_rebound: false,
            update_response_rebound: false,
            exec_request_identity_reused: false,
            signal_process_request_identity_reused: false,
            write_stdin_request_identity_reused: false,
            close_stdin_request_identity_reused: false,
            resize_request_identity_reused: false,
            file_request_identity_reused: false,
            filesystem_request_identity_reused: false,
            pause_request_identity_reused: false,
            resume_request_identity_reused: false,
            update_request_identity_reused: false,
            processes_request_target_reused: false,
            stats_request_target_reused: false,
            read_output_request_identity_reused: false,
            wait_process_request_identity_reused: false,
            operation_replayed_without_driver_dispatch: false,
            cached_wait_replayed_without_driver_dispatch: false,
            first_operation_dispatches: 0,
            replacement_operation_dispatches: 0,
            host_stale_generation_rejected: false,
            guest_stale_generation_rejected: false,
            host_changed_request_rejected: false,
            guest_changed_request_rejected: false,
            marker_reset_before_replacement: false,
            replacement_workload_verified: false,
            first_exec_marker_verified: false,
            exec_marker_reset_before_replacement: false,
            replacement_exec_marker_verified: false,
            first_signal_marker_verified: false,
            signal_marker_reset_before_replacement: false,
            replacement_signal_marker_verified: false,
            first_write_marker_verified: false,
            write_marker_reset_before_replacement: false,
            replacement_write_marker_verified: false,
            first_close_marker_verified: false,
            close_marker_reset_before_replacement: false,
            replacement_close_marker_verified: false,
            first_resize_marker_verified: false,
            resize_marker_reset_before_replacement: false,
            replacement_resize_marker_verified: false,
            force_delete_completed: false,
            stopped_only_delete_completed: false,
            durable_records_empty: false,
            delete_journal_succeeded_empty_after_reopen: false,
            marker_absent_after_cleanup: false,
            exec_marker_absent_after_cleanup: false,
            signal_marker_absent_after_cleanup: false,
            write_marker_absent_after_cleanup: false,
            close_marker_absent_after_cleanup: false,
            resize_marker_absent_after_cleanup: false,
            file_effect_absent_after_cleanup: false,
            filesystem_effect_absent_after_cleanup: false,
            first_guest_runtime_clean: false,
            replacement_guest_runtime_clean: false,
            owners_distinct: false,
            state_root_removed: false,
            first_vm: AgentVmSmokeReport::initial(platform),
            replacement_vm: AgentVmSmokeReport::initial(platform),
            reason: None,
        }
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub(crate) fn unsupported_state(
        platform: HostPlatform,
        requested_stage: AgentTransportOperationStage,
    ) -> Self {
        let mut report = Self::initial_state(platform, requested_stage);
        report.status = CapabilityStatus::Unsupported;
        report.first_vm.status = CapabilityStatus::Unsupported;
        report.first_vm.reason = Some("the first HVF owner was not started".to_string());
        report.replacement_vm.status = CapabilityStatus::Unsupported;
        report.replacement_vm.reason =
            Some("the replacement HVF owner was not started".to_string());
        report.reason = Some(
            "real utility-VM operation reopen and owner replacement is implemented only for macOS aarch64/HVF"
                .to_string(),
        );
        report
    }

    /// Return whether the exact operation handoff and both VM cleanup gates passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available) && self.evidence_succeeded()
    }

    pub(crate) fn evidence_succeeded(&self) -> bool {
        match self.requested_operation {
            AgentOperation::CloseStdin => self.close_stdin_evidence_succeeded(),
            AgentOperation::Delete => self.delete_evidence_succeeded(),
            AgentOperation::Exec => self.exec_evidence_succeeded(),
            AgentOperation::File => self.file_evidence_succeeded(),
            AgentOperation::Filesystem => self.filesystem_evidence_succeeded(),
            AgentOperation::Kill => self.kill_evidence_succeeded(),
            AgentOperation::Pause => self.pause_evidence_succeeded(),
            AgentOperation::Processes => self.processes_evidence_succeeded(),
            AgentOperation::ReadOutput => self.read_output_evidence_succeeded(),
            AgentOperation::Resize => self.resize_evidence_succeeded(),
            AgentOperation::Resume => self.resume_evidence_succeeded(),
            AgentOperation::Stats => self.stats_evidence_succeeded(),
            AgentOperation::SignalProcess => self.signal_process_evidence_succeeded(),
            AgentOperation::State => self.state_evidence_succeeded(),
            AgentOperation::Start => self.start_evidence_succeeded(),
            AgentOperation::Wait => self.wait_evidence_succeeded(),
            AgentOperation::WaitProcess => self.wait_process_evidence_succeeded(),
            AgentOperation::Update => self.update_evidence_succeeded(),
            AgentOperation::WriteStdin => self.write_stdin_evidence_succeeded(),
            _ => false,
        }
    }

    fn state_evidence_succeeded(&self) -> bool {
        let expected_point = AgentTransportFaultPoint::Operation {
            protocol_version: AGENT_PROTOCOL_VERSION_MAX,
            operation: self.requested_operation,
            stage: self.requested_stage,
        }
        .to_string();
        let guest_stage = self.requested_stage.is_guest();
        let response_delivered = matches!(
            self.requested_stage,
            AgentTransportOperationStage::GuestAfterResponseWrite
        );
        let expected_error_operation = if guest_stage {
            self.first_operation_error_operation
                .as_deref()
                .is_some_and(crate::transport_cleanup_report::is_retryable_disconnect_operation)
        } else {
            self.first_operation_error_operation.as_deref() == Some(QUALIFICATION_FAULT_OPERATION)
        };
        let expected_guest_evidence = if guest_stage {
            self.guest_evidence_verified
                && self.guest_evidence_operation_id == self.qualification_operation_id
        } else {
            !self.guest_evidence_verified && self.guest_evidence_operation_id.is_none()
        };

        matches!(self.platform, HostPlatform::Macos)
            && self.first_vm.platform == self.platform
            && self.replacement_vm.platform == self.platform
            && self.bundle_loaded
            && self.requested_operation == AgentOperation::State
            && (self.requested_stage.is_host() || guest_stage)
            && self.qualification_operation_id.is_some()
            && self.setup_create_operation_id.is_some()
            && self.qualification_operation_id != self.setup_create_operation_id
            && self.container_id.is_some()
            && self.negotiated_protocol == Some(AGENT_PROTOCOL_VERSION_MAX)
            && self.injected_point.as_deref() == Some(expected_point.as_str())
            && self.fault_crossings == 1
            && self.first_operation_error_code == Some(ErrorCode::Unavailable)
            && expected_error_operation
            && self.first_operation_error_retryable
            && self.first_operation_response_received == response_delivered
            && self.disconnect_probe_attempted == response_delivered
            && self.first_response_matches_durable_record == response_delivered
            && self.durable_created_retained
            && self.first_created_pid.is_some_and(|pid| pid > 0)
            && self.generation_before_reopen.is_some()
            && expected_guest_evidence
            && self.host_service_reopened
            && self.replacement_recovery_calls == 1
            && self.replacement_rehydrated_created_record
            && self.operation_completed_after_reopen
            && self.generation_before_reopen == self.generation_after_reopen
            && self.replacement_created_pid.is_some_and(|pid| pid > 0)
            && self.replacement_response_matches_durable_record
            && self.same_generation_reused
            && self.setup_create_identity_reused
            && self.force_delete_completed
            && self.durable_records_empty
            && self.marker_absent_after_cleanup
            && self.first_guest_runtime_clean
            && self.replacement_guest_runtime_clean
            && self.owners_distinct
            && self.owner_identities_are_distinct()
            && self.state_root_removed
            && self.first_vm.is_success()
            && self.replacement_vm.is_success()
            && self.reason.is_none()
    }

    fn owner_identities_are_distinct(&self) -> bool {
        self.first_vm
            .endpoint_name
            .as_deref()
            .zip(self.replacement_vm.endpoint_name.as_deref())
            .is_some_and(|(first, replacement)| !first.is_empty() && first != replacement)
            && self
                .first_vm
                .shim_process_id
                .zip(self.replacement_vm.shim_process_id)
                .is_some_and(|(first, replacement)| first != 0 && first != replacement)
            && self
                .first_vm
                .bridge_process_id
                .zip(self.replacement_vm.bridge_process_id)
                .is_some_and(|(first, replacement)| first != 0 && first != replacement)
    }
}

mod close_stdin;
mod delete;
mod exec;
mod file;
mod filesystem;
mod kill;
mod pause;
mod processes;
mod read_output;
mod resize;
mod resume;
mod signal_process;
mod start;
mod stats;
mod update;
mod wait;
pub(crate) mod wait_process;
mod write_stdin;

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::{
        AgentOperation, AgentTransportOperationStage, AGENT_PROTOCOL_VERSION_MAX,
    };
    use a3s_oci_core::{CapabilityStatus, HostPlatform};
    use a3s_oci_sdk::{ContainerId, ErrorCode, Generation, OperationId};
    use serde_json::json;

    use super::OciVmOperationReopenReplacementReport;
    use crate::report::{AgentVmSmokeReport, MacosHostCleanupEvidence};

    #[test]
    fn state_report_requires_all_nine_exact_handoffs_and_complete_cleanup() {
        let mut report = OciVmOperationReopenReplacementReport::initial_state(
            HostPlatform::Macos,
            AgentTransportOperationStage::HostBeforeRequestWrite,
        );
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.qualification_operation_id =
            Some(OperationId::new("reopen-state").expect("qualification ID"));
        report.setup_create_operation_id =
            Some(OperationId::new("reopen-state-create").expect("Create ID"));
        report.container_id = Some(ContainerId::new("reopen-state").expect("container ID"));
        report.negotiated_protocol = Some(AGENT_PROTOCOL_VERSION_MAX);
        report.injected_point = Some(format!(
            "agent-v{AGENT_PROTOCOL_VERSION_MAX}.state-host-before-request-write"
        ));
        report.fault_crossings = 1;
        report.first_operation_error_code = Some(ErrorCode::Unavailable);
        report.first_operation_error_operation =
            Some("oci-vm-transport-qualification-fault".to_string());
        report.first_operation_error_retryable = true;
        report.durable_created_retained = true;
        report.first_created_pid = Some(41);
        report.generation_before_reopen = Some(Generation(1));
        report.host_service_reopened = true;
        report.replacement_recovery_calls = 1;
        report.replacement_rehydrated_created_record = true;
        report.operation_completed_after_reopen = true;
        report.generation_after_reopen = Some(Generation(1));
        report.replacement_created_pid = Some(42);
        report.replacement_response_matches_durable_record = true;
        report.same_generation_reused = true;
        report.setup_create_identity_reused = true;
        report.force_delete_completed = true;
        report.durable_records_empty = true;
        report.marker_absent_after_cleanup = true;
        report.first_guest_runtime_clean = true;
        report.replacement_guest_runtime_clean = true;
        report.owners_distinct = true;
        report.state_root_removed = true;
        report.first_vm = complete_macos_bridge("first", 11, 12);
        report.replacement_vm = complete_macos_bridge("replacement", 21, 22);
        assert!(report.is_success());

        for stage in AgentTransportOperationStage::ALL {
            let mut stage_report = report.clone();
            stage_report.requested_stage = stage;
            stage_report.injected_point = Some(format!(
                "agent-v{AGENT_PROTOCOL_VERSION_MAX}.state-{}",
                stage.as_str()
            ));
            if stage.is_guest() {
                stage_report.first_operation_error_operation =
                    Some("read-agent-frame-header".to_string());
                stage_report.guest_evidence_verified = true;
                stage_report.guest_evidence_operation_id =
                    stage_report.qualification_operation_id.clone();
            }
            if stage == AgentTransportOperationStage::GuestAfterResponseWrite {
                stage_report.first_operation_response_received = true;
                stage_report.disconnect_probe_attempted = true;
                stage_report.first_response_matches_durable_record = true;
            }
            assert!(stage_report.is_success(), "{stage_report:?}");
        }

        for incomplete in [
            OciVmOperationReopenReplacementReport {
                replacement_rehydrated_created_record: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                replacement_response_matches_durable_record: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                setup_create_identity_reused: false,
                ..report.clone()
            },
            OciVmOperationReopenReplacementReport {
                force_delete_completed: false,
                ..report.clone()
            },
        ] {
            assert!(!incomplete.is_success(), "{incomplete:?}");
        }

        report.replacement_vm.endpoint_name = report.first_vm.endpoint_name.clone();
        assert!(!report.is_success());
    }

    fn complete_macos_bridge(name: &str, shim: u32, bridge: u32) -> AgentVmSmokeReport {
        let mut report = AgentVmSmokeReport::initial(HostPlatform::Macos);
        report.status = CapabilityStatus::Available;
        report.endpoint_bound = true;
        report.endpoint_name = Some(format!("a3s-oci-agent-{name}"));
        report.shim_spawned = true;
        report.shim_process_id = Some(shim);
        report.bridge_process_id = Some(bridge);
        report.shim_client_verified = true;
        report.protocol_negotiated = true;
        report.selected_protocol = Some(AGENT_PROTOCOL_VERSION_MAX);
        report.agent_version = Some(env!("CARGO_PKG_VERSION").into());
        report.guest_architecture = Some("aarch64".into());
        report.advertised_operations = AgentOperation::ALL.to_vec();
        report.shim_report_verified = true;
        report.shim_exit_code = Some(0);
        report.console_created = true;
        report.shim_report = Some(json!({}));
        report.macos_cleanup = Some(MacosHostCleanupEvidence {
            endpoint_removed: true,
            shim_reaped: true,
            bridge_reaped: true,
            open_descriptors_before: Some(7),
            open_descriptors_after: Some(7),
            descriptor_inventory_restored: true,
            reason: None,
        });
        report
    }
}
