use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use a3s_oci_agent_protocol::AGENT_RUNTIME_SHARE_GUEST_ROOT;
use a3s_oci_sdk::{
    ContainerTarget, Error, ErrorCode, ProcessId, ProcessRecord, ProcessTarget, Result,
    CONTROL_CGROUP_NAME, WORKLOAD_CGROUP_NAME,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{sleep, Instant};

use super::cgroup::CgroupManager;
use super::device::{cleanup_device_target_manifest, load_device_target_manifest};
use super::intel_rdt::{is_resctrl_mountpoint, IntelRdtRecovery};
use super::pid_supervisor::terminate_pid;
use super::process::{PreparedProcess, SharedSessionSupervisor};
use super::session_supervisor::{HostSessionSupervisor, SessionSupervisorIdentity};

const RUNTIME_ROOT_PREFIX: &str = "a3s-oci-agent-";
const OWNER_RECORD_NAME: &str = "owner.json";
const CONTAINER_RECORD_NAME: &str = "recovery.json";
const CONFIG_SNAPSHOT_NAME: &str = "config.json";
const OWNER_SCHEMA_VERSION: &str = "a3s.oci.native-linux-executor-owner.v1";
const CONTAINER_SCHEMA_VERSION: &str = "a3s.oci.native-linux-recovery.v5";
const CONTAINER_SCHEMA_VERSION_V4: &str = "a3s.oci.native-linux-recovery.v4";
const CONTAINER_SCHEMA_VERSION_V3: &str = "a3s.oci.native-linux-recovery.v3";
const CONTAINER_SCHEMA_VERSION_V2: &str = "a3s.oci.native-linux-recovery.v2";
const CONTAINER_SCHEMA_VERSION_V1: &str = "a3s.oci.native-linux-recovery.v1";
const MAX_RECORD_BYTES: u64 = 64 * 1024;
const TERMINATION_TIMEOUT: Duration = Duration::from_secs(10);
const TERMINATION_POLL_INTERVAL: Duration = Duration::from_millis(10);
const CGROUP_EVENTS: &str = "cgroup.events";
const CGROUP_FREEZE: &str = "cgroup.freeze";
const CGROUP_KILL: &str = "cgroup.kill";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProcessIdentity {
    pid: i32,
    start_time_ticks: u64,
}

impl ProcessIdentity {
    pub(super) fn current() -> Result<Self> {
        let raw = std::process::id();
        let pid = i32::try_from(raw).map_err(|error| {
            recovery_error(
                ErrorCode::ResourceExhausted,
                format!("executor owner PID {raw} does not fit the recovery model: {error}"),
            )
        })?;
        Self::capture(pid, "executor owner")
    }

    /// Persist an already-authenticated PID + start-time identity.
    pub(super) const fn from_authenticated(pid: i32, start_time_ticks: u64) -> Self {
        Self {
            pid,
            start_time_ticks,
        }
    }

    pub(super) const fn pid(self) -> i32 {
        self.pid
    }

    pub(super) const fn start_time_ticks(self) -> u64 {
        self.start_time_ticks
    }

    fn capture(pid: i32, role: &str) -> Result<Self> {
        let observation = process_observation(pid)?
            .filter(|observation| !observation.is_terminated())
            .ok_or_else(|| {
                recovery_error(
                    ErrorCode::Unavailable,
                    format!("{role} PID {pid} exited before its recovery identity was captured"),
                )
                .retryable(true)
            })?;
        Ok(Self {
            pid,
            start_time_ticks: observation.start_time_ticks,
        })
    }

    fn is_live(self) -> Result<bool> {
        Ok(process_observation(self.pid)?.is_some_and(|observation| {
            observation.start_time_ticks == self.start_time_ticks && !observation.is_terminated()
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessObservation {
    start_time_ticks: u64,
    state: u8,
}

impl ProcessObservation {
    const fn is_terminated(self) -> bool {
        matches!(self.state, b'Z' | b'X' | b'x')
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecutorOwnerRecord {
    schema_version: String,
    owner: ProcessIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryCgroupRecord {
    authority_root: PathBuf,
    manager_root: PathBuf,
    leaf: PathBuf,
    created: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyRecoveryCgroupRecord {
    manager_root: PathBuf,
    leaf: PathBuf,
    created: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryIntelRdtRecord {
    mountpoint: PathBuf,
    control_group: PathBuf,
    remove_control_group: bool,
    monitoring_group: Option<PathBuf>,
}

impl From<IntelRdtRecovery> for RecoveryIntelRdtRecord {
    fn from(recovery: IntelRdtRecovery) -> Self {
        Self {
            mountpoint: recovery.mountpoint,
            control_group: recovery.control_group,
            remove_control_group: recovery.remove_control_group,
            monitoring_group: recovery.monitoring_group,
        }
    }
}

/// Authenticated exec identity retained for Live Host reopen inventory.
///
/// Only PID + start-time (plus process ID and terminal mode) are durable.
/// Exit status is never recorded here; dead identities are omitted from
/// inventory instead of inventing a terminal result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryExecRecord {
    process_id: ProcessId,
    identity: ProcessIdentity,
    terminal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContainerRecoveryRecord {
    schema_version: String,
    target: ContainerTarget,
    config_digest: String,
    owner: ProcessIdentity,
    launcher: ProcessIdentity,
    init: ProcessIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_supervisor: Option<ProcessIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    execs: Vec<RecoveryExecRecord>,
    cgroup: Option<RecoveryCgroupRecord>,
    intel_rdt: Option<RecoveryIntelRdtRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V4ContainerRecoveryRecord {
    schema_version: String,
    target: ContainerTarget,
    config_digest: String,
    owner: ProcessIdentity,
    launcher: ProcessIdentity,
    init: ProcessIdentity,
    #[serde(default)]
    session_supervisor: Option<ProcessIdentity>,
    cgroup: Option<RecoveryCgroupRecord>,
    intel_rdt: Option<RecoveryIntelRdtRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V3ContainerRecoveryRecord {
    schema_version: String,
    target: ContainerTarget,
    config_digest: String,
    owner: ProcessIdentity,
    launcher: ProcessIdentity,
    init: ProcessIdentity,
    cgroup: Option<RecoveryCgroupRecord>,
    intel_rdt: Option<RecoveryIntelRdtRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreviousContainerRecoveryRecord {
    schema_version: String,
    target: ContainerTarget,
    config_digest: String,
    owner: ProcessIdentity,
    launcher: ProcessIdentity,
    init: ProcessIdentity,
    cgroup: Option<RecoveryCgroupRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyContainerRecoveryRecord {
    schema_version: String,
    target: ContainerTarget,
    config_digest: String,
    owner: ProcessIdentity,
    launcher: ProcessIdentity,
    init: ProcessIdentity,
    cgroup: Option<LegacyRecoveryCgroupRecord>,
}

/// Exact stopped-generation cleanup evidence retained after owner death.
#[derive(Debug, Clone)]
pub struct LinuxExecutorTombstone {
    target: ContainerTarget,
    config_digest: String,
    runtime_root: PathBuf,
    runtime_directory: PathBuf,
    record: ContainerRecoveryRecord,
}

impl LinuxExecutorTombstone {
    /// Exact container generation represented by this tombstone.
    #[must_use]
    pub fn target(&self) -> &ContainerTarget {
        &self.target
    }

    /// Immutable OCI configuration digest bound to the recovered generation.
    #[must_use]
    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }
}

/// Outcome of reconciling one durable generation after its executor owner died.
///
/// A live recorded session supervisor is reattached rather than fail-closed.
/// Stopped generations retain only cleanup paths; live generations keep an
/// authenticated supervisor control handle for wait/kill without inventing
/// exit status or deleting live resources.
#[derive(Debug)]
pub enum StaleGenerationRecovery {
    /// Owner, launcher, init, and any session supervisor have all exited.
    Stopped(LinuxExecutorTombstone),
    /// Session supervisor is still live; control has been reattached.
    Live(LinuxLiveSupervisedSession),
}

/// Cache of reattached session supervisors keyed by authenticated identity.
///
/// A multi-container Host shares one `HostSessionSupervisor`. After Host EOF
/// that supervisor accepts exactly one replacement control connection, so
/// recovering several generations must reuse one reattached handle instead of
/// calling [`HostSessionSupervisor::reattach`] per container.
#[derive(Debug, Default)]
pub(crate) struct SessionSupervisorReattachCache {
    entries: Mutex<BTreeMap<(i32, u64), SharedSessionSupervisor>>,
}

impl SessionSupervisorReattachCache {
    /// Return the shared supervisor for `expected`, reattaching at most once.
    pub(crate) fn get_or_reattach(
        &self,
        expected: &SessionSupervisorIdentity,
    ) -> Result<SharedSessionSupervisor> {
        let key = (expected.pid(), expected.start_time_ticks());
        let mut entries = self.entries.lock().map_err(|_| {
            recovery_error(
                ErrorCode::Internal,
                "session supervisor reattach cache lock is poisoned",
            )
        })?;
        if let Some(existing) = entries.get(&key) {
            return Ok(Arc::clone(existing));
        }
        let reattached = HostSessionSupervisor::reattach(expected)?;
        let shared = Arc::new(Mutex::new(reattached));
        entries.insert(key, Arc::clone(&shared));
        Ok(shared)
    }

    /// Number of distinct supervisor identities retained by this Host reopen.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries
            .lock()
            .map(|entries| entries.len())
            .unwrap_or(0)
    }
}

/// Host-reopen handle for one generation whose session supervisor survived.
///
/// This restores supervisor control for wait/kill of the recorded launcher, a
/// process inventory of the authenticated live init plus still-live durable
/// exec identities, an authentic stdin write end when the original Host
/// deposited one, and exclusive capture stdout/stderr through the supervisor
/// IPC relay when those read ends were moved at create. Missing output deposit
/// fail-closes [`Self::read_output`] with [`ErrorCode::Unavailable`] instead of
/// inventing empty output. Dead exec identities are omitted from inventory
/// without inventing exit status. Full `PreparedProcess` restore for signal /
/// wait / new exec remains open.
#[derive(Debug)]
pub struct LinuxLiveSupervisedSession {
    target: ContainerTarget,
    config_digest: String,
    runtime_root: PathBuf,
    runtime_directory: PathBuf,
    record: ContainerRecoveryRecord,
    supervisor: SharedSessionSupervisor,
    launcher_wait_status: Mutex<Option<i32>>,
    /// Restored Host stdin write end taken from the supervisor deposit.
    stdin: AsyncMutex<Option<tokio::fs::File>>,
}

impl LinuxLiveSupervisedSession {
    /// Exact container generation represented by this live session.
    #[must_use]
    pub fn target(&self) -> &ContainerTarget {
        &self.target
    }

    /// Shared reattached supervisor handle for this generation.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn shared_supervisor(&self) -> &SharedSessionSupervisor {
        &self.supervisor
    }

    /// Whether an authentic stdin write end was restored from the supervisor.
    #[must_use]
    pub fn has_restored_stdin(&self) -> bool {
        self.stdin
            .try_lock()
            .map(|stdin| stdin.is_some())
            .unwrap_or(true)
    }

    /// Immutable OCI configuration digest bound to the recovered generation.
    #[must_use]
    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }

    /// Recorded supervised launcher PID from recovery evidence.
    #[must_use]
    pub fn launcher_pid(&self) -> i32 {
        self.record.launcher.pid()
    }

    /// Recorded container init PID from recovery evidence.
    #[must_use]
    pub fn init_pid(&self) -> i32 {
        self.record.init.pid()
    }

    /// Whether the recorded launcher identity is still live.
    pub fn launcher_is_live(&self) -> Result<bool> {
        self.record.launcher.is_live()
    }

    /// Whether the recorded init identity is still live.
    pub fn init_is_live(&self) -> Result<bool> {
        self.record.init.is_live()
    }

    /// Process inventory for Host reopen.
    ///
    /// Returns the authenticated init [`ProcessRecord`] when that identity is
    /// still live, plus every durable exec whose PID + start-time identity is
    /// still live. Dead init or exec identities are omitted. Does not invent
    /// exit status for missing processes.
    pub fn process_inventory(&self) -> Result<Vec<ProcessRecord>> {
        let mut records = Vec::new();
        if self.init_is_live()? {
            let pid = u32::try_from(self.init_pid()).map_err(|error| {
                recovery_error(
                    ErrorCode::Internal,
                    format!(
                        "live supervised init PID {} does not fit the SDK process model: {error}",
                        self.init_pid()
                    ),
                )
            })?;
            if pid == 0 {
                return Err(recovery_error(
                    ErrorCode::Internal,
                    "live supervised process inventory contained PID zero",
                ));
            }
            records.push(ProcessRecord {
                target: ProcessTarget {
                    container: self.target.clone(),
                    process_id: ProcessId::init(),
                },
                pid: Some(pid),
                terminal: false,
            });
        }
        for exec in &self.record.execs {
            if exec.process_id.is_init() {
                return Err(recovery_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "container {} generation {:?} recovery retained init as an exec identity",
                        self.target.id, self.target.generation
                    ),
                ));
            }
            if !exec.identity.is_live()? {
                continue;
            }
            let pid = u32::try_from(exec.identity.pid()).map_err(|error| {
                recovery_error(
                    ErrorCode::Internal,
                    format!(
                        "live supervised exec PID {} does not fit the SDK process model: {error}",
                        exec.identity.pid()
                    ),
                )
            })?;
            if pid == 0 {
                return Err(recovery_error(
                    ErrorCode::Internal,
                    "live supervised exec inventory contained PID zero",
                ));
            }
            records.push(ProcessRecord {
                target: ProcessTarget {
                    container: self.target.clone(),
                    process_id: exec.process_id.clone(),
                },
                pid: Some(pid),
                terminal: exec.terminal,
            });
        }
        Ok(records)
    }

    /// Authenticated session-supervisor identity that parents the launcher.
    #[must_use]
    pub fn supervisor_pid(&self) -> i32 {
        self.record
            .session_supervisor
            .expect("live supervised session always records a supervisor")
            .pid()
    }

    /// Poll authentic captured chunks from the supervisor-owned exclusive drain.
    ///
    /// When create moved capture read ends to the supervisor, this returns the
    /// same sequence-bearing chunks as the live Host path. When no output
    /// deposit exists, returns [`ErrorCode::Unavailable`] instead of inventing
    /// an empty successful stream.
    pub fn read_output(
        &self,
        after_sequence: u64,
        max_bytes: u32,
        wait_timeout_ms: Option<u64>,
    ) -> Result<Vec<a3s_oci_sdk::OutputChunk>> {
        let mut guard = self.supervisor.lock().map_err(|_| {
            recovery_error(
                ErrorCode::Internal,
                "live supervised session supervisor lock is poisoned during read-output",
            )
        })?;
        guard
            .read_output(
                self.launcher_pid(),
                after_sequence,
                max_bytes,
                wait_timeout_ms,
            )
            .map_err(|error| {
                // Preserve fail-closed codes from the relay (Unavailable for
                // missing deposit, ResourceExhausted for stale cursors).
                recovery_error(error.code, error.message)
            })
    }

    /// Write to the authentic restored stdin pipe end.
    pub async fn write_stdin(&self, data: &[u8]) -> Result<()> {
        let mut guard = self.stdin.lock().await;
        let stdin = guard.as_mut().ok_or_else(|| {
            recovery_error(
                ErrorCode::Unavailable,
                format!(
                    "container {} generation {:?} has no restored stdin write end after Host reopen",
                    self.target.id, self.target.generation
                ),
            )
        })?;
        stdin.write_all(data).await.map_err(|error| {
            recovery_error(
                ErrorCode::Unavailable,
                format!(
                    "failed to write restored stdin for container {} generation {:?}: {error}",
                    self.target.id, self.target.generation
                ),
            )
        })?;
        stdin.flush().await.map_err(|error| {
            recovery_error(
                ErrorCode::Unavailable,
                format!(
                    "failed to flush restored stdin for container {} generation {:?}: {error}",
                    self.target.id, self.target.generation
                ),
            )
        })
    }

    /// Close the restored stdin write end and drop any remaining supervisor deposit.
    pub async fn close_stdin(&self) -> Result<()> {
        {
            let mut guard = self.stdin.lock().await;
            guard.take();
        }
        let mut supervisor = self.supervisor.lock().map_err(|_| {
            recovery_error(
                ErrorCode::Internal,
                "live supervised session supervisor lock is poisoned during stdin close",
            )
        })?;
        supervisor.close_deposited_stdin(self.launcher_pid())?;
        Ok(())
    }

    /// Block until the supervised launcher exits and return its raw wait status.
    ///
    /// Status comes from the reattached supervisor (`MSG_WAIT`). This never
    /// invents an exit code for a still-live launcher.
    pub fn wait_launcher(&self) -> Result<i32> {
        if let Some(status) = *self.launcher_wait_status.lock().map_err(|_| {
            recovery_error(
                ErrorCode::Internal,
                "live supervised session wait-status lock is poisoned",
            )
        })? {
            return Ok(status);
        }
        let mut guard = self.supervisor.lock().map_err(|_| {
            recovery_error(
                ErrorCode::Internal,
                "live supervised session supervisor lock is poisoned",
            )
        })?;
        let status = guard.wait_launcher(self.launcher_pid())?;
        drop(guard);
        *self.launcher_wait_status.lock().map_err(|_| {
            recovery_error(
                ErrorCode::Internal,
                "live supervised session wait-status lock is poisoned",
            )
        })? = Some(status);
        Ok(status)
    }

    /// Deliver `SIGKILL` to the recorded launcher without inventing exit status.
    ///
    /// Call [`wait_launcher`] afterward for the authentic supervised status.
    pub fn kill_launcher(&self) -> Result<()> {
        if self.launcher_is_live()? {
            terminate_pid(self.launcher_pid());
        }
        Ok(())
    }

    /// Deliver `SIGKILL` to the recorded init when it is still live.
    pub fn kill_init(&self) -> Result<()> {
        if self.init_is_live()? {
            terminate_pid(self.init_pid());
        }
        Ok(())
    }

    /// Build stopped-only cleanup evidence after launcher and init have exited.
    ///
    /// Refuses while either identity is live. Does not shut down the shared
    /// session supervisor (it may still parent other generations).
    pub fn stopped_tombstone(&self) -> Result<LinuxExecutorTombstone> {
        if self.launcher_is_live()? || self.init_is_live()? {
            return Err(recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "refusing to tombstone live supervised resources for container {} generation {:?}",
                    self.target.id, self.target.generation
                ),
            ));
        }
        Ok(LinuxExecutorTombstone {
            target: self.target.clone(),
            config_digest: self.config_digest.clone(),
            runtime_root: self.runtime_root.clone(),
            runtime_directory: self.runtime_directory.clone(),
            record: self.record.clone(),
        })
    }

    /// Consume this handle into stopped cleanup evidence.
    ///
    /// When this is the last strong reference to the reattached supervisor,
    /// the control channel is forgotten instead of `MSG_SHUTDOWN` so a shared
    /// supervisor may continue parenting other generations.
    pub fn into_tombstone(self) -> Result<LinuxExecutorTombstone> {
        let tombstone = self.stopped_tombstone()?;
        if let Ok(mutex) = Arc::try_unwrap(self.supervisor) {
            if let Ok(supervisor) = mutex.into_inner() {
                std::mem::forget(supervisor);
            }
        }
        Ok(tombstone)
    }

    fn from_tombstone_and_supervisor(
        tombstone: LinuxExecutorTombstone,
        supervisor: SharedSessionSupervisor,
    ) -> Self {
        // Take before moving `supervisor` into Self; drop the lock first.
        let stdin = take_deposited_stdin(&supervisor, tombstone.record.launcher.pid());
        Self {
            target: tombstone.target,
            config_digest: tombstone.config_digest,
            runtime_root: tombstone.runtime_root,
            runtime_directory: tombstone.runtime_directory,
            record: tombstone.record,
            supervisor,
            launcher_wait_status: Mutex::new(None),
            stdin: AsyncMutex::new(stdin),
        }
    }
}

fn take_deposited_stdin(
    supervisor: &SharedSessionSupervisor,
    launcher_pid: i32,
) -> Option<tokio::fs::File> {
    let mut guard = supervisor.lock().ok()?;
    let fd = match guard.take_stdin(launcher_pid) {
        Ok(fd) => fd,
        Err(_) => return None,
    };
    drop(guard);
    Some(owned_fd_to_tokio_file(fd))
}

fn owned_fd_to_tokio_file(fd: OwnedFd) -> tokio::fs::File {
    let raw = fd.into_raw_fd();
    // SAFETY: take_stdin transferred ownership of an open write end.
    let std_file = unsafe { std::fs::File::from_raw_fd(raw) };
    tokio::fs::File::from_std(std_file)
}

pub(super) fn runtime_root_name(owner: ProcessIdentity) -> String {
    format!(
        "{RUNTIME_ROOT_PREFIX}{}-{:016x}",
        owner.pid, owner.start_time_ticks
    )
}

pub(super) fn transient_runtime_root_name(pid: u32) -> String {
    format!("{RUNTIME_ROOT_PREFIX}{pid}")
}

pub(super) async fn write_owner_record(runtime_root: &Path, owner: ProcessIdentity) -> Result<()> {
    let record = ExecutorOwnerRecord {
        schema_version: OWNER_SCHEMA_VERSION.to_string(),
        owner,
    };
    write_atomic_record(&runtime_root.join(OWNER_RECORD_NAME), &record)
}

pub(super) async fn write_container_record(
    runtime_directory: &Path,
    config_snapshot: &Path,
    target: &ContainerTarget,
    config_digest: &str,
    owner: ProcessIdentity,
    process: &PreparedProcess,
    cgroup_manager: Option<&CgroupManager>,
    session_supervisor: Option<ProcessIdentity>,
) -> Result<()> {
    let snapshot = read_bounded_plain_file(config_snapshot, MAX_RECORD_BYTES)?;
    let observed_digest = config_digest_for(&snapshot);
    if observed_digest != config_digest {
        return Err(recovery_error(
            ErrorCode::Conflict,
            format!(
                "native recovery snapshot digest mismatch for container {}: expected {config_digest}, observed {observed_digest}",
                target.id
            ),
        ));
    }
    let launcher = ProcessIdentity::capture(process.launcher_pid()?, "container launcher")?;
    let init = ProcessIdentity::capture(process.pid(), "container init")?;
    let cgroup = match (process.recovery_cgroup_paths(), cgroup_manager) {
        (None, _) => None,
        (Some(_), None) => {
            return Err(recovery_error(
                ErrorCode::Internal,
                "container recovery lost its private cgroup manager",
            ));
        }
        (Some((leaf, created)), Some(manager)) => Some(RecoveryCgroupRecord {
            authority_root: manager.authority_root().to_path_buf(),
            manager_root: manager.root().to_path_buf(),
            leaf: leaf.to_path_buf(),
            created: created.to_vec(),
        }),
    };
    if let Some(cgroup) = &cgroup {
        validate_cgroup_record(cgroup)?;
    }
    let intel_rdt = process
        .recovery_intel_rdt()
        .map(RecoveryIntelRdtRecord::from);
    if let Some(intel_rdt) = &intel_rdt {
        validate_intel_rdt_record(intel_rdt, target.id.as_str())?;
    }
    if let Some(supervisor) = session_supervisor {
        if !supervisor.is_live()? {
            return Err(recovery_error(
                ErrorCode::Unavailable,
                format!(
                    "session supervisor PID {} exited before recovery evidence was persisted",
                    supervisor.pid
                ),
            )
            .retryable(true));
        }
    }
    let record = ContainerRecoveryRecord {
        schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
        target: target.clone(),
        config_digest: config_digest.to_string(),
        owner,
        launcher,
        init,
        session_supervisor,
        execs: Vec::new(),
        cgroup,
        intel_rdt,
    };
    write_atomic_record(&runtime_directory.join(CONTAINER_RECORD_NAME), &record)
}

/// Persist one authenticated exec identity into the generation recovery record.
///
/// Only called for supervised generations (`sessionSupervisor` present). Captures
/// PID + start-time before returning success; never records exit status.
pub(super) fn record_exec_identity(
    runtime_directory: &Path,
    process_id: &ProcessId,
    pid: i32,
    terminal: bool,
) -> Result<()> {
    if process_id.is_init() {
        return Err(recovery_error(
            ErrorCode::InvalidArgument,
            "recovery exec identity cannot use the reserved init process ID",
        ));
    }
    let path = runtime_directory.join(CONTAINER_RECORD_NAME);
    let mut record = read_container_record(&path)?;
    if record.session_supervisor.is_none() {
        return Err(recovery_error(
            ErrorCode::FailedPrecondition,
            format!(
                "refusing to persist exec {} without a recorded session supervisor under {}",
                process_id,
                runtime_directory.display()
            ),
        ));
    }
    if record
        .execs
        .iter()
        .any(|exec| &exec.process_id == process_id)
    {
        return Err(recovery_error(
            ErrorCode::AlreadyExists,
            format!(
                "process {} already has durable recovery evidence under {}",
                process_id,
                runtime_directory.display()
            ),
        ));
    }
    let identity = ProcessIdentity::capture(pid, "container exec")?;
    record.schema_version = CONTAINER_SCHEMA_VERSION.to_string();
    record.execs.push(RecoveryExecRecord {
        process_id: process_id.clone(),
        identity,
        terminal,
    });
    write_atomic_record(&path, &record)
}

/// Whether the generation recovery record retained a live session supervisor.
pub(super) fn recovery_has_session_supervisor(runtime_directory: &Path) -> Result<bool> {
    let path = runtime_directory.join(CONTAINER_RECORD_NAME);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => Ok(read_container_record(&path)?.session_supervisor.is_some()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(recovery_io_error(
            format!(
                "failed to inspect native recovery record {}: {error}",
                path.display()
            ),
            error,
        )),
    }
}

pub(super) async fn recover_stale_generation(
    runtime_parent: &Path,
    current_runtime_root: &Path,
    target: &ContainerTarget,
    config_digest: &str,
    durable_pid: Option<i32>,
    supervisors: &SessionSupervisorReattachCache,
) -> Result<Option<StaleGenerationRecovery>> {
    if target.generation.is_none() {
        return Err(recovery_error(
            ErrorCode::InvalidArgument,
            format!(
                "native Linux recovery requires an exact generation for container {}",
                target.id
            ),
        ));
    }
    let mut matches = Vec::new();
    let mut roots = list_real_directories(runtime_parent, RUNTIME_ROOT_PREFIX)?;
    roots.sort();
    for runtime_root in roots {
        if runtime_root == current_runtime_root {
            continue;
        }
        let Some(name) = runtime_root.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(name_identity) = parse_runtime_root_name(name) else {
            continue;
        };
        let owner: ExecutorOwnerRecord =
            read_json_record(&runtime_root.join(OWNER_RECORD_NAME), MAX_RECORD_BYTES)?;
        if owner.schema_version != OWNER_SCHEMA_VERSION || owner.owner != name_identity {
            return Err(recovery_error(
                ErrorCode::PermissionDenied,
                format!(
                    "native executor owner record does not match protected root {}",
                    runtime_root.display()
                ),
            ));
        }
        let owner_live = owner.owner.is_live()?;
        let mut slots = list_real_directories(&runtime_root, "c-")?;
        slots.sort();
        for runtime_directory in slots {
            let record_path = runtime_directory.join(CONTAINER_RECORD_NAME);
            let record = match std::fs::symlink_metadata(&record_path) {
                Ok(_) => read_container_record(&record_path)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(recovery_io_error(
                        format!(
                            "failed to inspect native recovery record {}: {error}",
                            record_path.display()
                        ),
                        error,
                    ));
                }
            };
            validate_container_record(
                &record,
                &owner,
                &runtime_directory,
                target,
                config_digest,
                durable_pid,
            )?;
            if &record.target != target {
                continue;
            }
            if owner_live {
                return Err(recovery_error(
                    ErrorCode::Conflict,
                    format!(
                        "container {} generation {:?} still belongs to live native executor PID {}",
                        target.id, target.generation, owner.owner.pid
                    ),
                ));
            }
            matches.push(LinuxExecutorTombstone {
                target: target.clone(),
                config_digest: config_digest.to_string(),
                runtime_root: runtime_root.clone(),
                runtime_directory,
                record,
            });
        }
    }
    let tombstone = match matches.len() {
        1 => matches.pop().expect("one recovery match"),
        0 => return Ok(None),
        count => {
            return Err(recovery_error(
                ErrorCode::Conflict,
                format!(
                    "found {count} native recovery records for container {} generation {:?}",
                    target.id, target.generation
                ),
            ));
        }
    };

    let deadline = Instant::now() + TERMINATION_TIMEOUT;
    if let Some(supervisor) = tombstone.record.session_supervisor {
        if supervisor.is_live()? {
            let expected = SessionSupervisorIdentity::from_authenticated(
                supervisor.pid(),
                supervisor.start_time_ticks(),
            );
            expected.authenticate_live().map_err(|error| {
                recovery_error(
                    error.code,
                    format!(
                        "container {} generation {:?} retained live session supervisor PID {} but authentication failed: {}",
                        target.id, target.generation, supervisor.pid(), error.message
                    ),
                )
                .retryable(error.retryable)
            })?;
            let reattached = supervisors.get_or_reattach(&expected).map_err(|error| {
                recovery_error(
                    error.code,
                    format!(
                        "container {} generation {:?} failed to reattach live session supervisor PID {}: {}",
                        target.id, target.generation, supervisor.pid(), error.message
                    ),
                )
                .retryable(error.retryable)
            })?;
            return Ok(Some(StaleGenerationRecovery::Live(
                LinuxLiveSupervisedSession::from_tombstone_and_supervisor(tombstone, reattached),
            )));
        }
        wait_for_identity_exit(supervisor, "session supervisor", deadline).await?;
    }
    wait_for_identity_exit(tombstone.record.launcher, "container launcher", deadline).await?;
    wait_for_identity_exit(tombstone.record.init, "container init", deadline).await?;
    Ok(Some(StaleGenerationRecovery::Stopped(tombstone)))
}

pub(super) async fn delete_stale_generation(tombstone: &LinuxExecutorTombstone) -> Result<()> {
    let record = read_container_record(&tombstone.runtime_directory.join(CONTAINER_RECORD_NAME))?;
    if record != tombstone.record
        || record.target != tombstone.target
        || record.config_digest != tombstone.config_digest
    {
        return Err(recovery_error(
            ErrorCode::Conflict,
            format!(
                "native recovery evidence changed before delete for container {} generation {:?}",
                tombstone.target.id, tombstone.target.generation
            ),
        ));
    }
    if record.owner.is_live()? || record.launcher.is_live()? || record.init.is_live()? {
        return Err(recovery_error(
            ErrorCode::FailedPrecondition,
            format!(
                "refusing to delete live native recovery resources for container {} generation {:?}",
                tombstone.target.id, tombstone.target.generation
            ),
        ));
    }
    // A live session supervisor is Host-shared and must not block stopped-only
    // delete after the recorded launcher and init have exited.
    if let Some(intel_rdt) = &record.intel_rdt {
        cleanup_intel_rdt(intel_rdt, record.target.id.as_str())?;
    }
    if let Some(cgroup) = &record.cgroup {
        cleanup_cgroup(cgroup).await?;
    }
    ensure_private_directory(&tombstone.runtime_root, 0o700)?;
    ensure_private_directory(&tombstone.runtime_directory, 0o700)?;
    if tombstone.runtime_directory.parent() != Some(tombstone.runtime_root.as_path()) {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "refusing to delete native recovery directory outside its owner root: {}",
                tombstone.runtime_directory.display()
            ),
        ));
    }
    reject_symlinks_below(&tombstone.runtime_directory)?;
    if let Some(manifest) = load_device_target_manifest(&tombstone.runtime_directory)? {
        cleanup_device_target_manifest(&manifest)?;
    }
    std::fs::remove_dir_all(&tombstone.runtime_directory).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to remove recovered native container directory {}: {error}",
                tombstone.runtime_directory.display()
            ),
            error,
        )
    })?;
    cleanup_empty_runtime_root(&tombstone.runtime_root)
}

fn validate_container_record(
    record: &ContainerRecoveryRecord,
    owner: &ExecutorOwnerRecord,
    runtime_directory: &Path,
    target: &ContainerTarget,
    config_digest: &str,
    durable_pid: Option<i32>,
) -> Result<()> {
    if record.schema_version != CONTAINER_SCHEMA_VERSION || record.owner != owner.owner {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "native container recovery record is not owned by {}",
                runtime_directory.display()
            ),
        ));
    }
    if let Some(cgroup) = &record.cgroup {
        validate_cgroup_record(cgroup)?;
    }
    if let Some(intel_rdt) = &record.intel_rdt {
        validate_intel_rdt_record(intel_rdt, record.target.id.as_str())?;
    }
    let snapshot = read_bounded_plain_file(
        &runtime_directory.join(CONFIG_SNAPSHOT_NAME),
        MAX_RECORD_BYTES,
    )?;
    let observed_digest = config_digest_for(&snapshot);
    if observed_digest != record.config_digest {
        return Err(recovery_error(
            ErrorCode::Conflict,
            format!(
                "native recovery configuration changed below {}: record {}, snapshot {observed_digest}",
                runtime_directory.display(), record.config_digest
            ),
        ));
    }
    if &record.target != target {
        return Ok(());
    }
    if record.config_digest != config_digest {
        return Err(recovery_error(
            ErrorCode::Conflict,
            format!(
                "native recovery config digest mismatch for container {} generation {:?}: durable {config_digest}, recovery {}",
                target.id, target.generation, record.config_digest
            ),
        ));
    }
    if durable_pid.is_some_and(|pid| pid != record.init.pid) {
        return Err(recovery_error(
            ErrorCode::Conflict,
            format!(
                "native recovery init PID mismatch for container {} generation {:?}: durable {durable_pid:?}, recovery {}",
                target.id, target.generation, record.init.pid
            ),
        ));
    }
    Ok(())
}

fn read_container_record(path: &Path) -> Result<ContainerRecoveryRecord> {
    let value: serde_json::Value = read_json_record(path, MAX_RECORD_BYTES)?;
    let schema_version = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "native container recovery record {} has no schema version",
                    path.display()
                ),
            )
        })?;
    match schema_version {
        CONTAINER_SCHEMA_VERSION => serde_json::from_value(value).map_err(|error| {
            recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "native container recovery record {} is invalid: {error}",
                    path.display()
                ),
            )
        }),
        CONTAINER_SCHEMA_VERSION_V4 => {
            let previous: V4ContainerRecoveryRecord =
                serde_json::from_value(value).map_err(|error| {
                    recovery_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "v4 native container recovery record {} is invalid: {error}",
                            path.display()
                        ),
                    )
                })?;
            Ok(normalize_v4_container_record(previous))
        }
        CONTAINER_SCHEMA_VERSION_V3 => {
            let previous: V3ContainerRecoveryRecord =
                serde_json::from_value(value).map_err(|error| {
                    recovery_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "v3 native container recovery record {} is invalid: {error}",
                            path.display()
                        ),
                    )
                })?;
            Ok(normalize_v3_container_record(previous))
        }
        CONTAINER_SCHEMA_VERSION_V2 => {
            let previous: PreviousContainerRecoveryRecord =
                serde_json::from_value(value).map_err(|error| {
                    recovery_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "v2 native container recovery record {} is invalid: {error}",
                            path.display()
                        ),
                    )
                })?;
            Ok(normalize_v2_container_record(previous))
        }
        CONTAINER_SCHEMA_VERSION_V1 => {
            let legacy: LegacyContainerRecoveryRecord =
                serde_json::from_value(value).map_err(|error| {
                    recovery_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "legacy native container recovery record {} is invalid: {error}",
                            path.display()
                        ),
                    )
                })?;
            normalize_legacy_container_record(legacy)
        }
        other => Err(recovery_error(
            ErrorCode::FailedPrecondition,
            format!(
                "native container recovery record {} has unsupported schema {other}",
                path.display()
            ),
        )),
    }
}

fn normalize_legacy_container_record(
    legacy: LegacyContainerRecoveryRecord,
) -> Result<ContainerRecoveryRecord> {
    let cgroup = legacy
        .cgroup
        .map(|legacy| {
            let authority_root = legacy.manager_root.parent().ok_or_else(|| {
                recovery_error(
                    ErrorCode::PermissionDenied,
                    "legacy native recovery cgroup manager has no authority root",
                )
            })?;
            if authority_root != Path::new("/sys/fs/cgroup") {
                return Err(recovery_error(
                    ErrorCode::PermissionDenied,
                    format!(
                        "legacy native recovery cgroup is not a direct rootful cgroup-v2 manager: {}",
                        legacy.manager_root.display()
                    ),
                ));
            }
            let normalized = RecoveryCgroupRecord {
                authority_root: authority_root.to_path_buf(),
                manager_root: legacy.manager_root,
                leaf: legacy.leaf,
                created: legacy.created,
            };
            validate_cgroup_record(&normalized)?;
            Ok(normalized)
        })
        .transpose()?;
    Ok(ContainerRecoveryRecord {
        schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
        target: legacy.target,
        config_digest: legacy.config_digest,
        owner: legacy.owner,
        launcher: legacy.launcher,
        init: legacy.init,
        session_supervisor: None,
        execs: Vec::new(),
        cgroup,
        intel_rdt: None,
    })
}

fn normalize_v4_container_record(previous: V4ContainerRecoveryRecord) -> ContainerRecoveryRecord {
    ContainerRecoveryRecord {
        schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
        target: previous.target,
        config_digest: previous.config_digest,
        owner: previous.owner,
        launcher: previous.launcher,
        init: previous.init,
        session_supervisor: previous.session_supervisor,
        execs: Vec::new(),
        cgroup: previous.cgroup,
        intel_rdt: previous.intel_rdt,
    }
}

fn normalize_v3_container_record(previous: V3ContainerRecoveryRecord) -> ContainerRecoveryRecord {
    ContainerRecoveryRecord {
        schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
        target: previous.target,
        config_digest: previous.config_digest,
        owner: previous.owner,
        launcher: previous.launcher,
        init: previous.init,
        session_supervisor: None,
        execs: Vec::new(),
        cgroup: previous.cgroup,
        intel_rdt: previous.intel_rdt,
    }
}

fn normalize_v2_container_record(
    previous: PreviousContainerRecoveryRecord,
) -> ContainerRecoveryRecord {
    ContainerRecoveryRecord {
        schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
        target: previous.target,
        config_digest: previous.config_digest,
        owner: previous.owner,
        launcher: previous.launcher,
        init: previous.init,
        session_supervisor: None,
        execs: Vec::new(),
        cgroup: previous.cgroup,
        intel_rdt: None,
    }
}

fn validate_intel_rdt_record(intel_rdt: &RecoveryIntelRdtRecord, container_id: &str) -> Result<()> {
    validate_absolute_normalized(&intel_rdt.mountpoint, "resctrl mountpoint")?;
    validate_absolute_normalized(&intel_rdt.control_group, "resctrl control group")?;
    if intel_rdt.mountpoint == Path::new("/") {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            "native recovery resctrl mountpoint must not be the filesystem root",
        ));
    }

    let root_control = intel_rdt.control_group == intel_rdt.mountpoint;
    let direct_child = intel_rdt.control_group.parent() == Some(intel_rdt.mountpoint.as_path())
        && intel_rdt.control_group.file_name().is_some();
    if !root_control && !direct_child {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "native recovery resctrl control group is outside the direct mount layout: {}",
                intel_rdt.control_group.display()
            ),
        ));
    }
    if intel_rdt.remove_control_group
        && (!direct_child
            || intel_rdt
                .control_group
                .file_name()
                .and_then(|name| name.to_str())
                != Some(container_id))
    {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "native recovery may remove only the container-owned resctrl CLOS for {container_id}: {}",
                intel_rdt.control_group.display()
            ),
        ));
    }
    if let Some(monitoring_group) = &intel_rdt.monitoring_group {
        validate_absolute_normalized(monitoring_group, "resctrl monitoring group")?;
        let expected = intel_rdt
            .control_group
            .join("mon_groups")
            .join(container_id);
        if monitoring_group != &expected {
            return Err(recovery_error(
                ErrorCode::PermissionDenied,
                format!(
                    "native recovery resctrl monitoring group does not match the container-owned path: {}",
                    monitoring_group.display()
                ),
            ));
        }
    }
    if !intel_rdt.remove_control_group && intel_rdt.monitoring_group.is_none() {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            "native recovery resctrl record does not own any cleanup path",
        ));
    }
    Ok(())
}

fn cleanup_intel_rdt(intel_rdt: &RecoveryIntelRdtRecord, container_id: &str) -> Result<()> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").map_err(|error| {
        recovery_io_error(
            format!("failed to read resctrl mount topology during native recovery: {error}"),
            error,
        )
    })?;
    cleanup_intel_rdt_with_mountinfo(intel_rdt, container_id, &mountinfo)
}

fn cleanup_intel_rdt_with_mountinfo(
    intel_rdt: &RecoveryIntelRdtRecord,
    container_id: &str,
    mountinfo: &str,
) -> Result<()> {
    validate_intel_rdt_record(intel_rdt, container_id)?;
    if !is_resctrl_mountpoint(mountinfo, &intel_rdt.mountpoint) {
        return Err(recovery_error(
            ErrorCode::FailedPrecondition,
            format!(
                "native recovery resctrl mountpoint is no longer mounted as resctrl: {}",
                intel_rdt.mountpoint.display()
            ),
        )
        .retryable(true));
    }
    if let Some(monitoring_group) = &intel_rdt.monitoring_group {
        remove_recovered_resctrl_directory(monitoring_group, "monitoring group")?;
    }
    if intel_rdt.remove_control_group {
        remove_recovered_resctrl_directory(&intel_rdt.control_group, "control group")?;
    }
    Ok(())
}

fn remove_recovered_resctrl_directory(path: &Path, role: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(recovery_error(
                ErrorCode::PermissionDenied,
                format!(
                    "recovered resctrl {role} is not a real directory: {}",
                    path.display()
                ),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(recovery_io_error(
                format!(
                    "failed to inspect recovered resctrl {role} {}: {error}",
                    path.display()
                ),
                error,
            ));
        }
    }
    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(recovery_io_error(
            format!(
                "failed to remove recovered resctrl {role} {}: {error}",
                path.display()
            ),
            error,
        )),
    }
}

async fn wait_for_identity_exit(
    identity: ProcessIdentity,
    role: &str,
    deadline: Instant,
) -> Result<()> {
    loop {
        if !identity.is_live()? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(recovery_error(
                ErrorCode::DeadlineExceeded,
                format!(
                    "timed out waiting for exact {role} PID {} start-time {} to terminate after native owner death",
                    identity.pid, identity.start_time_ticks
                ),
            )
            .retryable(true));
        }
        sleep(TERMINATION_POLL_INTERVAL).await;
    }
}

fn validate_cgroup_record(cgroup: &RecoveryCgroupRecord) -> Result<()> {
    validate_absolute_normalized(&cgroup.authority_root, "cgroup authority root")?;
    validate_absolute_normalized(&cgroup.manager_root, "cgroup manager root")?;
    if cgroup.authority_root == Path::new("/") {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            "native recovery cgroup authority root must not be the filesystem root",
        ));
    }
    let manager_name = cgroup
        .manager_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if !manager_name.starts_with("a3s-oci-")
        || cgroup.manager_root.parent() != Some(cgroup.authority_root.as_path())
        || cgroup.created.is_empty()
    {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "native recovery cgroup manager is outside the runtime-owned layout: {}",
                cgroup.manager_root.display()
            ),
        ));
    }
    validate_absolute_normalized(&cgroup.leaf, "cgroup leaf")?;
    let ownership_root = if cgroup.leaf.starts_with(&cgroup.manager_root) {
        &cgroup.manager_root
    } else {
        &cgroup.authority_root
    };
    if cgroup.leaf == *ownership_root || !cgroup.leaf.starts_with(ownership_root) {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "native recovery cgroup leaf escapes its recorded authority: {}",
                cgroup.leaf.display()
            ),
        ));
    }
    let mut unique = std::collections::BTreeSet::new();
    for path in &cgroup.created {
        validate_absolute_normalized(path, "created cgroup")?;
        if path == ownership_root
            || path == &cgroup.manager_root
            || !path.starts_with(ownership_root)
            || !unique.insert(path)
        {
            return Err(recovery_error(
                ErrorCode::PermissionDenied,
                format!(
                    "native recovery cgroup path escapes its recorded authority or is duplicated: {}",
                    path.display()
                ),
            ));
        }
    }
    if !cgroup.created.iter().any(|path| path == &cgroup.leaf) {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            "native recovery cgroup leaf is not an exact runtime-created path",
        ));
    }
    Ok(())
}

async fn cleanup_cgroup(cgroup: &RecoveryCgroupRecord) -> Result<()> {
    validate_cgroup_record(cgroup)?;
    let termination_root = recovery_cgroup_termination_root(cgroup)?;
    let freeze = cgroup.leaf.join(CGROUP_FREEZE);
    match std::fs::write(&freeze, b"0") {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(recovery_io_error(
                format!(
                    "failed to thaw recovered native cgroup {}: {error}",
                    cgroup.leaf.display()
                ),
                error,
            ));
        }
    }
    drain_recovered_cgroup(termination_root).await?;
    for path in cgroup.created.iter().rev() {
        match std::fs::remove_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error)
                if error.kind() == io::ErrorKind::DirectoryNotEmpty && path != &cgroup.leaf =>
            {
                // OCI cgroupsPath may contain a shared intermediate prefix.
                // Removing the exact leaf is mandatory; a still-populated
                // ancestor remains owned by another durable generation.
            }
            Err(error) => {
                return Err(recovery_io_error(
                    format!(
                        "failed to remove recovered native cgroup {}: {error}",
                        path.display()
                    ),
                    error,
                ));
            }
        }
    }
    match std::fs::remove_dir(&cgroup.manager_root) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(recovery_io_error(
            format!(
                "failed to remove empty native cgroup manager {}: {error}",
                cgroup.manager_root.display()
            ),
            error,
        )),
    }
}

fn recovery_cgroup_termination_root(cgroup: &RecoveryCgroupRecord) -> Result<&Path> {
    let Some(parent) = cgroup.leaf.parent() else {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            "recovered native cgroup leaf has no parent",
        ));
    };
    let control = parent.join(CONTROL_CGROUP_NAME);
    let is_control_workload = cgroup
        .leaf
        .file_name()
        .is_some_and(|name| name == std::ffi::OsStr::new(WORKLOAD_CGROUP_NAME))
        && cgroup.created.iter().any(|path| path == parent)
        && cgroup.created.iter().any(|path| path == &control);
    if is_control_workload {
        Ok(parent)
    } else {
        Ok(&cgroup.leaf)
    }
}

async fn drain_recovered_cgroup(path: &Path) -> Result<()> {
    let events = path.join(CGROUP_EVENTS);
    match read_cgroup_populated(&events).await? {
        None | Some(false) => return Ok(()),
        Some(true) => {}
    }

    let kill = path.join(CGROUP_KILL);
    tokio::fs::write(&kill, b"1").await.map_err(|error| {
        recovery_io_error(
            format!(
                "failed to terminate recovered native cgroup {}: {error}",
                path.display()
            ),
            error,
        )
    })?;

    let deadline = Instant::now() + TERMINATION_TIMEOUT;
    loop {
        match read_cgroup_populated(&events).await? {
            None | Some(false) => return Ok(()),
            Some(true) => {}
        }
        if Instant::now() >= deadline {
            return Err(recovery_error(
                ErrorCode::DeadlineExceeded,
                format!(
                    "timed out waiting for recovered native cgroup {} to become empty",
                    path.display()
                ),
            )
            .retryable(true));
        }
        sleep(TERMINATION_POLL_INTERVAL).await;
    }
}

async fn read_cgroup_populated(path: &Path) -> Result<Option<bool>> {
    let encoded = match tokio::fs::read_to_string(path).await {
        Ok(encoded) => encoded,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(recovery_io_error(
                format!(
                    "failed to inspect recovered native cgroup events {}: {error}",
                    path.display()
                ),
                error,
            ));
        }
    };
    parse_cgroup_populated(&encoded).map(Some)
}

fn parse_cgroup_populated(events: &str) -> Result<bool> {
    for line in events.lines() {
        let mut fields = line.split_ascii_whitespace();
        if fields.next() != Some("populated") {
            continue;
        }
        return match (fields.next(), fields.next()) {
            (Some("0"), None) => Ok(false),
            (Some("1"), None) => Ok(true),
            _ => Err(recovery_error(
                ErrorCode::FailedPrecondition,
                "recovered native cgroup has an invalid populated event",
            )),
        };
    }
    Err(recovery_error(
        ErrorCode::FailedPrecondition,
        "recovered native cgroup events omit the populated state",
    ))
}

fn cleanup_empty_runtime_root(runtime_root: &Path) -> Result<()> {
    let mut remaining_slots = false;
    for entry in std::fs::read_dir(runtime_root).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to inspect recovered executor root {}: {error}",
                runtime_root.display()
            ),
            error,
        )
    })? {
        let entry = entry.map_err(|error| {
            recovery_io_error("failed to enumerate recovered executor root", error)
        })?;
        let name = entry.file_name();
        if name == OWNER_RECORD_NAME {
            continue;
        }
        let file_type = entry.file_type().map_err(|error| {
            recovery_io_error(
                format!(
                    "failed to inspect recovered entry {}",
                    entry.path().display()
                ),
                error,
            )
        })?;
        if file_type.is_dir()
            && !file_type.is_symlink()
            && name.to_str().is_some_and(|name| name.starts_with("c-"))
        {
            remaining_slots = true;
            continue;
        }
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "unexpected entry remains in recovered executor root: {}",
                entry.path().display()
            ),
        ));
    }
    if remaining_slots {
        return Ok(());
    }
    std::fs::remove_file(runtime_root.join(OWNER_RECORD_NAME)).map_err(|error| {
        recovery_io_error("failed to remove recovered executor owner record", error)
    })?;
    std::fs::remove_dir(runtime_root).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to remove empty recovered executor root {}: {error}",
                runtime_root.display()
            ),
            error,
        )
    })
}

fn list_real_directories(parent: &Path, prefix: &str) -> Result<Vec<PathBuf>> {
    ensure_private_directory(parent, 0o700)?;
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(parent).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to enumerate native recovery root {}: {error}",
                parent.display()
            ),
            error,
        )
    })? {
        let entry = entry.map_err(|error| {
            recovery_io_error("failed to enumerate native recovery entry", error)
        })?;
        let name = entry.file_name();
        if !name.to_str().is_some_and(|name| name.starts_with(prefix)) {
            continue;
        }
        let file_type = entry.file_type().map_err(|error| {
            recovery_io_error(
                format!(
                    "failed to inspect native recovery entry {}",
                    entry.path().display()
                ),
                error,
            )
        })?;
        if !file_type.is_dir() || file_type.is_symlink() {
            return Err(recovery_error(
                ErrorCode::PermissionDenied,
                format!(
                    "native recovery entry must be a real directory: {}",
                    entry.path().display()
                ),
            ));
        }
        ensure_private_directory(&entry.path(), 0o700)?;
        paths.push(entry.path());
    }
    Ok(paths)
}

fn ensure_private_directory(path: &Path, mode: u32) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to inspect protected directory {}: {error}",
                path.display()
            ),
            error,
        )
    })?;
    let uid = durable_owner_uid(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != mode
    {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "protected directory {} must be owned by UID {uid} with mode {mode:04o}",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Owner identity for durable executor state.
///
/// Native host paths use the current effective UID. Paths under the utility-VM
/// runtime share use the share root's owner instead: libkrun virtiofs remaps
/// guest-root writes to the Host Service UID, so `geteuid()` (often 0 in the
/// Guest Agent) does not match the on-disk owner.
fn durable_owner_uid(path: &Path) -> Result<u32> {
    durable_owner_uid_for(path, Path::new(AGENT_RUNTIME_SHARE_GUEST_ROOT))
}

fn durable_owner_uid_for(path: &Path, share_root: &Path) -> Result<u32> {
    if path == share_root || path.starts_with(share_root) {
        let metadata = std::fs::symlink_metadata(share_root).map_err(|error| {
            recovery_io_error(
                format!(
                    "failed to inspect runtime share root {}: {error}",
                    share_root.display()
                ),
                error,
            )
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(recovery_error(
                ErrorCode::PermissionDenied,
                format!(
                    "runtime share root must be a real directory: {}",
                    share_root.display()
                ),
            ));
        }
        return Ok(metadata.uid());
    }
    // SAFETY: geteuid has no preconditions or failure result.
    Ok(unsafe { libc::geteuid() })
}

fn reject_symlinks_below(path: &Path) -> Result<()> {
    for entry in std::fs::read_dir(path).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to inspect recovery directory {}: {error}",
                path.display()
            ),
            error,
        )
    })? {
        let entry =
            entry.map_err(|error| recovery_io_error("failed to inspect recovery entry", error))?;
        let file_type = entry.file_type().map_err(|error| {
            recovery_io_error(
                format!(
                    "failed to inspect recovery entry {}",
                    entry.path().display()
                ),
                error,
            )
        })?;
        if file_type.is_symlink() {
            return Err(recovery_error(
                ErrorCode::PermissionDenied,
                format!(
                    "recovery directory contains a symlink: {}",
                    entry.path().display()
                ),
            ));
        }
        if file_type.is_dir() {
            reject_symlinks_below(&entry.path())?;
        }
    }
    Ok(())
}

fn parse_runtime_root_name(name: &str) -> Option<ProcessIdentity> {
    let suffix = name.strip_prefix(RUNTIME_ROOT_PREFIX)?;
    let (pid, start) = suffix.split_once('-')?;
    if start.contains('-') {
        return None;
    }
    let identity = ProcessIdentity {
        pid: pid.parse().ok()?,
        start_time_ticks: u64::from_str_radix(start, 16).ok()?,
    };
    (identity.pid > 0 && runtime_root_name(identity) == name).then_some(identity)
}

fn process_observation(pid: i32) -> Result<Option<ProcessObservation>> {
    if pid <= 0 {
        return Err(recovery_error(
            ErrorCode::InvalidArgument,
            format!("recovery process PID must be positive; received {pid}"),
        ));
    }
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(recovery_io_error(
                format!(
                    "failed to read process identity {}: {error}",
                    path.display()
                ),
                error,
            ));
        }
    };
    if contents.len() > 4096 {
        return Err(recovery_error(
            ErrorCode::ResourceExhausted,
            format!("process identity exceeds 4096 bytes: {}", path.display()),
        ));
    }
    let closing = contents.rfind(") ").ok_or_else(|| {
        recovery_error(
            ErrorCode::FailedPrecondition,
            format!("process identity is malformed: {}", path.display()),
        )
    })?;
    let reported_pid = contents[..]
        .split_once(" (")
        .and_then(|(pid, _)| pid.parse::<i32>().ok())
        .ok_or_else(|| {
            recovery_error(
                ErrorCode::FailedPrecondition,
                format!("process identity has no valid PID: {}", path.display()),
            )
        })?;
    if reported_pid != pid {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "process identity PID mismatch at {}: expected {pid}, observed {reported_pid}",
                path.display()
            ),
        ));
    }
    let fields = contents[closing + 2..]
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    let state = fields
        .first()
        .filter(|field| field.len() == 1)
        .and_then(|field| field.as_bytes().first())
        .copied()
        .ok_or_else(|| {
            recovery_error(
                ErrorCode::FailedPrecondition,
                format!("process identity has no valid state: {}", path.display()),
            )
        })?;
    let start_time_ticks = fields
        .get(19)
        .and_then(|field| field.parse::<u64>().ok())
        .ok_or_else(|| {
            recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "process identity has no valid start time: {}",
                    path.display()
                ),
            )
        })?;
    Ok(Some(ProcessObservation {
        start_time_ticks,
        state,
    }))
}

fn write_atomic_record<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut encoded = serde_json::to_vec_pretty(value).map_err(|error| {
        recovery_error(
            ErrorCode::Internal,
            format!("failed to encode native recovery record: {error}"),
        )
    })?;
    encoded.push(b'\n');
    if encoded.len() as u64 > MAX_RECORD_BYTES {
        return Err(recovery_error(
            ErrorCode::ResourceExhausted,
            "native recovery record exceeds its bounded size",
        ));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            recovery_error(
                ErrorCode::InvalidArgument,
                format!(
                    "native recovery record has no UTF-8 filename: {}",
                    path.display()
                ),
            )
        })?;
    let pending = path.with_file_name(format!(".{name}.next"));
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let result = (|| -> io::Result<()> {
        let mut file = options.open(&pending)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        std::fs::hard_link(&pending, path)?;
        std::fs::remove_file(&pending)?;
        File::open(path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "recovery record has no parent")
        })?)?
        .sync_all()
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&pending);
        return Err(recovery_io_error(
            format!(
                "failed to persist native recovery record {}: {error}",
                path.display()
            ),
            error,
        ));
    }
    Ok(())
}

pub(super) fn read_json_record<T: for<'de> Deserialize<'de>>(path: &Path, limit: u64) -> Result<T> {
    let bytes = read_bounded_plain_file(path, limit)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        recovery_error(
            ErrorCode::FailedPrecondition,
            format!(
                "native recovery record {} is invalid: {error}",
                path.display()
            ),
        )
    })
}

fn read_bounded_plain_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to inspect native recovery file {}: {error}",
                path.display()
            ),
            error,
        )
    })?;
    let uid = durable_owner_uid(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > limit
    {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "native recovery file {} must be a bounded plain mode-0600 file owned by UID {uid}",
                path.display()
            ),
        ));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to open native recovery file {}: {error}",
                path.display()
            ),
            error,
        )
    })?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            recovery_io_error(
                format!(
                    "failed to read native recovery file {}: {error}",
                    path.display()
                ),
                error,
            )
        })?;
    if bytes.len() as u64 > limit {
        return Err(recovery_error(
            ErrorCode::ResourceExhausted,
            format!(
                "native recovery file grew beyond its limit: {}",
                path.display()
            ),
        ));
    }
    Ok(bytes)
}

fn config_digest_for(contents: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(contents))
}

fn validate_absolute_normalized(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(recovery_error(
            ErrorCode::PermissionDenied,
            format!(
                "{label} must be absolute and normalized: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn recovery_io_error(message: impl Into<String>, error: io::Error) -> Error {
    let code = match error.kind() {
        io::ErrorKind::NotFound => ErrorCode::FailedPrecondition,
        io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        io::ErrorKind::AlreadyExists => ErrorCode::Conflict,
        _ => ErrorCode::Internal,
    };
    recovery_error(code, message)
}

fn recovery_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("native-linux-recover")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn runtime_root_name_round_trips_exact_process_identity() {
        let identity = ProcessIdentity {
            pid: 42_001,
            start_time_ticks: 0x1234_abcd,
        };
        let name = runtime_root_name(identity);
        assert_eq!(parse_runtime_root_name(&name), Some(identity));
        assert_eq!(parse_runtime_root_name("a3s-oci-agent-42001"), None);
        assert_eq!(
            parse_runtime_root_name("a3s-oci-agent-0-0000000000000001"),
            None
        );
    }

    #[test]
    fn current_process_identity_is_live_and_pid_bound() {
        let identity = ProcessIdentity::current().expect("current process identity");
        assert!(identity.is_live().expect("inspect current identity"));
        assert_eq!(identity.pid as u32, std::process::id());

        let stale = ProcessIdentity {
            pid: identity.pid,
            start_time_ticks: identity.start_time_ticks.saturating_add(1),
        };
        assert!(
            !stale.is_live().expect("inspect reused numeric PID"),
            "a reused numeric PID must not match the authenticated start time"
        );
    }

    #[test]
    fn zombie_and_dead_process_states_are_terminal() {
        for state in *b"ZXx" {
            assert!(ProcessObservation {
                start_time_ticks: 1,
                state,
            }
            .is_terminated());
        }
        for state in *b"RSDTtI" {
            assert!(!ProcessObservation {
                start_time_ticks: 1,
                state,
            }
            .is_terminated());
        }
    }

    #[test]
    fn cgroup_record_rejects_broad_or_escaping_paths() {
        let broad = RecoveryCgroupRecord {
            authority_root: PathBuf::from("/sys/fs/cgroup"),
            manager_root: PathBuf::from("/sys/fs/cgroup"),
            leaf: PathBuf::from("/sys/fs/cgroup/workload"),
            created: vec![PathBuf::from("/sys/fs/cgroup/workload")],
        };
        assert!(validate_cgroup_record(&broad).is_err());

        let escaping = RecoveryCgroupRecord {
            authority_root: PathBuf::from("/sys/fs/cgroup"),
            manager_root: PathBuf::from("/sys/fs/cgroup/a3s-oci-1-test"),
            leaf: PathBuf::from("/outside/unrelated"),
            created: vec![PathBuf::from("/outside/unrelated")],
        };
        assert!(validate_cgroup_record(&escaping).is_err());

        let unrelated_authority = RecoveryCgroupRecord {
            authority_root: PathBuf::from("/sys/fs/cgroup/delegated-a"),
            manager_root: PathBuf::from("/sys/fs/cgroup/delegated-b/a3s-oci-1-test"),
            leaf: PathBuf::from("/sys/fs/cgroup/delegated-b/a3s-oci-1-test/workload"),
            created: vec![PathBuf::from(
                "/sys/fs/cgroup/delegated-b/a3s-oci-1-test/workload",
            )],
        };
        assert!(validate_cgroup_record(&unrelated_authority).is_err());

        let absolute = RecoveryCgroupRecord {
            authority_root: PathBuf::from("/sys/fs/cgroup"),
            manager_root: PathBuf::from("/sys/fs/cgroup/a3s-oci-1-test"),
            leaf: PathBuf::from("/sys/fs/cgroup/tenant/workload"),
            created: vec![
                PathBuf::from("/sys/fs/cgroup/tenant"),
                PathBuf::from("/sys/fs/cgroup/tenant/workload"),
            ],
        };
        validate_cgroup_record(&absolute).expect("absolute cgroup recovery record");

        let mut duplicate = absolute;
        duplicate.created.push(duplicate.leaf.clone());
        assert!(validate_cgroup_record(&duplicate).is_err());
    }

    #[test]
    fn recovered_cgroup_termination_root_is_generation_scoped() {
        let authority = PathBuf::from("/sys/fs/cgroup");
        let manager = authority.join("a3s-oci-1-test");
        let management = manager.join("tenant");
        let control = management.join(CONTROL_CGROUP_NAME);
        let workload = management.join(WORKLOAD_CGROUP_NAME);
        let control_workload = RecoveryCgroupRecord {
            authority_root: authority.clone(),
            manager_root: manager.clone(),
            leaf: workload.clone(),
            created: vec![management.clone(), control, workload],
        };
        validate_cgroup_record(&control_workload).expect("control/workload recovery record");
        assert_eq!(
            recovery_cgroup_termination_root(&control_workload)
                .expect("control/workload termination root"),
            management
        );

        let leaf = manager.join("plain");
        let plain = RecoveryCgroupRecord {
            authority_root: authority,
            manager_root: manager,
            leaf: leaf.clone(),
            created: vec![leaf.clone()],
        };
        validate_cgroup_record(&plain).expect("plain recovery record");
        assert_eq!(
            recovery_cgroup_termination_root(&plain).expect("plain termination root"),
            leaf
        );
    }

    #[test]
    fn recovered_cgroup_populated_event_is_strict() {
        assert!(parse_cgroup_populated("frozen 1\npopulated 1\n").expect("populated cgroup"));
        assert!(!parse_cgroup_populated("populated 0\nfrozen 0\n").expect("empty cgroup"));
        assert!(parse_cgroup_populated("frozen 0\n").is_err());
        assert!(parse_cgroup_populated("populated 2\n").is_err());
        assert!(parse_cgroup_populated("populated 0 trailing\n").is_err());
    }

    #[test]
    fn legacy_rootful_recovery_cgroup_normalizes_to_the_v3_model() {
        let legacy = LegacyContainerRecoveryRecord {
            schema_version: CONTAINER_SCHEMA_VERSION_V1.to_string(),
            target: ContainerTarget::exact(
                a3s_oci_sdk::ContainerId::new("legacy-rootful").expect("container ID"),
                a3s_oci_sdk::Generation(1),
            ),
            config_digest: "sha256:test".to_string(),
            owner: ProcessIdentity {
                pid: 100,
                start_time_ticks: 1,
            },
            launcher: ProcessIdentity {
                pid: 101,
                start_time_ticks: 2,
            },
            init: ProcessIdentity {
                pid: 102,
                start_time_ticks: 3,
            },
            cgroup: Some(LegacyRecoveryCgroupRecord {
                manager_root: PathBuf::from("/sys/fs/cgroup/a3s-oci-100-test"),
                leaf: PathBuf::from("/sys/fs/cgroup/a3s-oci-100-test/workload"),
                created: vec![PathBuf::from("/sys/fs/cgroup/a3s-oci-100-test/workload")],
            }),
        };

        let normalized =
            normalize_legacy_container_record(legacy).expect("normalize rootful v1 record");
        assert_eq!(normalized.schema_version, CONTAINER_SCHEMA_VERSION);
        assert_eq!(
            normalized.cgroup.expect("normalized cgroup").authority_root,
            PathBuf::from("/sys/fs/cgroup")
        );
    }

    #[test]
    fn v2_recovery_record_normalizes_without_inventing_resctrl_ownership() {
        let previous = PreviousContainerRecoveryRecord {
            schema_version: CONTAINER_SCHEMA_VERSION_V2.to_string(),
            target: ContainerTarget::exact(
                a3s_oci_sdk::ContainerId::new("v2-record").expect("container ID"),
                a3s_oci_sdk::Generation(1),
            ),
            config_digest: "sha256:test".to_string(),
            owner: ProcessIdentity {
                pid: 100,
                start_time_ticks: 1,
            },
            launcher: ProcessIdentity {
                pid: 101,
                start_time_ticks: 2,
            },
            init: ProcessIdentity {
                pid: 102,
                start_time_ticks: 3,
            },
            cgroup: None,
        };

        let normalized = normalize_v2_container_record(previous);
        assert_eq!(normalized.schema_version, CONTAINER_SCHEMA_VERSION);
        assert!(normalized.intel_rdt.is_none());
        assert!(normalized.session_supervisor.is_none());
        assert!(normalized.execs.is_empty());
    }

    #[test]
    fn v3_recovery_record_normalizes_without_inventing_session_supervisor() {
        let previous = V3ContainerRecoveryRecord {
            schema_version: CONTAINER_SCHEMA_VERSION_V3.to_string(),
            target: ContainerTarget::exact(
                a3s_oci_sdk::ContainerId::new("v3-record").expect("container ID"),
                a3s_oci_sdk::Generation(1),
            ),
            config_digest: "sha256:test".to_string(),
            owner: ProcessIdentity {
                pid: 100,
                start_time_ticks: 1,
            },
            launcher: ProcessIdentity {
                pid: 101,
                start_time_ticks: 2,
            },
            init: ProcessIdentity {
                pid: 102,
                start_time_ticks: 3,
            },
            cgroup: None,
            intel_rdt: None,
        };

        let normalized = normalize_v3_container_record(previous);
        assert_eq!(normalized.schema_version, CONTAINER_SCHEMA_VERSION);
        assert!(normalized.session_supervisor.is_none());
        assert!(normalized.execs.is_empty());
        assert!(normalized.intel_rdt.is_none());
    }

    #[test]
    fn v4_recovery_record_normalizes_without_inventing_exec_inventory() {
        let previous = V4ContainerRecoveryRecord {
            schema_version: CONTAINER_SCHEMA_VERSION_V4.to_string(),
            target: ContainerTarget::exact(
                a3s_oci_sdk::ContainerId::new("v4-record").expect("container ID"),
                a3s_oci_sdk::Generation(1),
            ),
            config_digest: "sha256:test".to_string(),
            owner: ProcessIdentity {
                pid: 100,
                start_time_ticks: 1,
            },
            launcher: ProcessIdentity {
                pid: 101,
                start_time_ticks: 2,
            },
            init: ProcessIdentity {
                pid: 102,
                start_time_ticks: 3,
            },
            session_supervisor: Some(ProcessIdentity {
                pid: 103,
                start_time_ticks: 4,
            }),
            cgroup: None,
            intel_rdt: None,
        };

        let normalized = normalize_v4_container_record(previous);
        assert_eq!(normalized.schema_version, CONTAINER_SCHEMA_VERSION);
        assert!(normalized.session_supervisor.is_some());
        assert!(
            normalized.execs.is_empty(),
            "v4 records must normalize without inventing durable exec entries"
        );
    }

    #[test]
    fn intel_rdt_recovery_rejects_broad_or_tampered_paths() {
        let valid = RecoveryIntelRdtRecord {
            mountpoint: PathBuf::from("/sys/fs/resctrl"),
            control_group: PathBuf::from("/sys/fs/resctrl/container-rdt"),
            remove_control_group: true,
            monitoring_group: Some(PathBuf::from(
                "/sys/fs/resctrl/container-rdt/mon_groups/container-rdt",
            )),
        };
        validate_intel_rdt_record(&valid, "container-rdt").expect("valid resctrl ownership");
        let error = cleanup_intel_rdt_with_mountinfo(
            &valid,
            "container-rdt",
            "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
        )
        .expect_err("recovery must not remove paths outside a current resctrl mount");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);

        let mut tampered = valid.clone();
        tampered.mountpoint = PathBuf::from("/");
        assert!(validate_intel_rdt_record(&tampered, "container-rdt").is_err());

        let mut tampered = valid.clone();
        tampered.control_group = PathBuf::from("/sys/fs/resctrl/shared/container-rdt");
        assert!(validate_intel_rdt_record(&tampered, "container-rdt").is_err());

        let mut tampered = valid.clone();
        tampered.control_group = PathBuf::from("/sys/fs/resctrl/unrelated");
        assert!(validate_intel_rdt_record(&tampered, "container-rdt").is_err());

        let mut tampered = valid;
        tampered.monitoring_group = Some(PathBuf::from(
            "/sys/fs/resctrl/container-rdt/mon_groups/another-container",
        ));
        assert!(validate_intel_rdt_record(&tampered, "container-rdt").is_err());
    }

    #[test]
    fn intel_rdt_recovery_removes_monitoring_before_owned_control_and_retries() {
        let temporary = tempfile::tempdir().expect("temporary resctrl fixture");
        let mountpoint = temporary.path().join("resctrl");
        let control_group = mountpoint.join("container-rdt");
        let monitoring_parent = control_group.join("mon_groups");
        let monitoring_group = monitoring_parent.join("container-rdt");
        std::fs::create_dir_all(&monitoring_group).expect("monitoring group");
        let record = RecoveryIntelRdtRecord {
            mountpoint,
            control_group: control_group.clone(),
            remove_control_group: true,
            monitoring_group: Some(monitoring_group.clone()),
        };
        let mountinfo = format!(
            "30 23 0:27 / {} rw - resctrl resctrl rw\n",
            record.mountpoint.display()
        );

        let error = cleanup_intel_rdt_with_mountinfo(&record, "container-rdt", &mountinfo)
            .expect_err("ordinary fixture still contains the virtual mon_groups parent");
        assert_eq!(error.code, ErrorCode::Internal);
        assert!(!monitoring_group.exists());
        assert!(control_group.exists());

        std::fs::remove_dir(&monitoring_parent).expect("remove fixture monitoring parent");
        cleanup_intel_rdt_with_mountinfo(&record, "container-rdt", &mountinfo)
            .expect("retry resctrl cleanup");
        assert!(!control_group.exists());
    }

    #[test]
    fn legacy_delegated_recovery_cgroup_fails_closed() {
        let legacy = LegacyContainerRecoveryRecord {
            schema_version: CONTAINER_SCHEMA_VERSION_V1.to_string(),
            target: ContainerTarget::exact(
                a3s_oci_sdk::ContainerId::new("legacy-delegated").expect("container ID"),
                a3s_oci_sdk::Generation(1),
            ),
            config_digest: "sha256:test".to_string(),
            owner: ProcessIdentity {
                pid: 100,
                start_time_ticks: 1,
            },
            launcher: ProcessIdentity {
                pid: 101,
                start_time_ticks: 2,
            },
            init: ProcessIdentity {
                pid: 102,
                start_time_ticks: 3,
            },
            cgroup: Some(LegacyRecoveryCgroupRecord {
                manager_root: PathBuf::from("/sys/fs/cgroup/delegated/a3s-oci-100-test"),
                leaf: PathBuf::from("/sys/fs/cgroup/delegated/a3s-oci-100-test/workload"),
                created: vec![PathBuf::from(
                    "/sys/fs/cgroup/delegated/a3s-oci-100-test/workload",
                )],
            }),
        };

        let error = normalize_legacy_container_record(legacy)
            .expect_err("v1 delegated authority is unknowable");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert!(error.message.contains("not a direct rootful"));
    }

    #[tokio::test]
    async fn stale_record_recovers_only_with_exact_snapshot_and_cleans_its_root() {
        let fixture = RecoveryFixture::new("exact-record");
        let recovery = recover_stale_generation(
            &fixture.parent,
            &fixture.current_root,
            &fixture.target,
            &fixture.digest,
            Some(fixture.init.pid),
            &SessionSupervisorReattachCache::default(),
        )
        .await
        .expect("search exact stale generation")
        .expect("recover exact stale generation");
        let StaleGenerationRecovery::Stopped(tombstone) = recovery else {
            panic!("fixture without session supervisor must recover as stopped");
        };
        assert_eq!(tombstone.target(), &fixture.target);
        delete_stale_generation(&tombstone)
            .await
            .expect("delete exact stale generation");
        assert!(!fixture.stale_root.exists());
    }

    #[tokio::test]
    async fn live_session_supervisor_reattaches_for_wait_kill_and_stopped_delete() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::path::Path;

        use super::super::pid_supervisor::{terminate_pid, wait_for_child};
        use super::super::session_supervisor::HostSessionSupervisor;

        let temporary = tempfile::tempdir().expect("temporary recovery parent");
        let parent = temporary.path().join("executor");
        std::fs::create_dir(&parent).expect("executor parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("protect executor parent");
        let current_root = parent.join("current");
        std::fs::create_dir(&current_root).expect("current root");
        std::fs::set_permissions(&current_root, std::fs::Permissions::from_mode(0o700))
            .expect("protect current root");

        let (mut parent_ready, mut child_ready) =
            UnixStream::pair().expect("recovery reattach ready channel");
        // SAFETY: parent reaps the fake Host; child owns the production supervisor.
        let host_pid = unsafe { libc::fork() };
        assert!(host_pid >= 0, "fork fake host for recovery reattach");
        if host_pid == 0 {
            drop(parent_ready);
            let mut supervisor = match HostSessionSupervisor::start_via_fork() {
                Ok(supervisor) => supervisor,
                Err(_) => unsafe { libc::_exit(121) },
            };
            let launcher_pid = match supervisor.spawn_launcher(
                Path::new("/bin/sleep"),
                &["30".into()],
                None,
                None,
                None,
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(122) },
            };
            let identity = supervisor.identity().clone();
            let mut payload = Vec::with_capacity(16);
            payload.extend_from_slice(&identity.pid().to_be_bytes());
            payload.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
            payload.extend_from_slice(&launcher_pid.to_be_bytes());
            if child_ready.write_all(&payload).is_err() {
                unsafe { libc::_exit(123) }
            }
            std::mem::forget(supervisor);
            loop {
                unsafe { libc::pause() };
            }
        }
        drop(child_ready);
        let mut payload = [0_u8; 16];
        parent_ready
            .read_exact(&mut payload)
            .expect("read live supervisor evidence");
        let supervisor_pid = i32::from_be_bytes(payload[0..4].try_into().expect("pid bytes"));
        let supervisor_start = u64::from_be_bytes(payload[4..12].try_into().expect("start bytes"));
        let launcher_pid = i32::from_be_bytes(payload[12..16].try_into().expect("launcher bytes"));

        let owner = ProcessIdentity {
            pid: 2_100_000,
            start_time_ticks: 0x111,
        };
        let stale_root = parent.join(runtime_root_name(owner));
        std::fs::create_dir(&stale_root).expect("stale root");
        std::fs::set_permissions(&stale_root, std::fs::Permissions::from_mode(0o700))
            .expect("protect stale root");
        write_atomic_record(
            &stale_root.join(OWNER_RECORD_NAME),
            &ExecutorOwnerRecord {
                schema_version: OWNER_SCHEMA_VERSION.to_string(),
                owner,
            },
        )
        .expect("owner record");
        let slot = stale_root.join("c-0000000000000001");
        std::fs::create_dir(&slot).expect("container slot");
        std::fs::set_permissions(&slot, std::fs::Permissions::from_mode(0o700))
            .expect("protect container slot");
        let config = br#"{"ociVersion":"1.3.0"}"#;
        let digest = config_digest_for(config);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options
            .open(slot.join(CONFIG_SNAPSHOT_NAME))
            .and_then(|mut file| file.write_all(config))
            .expect("configuration snapshot");
        let target = ContainerTarget::exact(
            a3s_oci_sdk::ContainerId::new("live-supervisor").expect("container ID"),
            a3s_oci_sdk::Generation(1),
        );
        let init = ProcessIdentity {
            pid: launcher_pid,
            start_time_ticks: process_observation(launcher_pid)
                .expect("observe launcher")
                .expect("launcher live")
                .start_time_ticks,
        };
        write_atomic_record(
            &slot.join(CONTAINER_RECORD_NAME),
            &ContainerRecoveryRecord {
                schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
                target: target.clone(),
                config_digest: digest.clone(),
                owner,
                launcher: init,
                init,
                session_supervisor: Some(ProcessIdentity::from_authenticated(
                    supervisor_pid,
                    supervisor_start,
                )),
                execs: Vec::new(),
                cgroup: None,
                intel_rdt: None,
            },
        )
        .expect("container recovery record");

        terminate_pid(host_pid);
        let _ = wait_for_child(host_pid);

        let supervisors = SessionSupervisorReattachCache::default();
        let recovery = recover_stale_generation(
            &parent,
            &current_root,
            &target,
            &digest,
            Some(launcher_pid),
            &supervisors,
        )
        .await
        .expect("live supervisor must reattach instead of fail-closed")
        .expect("recovery match");
        let StaleGenerationRecovery::Live(live) = recovery else {
            panic!("live session supervisor must recover as Live");
        };
        assert_eq!(live.launcher_pid(), launcher_pid);
        assert_eq!(live.supervisor_pid(), supervisor_pid);
        assert!(live.launcher_is_live().expect("launcher liveness"));
        assert!(live.init_is_live().expect("init liveness"));

        let inventory = live
            .process_inventory()
            .expect("live inventory must not invent failure");
        assert_eq!(
            inventory.len(),
            1,
            "live reopen must expose exactly the authenticated init"
        );
        assert_eq!(inventory[0].target.container, target);
        assert!(inventory[0].target.process_id.is_init());
        assert_eq!(
            inventory[0].pid,
            Some(u32::try_from(launcher_pid).expect("launcher pid fits u32"))
        );
        assert!(
            !inventory[0].terminal,
            "partial inventory must not invent terminal mode"
        );

        let read_error = live
            .read_output(0, 4096, None)
            .expect_err("read-output must fail closed without restored capture stdio");
        assert_eq!(
            read_error.code,
            ErrorCode::Unavailable,
            "read-output must be Unavailable, not an invented empty stream"
        );
        assert!(
            !live.has_restored_stdin(),
            "fixture without stdin deposit must not invent a restored write end"
        );
        let write_error = live
            .write_stdin(b"nope")
            .await
            .expect_err("write-stdin without deposit must fail closed");
        assert_eq!(write_error.code, ErrorCode::Unavailable);

        live.kill_launcher().expect("kill supervised launcher");
        let status = live
            .wait_launcher()
            .expect("wait must return authentic supervised status");
        assert_eq!(
            status,
            libc::SIGKILL,
            "wait must surface the real SIGKILL status, not an invented exit code"
        );
        assert!(
            !live.launcher_is_live().expect("launcher should be dead"),
            "launcher must be reaped after authentic wait"
        );
        assert!(
            live.process_inventory()
                .expect("dead init inventory")
                .is_empty(),
            "inventory must be empty after init exits; never invent entries"
        );

        let tombstone = live
            .into_tombstone()
            .expect("dead supervised children can become a stopped tombstone");
        delete_stale_generation(&tombstone)
            .await
            .expect("stopped-only delete after live wait");
        assert!(!stale_root.exists());
        // Ensure the forgotten supervisor is cleaned up for the test process.
        terminate_pid(supervisor_pid);
        let _ = wait_for_child(supervisor_pid);
    }

    #[tokio::test]
    async fn live_session_inventory_exposes_live_exec_and_omits_dead_without_inventing_exit() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::path::Path;

        use super::super::pid_supervisor::{terminate_pid, wait_for_child};
        use super::super::session_supervisor::HostSessionSupervisor;

        let temporary = tempfile::tempdir().expect("temporary recovery parent");
        let parent = temporary.path().join("executor");
        std::fs::create_dir(&parent).expect("executor parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("protect executor parent");
        let current_root = parent.join("current");
        std::fs::create_dir(&current_root).expect("current root");
        std::fs::set_permissions(&current_root, std::fs::Permissions::from_mode(0o700))
            .expect("protect current root");

        let (mut parent_ready, mut child_ready) =
            UnixStream::pair().expect("exec inventory ready channel");
        // SAFETY: parent reaps the fake Host; child owns the production supervisor.
        let host_pid = unsafe { libc::fork() };
        assert!(host_pid >= 0, "fork fake host for exec inventory");
        if host_pid == 0 {
            drop(parent_ready);
            let mut supervisor = match HostSessionSupervisor::start_via_fork() {
                Ok(supervisor) => supervisor,
                Err(_) => unsafe { libc::_exit(151) },
            };
            let launcher_pid = match supervisor.spawn_launcher(
                Path::new("/bin/sleep"),
                &["30".into()],
                None,
                None,
                None,
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(152) },
            };
            let exec_pid = match supervisor.spawn_launcher(
                Path::new("/bin/sleep"),
                &["30".into()],
                None,
                None,
                None,
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(153) },
            };
            let identity = supervisor.identity().clone();
            let mut payload = Vec::with_capacity(20);
            payload.extend_from_slice(&identity.pid().to_be_bytes());
            payload.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
            payload.extend_from_slice(&launcher_pid.to_be_bytes());
            payload.extend_from_slice(&exec_pid.to_be_bytes());
            if child_ready.write_all(&payload).is_err() {
                unsafe { libc::_exit(154) }
            }
            std::mem::forget(supervisor);
            loop {
                unsafe { libc::pause() };
            }
        }
        drop(child_ready);
        let mut payload = [0_u8; 20];
        parent_ready
            .read_exact(&mut payload)
            .expect("read exec-inventory supervisor evidence");
        let supervisor_pid = i32::from_be_bytes(payload[0..4].try_into().expect("pid bytes"));
        let supervisor_start = u64::from_be_bytes(payload[4..12].try_into().expect("start bytes"));
        let launcher_pid = i32::from_be_bytes(payload[12..16].try_into().expect("launcher bytes"));
        let exec_pid = i32::from_be_bytes(payload[16..20].try_into().expect("exec bytes"));

        let owner = ProcessIdentity {
            pid: 2_100_500,
            start_time_ticks: 0x515,
        };
        let stale_root = parent.join(runtime_root_name(owner));
        std::fs::create_dir(&stale_root).expect("stale root");
        std::fs::set_permissions(&stale_root, std::fs::Permissions::from_mode(0o700))
            .expect("protect stale root");
        write_atomic_record(
            &stale_root.join(OWNER_RECORD_NAME),
            &ExecutorOwnerRecord {
                schema_version: OWNER_SCHEMA_VERSION.to_string(),
                owner,
            },
        )
        .expect("owner record");
        let slot = stale_root.join("c-0000000000000001");
        std::fs::create_dir(&slot).expect("container slot");
        std::fs::set_permissions(&slot, std::fs::Permissions::from_mode(0o700))
            .expect("protect container slot");
        let config = br#"{"ociVersion":"1.3.0"}"#;
        let digest = config_digest_for(config);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options
            .open(slot.join(CONFIG_SNAPSHOT_NAME))
            .and_then(|mut file| file.write_all(config))
            .expect("configuration snapshot");
        let target = ContainerTarget::exact(
            a3s_oci_sdk::ContainerId::new("live-exec-inventory").expect("container ID"),
            a3s_oci_sdk::Generation(1),
        );
        let init = ProcessIdentity {
            pid: launcher_pid,
            start_time_ticks: process_observation(launcher_pid)
                .expect("observe launcher")
                .expect("launcher live")
                .start_time_ticks,
        };
        let exec_id = a3s_oci_sdk::ProcessId::new("worker").expect("exec process ID");
        let exec_identity = ProcessIdentity {
            pid: exec_pid,
            start_time_ticks: process_observation(exec_pid)
                .expect("observe exec")
                .expect("exec live")
                .start_time_ticks,
        };
        write_atomic_record(
            &slot.join(CONTAINER_RECORD_NAME),
            &ContainerRecoveryRecord {
                schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
                target: target.clone(),
                config_digest: digest.clone(),
                owner,
                launcher: init,
                init,
                session_supervisor: Some(ProcessIdentity::from_authenticated(
                    supervisor_pid,
                    supervisor_start,
                )),
                execs: vec![RecoveryExecRecord {
                    process_id: exec_id.clone(),
                    identity: exec_identity,
                    terminal: false,
                }],
                cgroup: None,
                intel_rdt: None,
            },
        )
        .expect("container recovery record");

        terminate_pid(host_pid);
        let _ = wait_for_child(host_pid);

        let supervisors = SessionSupervisorReattachCache::default();
        let recovery = recover_stale_generation(
            &parent,
            &current_root,
            &target,
            &digest,
            Some(launcher_pid),
            &supervisors,
        )
        .await
        .expect("live supervisor must reattach with durable exec inventory")
        .expect("recovery match");
        let StaleGenerationRecovery::Live(live) = recovery else {
            panic!("live session supervisor must recover as Live");
        };

        let inventory = live
            .process_inventory()
            .expect("live inventory must not invent failure");
        assert_eq!(
            inventory.len(),
            2,
            "live reopen must expose authenticated init plus still-live exec"
        );
        assert!(inventory[0].target.process_id.is_init());
        assert_eq!(
            inventory[0].pid,
            Some(u32::try_from(launcher_pid).expect("launcher pid fits u32"))
        );
        assert_eq!(inventory[1].target.process_id, exec_id);
        assert_eq!(
            inventory[1].pid,
            Some(u32::try_from(exec_pid).expect("exec pid fits u32"))
        );
        assert!(
            !inventory[1].terminal,
            "inventory must retain durable terminal mode, not invent one"
        );

        terminate_pid(exec_pid);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let gone = process_observation(exec_pid)
                .expect("observe terminated exec")
                .is_none_or(|observation| observation.is_terminated());
            if gone {
                break;
            }
            if Instant::now() >= deadline {
                panic!("exec PID {exec_pid} did not exit after SIGKILL");
            }
            sleep(Duration::from_millis(10)).await;
        }
        let after_exit = live
            .process_inventory()
            .expect("inventory after exec exit must not invent failure");
        assert_eq!(after_exit.len(), 1, "dead exec must be omitted");
        assert!(after_exit[0].target.process_id.is_init());
        assert!(
            after_exit.iter().all(|record| record.pid.is_some()),
            "omitting a dead exec must not invent a terminal ProcessRecord"
        );

        live.kill_launcher().expect("kill supervised launcher");
        let _ = live.wait_launcher().expect("wait supervised launcher");
        let tombstone = live
            .into_tombstone()
            .expect("dead supervised children can become a stopped tombstone");
        delete_stale_generation(&tombstone)
            .await
            .expect("stopped-only delete after live wait");
        terminate_pid(supervisor_pid);
        let _ = wait_for_child(supervisor_pid);
    }

    #[tokio::test]
    async fn live_session_restores_deposited_stdin_and_fail_closes_read_output() {
        use std::io::{Read, Write};
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::net::UnixStream;
        use std::path::Path;

        use super::super::pid_supervisor::{terminate_pid, wait_for_child};
        use super::super::session_supervisor::HostSessionSupervisor;

        let temporary = tempfile::tempdir().expect("temporary recovery parent");
        let parent = temporary.path().join("executor");
        std::fs::create_dir(&parent).expect("executor parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("protect executor parent");
        let current_root = parent.join("current");
        std::fs::create_dir(&current_root).expect("current root");
        std::fs::set_permissions(&current_root, std::fs::Permissions::from_mode(0o700))
            .expect("protect current root");

        let (mut parent_ready, mut child_ready) =
            UnixStream::pair().expect("stdin restore ready channel");
        // SAFETY: parent reaps the fake Host; child owns the production supervisor.
        let host_pid = unsafe { libc::fork() };
        assert!(host_pid >= 0, "fork fake host for stdin restore");
        if host_pid == 0 {
            drop(parent_ready);
            let mut supervisor = match HostSessionSupervisor::start_via_fork() {
                Ok(supervisor) => supervisor,
                Err(_) => unsafe { libc::_exit(141) },
            };
            let mut fds = [0, 0];
            if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
                unsafe { libc::_exit(142) }
            }
            let child_stdin = unsafe { OwnedFd::from_raw_fd(fds[0]) };
            let host_stdin = unsafe { OwnedFd::from_raw_fd(fds[1]) };
            let deposit = unsafe { libc::fcntl(host_stdin.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if deposit < 0 {
                unsafe { libc::_exit(143) }
            }
            let launcher_pid = match supervisor.spawn_launcher(
                Path::new("/bin/cat"),
                &[],
                None,
                None,
                Some((Some(child_stdin.as_raw_fd()), None, None)),
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(144) },
            };
            drop(child_stdin);
            if supervisor.deposit_stdin(launcher_pid, deposit).is_err() {
                unsafe { libc::_exit(145) }
            }
            unsafe {
                libc::close(deposit);
            }
            let identity = supervisor.identity().clone();
            let mut payload = Vec::with_capacity(16);
            payload.extend_from_slice(&identity.pid().to_be_bytes());
            payload.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
            payload.extend_from_slice(&launcher_pid.to_be_bytes());
            if child_ready.write_all(&payload).is_err() {
                unsafe { libc::_exit(146) }
            }
            drop(host_stdin);
            std::mem::forget(supervisor);
            loop {
                unsafe { libc::pause() };
            }
        }
        drop(child_ready);
        let mut payload = [0_u8; 16];
        parent_ready
            .read_exact(&mut payload)
            .expect("read stdin-restore supervisor evidence");
        let supervisor_pid = i32::from_be_bytes(payload[0..4].try_into().expect("pid bytes"));
        let supervisor_start = u64::from_be_bytes(payload[4..12].try_into().expect("start bytes"));
        let launcher_pid = i32::from_be_bytes(payload[12..16].try_into().expect("launcher bytes"));

        let owner = ProcessIdentity {
            pid: 2_300_000,
            start_time_ticks: 0x333,
        };
        let stale_root = parent.join(runtime_root_name(owner));
        std::fs::create_dir(&stale_root).expect("stale root");
        std::fs::set_permissions(&stale_root, std::fs::Permissions::from_mode(0o700))
            .expect("protect stale root");
        write_atomic_record(
            &stale_root.join(OWNER_RECORD_NAME),
            &ExecutorOwnerRecord {
                schema_version: OWNER_SCHEMA_VERSION.to_string(),
                owner,
            },
        )
        .expect("owner record");
        let slot = stale_root.join("c-0000000000000001");
        std::fs::create_dir(&slot).expect("container slot");
        std::fs::set_permissions(&slot, std::fs::Permissions::from_mode(0o700))
            .expect("protect container slot");
        let config = br#"{"ociVersion":"1.3.0"}"#;
        let digest = config_digest_for(config);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options
            .open(slot.join(CONFIG_SNAPSHOT_NAME))
            .and_then(|mut file| file.write_all(config))
            .expect("configuration snapshot");
        let target = ContainerTarget::exact(
            a3s_oci_sdk::ContainerId::new("live-stdin-restore").expect("container ID"),
            a3s_oci_sdk::Generation(1),
        );
        let init = ProcessIdentity {
            pid: launcher_pid,
            start_time_ticks: process_observation(launcher_pid)
                .expect("observe launcher")
                .expect("launcher live")
                .start_time_ticks,
        };
        write_atomic_record(
            &slot.join(CONTAINER_RECORD_NAME),
            &ContainerRecoveryRecord {
                schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
                target: target.clone(),
                config_digest: digest.clone(),
                owner,
                launcher: init,
                init,
                session_supervisor: Some(ProcessIdentity::from_authenticated(
                    supervisor_pid,
                    supervisor_start,
                )),
                execs: Vec::new(),
                cgroup: None,
                intel_rdt: None,
            },
        )
        .expect("container recovery record");

        terminate_pid(host_pid);
        let _ = wait_for_child(host_pid);

        let supervisors = SessionSupervisorReattachCache::default();
        let recovery = recover_stale_generation(
            &parent,
            &current_root,
            &target,
            &digest,
            Some(launcher_pid),
            &supervisors,
        )
        .await
        .expect("live supervisor with stdin deposit must reattach")
        .expect("recovery match");
        let StaleGenerationRecovery::Live(live) = recovery else {
            panic!("stdin deposit recovery must be Live");
        };
        assert!(
            live.has_restored_stdin(),
            "Host reopen must restore the deposited stdin write end"
        );
        let read_error = live
            .read_output(0, 4096, None)
            .expect_err("capture stdio must stay Unavailable");
        assert_eq!(read_error.code, ErrorCode::Unavailable);

        live.write_stdin(b"hello-reopen\n")
            .await
            .expect("restored stdin must accept authentic writes");
        live.close_stdin()
            .await
            .expect("close restored stdin must deliver EOF without inventing status");
        let status = live
            .wait_launcher()
            .expect("wait must return authentic cat status");
        assert_eq!(status, 0, "cat must exit after authentic stdin EOF");

        let tombstone = live
            .into_tombstone()
            .expect("dead cat becomes stopped tombstone");
        delete_stale_generation(&tombstone)
            .await
            .expect("stopped-only delete");
        terminate_pid(supervisor_pid);
        let _ = wait_for_child(supervisor_pid);
    }

    #[tokio::test]
    async fn live_session_restores_deposited_output_relay() {
        use std::io::Write;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::net::UnixStream;
        use std::path::Path;

        use super::super::pid_supervisor::{terminate_pid, wait_for_child};
        use super::super::session_supervisor::HostSessionSupervisor;

        let temporary = tempfile::tempdir().expect("temporary recovery parent");
        let parent = temporary.path().join("executor");
        std::fs::create_dir(&parent).expect("executor parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("protect executor parent");
        let current_root = parent.join("current");
        std::fs::create_dir(&current_root).expect("current root");
        std::fs::set_permissions(&current_root, std::fs::Permissions::from_mode(0o700))
            .expect("protect current root");

        let (mut parent_ready, mut child_ready) =
            UnixStream::pair().expect("output restore ready channel");
        // SAFETY: parent reaps the fake Host; child owns the production supervisor.
        let host_pid = unsafe { libc::fork() };
        assert!(host_pid >= 0, "fork fake host for output restore");
        if host_pid == 0 {
            drop(parent_ready);
            let mut supervisor = match HostSessionSupervisor::start_via_fork() {
                Ok(supervisor) => supervisor,
                Err(_) => unsafe { libc::_exit(161) },
            };
            let mut fds = [0, 0];
            if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
                unsafe { libc::_exit(162) }
            }
            let host_stdout = unsafe { OwnedFd::from_raw_fd(fds[0]) };
            let child_stdout = unsafe { OwnedFd::from_raw_fd(fds[1]) };
            let launcher_pid = match supervisor.spawn_launcher(
                Path::new("/bin/echo"),
                &["reopen-out".into()],
                None,
                None,
                Some((None, Some(child_stdout.as_raw_fd()), None)),
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(163) },
            };
            drop(child_stdout);
            if supervisor
                .deposit_output(launcher_pid, Some(host_stdout), None)
                .is_err()
            {
                unsafe { libc::_exit(164) }
            }
            let identity = supervisor.identity().clone();
            let mut payload = Vec::with_capacity(16);
            payload.extend_from_slice(&identity.pid().to_be_bytes());
            payload.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
            payload.extend_from_slice(&launcher_pid.to_be_bytes());
            if child_ready.write_all(&payload).is_err() {
                unsafe { libc::_exit(165) }
            }
            std::mem::forget(supervisor);
            loop {
                unsafe { libc::pause() };
            }
        }
        drop(child_ready);
        let mut payload = [0_u8; 16];
        parent_ready
            .read_exact(&mut payload)
            .expect("read output-restore supervisor evidence");
        let supervisor_pid = i32::from_be_bytes(payload[0..4].try_into().expect("pid bytes"));
        let supervisor_start = u64::from_be_bytes(payload[4..12].try_into().expect("start bytes"));
        let launcher_pid = i32::from_be_bytes(payload[12..16].try_into().expect("launcher bytes"));

        let owner = ProcessIdentity {
            pid: 2_400_000,
            start_time_ticks: 0x444,
        };
        let stale_root = parent.join(runtime_root_name(owner));
        std::fs::create_dir(&stale_root).expect("stale root");
        std::fs::set_permissions(&stale_root, std::fs::Permissions::from_mode(0o700))
            .expect("protect stale root");
        write_atomic_record(
            &stale_root.join(OWNER_RECORD_NAME),
            &ExecutorOwnerRecord {
                schema_version: OWNER_SCHEMA_VERSION.to_string(),
                owner,
            },
        )
        .expect("owner record");
        let slot = stale_root.join("c-0000000000000001");
        std::fs::create_dir(&slot).expect("container slot");
        std::fs::set_permissions(&slot, std::fs::Permissions::from_mode(0o700))
            .expect("protect container slot");
        let config = br#"{"ociVersion":"1.3.0"}"#;
        let digest = config_digest_for(config);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options
            .open(slot.join(CONFIG_SNAPSHOT_NAME))
            .and_then(|mut file| file.write_all(config))
            .expect("configuration snapshot");
        let target = ContainerTarget::exact(
            a3s_oci_sdk::ContainerId::new("live-output-restore").expect("container ID"),
            a3s_oci_sdk::Generation(1),
        );
        let init = ProcessIdentity {
            pid: launcher_pid,
            start_time_ticks: process_observation(launcher_pid)
                .expect("observe launcher")
                .expect("launcher live")
                .start_time_ticks,
        };
        write_atomic_record(
            &slot.join(CONTAINER_RECORD_NAME),
            &ContainerRecoveryRecord {
                schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
                target: target.clone(),
                config_digest: digest.clone(),
                owner,
                launcher: init,
                init,
                session_supervisor: Some(ProcessIdentity::from_authenticated(
                    supervisor_pid,
                    supervisor_start,
                )),
                execs: Vec::new(),
                cgroup: None,
                intel_rdt: None,
            },
        )
        .expect("container recovery record");

        terminate_pid(host_pid);
        let _ = wait_for_child(host_pid);

        let supervisors = SessionSupervisorReattachCache::default();
        let recovery = recover_stale_generation(
            &parent,
            &current_root,
            &target,
            &digest,
            Some(launcher_pid),
            &supervisors,
        )
        .await
        .expect("live supervisor with output deposit must reattach")
        .expect("recovery match");
        let StaleGenerationRecovery::Live(live) = recovery else {
            panic!("output deposit recovery must be Live");
        };

        let mut after = 0_u64;
        let mut joined = Vec::new();
        let mut saw_eof = false;
        for _ in 0..100 {
            let chunks = live
                .read_output(after, 4096, Some(100))
                .expect("Host reopen must relay authentic capture chunks");
            if chunks.is_empty() {
                if saw_eof {
                    break;
                }
                continue;
            }
            if let Some(seq) = chunks.iter().map(|chunk| chunk.sequence).max() {
                after = seq;
            }
            for chunk in &chunks {
                if chunk.eof {
                    saw_eof = true;
                } else {
                    joined.extend_from_slice(&chunk.data);
                }
            }
            if saw_eof {
                break;
            }
        }
        assert!(
            joined
                .windows(b"reopen-out".len())
                .any(|w| w == b"reopen-out"),
            "reopen relay must surface authentic bytes, got {joined:?}"
        );
        assert!(saw_eof, "reopen relay must surface authentic EOF");

        let status = live
            .wait_launcher()
            .expect("wait must return authentic echo status");
        assert_eq!(status, 0, "echo must exit 0 after authentic drain");

        let tombstone = live
            .into_tombstone()
            .expect("dead echo becomes stopped tombstone");
        delete_stale_generation(&tombstone)
            .await
            .expect("stopped-only delete");
        terminate_pid(supervisor_pid);
        let _ = wait_for_child(supervisor_pid);
    }

    #[tokio::test]
    async fn changed_snapshot_fails_closed_before_stopped_recovery() {
        let fixture = RecoveryFixture::new("changed-snapshot");
        std::fs::write(fixture.slot.join(CONFIG_SNAPSHOT_NAME), b"changed")
            .expect("change protected snapshot fixture");
        let error = recover_stale_generation(
            &fixture.parent,
            &fixture.current_root,
            &fixture.target,
            &fixture.digest,
            Some(fixture.init.pid),
            &SessionSupervisorReattachCache::default(),
        )
        .await
        .expect_err("changed snapshot must fail closed");
        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(fixture.stale_root.exists());
    }

    #[tokio::test]
    async fn multi_container_host_reuses_one_reattached_session_supervisor() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::path::Path;
        use std::sync::Arc;

        use super::super::pid_supervisor::{terminate_pid, wait_for_child};
        use super::super::session_supervisor::HostSessionSupervisor;

        let temporary = tempfile::tempdir().expect("temporary recovery parent");
        let parent = temporary.path().join("executor");
        std::fs::create_dir(&parent).expect("executor parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("protect executor parent");
        let current_root = parent.join("current");
        std::fs::create_dir(&current_root).expect("current root");
        std::fs::set_permissions(&current_root, std::fs::Permissions::from_mode(0o700))
            .expect("protect current root");

        let (mut parent_ready, mut child_ready) =
            UnixStream::pair().expect("shared supervisor ready channel");
        // SAFETY: parent reaps the fake Host; child owns one shared supervisor.
        let host_pid = unsafe { libc::fork() };
        assert!(host_pid >= 0, "fork fake multi-container Host");
        if host_pid == 0 {
            drop(parent_ready);
            let mut supervisor = match HostSessionSupervisor::start_via_fork() {
                Ok(supervisor) => supervisor,
                Err(_) => unsafe { libc::_exit(131) },
            };
            let launcher_a = match supervisor.spawn_launcher(
                Path::new("/bin/sleep"),
                &["30".into()],
                None,
                None,
                None,
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(132) },
            };
            let launcher_b = match supervisor.spawn_launcher(
                Path::new("/bin/sleep"),
                &["30".into()],
                None,
                None,
                None,
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(133) },
            };
            let identity = supervisor.identity().clone();
            let mut payload = Vec::with_capacity(20);
            payload.extend_from_slice(&identity.pid().to_be_bytes());
            payload.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
            payload.extend_from_slice(&launcher_a.to_be_bytes());
            payload.extend_from_slice(&launcher_b.to_be_bytes());
            if child_ready.write_all(&payload).is_err() {
                unsafe { libc::_exit(134) }
            }
            std::mem::forget(supervisor);
            loop {
                unsafe { libc::pause() };
            }
        }
        drop(child_ready);
        let mut payload = [0_u8; 20];
        parent_ready
            .read_exact(&mut payload)
            .expect("read shared supervisor evidence");
        let supervisor_pid = i32::from_be_bytes(payload[0..4].try_into().expect("pid bytes"));
        let supervisor_start = u64::from_be_bytes(payload[4..12].try_into().expect("start bytes"));
        let launcher_a = i32::from_be_bytes(payload[12..16].try_into().expect("launcher a"));
        let launcher_b = i32::from_be_bytes(payload[16..20].try_into().expect("launcher b"));

        let owner = ProcessIdentity {
            pid: 2_200_000,
            start_time_ticks: 0x222,
        };
        let stale_root = parent.join(runtime_root_name(owner));
        std::fs::create_dir(&stale_root).expect("stale root");
        std::fs::set_permissions(&stale_root, std::fs::Permissions::from_mode(0o700))
            .expect("protect stale root");
        write_atomic_record(
            &stale_root.join(OWNER_RECORD_NAME),
            &ExecutorOwnerRecord {
                schema_version: OWNER_SCHEMA_VERSION.to_string(),
                owner,
            },
        )
        .expect("owner record");

        let write_slot = |slot_name: &str, container_id: &str, generation: u64, launcher: i32| {
            let slot = stale_root.join(slot_name);
            std::fs::create_dir(&slot).expect("container slot");
            std::fs::set_permissions(&slot, std::fs::Permissions::from_mode(0o700))
                .expect("protect container slot");
            let config = br#"{"ociVersion":"1.3.0"}"#;
            let digest = config_digest_for(config);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            options
                .open(slot.join(CONFIG_SNAPSHOT_NAME))
                .and_then(|mut file| file.write_all(config))
                .expect("configuration snapshot");
            let target = ContainerTarget::exact(
                a3s_oci_sdk::ContainerId::new(container_id).expect("container ID"),
                a3s_oci_sdk::Generation(generation),
            );
            let init = ProcessIdentity {
                pid: launcher,
                start_time_ticks: process_observation(launcher)
                    .expect("observe launcher")
                    .expect("launcher live")
                    .start_time_ticks,
            };
            write_atomic_record(
                &slot.join(CONTAINER_RECORD_NAME),
                &ContainerRecoveryRecord {
                    schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
                    target: target.clone(),
                    config_digest: digest.clone(),
                    owner,
                    launcher: init,
                    init,
                    session_supervisor: Some(ProcessIdentity::from_authenticated(
                        supervisor_pid,
                        supervisor_start,
                    )),
                    execs: Vec::new(),
                    cgroup: None,
                    intel_rdt: None,
                },
            )
            .expect("container recovery record");
            (target, digest)
        };

        let (target_a, digest_a) =
            write_slot("c-0000000000000001", "shared-supervisor-a", 1, launcher_a);
        let (target_b, digest_b) =
            write_slot("c-0000000000000002", "shared-supervisor-b", 1, launcher_b);

        terminate_pid(host_pid);
        let _ = wait_for_child(host_pid);

        let supervisors = SessionSupervisorReattachCache::default();
        let recovery_a = recover_stale_generation(
            &parent,
            &current_root,
            &target_a,
            &digest_a,
            Some(launcher_a),
            &supervisors,
        )
        .await
        .expect("first generation reattach")
        .expect("first recovery match");
        let StaleGenerationRecovery::Live(live_a) = recovery_a else {
            panic!("first generation must recover as Live");
        };

        // Without the cache, a second reattach would fail: the supervisor
        // accepts only one replacement control connection after Host EOF.
        let recovery_b = recover_stale_generation(
            &parent,
            &current_root,
            &target_b,
            &digest_b,
            Some(launcher_b),
            &supervisors,
        )
        .await
        .expect("second generation must reuse the cached control connection")
        .expect("second recovery match");
        let StaleGenerationRecovery::Live(live_b) = recovery_b else {
            panic!("second generation must recover as Live");
        };

        assert_eq!(supervisors.len(), 1, "one supervisor identity, one control");
        assert!(
            Arc::ptr_eq(live_a.shared_supervisor(), live_b.shared_supervisor()),
            "both live sessions must share the same reattached supervisor Arc"
        );

        live_a.kill_launcher().expect("kill launcher a");
        let status_a = live_a
            .wait_launcher()
            .expect("wait launcher a through shared control");
        assert_eq!(status_a, libc::SIGKILL);

        live_b.kill_launcher().expect("kill launcher b");
        let status_b = live_b
            .wait_launcher()
            .expect("wait launcher b through shared control");
        assert_eq!(status_b, libc::SIGKILL);

        // Deleting the first generation must not shut down the shared supervisor.
        let tombstone_a = live_a
            .into_tombstone()
            .expect("launcher a can become a stopped tombstone");
        delete_stale_generation(&tombstone_a)
            .await
            .expect("delete first generation while supervisor still shared");

        assert!(
            live_b.launcher_is_live().is_ok_and(|live| !live),
            "launcher b already waited"
        );
        let tombstone_b = live_b
            .into_tombstone()
            .expect("launcher b can become a stopped tombstone");
        // Keep the cache alive so Drop does not SHUTDOWN before second delete.
        delete_stale_generation(&tombstone_b)
            .await
            .expect("delete second generation");
        drop(supervisors);
        terminate_pid(supervisor_pid);
        let _ = wait_for_child(supervisor_pid);
        assert!(!stale_root.exists());
    }

    struct RecoveryFixture {
        _temporary: tempfile::TempDir,
        parent: PathBuf,
        current_root: PathBuf,
        stale_root: PathBuf,
        slot: PathBuf,
        target: ContainerTarget,
        digest: String,
        init: ProcessIdentity,
    }

    impl RecoveryFixture {
        fn new(id: &str) -> Self {
            let temporary = tempfile::tempdir().expect("temporary recovery parent");
            let parent = temporary.path().join("executor");
            std::fs::create_dir(&parent).expect("executor parent");
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
                .expect("protect executor parent");
            let current_root = parent.join("current");
            std::fs::create_dir(&current_root).expect("current root");
            std::fs::set_permissions(&current_root, std::fs::Permissions::from_mode(0o700))
                .expect("protect current root");

            let owner = ProcessIdentity {
                pid: 2_000_000,
                start_time_ticks: 0xabc,
            };
            let stale_root = parent.join(runtime_root_name(owner));
            std::fs::create_dir(&stale_root).expect("stale root");
            std::fs::set_permissions(&stale_root, std::fs::Permissions::from_mode(0o700))
                .expect("protect stale root");
            write_atomic_record(
                &stale_root.join(OWNER_RECORD_NAME),
                &ExecutorOwnerRecord {
                    schema_version: OWNER_SCHEMA_VERSION.to_string(),
                    owner,
                },
            )
            .expect("owner record");

            let slot = stale_root.join("c-0000000000000001");
            std::fs::create_dir(&slot).expect("container slot");
            std::fs::set_permissions(&slot, std::fs::Permissions::from_mode(0o700))
                .expect("protect container slot");
            let config = br#"{"ociVersion":"1.3.0"}"#;
            let digest = config_digest_for(config);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            options
                .open(slot.join(CONFIG_SNAPSHOT_NAME))
                .and_then(|mut file| file.write_all(config))
                .expect("configuration snapshot");
            let target = ContainerTarget::exact(
                a3s_oci_sdk::ContainerId::new(id).expect("container ID"),
                a3s_oci_sdk::Generation(1),
            );
            let init = ProcessIdentity {
                pid: 2_000_002,
                start_time_ticks: 0xdef,
            };
            write_atomic_record(
                &slot.join(CONTAINER_RECORD_NAME),
                &ContainerRecoveryRecord {
                    schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
                    target: target.clone(),
                    config_digest: digest.clone(),
                    owner,
                    launcher: ProcessIdentity {
                        pid: 2_000_001,
                        start_time_ticks: 0xcde,
                    },
                    init,
                    session_supervisor: None,
                    execs: Vec::new(),
                    cgroup: None,
                    intel_rdt: None,
                },
            )
            .expect("container recovery record");

            Self {
                _temporary: temporary,
                parent,
                current_root,
                stale_root,
                slot,
                target,
                digest,
                init,
            }
        }
    }

    #[test]
    fn durable_owner_uses_effective_uid_outside_the_runtime_share() {
        let temporary = tempfile::tempdir().expect("temporary path");
        let path = temporary.path().join("recovery.json");
        std::fs::write(&path, "{}").expect("write recovery file");
        let share_root = temporary.path().join("not-the-share");
        std::fs::create_dir(&share_root).expect("create unused share root");
        let uid = durable_owner_uid_for(&path, &share_root).expect("owner uid");
        // SAFETY: geteuid has no preconditions or failure result.
        assert_eq!(uid, unsafe { libc::geteuid() });
    }

    #[test]
    fn durable_owner_uses_runtime_share_root_for_virtiofs_paths() {
        let temporary = tempfile::tempdir().expect("temporary share");
        let share_root = temporary.path().join("run-a3s-oci-runtime");
        std::fs::create_dir(&share_root).expect("create share root");
        std::fs::set_permissions(&share_root, std::fs::Permissions::from_mode(0o700))
            .expect("protect share root");
        let nested = share_root.join("run").join("a3s-oci-agent-1").join("c-1");
        std::fs::create_dir_all(&nested).expect("create nested runtime path");
        let path = nested.join("device-targets.json");
        std::fs::write(&path, "{}").expect("write device targets");
        let uid = durable_owner_uid_for(&path, &share_root).expect("share owner uid");
        let share_uid = std::fs::symlink_metadata(&share_root)
            .expect("share metadata")
            .uid();
        assert_eq!(uid, share_uid);
    }
}
