use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use a3s_oci_agent_protocol::AGENT_RUNTIME_SHARE_GUEST_ROOT;
use a3s_oci_sdk::oci_spec::runtime::{LinuxResources, Process};
use a3s_oci_sdk::{
    ContainerStats, ContainerTarget, Error, ErrorCode, FileRequest, FileResponse, FilesystemRequest,
    FilesystemResponse, IoMode, OciBundle, ProcessId, ProcessIo, ProcessRecord, ProcessTarget,
    Result, ValidateRequest, CONTROL_CGROUP_NAME, WORKLOAD_CGROUP_NAME,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{sleep, Instant};

use super::capability::CapabilityPlan;
use super::cgroup::{
    leaf_is_frozen, open_cgroup_procs, set_leaf_frozen, stats_from_leaf, update_from_leaf,
    CgroupManager,
};
use super::device::{cleanup_device_target_manifest, load_device_target_manifest};
use super::exec_process::{ExecProcess, ExecSpawnContext};
use super::intel_rdt::{is_resctrl_mountpoint, IntelRdtRecovery};
use super::namespace::{NamespacePlan, RetainedExecutionContext};
use super::pid_supervisor::terminate_pid;
use super::pidfd::{PidFd, SignalOutcome};
use super::plan::ProcessPlan;
use super::process::{PreparedProcess, SharedSessionSupervisor};
use super::seccomp::SeccompPlan;
use super::session_supervisor::{HostSessionSupervisor, SessionSupervisorIdentity};

const RUNTIME_ROOT_PREFIX: &str = "a3s-oci-agent-";
const OWNER_RECORD_NAME: &str = "owner.json";
const CONTAINER_RECORD_NAME: &str = "recovery.json";
const CONFIG_SNAPSHOT_NAME: &str = "config.json";
const OWNER_SCHEMA_VERSION: &str = "a3s.oci.native-linux-executor-owner.v1";
const CONTAINER_SCHEMA_VERSION: &str = "a3s.oci.native-linux-recovery.v6";
const CONTAINER_SCHEMA_VERSION_V5: &str = "a3s.oci.native-linux-recovery.v5";
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
        let observation = process_observation(pid)?.ok_or_else(|| {
            recovery_error(
                ErrorCode::Unavailable,
                format!("{role} PID {pid} exited before its recovery identity was captured"),
            )
            .retryable(true)
        })?;
        // Zombies still expose authentic start-time in `/proc/<pid>/stat`. Short
        // captured exec payloads (e.g. `printf`) can exit before Host persists
        // recovery evidence; refusing `Z` turned that race into Unavailable and
        // broke Live Host-reopen keyed exec. Fully reaped tasks (`X`/`x` or no
        // `/proc` entry) still fail closed.
        if matches!(observation.state, b'X' | b'x') {
            return Err(recovery_error(
                ErrorCode::Unavailable,
                format!("{role} PID {pid} exited before its recovery identity was captured"),
            )
            .retryable(true));
        }
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

    /// Open a pidfd only after re-authenticating PID + start-time.
    ///
    /// Refuses when the recorded identity is not live. After `pidfd_open`, a
    /// start-time drift means PID reuse — fail closed without signaling the
    /// wrong process. A disappeared `/proc` entry after open means the target
    /// exited; the pidfd is retained so `pidfd_send_signal` can report
    /// [`SignalOutcome::Exited`] without inventing success.
    fn open_authenticated_pidfd(self, role: &str) -> Result<PidFd> {
        if !self.is_live()? {
            return Err(recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "{role} PID {} is not live under its recorded start-time identity",
                    self.pid
                ),
            ));
        }
        let pidfd = PidFd::open(self.pid).map_err(|error| {
            recovery_error(
                error.code,
                format!(
                    "failed to open authenticated pidfd for {role} PID {}: {}",
                    self.pid, error.message
                ),
            )
        })?;
        match process_observation(self.pid)? {
            Some(observation)
                if observation.start_time_ticks == self.start_time_ticks
                    && !observation.is_terminated() =>
            {
                Ok(pidfd)
            }
            Some(observation) if observation.start_time_ticks != self.start_time_ticks => {
                Err(recovery_error(
                    ErrorCode::Unavailable,
                    format!(
                        "{role} PID {} start-time drifted after pidfd open (recorded {}, observed {}); refusing to signal a reused PID",
                        self.pid, self.start_time_ticks, observation.start_time_ticks
                    ),
                ))
            }
            Some(_) | None => Ok(pidfd),
        }
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
/// `identity` is the payload (signal/inventory target). `helper` is the
/// supervisor-child wait target for authentic `wait_process` after Host reopen.
/// Only PID + start-time (plus process ID and terminal mode) are durable.
/// Exit status is never recorded here; dead identities are omitted from
/// inventory instead of inventing a terminal result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryExecRecord {
    process_id: ProcessId,
    identity: ProcessIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    helper: Option<ProcessIdentity>,
    terminal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V5RecoveryExecRecord {
    process_id: ProcessId,
    identity: ProcessIdentity,
    terminal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V5ContainerRecoveryRecord {
    schema_version: String,
    target: ContainerTarget,
    config_digest: String,
    owner: ProcessIdentity,
    launcher: ProcessIdentity,
    init: ProcessIdentity,
    #[serde(default)]
    session_supervisor: Option<ProcessIdentity>,
    #[serde(default)]
    execs: Vec<V5RecoveryExecRecord>,
    cgroup: Option<RecoveryCgroupRecord>,
    intel_rdt: Option<RecoveryIntelRdtRecord>,
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
/// exec identities, authenticated [`Self::signal_process`] for those durable
/// identities via pidfd after PID + start-time re-auth, an authentic stdin
/// write end when the original Host deposited one, and exclusive capture
/// stdout/stderr through the supervisor IPC relay when those read ends were
/// moved at create. Missing output deposit fail-closes [`Self::read_output`]
/// with [`ErrorCode::Unavailable`] instead of inventing empty output. Dead
/// exec identities are omitted from inventory without inventing exit status.
/// [`Self::wait_process`] for init uses the supervised launcher wait path; exec
/// waits require a recorded helper identity and use authentic superviso
/// `MSG_WAIT`. v5 exec records without helper fail closed with
/// [`ErrorCode::Unavailable`]. Authentic [`Self::pause`] / [`Self::resume`] /
/// [`Self::stats`] / [`Self::update`] use the durable recovery cgroup leaf
/// (kernel freezer, cgroup-v2 counters, and supported resource fields) without
/// restoring a fake [`PreparedProcess`]. Missing cgroup evidence fail-closes
/// with [`ErrorCode::Unavailable`]. Device-policy updates remain Unavailable
/// because recovery does not retain device-authority state. New `exec`
/// rebuilds the minimum authentic spawn context from the durable config
/// snapshot plus live init namespace/root descriptors (and the recovery cgroup
/// leaf when present), then supervisor-parents the helper with the same
/// capture/pipe deposit path as supervised create. Terminal/inherit remain
/// Unavailable. Missing config or live init fail-closes without inventing exit
/// status.
#[derive(Debug)]
pub struct LinuxLiveSupervisedSession {
    target: ContainerTarget,
    config_digest: String,
    runtime_root: PathBuf,
    runtime_directory: PathBuf,
    record: ContainerRecoveryRecord,
    supervisor: SharedSessionSupervisor,
    launcher_wait_status: Mutex<Option<i32>>,
    exec_wait_status: Mutex<BTreeMap<ProcessId, i32>>,
    /// Exec identities spawned after Host reopen (also persisted on disk).
    post_reopen_execs: Mutex<Vec<RecoveryExecRecord>>,
    /// Restored stdin write ends taken from supervisor deposits, keyed by
    /// process id (init uses the create launcher deposit; exec uses the helpe
    /// deposit). A single init-only slot cannot serve retained streaming exec.
    stdin: AsyncMutex<BTreeMap<ProcessId, tokio::fs::File>>,
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

    /// Whether an authentic stdin write end was restored for the init process.
    #[must_use]
    pub fn has_restored_stdin(&self) -> bool {
        self.has_restored_stdin_for(&ProcessId::init())
    }

    /// Whether an authentic stdin write end was restored for `process_id`.
    #[must_use]
    pub fn has_restored_stdin_for(&self, process_id: &ProcessId) -> bool {
        self.stdin
            .try_lock()
            .map(|stdin| stdin.contains_key(process_id))
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
        for exec in self.iter_exec_records()? {
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
    /// Init uses the create-time launcher deposit. Exec uses the recorded helpe
    /// PID from recovery / post-reopen spawn — never the create launcher, o
    /// Host would drain the wrong buffer and observe exit without capture EOF.
    /// When no output deposit exists, returns [`ErrorCode::Unavailable`] instead
    /// of inventing an empty successful stream.
    pub fn read_output(
        &self,
        process_id: &ProcessId,
        after_sequence: u64,
        max_bytes: u32,
        wait_timeout_ms: Option<u64>,
    ) -> Result<Vec<a3s_oci_sdk::OutputChunk>> {
        let launcher_pid = if process_id.is_init() {
            self.launcher_pid()
        } else {
            let exec = self.find_exec_record(process_id)?;
            let helper = exec.helper.ok_or_else(|| {
                recovery_error(
                    ErrorCode::Unavailable,
                    format!(
                        "process {} in container {} generation {:?} has no recorded capture wait target after Host reopen",
                        process_id, self.target.id, self.target.generation
                    ),
                )
            })?;
            helper.pid()
        };
        let mut guard = self.supervisor.lock().map_err(|_| {
            recovery_error(
                ErrorCode::Internal,
                "live supervised session supervisor lock is poisoned during read-output",
            )
        })?;
        guard
            .read_output(launcher_pid, after_sequence, max_bytes, wait_timeout_ms)
            .map_err(|error| {
                // Preserve fail-closed codes from the relay (Unavailable fo
                // missing deposit, ResourceExhausted for stale cursors).
                recovery_error(error.code, error.message)
            })
    }

    /// Write to the authentic restored stdin pipe end for `process_id`.
    pub async fn write_stdin(&self, process_id: &ProcessId, data: &[u8]) -> Result<()> {
        let mut guard = self.stdin.lock().await;
        let stdin = guard.get_mut(process_id).ok_or_else(|| {
            recovery_error(
                ErrorCode::Unavailable,
                format!(
                    "process {} in container {} generation {:?} has no restored stdin write end after Host reopen",
                    process_id, self.target.id, self.target.generation
                ),
            )
        })?;
        stdin.write_all(data).await.map_err(|error| {
            recovery_error(
                ErrorCode::Unavailable,
                format!(
                    "failed to write restored stdin for process {} in container {} generation {:?}: {error}",
                    process_id, self.target.id, self.target.generation
                ),
            )
        })?;
        stdin.flush().await.map_err(|error| {
            recovery_error(
                ErrorCode::Unavailable,
                format!(
                    "failed to flush restored stdin for process {} in container {} generation {:?}: {error}",
                    process_id, self.target.id, self.target.generation
                ),
            )
        })
    }

    /// Close the restored stdin write end for `process_id` and drop any remaining
    /// supervisor deposit for that wait target.
    pub async fn close_stdin(&self, process_id: &ProcessId) -> Result<()> {
        {
            let mut guard = self.stdin.lock().await;
            guard.remove(process_id);
        }
        let deposit_pid = if process_id.is_init() {
            self.launcher_pid()
        } else {
            let exec = self.find_exec_record(process_id)?;
            let helper = exec.helper.ok_or_else(|| {
                recovery_error(
                    ErrorCode::Unavailable,
                    format!(
                        "process {} in container {} generation {:?} has no recorded supervisor wait target after Host reopen",
                        process_id, self.target.id, self.target.generation
                    ),
                )
            })?;
            helper.pid()
        };
        let mut supervisor = self.supervisor.lock().map_err(|_| {
            recovery_error(
                ErrorCode::Internal,
                "live supervised session supervisor lock is poisoned during stdin close",
            )
        })?;
        supervisor.close_deposited_stdin(deposit_pid)?;
        Ok(())
    }

    /// Authentic cgroup freezer observation for Host reopen state.
    ///
    /// Reads kernel `cgroup.events` on the durable recovery leaf. Missing cgroup
    /// evidence fail-closes with [`ErrorCode::Unavailable`] instead of inventing
    /// an unpaused observation.
    pub fn is_paused(&self) -> Result<bool> {
        leaf_is_frozen(self.recovery_cgroup_leaf()?)
    }

    /// Freeze the durable recovery cgroup leaf (OCI pause).
    ///
    /// Requires a live init identity and a recorded cgroup leaf. Writes
    /// `cgroup.freeze` and waits for kernel confirmation — the same evidence
    /// path as [`PreparedProcess`] pause, without restoring process-session
    /// state.
    pub async fn pause(&self) -> Result<()> {
        if !self.init_is_live()? {
            return Err(recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "container {} generation {:?} cannot pause without a live init identity",
                    self.target.id, self.target.generation
                ),
            ));
        }
        set_leaf_frozen(self.recovery_cgroup_leaf()?, true).await
    }

    /// Thaw the durable recovery cgroup leaf (OCI resume).
    pub async fn resume(&self) -> Result<()> {
        if !self.init_is_live()? {
            return Err(recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "container {} generation {:?} cannot resume without a live init identity",
                    self.target.id, self.target.generation
                ),
            ));
        }
        set_leaf_frozen(self.recovery_cgroup_leaf()?, false).await
    }

    /// Read normalized cgroup-v2 stats from the durable recovery leaf.
    pub async fn stats(&self) -> Result<ContainerStats> {
        stats_from_leaf(self.recovery_cgroup_leaf()?, self.target.clone()).await
    }

    /// Apply supported OCI Linux resource fields to the durable recovery leaf.
    ///
    /// Mirrors [`PreparedProcess`] resource update against the recorded leaf
    /// without restoring process-session state. Device-policy fields fail
    /// closed because recovery does not retain device-authority state.
    pub async fn update(&self, resources: &LinuxResources) -> Result<()> {
        if !self.init_is_live()? {
            return Err(recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "container {} generation {:?} cannot update resources without a live init identity",
                    self.target.id, self.target.generation
                ),
            ));
        }
        update_from_leaf(self.recovery_cgroup_leaf()?, resources).await
    }

    /// Exact-generation file transfer after Host reopen.
    ///
    /// Rebuilds [`RetainedExecutionContext`] the same way post-reopen exec does
    /// (durable `config.json` + live init namespace/root descriptors), then
    /// calls the existing descriptor-confined filesystem helper. Fail-closes
    /// when init is gone. Wrong generation fail-closes with Conflict. Does not
    /// invent payload bytes.
    pub async fn file(
        &self,
        init_executable: &Path,
        request: FileRequest,
    ) -> Result<FileResponse> {
        request.validate()?;
        self.require_live_filesystem_target(&request.target, "file")?;
        let execution_context = self.rebuild_retained_execution_context().await?;
        super::filesystem::file_with_context(init_executable, &execution_context, &request).await
    }

    /// Exact-generation filesystem metadata or mutation after Host reopen.
    ///
    /// Same retained-context rebuild as [`Self::file`] / post-reopen exec.
    pub async fn filesystem(
        &self,
        init_executable: &Path,
        request: FilesystemRequest,
    ) -> Result<FilesystemResponse> {
        request.validate()?;
        self.require_live_filesystem_target(&request.target, "filesystem")?;
        let execution_context = self.rebuild_retained_execution_context().await?;
        super::filesystem::filesystem_with_context(init_executable, &execution_context, &request)
            .await
    }

    /// Spawn a new supervisor-parented exec after Host reopen.
    ///
    /// Rebuilds the minimum authentic spawn context from the durable
    /// `config.json` snapshot (namespace plan, capability ceiling, seccomp) plus
    /// live init namespace/root descriptors and the recovery cgroup leaf.
    /// Null/capture/pipe I/O is accepted: capture and pipe deposit into the
    /// session supervisor the same way supervised create does. Terminal and
    /// inherit remain Unavailable. Successful spawn persists a v6 exec identity
    /// (payload + helper) so inventory / signal / wait continue without
    /// inventing exit status.
    pub async fn exec(
        &self,
        process_id: &ProcessId,
        process: &Process,
        io: &ProcessIo,
        init_executable: &Path,
    ) -> Result<(i32, bool)> {
        if process_id.is_init() {
            return Err(recovery_error(
                ErrorCode::InvalidArgument,
                "exec process ID `init` is reserved for the configured process",
            ));
        }
        if !self.init_is_live()? {
            return Err(recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "container {} generation {:?} cannot exec without a live init identity",
                    self.target.id, self.target.generation
                ),
            ));
        }
        match self.is_paused() {
            Ok(true) => {
                return Err(recovery_error(
                    ErrorCode::FailedPrecondition,
                    "container exec is unavailable while the container is paused",
                ));
            }
            Ok(false) => {}
            Err(error) if error.code == ErrorCode::Unavailable => {}
            Err(error) => return Err(error),
        }
        require_supervised_exec_process_io(io)?;
        if self.find_exec_record(process_id).is_ok() {
            return Err(recovery_error(
                ErrorCode::AlreadyExists,
                format!(
                    "process {} already exists in durable recovery for container {} generation {:?}",
                    process_id, self.target.id, self.target.generation
                ),
            ));
        }

        let rebuilt = self.rebuild_exec_spawn_inputs().await?;
        let process_io = io.resolve_for_process(process)?;
        let mut plan = ProcessPlan::from_exec_process(process, &process_io)?;
        plan.attach_seccomp(&rebuilt.seccomp);
        plan.capabilities
            .validate_exec_ceiling(rebuilt.capabilities)?;
        rebuilt.execution_context.validate_process_ids(
            plan.uid,
            plan.gid,
            &plan.additional_gids,
        )?;

        let process_directory = allocate_process_directory(&self.runtime_directory)?;
        super::create_private_directory(&process_directory).await?;
        let snapshot = process_directory.join("process.json");
        let encoded = serde_json::to_string(&plan).map_err(|error| {
            recovery_error(
                ErrorCode::Internal,
                format!("failed to encode Host-reopen exec process plan: {error}"),
            )
        })?;
        if let Err(error) = super::write_private_snapshot(&snapshot, &encoded).await {
            let _ =
                super::remove_process_directory(&self.runtime_directory, &process_directory).await;
            return Err(error);
        }

        let spawn_context = ExecSpawnContext {
            execution_context: &rebuilt.execution_context,
            init_pidfd: rebuilt.init_pidfd.raw_descriptor(),
            workload_cgroup_procs: rebuilt
                .workload_cgroup_procs
                .as_ref()
                .map(std::os::fd::AsRawFd::as_raw_fd),
            init_signal: &rebuilt.init_pidfd,
        };
        let mut process = match ExecProcess::spawn_with_context(
            &snapshot,
            init_executable,
            &spawn_context,
            process.terminal().unwrap_or(false),
            &process_io,
            Some(Arc::clone(&self.supervisor)),
        )
        .await
        {
            Ok(process) => process,
            Err(error) => {
                let _ =
                    super::remove_process_directory(&self.runtime_directory, &process_directory)
                        .await;
                return Err(error);
            }
        };

        let payload_pid = process.pid();
        let helper_pid = process.helper_pid();
        let terminal = process.terminal();
        let (identity, helper) = match record_exec_identity(
            &self.runtime_directory,
            process_id,
            payload_pid,
            helper_pid,
            terminal,
        ) {
            Ok(identities) => identities,
            Err(error) => {
                let _ = process.force_stop().await;
                let _ =
                    super::remove_process_directory(&self.runtime_directory, &process_directory)
                        .await;
                return Err(error);
            }
        };
        self.post_reopen_execs
            .lock()
            .map_err(|_| {
                recovery_error(
                    ErrorCode::Internal,
                    "live supervised session post-reopen exec lock is poisoned",
                )
            })?
            .push(RecoveryExecRecord {
                process_id: process_id.clone(),
                identity,
                helper: Some(helper.clone()),
                terminal,
            });
        // Move the helper stdin deposit into the Live map before dropping the
        // local ExecProcess write end — otherwise post-reopen write_stdin has
        // nothing authentic to use.
        if let Some(file) = take_deposited_stdin(&self.supervisor, helper.pid()) {
            self.stdin.lock().await.insert(process_id.clone(), file);
        }
        // Helper stays parented by the reattached supervisor; drop local wait
        // ownership so Live wait_process uses durable MSG_WAIT.
        drop(process);
        Ok((payload_pid, terminal))
    }

    fn recovery_cgroup_leaf(&self) -> Result<&Path> {
        self.record.cgroup.as_ref().map(|cgroup| cgroup.leaf.as_path()).ok_or_else(|| {
            recovery_error(
                ErrorCode::Unavailable,
                format!(
                    "container {} generation {:?} has no durable cgroup leaf after Host reopen; pause/resume/stats/update require recorded cgroup evidence",
                    self.target.id, self.target.generation
                ),
            )
        })
    }

    /// Block until a durable process exits and return its raw wait status.
    ///
    /// Init uses the supervised launcher wait path. Exec requires a recorded
    /// helper identity and waits that supervisor child via `MSG_WAIT`. v5 exec
    /// records without helper fail closed with [`ErrorCode::Unavailable`].
    /// Cached status is returned on subsequent waits. This never invents exit
    /// evidence.
    pub fn wait_process(&self, process_id: &ProcessId) -> Result<i32> {
        if process_id.is_init() {
            return self.wait_launcher();
        }
        let exec = self.find_exec_record(process_id)?;
        let helper = exec.helper.ok_or_else(|| {
            recovery_error(
                ErrorCode::Unavailable,
                format!(
                    "process {} in container {} generation {:?} has no recorded supervisor wait target after Host reopen",
                    process_id, self.target.id, self.target.generation
                ),
            )
        })?;
        if let Some(status) = self
            .exec_wait_status
            .lock()
            .map_err(|_| {
                recovery_error(
                    ErrorCode::Internal,
                    "live supervised session exec wait-status lock is poisoned",
                )
            })?
            .get(process_id)
            .copied()
        {
            return Ok(status);
        }
        let payload_live = exec.identity.is_live()?;
        let mut guard = self.supervisor.lock().map_err(|_| {
            recovery_error(
                ErrorCode::Internal,
                "live supervised session supervisor lock is poisoned during exec wait",
            )
        })?;
        let wait_result = guard.wait_launcher(helper.pid());
        drop(guard);
        let status = match wait_result {
            Ok(status) => status,
            Err(error) if !payload_live => {
                return Err(recovery_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "process {} already exited and no authentic wait status was recorded: {}",
                        process_id, error.message
                    ),
                ));
            }
            Err(error) => return Err(error),
        };
        self.exec_wait_status
            .lock()
            .map_err(|_| {
                recovery_error(
                    ErrorCode::Internal,
                    "live supervised session exec wait-status lock is poisoned",
                )
            })?
            .insert(process_id.clone(), status);
        Ok(status)
    }

    /// Block until the supervised launcher exits and return its raw wait status.
    ///
    /// Status comes from the reattached supervisor (`MSG_WAIT`). This neve
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

    /// Signal a durable init or exec identity after Host reopen.
    ///
    /// Re-authenticates the recorded PID + start-time, opens a pidfd, and
    /// delivers `signal` through that pidfd. Does not restore a fake
    /// [`PreparedProcess`]. Unknown process IDs fail with [`ErrorCode::NotFound`].
    /// Dead or start-time-mismatched identities fail closed without inventing
    /// delivery success. Exit status is never synthesized here — callers that
    /// need wait evidence must use a path that holds authentic wait ownership.
    pub fn signal_process(&self, process_id: &ProcessId, signal: i32) -> Result<()> {
        let identity = self.recorded_process_identity(process_id)?;
        let role = if process_id.is_init() {
            "live supervised init"
        } else {
            "live supervised exec"
        };
        let pidfd = identity.open_authenticated_pidfd(role)?;
        match pidfd.send_signal(signal).map_err(|error| {
            recovery_error(
                error.code,
                format!(
                    "failed to signal {role} process {} (PID {}): {}",
                    process_id,
                    identity.pid(),
                    error.message
                ),
            )
        })? {
            SignalOutcome::Delivered => Ok(()),
            SignalOutcome::Exited => Err(recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "process {} exited before signal delivery after Host reopen",
                    process_id
                ),
            )),
        }
    }

    fn recorded_process_identity(&self, process_id: &ProcessId) -> Result<ProcessIdentity> {
        if process_id.is_init() {
            return Ok(self.record.init);
        }
        Ok(self.find_exec_record(process_id)?.identity)
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
        let mut record = self.record.clone();
        record.execs.extend(
            self.post_reopen_execs
                .lock()
                .map_err(|_| {
                    recovery_error(
                        ErrorCode::Internal,
                        "live supervised session post-reopen exec lock is poisoned",
                    )
                })?
                .iter()
                .cloned(),
        );
        Ok(LinuxExecutorTombstone {
            target: self.target.clone(),
            config_digest: self.config_digest.clone(),
            runtime_root: self.runtime_root.clone(),
            runtime_directory: self.runtime_directory.clone(),
            record,
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
        let stdin = take_deposited_stdin_by_process(&supervisor, &tombstone.record);
        Self {
            target: tombstone.target,
            config_digest: tombstone.config_digest,
            runtime_root: tombstone.runtime_root,
            runtime_directory: tombstone.runtime_directory,
            record: tombstone.record,
            supervisor,
            launcher_wait_status: Mutex::new(None),
            exec_wait_status: Mutex::new(BTreeMap::new()),
            post_reopen_execs: Mutex::new(Vec::new()),
            stdin: AsyncMutex::new(stdin),
        }
    }

    fn iter_exec_records(&self) -> Result<Vec<RecoveryExecRecord>> {
        let mut execs = self.record.execs.clone();
        execs.extend(
            self.post_reopen_execs
                .lock()
                .map_err(|_| {
                    recovery_error(
                        ErrorCode::Internal,
                        "live supervised session post-reopen exec lock is poisoned",
                    )
                })?
                .iter()
                .cloned(),
        );
        Ok(execs)
    }

    fn find_exec_record(&self, process_id: &ProcessId) -> Result<RecoveryExecRecord> {
        self.iter_exec_records()?
            .into_iter()
            .find(|exec| &exec.process_id == process_id)
            .ok_or_else(|| {
                recovery_error(
                    ErrorCode::NotFound,
                    format!(
                        "process {} does not exist in durable recovery for container {} generation {:?}",
                        process_id, self.target.id, self.target.generation
                    ),
                )
            })
    }

    fn require_live_filesystem_target(
        &self,
        target: &ContainerTarget,
        operation: &'static str,
    ) -> Result<()> {
        if target != &self.target {
            return Err(recovery_error(
                ErrorCode::Conflict,
                format!(
                    "container {} has live supervised recovery for generation {:?}, not requested generation {:?} during {operation}",
                    self.target.id, self.target.generation, target.generation
                ),
            ));
        }
        if !self.init_is_live()? {
            return Err(recovery_error(
                ErrorCode::Unavailable,
                format!(
                    "container {} generation {:?} cannot {operation} without a live init identity",
                    self.target.id, self.target.generation
                ),
            ));
        }
        Ok(())
    }

    async fn rebuild_retained_execution_context(&self) -> Result<RetainedExecutionContext> {
        let snapshot = read_bounded_plain_file(
            &self.runtime_directory.join(CONFIG_SNAPSHOT_NAME),
            MAX_RECORD_BYTES,
        )?;
        let observed = config_digest_for(&snapshot);
        if observed != self.config_digest {
            return Err(recovery_error(
                ErrorCode::Conflict,
                format!(
                    "native recovery configuration changed under {}: record {}, snapshot {observed}",
                    self.runtime_directory.display(),
                    self.config_digest
                ),
            ));
        }
        let config_json = String::from_utf8(snapshot).map_err(|error| {
            recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "native recovery config snapshot is not UTF-8 under {}: {error}",
                    self.runtime_directory.display()
                ),
            )
        })?;
        let bundle =
            OciBundle::from_json(self.runtime_directory.clone(), config_json).map_err(|error| {
                recovery_error(
                    error.code,
                    format!(
                        "failed to reload durable config for Host-reopen filesystem under {}: {}",
                        self.runtime_directory.display(),
                        error.message
                    ),
                )
            })?;
        if bundle.config_digest() != self.config_digest {
            return Err(recovery_error(
                ErrorCode::Conflict,
                format!(
                    "reloaded config digest {} does not match recovery {}",
                    bundle.config_digest(),
                    self.config_digest
                ),
            ));
        }
        let spec = bundle.spec();
        let init_process = spec.process().as_ref().ok_or_else(|| {
            recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "container {} generation {:?} durable config has no init process for retained context rebuild",
                    self.target.id, self.target.generation
                ),
            )
        })?;
        let init_uid = init_process.user().uid();
        let init_gid = init_process.user().gid();
        let additional_gids = init_process
            .user()
            .additional_gids()
            .as_ref()
            .cloned()
            .unwrap_or_default();
        let namespace_plan =
            NamespacePlan::from_linux(spec.linux().as_ref(), init_uid, init_gid, &additional_gids)
                .map_err(|error| {
                    recovery_error(
                        error.code,
                        format!(
                            "failed to rebuild namespace plan for Host-reopen retained context: {}",
                            error.message
                        ),
                    )
                })?;

        let init_pid = self.init_pid();
        let rootfs = tokio::fs::File::open(format!("/proc/{init_pid}/root"))
            .await
            .map_err(|error| {
                recovery_error(
                    ErrorCode::Unavailable,
                    format!(
                        "failed to open live init root for Host-reopen retained context PID {init_pid}: {error}"
                    ),
                )
            })?
            .into_std()
            .await;
        RetainedExecutionContext::capture(&namespace_plan, init_pid, rootfs)
            .await
            .map_err(|error| {
                recovery_error(
                    error.code,
                    format!(
                        "failed to rebuild retained execution context from live init PID {init_pid}: {}",
                        error.message
                    ),
                )
            })
    }

    async fn rebuild_exec_spawn_inputs(&self) -> Result<RebuiltExecSpawnInputs> {
        let snapshot = read_bounded_plain_file(
            &self.runtime_directory.join(CONFIG_SNAPSHOT_NAME),
            MAX_RECORD_BYTES,
        )?;
        let observed = config_digest_for(&snapshot);
        if observed != self.config_digest {
            return Err(recovery_error(
                ErrorCode::Conflict,
                format!(
                    "native recovery configuration changed under {}: record {}, snapshot {observed}",
                    self.runtime_directory.display(),
                    self.config_digest
                ),
            ));
        }
        let config_json = String::from_utf8(snapshot).map_err(|error| {
            recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "native recovery config snapshot is not UTF-8 under {}: {error}",
                    self.runtime_directory.display()
                ),
            )
        })?;
        let bundle =
            OciBundle::from_json(self.runtime_directory.clone(), config_json).map_err(|error| {
                recovery_error(
                    error.code,
                    format!(
                        "failed to reload durable config for Host-reopen exec under {}: {}",
                        self.runtime_directory.display(),
                        error.message
                    ),
                )
            })?;
        if bundle.config_digest() != self.config_digest {
            return Err(recovery_error(
                ErrorCode::Conflict,
                format!(
                    "reloaded config digest {} does not match recovery {}",
                    bundle.config_digest(),
                    self.config_digest
                ),
            ));
        }
        let spec = bundle.spec();
        let init_process = spec.process().as_ref().ok_or_else(|| {
            recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "container {} generation {:?} durable config has no init process for exec ceiling rebuild",
                    self.target.id, self.target.generation
                ),
            )
        })?;
        let capabilities =
            CapabilityPlan::from_oci(init_process.capabilities().as_ref()).map_err(|error| {
                recovery_error(
                    error.code,
                    format!(
                        "failed to rebuild capability ceiling for Host-reopen exec: {}",
                        error.message
                    ),
                )
            })?;
        let seccomp = SeccompPlan::from_linux(spec.linux().as_ref()).map_err(|error| {
            recovery_error(
                error.code,
                format!(
                    "failed to rebuild seccomp plan for Host-reopen exec: {}",
                    error.message
                ),
            )
        })?;

        let execution_context = self.rebuild_retained_execution_context().await?;
        let init_pidfd = self
            .record
            .init
            .open_authenticated_pidfd("live supervised init")?;
        let workload_cgroup_procs = match self.record.cgroup.as_ref() {
            Some(cgroup) => Some(open_cgroup_procs(&cgroup.leaf).map_err(|error| {
                recovery_error(
                    error.code,
                    format!(
                        "failed to reopen durable workload cgroup.procs at {} for Host-reopen exec: {}",
                        cgroup.leaf.display(),
                        error.message
                    ),
                )
            })?),
            None => None,
        };
        Ok(RebuiltExecSpawnInputs {
            execution_context,
            init_pidfd,
            workload_cgroup_procs,
            capabilities,
            seccomp,
        })
    }
}

struct RebuiltExecSpawnInputs {
    execution_context: RetainedExecutionContext,
    init_pidfd: PidFd,
    workload_cgroup_procs: Option<std::fs::File>,
    capabilities: CapabilityPlan,
    seccomp: SeccompPlan,
}

fn require_supervised_exec_process_io(io: &ProcessIo) -> Result<()> {
    for (stream, mode) in [
        ("stdin", io.stdin),
        ("stdout", io.stdout),
        ("stderr", io.stderr),
    ] {
        match mode {
            IoMode::Null | IoMode::Capture | IoMode::Pipe => {}
            IoMode::Terminal | IoMode::Inherit => {
                return Err(recovery_error(
                    ErrorCode::Unavailable,
                    format!(
                        "Host-reopen exec does not support {mode:?} {stream}; \
                         use Null/Capture/Pipe (terminal/inherit remain Unavailable)"
                    ),
                ));
            }
        }
    }
    if io.terminal_size.is_some() {
        return Err(recovery_error(
            ErrorCode::Unavailable,
            "Host-reopen exec does not support terminal process I/O",
        ));
    }
    Ok(())
}

fn allocate_process_directory(runtime_directory: &Path) -> Result<PathBuf> {
    let mut max_slot = 0_u64;
    let entries = std::fs::read_dir(runtime_directory).map_err(|error| {
        recovery_error(
            ErrorCode::Internal,
            format!(
                "failed to scan process directories under {}: {error}",
                runtime_directory.display()
            ),
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            recovery_error(
                ErrorCode::Internal,
                format!(
                    "failed to read process directory entry under {}: {error}",
                    runtime_directory.display()
                ),
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(hex) = name.strip_prefix("p-") else {
            continue;
        };
        if let Ok(slot) = u64::from_str_radix(hex, 16) {
            max_slot = max_slot.max(slot);
        }
    }
    let slot = max_slot.checked_add(1).ok_or_else(|| {
        recovery_error(
            ErrorCode::ResourceExhausted,
            "guest process slot space is exhausted after Host reopen",
        )
    })?;
    Ok(runtime_directory.join(format!("p-{slot:016x}")))
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

/// Restore every authentic stdin deposit recorded for this generation.
///
/// Init uses the create launcher PID. Each durable exec uses its helper PID —
/// the same key `ExecProcess` used at deposit time. Missing deposits are
/// omitted (callers fail closed on write) rather than inventing a pipe.
fn take_deposited_stdin_by_process(
    supervisor: &SharedSessionSupervisor,
    record: &ContainerRecoveryRecord,
) -> BTreeMap<ProcessId, tokio::fs::File> {
    let mut stdin = BTreeMap::new();
    if let Some(file) = take_deposited_stdin(supervisor, record.launcher.pid()) {
        stdin.insert(ProcessId::init(), file);
    }
    for exec in &record.execs {
        let Some(helper) = exec.helper.as_ref() else {
            continue;
        };
        if let Some(file) = take_deposited_stdin(supervisor, helper.pid()) {
            stdin.insert(exec.process_id.clone(), file);
        }
    }
    stdin
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
    payload_pid: i32,
    helper_pid: i32,
    terminal: bool,
) -> Result<(ProcessIdentity, ProcessIdentity)> {
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
    let identity = ProcessIdentity::capture(payload_pid, "container exec payload")?;
    let helper = ProcessIdentity::capture(helper_pid, "container exec helper")?;
    record.schema_version = CONTAINER_SCHEMA_VERSION.to_string();
    record.execs.push(RecoveryExecRecord {
        process_id: process_id.clone(),
        identity,
        helper: Some(helper),
        terminal,
    });
    write_atomic_record(&path, &record)?;
    Ok((identity, helper))
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
        CONTAINER_SCHEMA_VERSION_V5 => {
            let previous: V5ContainerRecoveryRecord =
                serde_json::from_value(value).map_err(|error| {
                    recovery_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "v5 native container recovery record {} is invalid: {error}",
                            path.display()
                        ),
                    )
                })?;
            Ok(normalize_v5_container_record(previous))
        }
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

fn normalize_v5_container_record(previous: V5ContainerRecoveryRecord) -> ContainerRecoveryRecord {
    ContainerRecoveryRecord {
        schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
        target: previous.target,
        config_digest: previous.config_digest,
        owner: previous.owner,
        launcher: previous.launcher,
        init: previous.init,
        session_supervisor: previous.session_supervisor,
        execs: previous
            .execs
            .into_iter()
            .map(|exec| RecoveryExecRecord {
                process_id: exec.process_id,
                identity: exec.identity,
                helper: None,
                terminal: exec.terminal,
            })
            .collect(),
        cgroup: previous.cgroup,
        intel_rdt: previous.intel_rdt,
    }
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
    // Publish with rename, not hard_link: container recovery is updated afte
    // create (supervised exec identities). hard_link to an existing path fails
    // with EEXIST and left keyed exec stuck after a successful spawn.
    let result = (|| -> io::Result<()> {
        let mut file = options.open(&pending)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        std::fs::rename(&pending, path)?;
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
    fn process_identity_capture_accepts_zombie_start_time() {
        // SAFETY: parent reaps; child exits immediately to become a zombie.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork zombie payload");
        if child == 0 {
            unsafe { libc::_exit(0) };
        }
        let mut saw_zombie = false;
        for _ in 0..200 {
            match process_observation(child) {
                Ok(Some(observation)) if observation.state == b'Z' => {
                    saw_zombie = true;
                    break;
                }
                Ok(Some(_)) => std::thread::sleep(Duration::from_millis(5)),
                Ok(None) | Err(_) => break,
            }
        }
        assert!(saw_zombie, "child must still be a zombie under the parent");
        let identity = ProcessIdentity::capture(child, "zombie payload")
            .expect("zombie /proc start-time must still authenticate recovery identity");
        assert_eq!(identity.pid(), child);
        assert!(
            !identity.is_live().expect("inspect zombie identity"),
            "zombie identity must not report live"
        );
        let mut status = 0;
        // SAFETY: reap the test zombie.
        let reaped = unsafe { libc::waitpid(child, &mut status, 0) };
        assert_eq!(reaped, child);
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
            .read_output(&ProcessId::init(), 0, 4096, None)
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
            .write_stdin(&ProcessId::init(), b"nope")
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
                    helper: Some(exec_identity),
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
    async fn live_session_signals_durable_exec_after_host_reopen_without_inventing_wait() {
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
            UnixStream::pair().expect("signal-process ready channel");
        // SAFETY: parent reaps the fake Host; child owns the production supervisor.
        let host_pid = unsafe { libc::fork() };
        assert!(host_pid >= 0, "fork fake host for signal-process reopen");
        if host_pid == 0 {
            drop(parent_ready);
            let mut supervisor = match HostSessionSupervisor::start_via_fork() {
                Ok(supervisor) => supervisor,
                Err(_) => unsafe { libc::_exit(161) },
            };
            let launcher_pid = match supervisor.spawn_launcher(
                Path::new("/bin/sleep"),
                &["30".into()],
                None,
                None,
                None,
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(162) },
            };
            let exec_pid = match supervisor.spawn_launcher(
                Path::new("/bin/sleep"),
                &["30".into()],
                None,
                None,
                None,
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(163) },
            };
            let identity = supervisor.identity().clone();
            let mut payload = Vec::with_capacity(20);
            payload.extend_from_slice(&identity.pid().to_be_bytes());
            payload.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
            payload.extend_from_slice(&launcher_pid.to_be_bytes());
            payload.extend_from_slice(&exec_pid.to_be_bytes());
            if child_ready.write_all(&payload).is_err() {
                unsafe { libc::_exit(164) }
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
            .expect("read signal-process supervisor evidence");
        let supervisor_pid = i32::from_be_bytes(payload[0..4].try_into().expect("pid bytes"));
        let supervisor_start = u64::from_be_bytes(payload[4..12].try_into().expect("start bytes"));
        let launcher_pid = i32::from_be_bytes(payload[12..16].try_into().expect("launcher bytes"));
        let exec_pid = i32::from_be_bytes(payload[16..20].try_into().expect("exec bytes"));

        let owner = ProcessIdentity {
            pid: 2_100_600,
            start_time_ticks: 0x616,
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
            a3s_oci_sdk::ContainerId::new("live-signal-exec").expect("container ID"),
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
                    helper: Some(exec_identity),
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
        .expect("live supervisor must reattach for signal-process")
        .expect("recovery match");
        let StaleGenerationRecovery::Live(live) = recovery else {
            panic!("live session supervisor must recover as Live");
        };

        let missing = a3s_oci_sdk::ProcessId::new("missing-exec").expect("missing process ID");
        let missing_error = live
            .signal_process(&missing, libc::SIGTERM)
            .expect_err("unknown durable process must fail closed");
        assert_eq!(missing_error.code, ErrorCode::NotFound);

        live.signal_process(&exec_id, libc::SIGKILL)
            .expect("authenticated durable exec must accept signal after Host reopen");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let gone = process_observation(exec_pid)
                .expect("observe signaled exec")
                .is_none_or(|observation| {
                    observation.is_terminated()
                        || observation.start_time_ticks != exec_identity.start_time_ticks()
                });
            if gone {
                break;
            }
            if Instant::now() >= deadline {
                panic!("durable exec PID {exec_pid} did not exit after authenticated SIGKILL");
            }
            sleep(Duration::from_millis(10)).await;
        }

        let after_exit = live
            .signal_process(&exec_id, libc::SIGTERM)
            .expect_err("dead durable exec must not invent signal delivery");
        assert_eq!(after_exit.code, ErrorCode::FailedPrecondition);

        // Signaled-dead exec is omitted from inventory without inventing wait status.
        let inventory = live
            .process_inventory()
            .expect("inventory after signal must not invent failure");
        assert!(
            inventory
                .iter()
                .all(|record| record.target.process_id != exec_id),
            "signaled-dead exec must be omitted without inventing wait status"
        );

        live.kill_launcher().expect("kill supervised launcher");
        let _ = live.wait_launcher().expect("wait supervised launcher");
        let tombstone = live
            .into_tombstone()
            .expect("dead supervised children can become a stopped tombstone");
        delete_stale_generation(&tombstone)
            .await
            .expect("stopped-only delete after live signal");
        terminate_pid(supervisor_pid);
        let _ = wait_for_child(supervisor_pid);
    }

    #[tokio::test]
    async fn live_session_waits_durable_exec_after_host_reopen_with_authentic_status() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::os::unix::process::ExitStatusExt;
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
            UnixStream::pair().expect("wait-process ready channel");
        // SAFETY: parent reaps the fake Host; child owns the production supervisor.
        let host_pid = unsafe { libc::fork() };
        assert!(host_pid >= 0, "fork fake host for wait-process reopen");
        if host_pid == 0 {
            drop(parent_ready);
            let mut supervisor = match HostSessionSupervisor::start_via_fork() {
                Ok(supervisor) => supervisor,
                Err(_) => unsafe { libc::_exit(171) },
            };
            let launcher_pid = match supervisor.spawn_launcher(
                Path::new("/bin/sleep"),
                &["30".into()],
                None,
                None,
                None,
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(172) },
            };
            let exec_pid = match supervisor.spawn_launcher(
                Path::new("/bin/sleep"),
                &["30".into()],
                None,
                None,
                None,
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(173) },
            };
            let v5_exec_pid = match supervisor.spawn_launcher(
                Path::new("/bin/sleep"),
                &["30".into()],
                None,
                None,
                None,
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(174) },
            };
            let identity = supervisor.identity().clone();
            let mut payload = Vec::with_capacity(24);
            payload.extend_from_slice(&identity.pid().to_be_bytes());
            payload.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
            payload.extend_from_slice(&launcher_pid.to_be_bytes());
            payload.extend_from_slice(&exec_pid.to_be_bytes());
            payload.extend_from_slice(&v5_exec_pid.to_be_bytes());
            if child_ready.write_all(&payload).is_err() {
                unsafe { libc::_exit(175) }
            }
            std::mem::forget(supervisor);
            loop {
                unsafe { libc::pause() };
            }
        }
        drop(child_ready);
        let mut payload = [0_u8; 24];
        parent_ready
            .read_exact(&mut payload)
            .expect("read wait-process supervisor evidence");
        let supervisor_pid = i32::from_be_bytes(payload[0..4].try_into().expect("pid bytes"));
        let supervisor_start = u64::from_be_bytes(payload[4..12].try_into().expect("start bytes"));
        let launcher_pid = i32::from_be_bytes(payload[12..16].try_into().expect("launcher bytes"));
        let exec_pid = i32::from_be_bytes(payload[16..20].try_into().expect("exec bytes"));
        let v5_exec_pid = i32::from_be_bytes(payload[20..24].try_into().expect("v5 exec bytes"));

        let owner = ProcessIdentity {
            pid: 2_100_700,
            start_time_ticks: 0x717,
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
            a3s_oci_sdk::ContainerId::new("live-wait-exec").expect("container ID"),
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
        let v5_exec_id = a3s_oci_sdk::ProcessId::new("legacy-worker").expect("v5 exec process ID");
        let v5_exec_identity = ProcessIdentity {
            pid: v5_exec_pid,
            start_time_ticks: process_observation(v5_exec_pid)
                .expect("observe v5 exec")
                .expect("v5 exec live")
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
                execs: vec![
                    RecoveryExecRecord {
                        process_id: exec_id.clone(),
                        identity: exec_identity,
                        helper: Some(exec_identity),
                        terminal: false,
                    },
                    RecoveryExecRecord {
                        process_id: v5_exec_id.clone(),
                        identity: v5_exec_identity,
                        helper: None,
                        terminal: false,
                    },
                ],
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
        .expect("live supervisor must reattach for wait-process")
        .expect("recovery match");
        let StaleGenerationRecovery::Live(live) = recovery else {
            panic!("live session supervisor must recover as Live");
        };

        let missing = a3s_oci_sdk::ProcessId::new("missing-exec").expect("missing process ID");
        let missing_error = live
            .wait_process(&missing)
            .expect_err("unknown durable process must fail closed");
        assert_eq!(missing_error.code, ErrorCode::NotFound);

        let v5_unavailable = live
            .wait_process(&v5_exec_id)
            .expect_err("v5 exec without helper must fail closed");
        assert_eq!(v5_unavailable.code, ErrorCode::Unavailable);

        live.signal_process(&exec_id, libc::SIGKILL)
            .expect("authenticated durable exec must accept signal before wait");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let gone = process_observation(exec_pid)
                .expect("observe signaled exec")
                .is_none_or(|observation| {
                    observation.is_terminated()
                        || observation.start_time_ticks != exec_identity.start_time_ticks()
                });
            if gone {
                break;
            }
            if Instant::now() >= deadline {
                panic!("durable exec PID {exec_pid} did not exit before wait_process");
            }
            sleep(Duration::from_millis(10)).await;
        }

        let raw = live
            .wait_process(&exec_id)
            .expect("authentic supervised wait must not invent exit status");
        let status = std::process::ExitStatus::from_raw(raw);
        assert!(
            status.signal().is_some() || status.code().is_some(),
            "wait_process must return authentic kernel wait status, not invented evidence"
        );

        let cached = live
            .wait_process(&exec_id)
            .expect("second wait must return cached authentic status");
        assert_eq!(cached, raw, "cached wait must match first authentic status");

        live.kill_launcher().expect("kill supervised launcher");
        let _ = live.wait_launcher().expect("wait supervised launcher");
        let tombstone = live
            .into_tombstone()
            .expect("dead supervised children can become a stopped tombstone");
        delete_stale_generation(&tombstone)
            .await
            .expect("stopped-only delete after live wait-process");
        terminate_pid(supervisor_pid);
        let _ = wait_for_child(supervisor_pid);
    }

    #[tokio::test]
    async fn live_session_pauses_resumes_updates_and_reads_stats_from_recovery_cgroup_leaf() {
        use std::io::{Read, Write};
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixStream;
        use std::path::Path;

        use super::super::pid_supervisor::{terminate_pid, wait_for_child};
        use super::super::session_supervisor::HostSessionSupervisor;

        let cgroup_root = Path::new("/sys/fs/cgroup");
        if !cgroup_root.join("cgroup.controllers").is_file() {
            eprintln!("skipping: host lacks cgroup v2 controllers for live pause/stats");
            return;
        }
        let manager_root = cgroup_root.join(format!(
            "a3s-oci-{}-live-cgroup-controls",
            std::process::id()
        ));
        if let Err(error) = std::fs::create_dir(&manager_root) {
            eprintln!(
                "skipping: cannot create test cgroup manager {}: {error}",
                manager_root.display()
            );
            return;
        }
        for controller in ["+cpu", "+memory", "+pids"] {
            if let Err(error) =
                std::fs::write(manager_root.join("cgroup.subtree_control"), controller)
            {
                let _ = std::fs::remove_dir(&manager_root);
                eprintln!(
                    "skipping: cannot enable {controller} on {}: {error}",
                    manager_root.display()
                );
                return;
            }
        }
        let leaf = manager_root.join("workload");
        if let Err(error) = std::fs::create_dir(&leaf) {
            let _ = std::fs::remove_dir(&manager_root);
            eprintln!(
                "skipping: cannot create test cgroup leaf {}: {error}",
                leaf.display()
            );
            return;
        }
        let required = [
            leaf.join("cgroup.freeze"),
            leaf.join("cgroup.events"),
            leaf.join("cpu.stat"),
            leaf.join("memory.current"),
            leaf.join("memory.max"),
            leaf.join("memory.events"),
            leaf.join("pids.current"),
            leaf.join("pids.max"),
            leaf.join("pids.events"),
        ];
        if let Some(missing) = required.iter().find(|path| !path.exists()) {
            let _ = std::fs::remove_dir(&leaf);
            let _ = std::fs::remove_dir(&manager_root);
            eprintln!(
                "skipping: test cgroup leaf lacks required control {}",
                missing.display()
            );
            return;
        }

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
            UnixStream::pair().expect("cgroup controls ready channel");
        // SAFETY: parent reaps the fake Host; child owns the production supervisor.
        let host_pid = unsafe { libc::fork() };
        assert!(host_pid >= 0, "fork fake host for cgroup controls reopen");
        if host_pid == 0 {
            drop(parent_ready);
            let mut supervisor = match HostSessionSupervisor::start_via_fork() {
                Ok(supervisor) => supervisor,
                Err(_) => unsafe { libc::_exit(181) },
            };
            let launcher_pid = match supervisor.spawn_launcher(
                Path::new("/bin/sleep"),
                &["30".into()],
                None,
                None,
                None,
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(182) },
            };
            if std::fs::write(leaf.join("cgroup.procs"), format!("{launcher_pid}\n")).is_err() {
                unsafe { libc::_exit(183) };
            }
            let identity = supervisor.identity().clone();
            let mut payload = Vec::with_capacity(16);
            payload.extend_from_slice(&identity.pid().to_be_bytes());
            payload.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
            payload.extend_from_slice(&launcher_pid.to_be_bytes());
            if child_ready.write_all(&payload).is_err() {
                unsafe { libc::_exit(184) }
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
            .expect("read cgroup-controls supervisor evidence");
        let supervisor_pid = i32::from_be_bytes(payload[0..4].try_into().expect("pid bytes"));
        let supervisor_start = u64::from_be_bytes(payload[4..12].try_into().expect("start bytes"));
        let launcher_pid = i32::from_be_bytes(payload[12..16].try_into().expect("launcher bytes"));

        let owner = ProcessIdentity {
            pid: 2_100_800,
            start_time_ticks: 0x818,
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
            a3s_oci_sdk::ContainerId::new("live-cgroup-controls").expect("container ID"),
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
                session_supervisor: Some(ProcessIdentity {
                    pid: supervisor_pid,
                    start_time_ticks: supervisor_start,
                }),
                execs: Vec::new(),
                cgroup: Some(RecoveryCgroupRecord {
                    authority_root: cgroup_root.to_path_buf(),
                    manager_root: manager_root.clone(),
                    leaf: leaf.clone(),
                    created: vec![leaf.clone()],
                }),
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
        .expect("live supervisor must reattach for cgroup controls")
        .expect("recovery match");
        let StaleGenerationRecovery::Live(live) = recovery else {
            panic!("live session supervisor must recover as Live");
        };

        assert!(
            !live.is_paused().expect("unpaused freezer observation"),
            "fresh recovery leaf must start unfrozen"
        );
        live.pause()
            .await
            .expect("authentic pause must freeze the recovery cgroup leaf");
        assert!(
            live.is_paused().expect("paused freezer observation"),
            "pause must observe kernel frozen=1"
        );
        let frozen_stats = live
            .stats()
            .await
            .expect("stats must read authentic cgroup counters");
        assert_eq!(frozen_stats.target, target);
        assert!(
            frozen_stats.process_count >= 1,
            "frozen leaf must still report the supervised launcher membership"
        );

        live.resume()
            .await
            .expect("authentic resume must thaw the recovery cgroup leaf");
        assert!(
            !live.is_paused().expect("resumed freezer observation"),
            "resume must observe kernel frozen=0"
        );

        let resources: a3s_oci_sdk::oci_spec::runtime::LinuxResources =
            serde_json::from_value(serde_json::json!({
                "memory": {"limit": 67_108_864},
                "pids": {"limit": 128}
            }))
            .expect("live update resources");
        live.update(&resources)
            .await
            .expect("authentic update must write the recovery cgroup leaf");
        let memory_max = std::fs::read_to_string(leaf.join("memory.max"))
            .expect("read memory.max after live update");
        assert_eq!(
            memory_max.trim(),
            "67108864",
            "live update must read back the written memory.max"
        );
        let pids_max =
            std::fs::read_to_string(leaf.join("pids.max")).expect("read pids.max after live update");
        assert_eq!(
            pids_max.trim(),
            "128",
            "live update must read back the written pids.max"
        );
        let updated_stats = live
            .stats()
            .await
            .expect("stats after update must remain authentic");
        assert_eq!(updated_stats.memory.limit_bytes, Some(67_108_864));

        live.kill_launcher().expect("kill supervised launcher");
        let _ = live.wait_launcher().expect("wait supervised launcher");
        let tombstone = live
            .into_tombstone()
            .expect("dead supervised children can become a stopped tombstone");
        delete_stale_generation(&tombstone)
            .await
            .expect("stopped-only delete after live cgroup controls");
        terminate_pid(supervisor_pid);
        let _ = wait_for_child(supervisor_pid);
        let _ = std::fs::remove_dir(&leaf);
        let _ = std::fs::remove_dir(&manager_root);
    }

    #[tokio::test]
    async fn live_session_fail_closes_pause_without_recovery_cgroup_leaf() {
        use std::io::{Read, Write};
        use std::os::unix::fs::PermissionsExt;
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
            UnixStream::pair().expect("missing-cgroup ready channel");
        let host_pid = unsafe { libc::fork() };
        assert!(host_pid >= 0, "fork fake host for missing-cgroup reopen");
        if host_pid == 0 {
            drop(parent_ready);
            let mut supervisor = match HostSessionSupervisor::start_via_fork() {
                Ok(supervisor) => supervisor,
                Err(_) => unsafe { libc::_exit(191) },
            };
            let launcher_pid = match supervisor.spawn_launcher(
                Path::new("/bin/sleep"),
                &["30".into()],
                None,
                None,
                None,
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(192) },
            };
            let identity = supervisor.identity().clone();
            let mut payload = Vec::with_capacity(16);
            payload.extend_from_slice(&identity.pid().to_be_bytes());
            payload.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
            payload.extend_from_slice(&launcher_pid.to_be_bytes());
            if child_ready.write_all(&payload).is_err() {
                unsafe { libc::_exit(193) }
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
            .expect("read missing-cgroup supervisor evidence");
        let supervisor_pid = i32::from_be_bytes(payload[0..4].try_into().expect("pid bytes"));
        let supervisor_start = u64::from_be_bytes(payload[4..12].try_into().expect("start bytes"));
        let launcher_pid = i32::from_be_bytes(payload[12..16].try_into().expect("launcher bytes"));

        let owner = ProcessIdentity {
            pid: 2_100_801,
            start_time_ticks: 0x819,
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
            a3s_oci_sdk::ContainerId::new("live-missing-cgroup").expect("container ID"),
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
                session_supervisor: Some(ProcessIdentity {
                    pid: supervisor_pid,
                    start_time_ticks: supervisor_start,
                }),
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
        .expect("live supervisor must reattach without inventing cgroup evidence")
        .expect("recovery match");
        let StaleGenerationRecovery::Live(live) = recovery else {
            panic!("live session supervisor must recover as Live");
        };

        let pause_error = live
            .pause()
            .await
            .expect_err("pause without recovery cgroup must fail closed");
        assert_eq!(pause_error.code, ErrorCode::Unavailable);
        let stats_error = live
            .stats()
            .await
            .expect_err("stats without recovery cgroup must fail closed");
        assert_eq!(stats_error.code, ErrorCode::Unavailable);
        let update_error = live
            .update(&a3s_oci_sdk::oci_spec::runtime::LinuxResources::default())
            .await
            .expect_err("update without recovery cgroup must fail closed");
        assert_eq!(update_error.code, ErrorCode::Unavailable);

        live.kill_launcher().expect("kill supervised launcher");
        let _ = live.wait_launcher().expect("wait supervised launcher");
        let tombstone = live
            .into_tombstone()
            .expect("dead supervised children can become a stopped tombstone");
        delete_stale_generation(&tombstone)
            .await
            .expect("stopped-only delete after missing-cgroup fail-closed");
        terminate_pid(supervisor_pid);
        let _ = wait_for_child(supervisor_pid);
    }

    #[tokio::test]
    async fn live_session_fail_closes_non_null_exec_io_after_host_reopen() {
        use std::io::{Read, Write};
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixStream;
        use std::path::Path;

        use a3s_oci_sdk::oci_spec::runtime::Process;
        use a3s_oci_sdk::{IoMode, ProcessId, ProcessIo};

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
            UnixStream::pair().expect("exec-io ready channel");
        let host_pid = unsafe { libc::fork() };
        assert!(host_pid >= 0, "fork fake host for exec-io reopen");
        if host_pid == 0 {
            drop(parent_ready);
            let mut supervisor = match HostSessionSupervisor::start_via_fork() {
                Ok(supervisor) => supervisor,
                Err(_) => unsafe { libc::_exit(201) },
            };
            let launcher_pid = match supervisor.spawn_launcher(
                Path::new("/bin/sleep"),
                &["30".into()],
                None,
                None,
                None,
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(202) },
            };
            let identity = supervisor.identity().clone();
            let mut payload = Vec::with_capacity(16);
            payload.extend_from_slice(&identity.pid().to_be_bytes());
            payload.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
            payload.extend_from_slice(&launcher_pid.to_be_bytes());
            if child_ready.write_all(&payload).is_err() {
                unsafe { libc::_exit(203) }
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
            .expect("read exec-io supervisor evidence");
        let supervisor_pid = i32::from_be_bytes(payload[0..4].try_into().expect("pid bytes"));
        let supervisor_start = u64::from_be_bytes(payload[4..12].try_into().expect("start bytes"));
        let launcher_pid = i32::from_be_bytes(payload[12..16].try_into().expect("launcher bytes"));

        let owner = ProcessIdentity {
            pid: 2_100_802,
            start_time_ticks: 0x81a,
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
        let config = br#"{"ociVersion":"1.3.0","process":{"user":{"uid":0,"gid":0},"args":["/bin/true"]},"root":{"path":"rootfs"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"}]}}"#;
        let digest = config_digest_for(config);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options
            .open(slot.join(CONFIG_SNAPSHOT_NAME))
            .and_then(|mut file| file.write_all(config))
            .expect("configuration snapshot");
        let target = ContainerTarget::exact(
            a3s_oci_sdk::ContainerId::new("live-exec-io").expect("container ID"),
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
                session_supervisor: Some(ProcessIdentity {
                    pid: supervisor_pid,
                    start_time_ticks: supervisor_start,
                }),
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
        .expect("live supervisor must reattach for exec-io gate")
        .expect("recovery match");
        let StaleGenerationRecovery::Live(live) = recovery else {
            panic!("live session supervisor must recover as Live");
        };

        let process: Process = serde_json::from_value(serde_json::json!({
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/true"],
            "cwd": "/"
        }))
        .expect("exec process");
        let capture_io = ProcessIo {
            stdin: IoMode::Null,
            stdout: IoMode::Capture,
            stderr: IoMode::Null,
            terminal_size: None,
        };
        // Capture is now admitted at the I/O gate; without a real agent
        // container-exec helper the spawn still fail-closes — never invents
        // success or an empty capture stream.
        let capture_spawn_error = live
            .exec(
                &ProcessId::new("post-reopen-exec").expect("process id"),
                &process,
                &capture_io,
                Path::new("/bin/true"),
            )
            .await
            .expect_err("non-agent helper must fail closed without inventing capture exec success");
        assert!(
            matches!(
                capture_spawn_error.code,
                ErrorCode::FailedPrecondition
                    | ErrorCode::Internal
                    | ErrorCode::Unavailable
                    | ErrorCode::PermissionDenied
                    | ErrorCode::InvalidArgument
            ),
            "capture spawn must fail closed with a real error, got {:?}",
            capture_spawn_error.code
        );

        let null_io = ProcessIo {
            stdin: IoMode::Null,
            stdout: IoMode::Null,
            stderr: IoMode::Null,
            terminal_size: None,
        };
        // Rebuild reaches authentic namespace capture; without a real agent
        // container-exec helper the spawn fails closed — never invents success.
        let spawn_error = live
            .exec(
                &ProcessId::new("post-reopen-null").expect("process id"),
                &process,
                &null_io,
                Path::new("/bin/true"),
            )
            .await
            .expect_err("non-agent helper must fail closed without inventing exec success");
        assert!(
            matches!(
                spawn_error.code,
                ErrorCode::FailedPrecondition
                    | ErrorCode::Internal
                    | ErrorCode::Unavailable
                    | ErrorCode::PermissionDenied
                    | ErrorCode::InvalidArgument
            ),
            "spawn must fail closed with a real error, got {:?}",
            spawn_error.code
        );

        live.kill_launcher().expect("kill supervised launcher");
        let _ = live.wait_launcher().expect("wait supervised launcher");
        let tombstone = live
            .into_tombstone()
            .expect("dead supervised children can become a stopped tombstone");
        delete_stale_generation(&tombstone)
            .await
            .expect("stopped-only delete after exec-io fail-closed");
        terminate_pid(supervisor_pid);
        let _ = wait_for_child(supervisor_pid);
    }

    #[test]
    fn require_supervised_exec_process_io_rejects_terminal_and_inherit() {
        use a3s_oci_sdk::{IoMode, ProcessIo};

        let ok = ProcessIo {
            stdin: IoMode::Null,
            stdout: IoMode::Capture,
            stderr: IoMode::Pipe,
            terminal_size: None,
        };
        require_supervised_exec_process_io(&ok).expect("Null/Capture/Pipe I/O is accepted");

        let terminal = ProcessIo {
            stdin: IoMode::Terminal,
            stdout: IoMode::Terminal,
            stderr: IoMode::Terminal,
            terminal_size: None,
        };
        let error =
            require_supervised_exec_process_io(&terminal).expect_err("terminal must fail closed");
        assert_eq!(error.code, ErrorCode::Unavailable);

        let inherit = ProcessIo {
            stdin: IoMode::Inherit,
            stdout: IoMode::Null,
            stderr: IoMode::Null,
            terminal_size: None,
        };
        let error =
            require_supervised_exec_process_io(&inherit).expect_err("inherit must fail closed");
        assert_eq!(error.code, ErrorCode::Unavailable);
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
            .read_output(&ProcessId::init(), 0, 4096, None)
            .expect_err("capture stdio must stay Unavailable");
        assert_eq!(read_error.code, ErrorCode::Unavailable);

        live.write_stdin(&ProcessId::init(), b"hello-reopen\n")
            .await
            .expect("restored stdin must accept authentic writes");
        live.close_stdin(&ProcessId::init())
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
                .read_output(&ProcessId::init(), after, 4096, Some(100))
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

        // Without the cache, a second reattach would fail: the superviso
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

    fn resolve_test_agent_executable() -> PathBuf {
        if let Ok(path) = std::env::var("CARGO_BIN_EXE_a3s-oci-agent") {
            return PathBuf::from(path);
        }
        let mut path = std::env::current_exe().expect("current test executable");
        path.pop();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "deps")
        {
            path.pop();
        }
        let candidate = path.join("a3s-oci-agent");
        assert!(
            candidate.is_file(),
            "a3s-oci-agent must be built beside the test profile at {}",
            candidate.display()
        );
        candidate
    }

    async fn recover_live_filesystem_fixture(
        label: &str,
    ) -> (
        tempfile::TempDir,
        SessionSupervisorReattachCache,
        LinuxLiveSupervisedSession,
        i32,
        ContainerTarget,
    ) {
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
            UnixStream::pair().expect("live filesystem ready channel");
        let host_pid = unsafe { libc::fork() };
        assert!(host_pid >= 0, "fork fake host for live filesystem");
        if host_pid == 0 {
            drop(parent_ready);
            let mut supervisor = match HostSessionSupervisor::start_via_fork() {
                Ok(supervisor) => supervisor,
                Err(_) => unsafe { libc::_exit(221) },
            };
            let launcher_pid = match supervisor.spawn_launcher(
                Path::new("/bin/sleep"),
                &["30".into()],
                None,
                None,
                None,
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(222) },
            };
            let identity = supervisor.identity().clone();
            let mut payload = Vec::with_capacity(16);
            payload.extend_from_slice(&identity.pid().to_be_bytes());
            payload.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
            payload.extend_from_slice(&launcher_pid.to_be_bytes());
            if child_ready.write_all(&payload).is_err() {
                unsafe { libc::_exit(223) }
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
            .expect("read live filesystem supervisor evidence");
        let supervisor_pid = i32::from_be_bytes(payload[0..4].try_into().expect("pid bytes"));
        let supervisor_start = u64::from_be_bytes(payload[4..12].try_into().expect("start bytes"));
        let launcher_pid = i32::from_be_bytes(payload[12..16].try_into().expect("launcher bytes"));

        let owner = ProcessIdentity {
            pid: 2_100_901,
            start_time_ticks: 0x91a,
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
        // Mount namespace is declared so rebuild opens /proc/<init>/root. The
        // supervised sleep stays in the host mount namespace, so the helpe
        // operates against that exact root without inventing a private rootfs.
        // Match the calling euid/egid so Host-reopen upload/mkdir do not require
        // root when the test harness is unprivileged.
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let config = format!(
            r#"{{"ociVersion":"1.3.0","process":{{"user":{{"uid":{uid},"gid":{gid}}},"args":["/bin/sleep","30"],"cwd":"/"}},"root":{{"path":"rootfs"}},"linux":{{"namespaces":[{{"type":"pid"}},{{"type":"mount"}}]}}}}"#
        );
        let config = config.into_bytes();
        let digest = config_digest_for(&config);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options
            .open(slot.join(CONFIG_SNAPSHOT_NAME))
            .and_then(|mut file| file.write_all(&config))
            .expect("configuration snapshot");
        let target = ContainerTarget::exact(
            a3s_oci_sdk::ContainerId::new(format!("live-fs-{label}")).expect("container ID"),
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
                session_supervisor: Some(ProcessIdentity {
                    pid: supervisor_pid,
                    start_time_ticks: supervisor_start,
                }),
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
        .expect("live supervisor must reattach for filesystem continuity")
        .expect("recovery match");
        let StaleGenerationRecovery::Live(live) = recovery else {
            panic!("live session supervisor must recover as Live");
        };
        (temporary, supervisors, live, supervisor_pid, target)
    }

    async fn cleanup_live_filesystem_session(
        live: LinuxLiveSupervisedSession,
        supervisor_pid: i32,
        supervisors: SessionSupervisorReattachCache,
    ) {
        use super::super::pid_supervisor::{terminate_pid, wait_for_child};

        let _ = live.kill_launcher();
        let _ = live.wait_launcher();
        if let Ok(tombstone) = live.into_tombstone() {
            let _ = delete_stale_generation(&tombstone).await;
        }
        drop(supervisors);
        terminate_pid(supervisor_pid);
        let _ = wait_for_child(supervisor_pid);
    }

    #[tokio::test]
    async fn live_session_downloads_bytes_planted_before_host_reattach() {
        use a3s_oci_sdk::{FileOp, FileRequest};
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let agent = resolve_test_agent_executable();
        let (_temporary, supervisors, live, supervisor_pid, target) =
            recover_live_filesystem_fixture("preplant").await;

        let nonce = format!("{}-{}", std::process::id(), live.init_pid());
        let path = format!("/tmp/.a3s-oci-live-fs-preplant-{nonce}.bin");
        let expected = format!("a3s-oci-live-fs-preplant-{nonce}\0binary\n").into_bytes();
        // Simulate FileOp::Upload completed before Host death: bytes already
        // visible through the live init root before reopen helpers run.
        std::fs::write(&path, &expected).expect("plant retained filesystem bytes");

        let downloaded = live
            .file(
                &agent,
                FileRequest {
                    target: target.clone(),
                    op: FileOp::Download,
                    path: path.clone(),
                    data: None,
                    user: None,
                    context: None,
                },
            )
            .await
            .expect("Host-reopen download must return planted bytes");
        let decoded = downloaded
            .data
            .as_deref()
            .map(|value| STANDARD.decode(value))
            .transpose()
            .expect("download payload must be base64")
            .expect("download payload must be present");
        assert_eq!(decoded, expected);
        assert_eq!(downloaded.size, expected.len() as u64);

        let _ = std::fs::remove_file(&path);
        cleanup_live_filesystem_session(live, supervisor_pid, supervisors).await;
    }

    #[tokio::test]
    async fn live_session_upload_stat_and_download_after_reattach() {
        use a3s_oci_sdk::{
            FileOp, FileRequest, FilesystemEntryKind, FilesystemOp, FilesystemRequest,
            OperationContext, OperationId,
        };
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let agent = resolve_test_agent_executable();
        let (_temporary, supervisors, live, supervisor_pid, target) =
            recover_live_filesystem_fixture("upload").await;

        let nonce = format!("{}-{}", std::process::id(), live.init_pid());
        let dir = format!("/tmp/.a3s-oci-live-fs-dir-{nonce}");
        let path = format!("{dir}/payload.bin");
        let expected = format!("a3s-oci-live-fs-upload-{nonce}\0binary\n").into_bytes();
        // request.user defaults to root:root; unprivileged harnesses must pass
        // the calling ids or mkdir/upload chown fail-closes PermissionDenied.
        let owner = format!("{}:{}", unsafe { libc::geteuid() }, unsafe {
            libc::getegid()
        });

        live.filesystem(
            &agent,
            FilesystemRequest {
                target: target.clone(),
                op: FilesystemOp::MakeDir,
                path: dir.clone(),
                destination: None,
                depth: 0,
                user: Some(owner.clone()),
                context: Some(OperationContext::new(
                    OperationId::new(format!("live-fs-mkdir-{nonce}")).expect("operation id"),
                )),
            },
        )
        .await
        .expect("Host-reopen mkdir must succeed against live init root");

        live.file(
            &agent,
            FileRequest {
                target: target.clone(),
                op: FileOp::Upload,
                path: path.clone(),
                data: Some(STANDARD.encode(&expected)),
                user: Some(owner.clone()),
                context: Some(OperationContext::new(
                    OperationId::new(format!("live-fs-upload-{nonce}")).expect("operation id"),
                )),
            },
        )
        .await
        .expect("Host-reopen upload must succeed");

        let statted = live
            .filesystem(
                &agent,
                FilesystemRequest {
                    target: target.clone(),
                    op: FilesystemOp::Stat,
                    path: path.clone(),
                    destination: None,
                    depth: 0,
                    user: Some(owner),
                    context: None,
                },
            )
            .await
            .expect("Host-reopen stat must see uploaded path");
        let entry = statted.entry.expect("stat must return an entry");
        assert_eq!(entry.kind, FilesystemEntryKind::File);
        assert_eq!(entry.size, expected.len() as i64);

        let downloaded = live
            .file(
                &agent,
                FileRequest {
                    target: target.clone(),
                    op: FileOp::Download,
                    path: path.clone(),
                    data: None,
                    user: None,
                    context: None,
                },
            )
            .await
            .expect("Host-reopen download must match upload");
        let decoded = downloaded
            .data
            .as_deref()
            .map(|value| STANDARD.decode(value))
            .transpose()
            .expect("download payload must be base64")
            .expect("download payload must be present");
        assert_eq!(decoded, expected);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
        cleanup_live_filesystem_session(live, supervisor_pid, supervisors).await;
    }

    #[tokio::test]
    async fn live_session_file_fail_closes_when_init_is_dead() {
        use a3s_oci_sdk::{FileOp, FileRequest};
        use std::path::Path;

        use super::super::pid_supervisor::terminate_pid;

        // Fail-closed before spawning the filesystem helper, so any path works.
        let agent = Path::new("/bin/true");
        let (_temporary, supervisors, live, supervisor_pid, target) =
            recover_live_filesystem_fixture("dead-init").await;

        terminate_pid(live.init_pid());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while live.init_is_live().expect("init observation") && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !live.init_is_live().expect("init observation"),
            "init must exit before Unavailable assertion"
        );

        let error = live
            .file(
                agent,
                FileRequest {
                    target: target.clone(),
                    op: FileOp::Download,
                    path: "/tmp/.a3s-oci-live-fs-missing.bin".to_string(),
                    data: None,
                    user: None,
                    context: None,
                },
            )
            .await
            .expect_err("dead init must fail closed");
        assert_eq!(error.code, ErrorCode::Unavailable);

        cleanup_live_filesystem_session(live, supervisor_pid, supervisors).await;
    }

    #[tokio::test]
    async fn live_session_file_fail_closes_wrong_generation() {
        use a3s_oci_sdk::{FileOp, FileRequest, Generation};
        use std::path::Path;

        // Fail-closed on the generation fence before spawning the helper.
        let agent = Path::new("/bin/true");
        let (_temporary, supervisors, live, supervisor_pid, target) =
            recover_live_filesystem_fixture("wrong-gen").await;

        let wrong = ContainerTarget::exact(target.id.clone(), Generation(99));
        let error = live
            .file(
                agent,
                FileRequest {
                    target: wrong,
                    op: FileOp::Download,
                    path: "/tmp/.a3s-oci-live-fs-wrong-gen.bin".to_string(),
                    data: None,
                    user: None,
                    context: None,
                },
            )
            .await
            .expect_err("wrong generation must Conflict");
        assert_eq!(error.code, ErrorCode::Conflict);

        cleanup_live_filesystem_session(live, supervisor_pid, supervisors).await;
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
    fn write_atomic_record_replaces_an_existing_recovery_file() {
        let temporary = tempfile::tempdir().expect("temporary path");
        let path = temporary.path().join("recovery.json");
        write_atomic_record(
            &path,
            &serde_json::json!({
                "schemaVersion": "probe",
                "generation": 1
            }),
        )
        .expect("create recovery record");
        write_atomic_record(
            &path,
            &serde_json::json!({
                "schemaVersion": "probe",
                "generation": 2
            }),
        )
        .expect("replace recovery record");
        let encoded = std::fs::read_to_string(&path).expect("read recovery record");
        assert!(encoded.contains("\"generation\": 2"), "{encoded}");
        let metadata = std::fs::symlink_metadata(&path).expect("metadata");
        assert_eq!(metadata.mode() & 0o777, 0o600);
    }

    #[test]
    fn record_exec_identity_updates_existing_supervised_recovery() {
        use std::process::{Command, Stdio};

        let temporary = tempfile::tempdir().expect("temporary path");
        let path = temporary.path().join(CONTAINER_RECORD_NAME);
        let self_pid = std::process::id() as i32;
        let owner = ProcessIdentity::capture(self_pid, "owner").expect("owner identity");
        let mut helper = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn helper");
        let helper_pid = helper.id() as i32;
        let launcher = ProcessIdentity::capture(self_pid, "launcher").expect("launcher");
        let init = ProcessIdentity::capture(self_pid, "init").expect("init");
        let supervisor =
            ProcessIdentity::capture(self_pid, "session supervisor").expect("supervisor");
        write_atomic_record(
            &path,
            &ContainerRecoveryRecord {
                schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
                target: ContainerTarget::exact(
                    a3s_oci_sdk::ContainerId::new("box-1").expect("container ID"),
                    a3s_oci_sdk::Generation(1),
                ),
                config_digest: "sha256:test".to_string(),
                owner,
                launcher,
                init,
                session_supervisor: Some(supervisor),
                execs: Vec::new(),
                cgroup: None,
                intel_rdt: None,
            },
        )
        .expect("seed supervised recovery");

        let process_id = a3s_oci_sdk::ProcessId::new("exec-1").expect("process ID");
        record_exec_identity(temporary.path(), &process_id, self_pid, helper_pid, false)
            .expect("append exec identity");
        let record = read_container_record(&path).expect("reread recovery");
        assert_eq!(record.execs.len(), 1);
        assert_eq!(record.execs[0].process_id, process_id);
        assert_eq!(record.execs[0].identity.pid, self_pid);
        assert_eq!(
            record.execs[0]
                .helper
                .as_ref()
                .expect("helper identity")
                .pid,
            helper_pid
        );
        let _ = helper.kill();
        let _ = helper.wait();
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
