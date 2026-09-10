//! Host-surviving session supervisor for Native Linux live process reattach.
//!
//! Current Native Linux owner-death recovery installs `PR_SET_PDEATHSIG(SIGKILL)`
//! against the Host Service owner, so a replacement process can only reconcile a
//! stopped tombstone. Box B2 / OCI R6 live process-session recovery needs a
//! different lifetime model:
//!
//! 1. a durable supervisor outlives Host Service death;
//! 2. workload helpers arm parent-death against that supervisor (real parent);
//! 3. a replacement Host authenticates the supervisor by PID **and** start-time
//!    ticks before claiming any live session;
//! 4. after Host control EOF, the same supervisor publishes a deterministic
//!    abstract reattach endpoint so the replacement can resume wait/spawn
//!    without re-exec (re-exec would break PDEATHSIG parentage and invent wait
//!    status).
//!
//! Qualification may enable production wiring with
//! `A3S_OCI_NATIVE_SESSION_SUPERVISOR=1`. Default create keeps Host-bound
//! PDEATHSIG so stopped-only recovery gates stay green.

mod output_buffer;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use a3s_oci_sdk::{Error, ErrorCode, OutputChunk, OutputStream, Result};
use serde::{Deserialize, Serialize};

use super::pid_supervisor::{
    terminate_pid, verify_and_arm_parent_death_signal, wait_for_child, ChildOutcome,
};
use super::pidfd::PidFd;
use output_buffer::{SyncOutputBuffer, OUTPUT_READER_CHUNK_BYTES};

const IDENTITY_SCHEMA_VERSION: &str = "a3s.oci.native-linux-session-supervisor-identity.v1";
const MAX_STAT_BYTES: usize = 4096;
const READY_BYTE: u8 = b'R';
const WORKLOAD_BYTE: u8 = b'W';
const SUPERVISE_CONTROL_FD: RawFd = 3;
const MSG_READY: u8 = 1;
const MSG_SPAWN: u8 = 2;
const MSG_SPAWNED: u8 = 3;
const MSG_ERROR: u8 = 4;
const MSG_SHUTDOWN: u8 = 5;
const MSG_WAIT: u8 = 6;
const MSG_WAITED: u8 = 7;
/// Host deposits a duplicate stdin write end so Host death does not EOF the child.
const MSG_DEPOSIT_STDIN: u8 = 8;
const MSG_DEPOSITED: u8 = 9;
/// Replacement Host retrieves the deposited stdin write end after control reattach.
const MSG_TAKE_STDIN: u8 = 10;
const MSG_STDIN_TAKEN: u8 = 11;
/// Close the deposited duplicate so intentional close_stdin can deliver EOF.
const MSG_CLOSE_DEPOSITED_STDIN: u8 = 12;
const MSG_DEPOSIT_CLOSED: u8 = 13;
/// Host moves exclusive stdout/stderr read ends to the supervisor (not F_DUPFD).
const MSG_DEPOSIT_OUTPUT: u8 = 14;
const MSG_OUTPUT_DEPOSITED: u8 = 15;
/// Host polls sequence-bearing chunks from the supervisor-owned drain buffer.
const MSG_READ_OUTPUT: u8 = 16;
const MSG_OUTPUT_CHUNKS: u8 = 17;
const FLAG_OUTPUT_STDOUT: u8 = 0b0000_0001;
const FLAG_OUTPUT_STDERR: u8 = 0b0000_0010;
const MAX_SPAWN_ARGS: usize = 64;
const MAX_ARG_BYTES: usize = 8 * 1024;
/// Known create FDs (≤6) plus inherited exec descriptors (rootfs, init pidfd,
/// cgroup.procs, retained namespaces). Worst case ≈ 3 stdio + 1 cgroup + 2
/// control/workload + 11 inherited ≈ 17; keep headroom for SCM_RIGHTS.
const MAX_SPAWN_FDS: usize = 20;
const MAX_INHERITED_SPAWN_FDS: usize = 16;
const ENV_OPT_IN: &str = "A3S_OCI_NATIVE_SESSION_SUPERVISOR";
const FLAG_JOIN_CGROUP: u8 = 0b0000_0001;
const FLAG_CONTROL_WORKLOAD: u8 = 0b0000_0010;
const FLAG_STDIN: u8 = 0b0000_0100;
const FLAG_STDOUT: u8 = 0b0000_1000;
const FLAG_STDERR: u8 = 0b0001_0000;
/// Additional descriptors installed at explicit target FD numbers before exec.
const FLAG_INHERITED: u8 = 0b0010_0000;
const REATTACH_ENDPOINT_PREFIX: &str = "a3s.oci.session-supervise.";
const REATTACH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REATTACH_ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
const REATTACH_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Shared Host handle for one authenticated session supervisor.
pub(crate) type SharedSessionSupervisor = Arc<Mutex<HostSessionSupervisor>>;

/// Authenticated identity of a host-surviving session supervisor.
///
/// Numeric PID alone is never sufficient. A replacement Host must observe the
/// same start-time ticks before reattaching live process sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SessionSupervisorIdentity {
    schema_version: String,
    pid: i32,
    start_time_ticks: u64,
}

impl SessionSupervisorIdentity {
    /// Capture the calling process as a supervisor identity.
    pub(crate) fn current() -> Result<Self> {
        let raw = std::process::id();
        let pid = i32::try_from(raw).map_err(|error| {
            supervisor_error(
                ErrorCode::ResourceExhausted,
                format!("session supervisor PID {raw} does not fit the identity model: {error}"),
            )
        })?;
        Self::capture(pid)
    }

    /// Capture a live process by PID and start-time ticks.
    pub(crate) fn capture(pid: i32) -> Result<Self> {
        let observation = process_observation(pid)?.ok_or_else(|| {
            supervisor_error(
                ErrorCode::Unavailable,
                format!("session supervisor PID {pid} exited before identity capture"),
            )
            .retryable(true)
        })?;
        if observation.is_terminated() {
            return Err(supervisor_error(
                ErrorCode::Unavailable,
                format!("session supervisor PID {pid} is already terminated"),
            )
            .retryable(true));
        }
        Ok(Self {
            schema_version: IDENTITY_SCHEMA_VERSION.to_string(),
            pid,
            start_time_ticks: observation.start_time_ticks,
        })
    }

    /// Build an identity from an already-authenticated PID + start-time pair
    /// (for example recovery v4 `sessionSupervisor`).
    pub(crate) fn from_authenticated(pid: i32, start_time_ticks: u64) -> Self {
        Self {
            schema_version: IDENTITY_SCHEMA_VERSION.to_string(),
            pid,
            start_time_ticks,
        }
    }

    /// Reject PID-only authentication. The observed start-time must match.
    pub(crate) fn authenticate_live(&self) -> Result<()> {
        if self.schema_version != IDENTITY_SCHEMA_VERSION {
            return Err(supervisor_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "unsupported session supervisor identity schema {}",
                    self.schema_version
                ),
            ));
        }
        if self.pid <= 0 {
            return Err(supervisor_error(
                ErrorCode::InvalidArgument,
                format!(
                    "session supervisor PID must be positive; received {}",
                    self.pid
                ),
            ));
        }
        let observation = process_observation(self.pid)?.ok_or_else(|| {
            supervisor_error(
                ErrorCode::Unavailable,
                format!("session supervisor PID {} is absent", self.pid),
            )
            .retryable(true)
        })?;
        if observation.start_time_ticks != self.start_time_ticks {
            return Err(supervisor_error(
                ErrorCode::PermissionDenied,
                format!(
                    "session supervisor PID {} start-time drifted: recorded {}, observed {}",
                    self.pid, self.start_time_ticks, observation.start_time_ticks
                ),
            ));
        }
        if observation.is_terminated() {
            return Err(supervisor_error(
                ErrorCode::Unavailable,
                format!("session supervisor PID {} is terminated", self.pid),
            )
            .retryable(true));
        }
        Ok(())
    }

    pub(crate) const fn pid(&self) -> i32 {
        self.pid
    }

    pub(crate) const fn start_time_ticks(&self) -> u64 {
        self.start_time_ticks
    }

    /// Deterministic abstract unix name used for Host control reattach.
    ///
    /// Knowledge of PID + start-time (from recovery v4) is required to locate
    /// the endpoint. A replacement Host must still call [`authenticate_live`]
    /// before claiming the session.
    pub(crate) fn reattach_endpoint_name(&self) -> String {
        format!(
            "{REATTACH_ENDPOINT_PREFIX}{}.{:016x}",
            self.pid, self.start_time_ticks
        )
    }
}

/// Whether Native create should attach workloads to a host-surviving supervisor.
pub(crate) fn session_supervisor_opt_in() -> bool {
    matches!(std::env::var_os(ENV_OPT_IN), Some(value) if value == "1")
}

/// Production host-surviving supervisor that can parent container launchers.
#[derive(Debug)]
pub(crate) struct HostSessionSupervisor {
    identity: SessionSupervisorIdentity,
    control: UnixStream,
    pidfd: PidFd,
}

impl HostSessionSupervisor {
    /// Start a durable supervisor process (same agent binary, `session-supervise`).
    pub(crate) fn start(init_executable: &Path) -> Result<Self> {
        let (parent_side, child_side) = UnixStream::pair().map_err(|error| {
            supervisor_error(
                ErrorCode::Internal,
                format!("failed to create session-supervisor control channel: {error}"),
            )
        })?;
        let child_fd = child_side.as_raw_fd();
        clear_cloexec(child_fd)?;
        let mut command = Command::new(init_executable);
        command
            .arg("session-supervise")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .env_clear();
        // SAFETY: pre_exec runs in the child before exec and only duplicates the
        // already-open control socket onto the fixed supervise FD.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(child_fd, SUPERVISE_CONTROL_FD) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|error| {
            supervisor_error(
                ErrorCode::Internal,
                format!("failed to spawn session-supervise: {error}"),
            )
        })?;
        drop(child_side);
        let raw_pid = child.id();
        let pid = i32::try_from(raw_pid).map_err(|error| {
            let _ = child.kill();
            let _ = child.wait();
            supervisor_error(
                ErrorCode::ResourceExhausted,
                format!(
                    "session supervisor PID {raw_pid} does not fit the identity model: {error}"
                ),
            )
        })?;
        // Track by pidfd; forgetting Child avoids a second local reaper race.
        std::mem::forget(child);
        finish_start(parent_side, pid)
    }

    /// Start the supervisor by fork for first-principles tests (no re-exec).
    #[cfg(test)]
    pub(crate) fn start_via_fork() -> Result<Self> {
        let (parent_side, child_side) = UnixStream::pair().map_err(|error| {
            supervisor_error(
                ErrorCode::Internal,
                format!("failed to create session-supervisor control channel: {error}"),
            )
        })?;
        // SAFETY: tests run this before spawning concurrent work in the child.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(last_os_error("fork session-supervise test supervisor"));
        }
        if pid == 0 {
            drop(parent_side);
            let raw = child_side.as_raw_fd();
            // SAFETY: install the control socket on the fixed supervise FD.
            if unsafe { libc::dup2(raw, SUPERVISE_CONTROL_FD) } < 0 {
                unsafe { libc::_exit(94) }
            }
            drop(child_side);
            let code = match run_session_supervise_service() {
                Ok(()) => 0,
                Err(_) => 95,
            };
            unsafe { libc::_exit(code) }
        }
        drop(child_side);
        finish_start(parent_side, pid)
    }

    pub(crate) fn identity(&self) -> &SessionSupervisorIdentity {
        &self.identity
    }

    /// Spawn `/bin/sleep` under the supervisor for first-principles lifetime tests.
    pub(crate) fn spawn_sleep_workload(&mut self, seconds: u64) -> Result<i32> {
        self.spawn_launcher(
            Path::new("/bin/sleep"),
            &[seconds.to_string().into()],
            None,
            None,
            None,
        )
    }

    /// Spawn a process as a real child of the supervisor with PDEATHSIG armed.
    ///
    /// `stdio` is `(stdin, stdout, stderr)` child-side descriptors. Present
    /// options are installed onto 0/1/2 in the launcher via `dup2`.
    ///
    /// `inherited` is `(source_fd, target_fd)` pairs: each source descriptor is
    /// sent via SCM_RIGHTS and installed onto `target_fd` in the child before
    /// exec (clearing `FD_CLOEXEC`). Used by supervised `container-exec` so
    /// argv-embedded FD numbers remain valid under supervisor parentage.
    pub(crate) fn spawn_launcher(
        &mut self,
        program: &Path,
        args: &[std::ffi::OsString],
        join_cgroup_procs: Option<RawFd>,
        control_workload: Option<(RawFd, RawFd)>,
        stdio: Option<(Option<RawFd>, Option<RawFd>, Option<RawFd>)>,
    ) -> Result<i32> {
        self.spawn_launcher_with_inherited(program, args, join_cgroup_procs, control_workload, stdio, &[])
    }

    /// Like [`Self::spawn_launcher`], with optional inherited target FD installs.
    pub(crate) fn spawn_launcher_with_inherited(
        &mut self,
        program: &Path,
        args: &[std::ffi::OsString],
        join_cgroup_procs: Option<RawFd>,
        control_workload: Option<(RawFd, RawFd)>,
        stdio: Option<(Option<RawFd>, Option<RawFd>, Option<RawFd>)>,
        inherited: &[(RawFd, i32)],
    ) -> Result<i32> {
        if args.len() > MAX_SPAWN_ARGS {
            return Err(supervisor_error(
                ErrorCode::InvalidArgument,
                format!(
                    "session supervisor spawn has {} arguments; maximum is {MAX_SPAWN_ARGS}",
                    args.len()
                ),
            ));
        }
        if inherited.len() > MAX_INHERITED_SPAWN_FDS {
            return Err(supervisor_error(
                ErrorCode::InvalidArgument,
                format!(
                    "session supervisor spawn has {} inherited descriptors; maximum is {MAX_INHERITED_SPAWN_FDS}",
                    inherited.len()
                ),
            ));
        }
        let mut payload = Vec::new();
        let argc = u32::try_from(args.len() + 1).map_err(|_| {
            supervisor_error(
                ErrorCode::InvalidArgument,
                "session supervisor spawn argument count does not fit u32",
            )
        })?;
        payload.extend_from_slice(&argc.to_be_bytes());
        write_os_string(&mut payload, program.as_os_str())?;
        for arg in args {
            write_os_string(&mut payload, arg)?;
        }
        let mut fds = Vec::new();
        let mut flags = 0_u8;
        if let Some(descriptor) = join_cgroup_procs {
            flags |= FLAG_JOIN_CGROUP;
            fds.push(descriptor);
        }
        if let Some((control, workload)) = control_workload {
            flags |= FLAG_CONTROL_WORKLOAD;
            fds.push(control);
            fds.push(workload);
        }
        if let Some((stdin, stdout, stderr)) = stdio {
            if let Some(descriptor) = stdin {
                flags |= FLAG_STDIN;
                fds.push(descriptor);
            }
            if let Some(descriptor) = stdout {
                flags |= FLAG_STDOUT;
                fds.push(descriptor);
            }
            if let Some(descriptor) = stderr {
                flags |= FLAG_STDERR;
                fds.push(descriptor);
            }
        }
        if !inherited.is_empty() {
            flags |= FLAG_INHERITED;
            let count = u8::try_from(inherited.len()).map_err(|_| {
                supervisor_error(
                    ErrorCode::InvalidArgument,
                    "session supervisor inherited descriptor count does not fit u8",
                )
            })?;
            for &(source, target) in inherited {
                if target <= libc::STDERR_FILENO {
                    return Err(supervisor_error(
                        ErrorCode::InvalidArgument,
                        format!(
                            "session supervisor inherited target FD {target} must be greater than stderr"
                        ),
                    ));
                }
                let _ = source;
                fds.push(source);
            }
            payload.push(flags);
            payload.push(count);
            for &(_, target) in inherited {
                payload.extend_from_slice(&target.to_be_bytes());
            }
        } else {
            payload.push(flags);
        }
        self.control.write_all(&[MSG_SPAWN]).map_err(|error| {
            supervisor_error(
                ErrorCode::Internal,
                format!("failed to write session-supervisor spawn header: {error}"),
            )
        })?;
        self.control.write_all(&payload).map_err(|error| {
            supervisor_error(
                ErrorCode::Internal,
                format!("failed to write session-supervisor spawn payload: {error}"),
            )
        })?;
        if !fds.is_empty() {
            send_with_fds(self.control.as_raw_fd(), &[0xFD], &fds)?;
        }
        match read_supervisor_response(&mut self.control)? {
            SupervisorResponse::Spawned(pid) => Ok(pid),
            SupervisorResponse::Error(message) => Err(supervisor_error(
                ErrorCode::Internal,
                format!("session supervisor spawn failed: {message}"),
            )),
            SupervisorResponse::Waited(_)
            | SupervisorResponse::Ack(_)
            | SupervisorResponse::StdinFd(_)
            | SupervisorResponse::OutputChunks(_) => Err(supervisor_error(
                ErrorCode::Internal,
                "session supervisor returned a non-spawn result for a spawn request",
            )),
        }
    }

    /// Block until a supervised child exits and return its raw wait status.
    pub(crate) fn wait_launcher(&mut self, pid: i32) -> Result<i32> {
        let mut payload = Vec::with_capacity(5);
        payload.push(MSG_WAIT);
        payload.extend_from_slice(&pid.to_be_bytes());
        self.control.write_all(&payload).map_err(|error| {
            supervisor_error(
                ErrorCode::Internal,
                format!("failed to write session-supervisor wait request: {error}"),
            )
        })?;
        match read_supervisor_response(&mut self.control)? {
            SupervisorResponse::Waited(status) => Ok(status),
            SupervisorResponse::Error(message) => Err(supervisor_error(
                ErrorCode::Internal,
                format!("session supervisor wait failed: {message}"),
            )),
            SupervisorResponse::Spawned(_)
            | SupervisorResponse::Ack(_)
            | SupervisorResponse::StdinFd(_)
            | SupervisorResponse::OutputChunks(_) => Err(supervisor_error(
                ErrorCode::Internal,
                "session supervisor returned a non-wait result for a wait request",
            )),
        }
    }

    /// Deposit a Host stdin write-end duplicate keyed by supervised launcher PID.
    ///
    /// Multiple writers on a pipe are safe. Host keeps its original write end for
    /// live I/O; the supervisor retains the duplicate so Host death does not
    /// deliver EOF. Intentional [`Self::close_deposited_stdin`] (paired with Host
    /// close) delivers EOF. Capture stdout/stderr use [`Self::deposit_output`]
    /// instead: those read ends must move exclusively (not `F_DUPFD`).
    pub(crate) fn deposit_stdin(&mut self, launcher_pid: i32, stdin: RawFd) -> Result<()> {
        let mut payload = Vec::with_capacity(5);
        payload.push(MSG_DEPOSIT_STDIN);
        payload.extend_from_slice(&launcher_pid.to_be_bytes());
        self.control.write_all(&payload).map_err(|error| {
            supervisor_error(
                ErrorCode::Internal,
                format!("failed to write session-supervisor stdin deposit header: {error}"),
            )
        })?;
        send_with_fds(self.control.as_raw_fd(), &[0xFD], &[stdin])?;
        match read_supervisor_response(&mut self.control)? {
            SupervisorResponse::Ack(MSG_DEPOSITED) => Ok(()),
            SupervisorResponse::Error(message) => Err(supervisor_error(
                ErrorCode::Internal,
                format!("session supervisor stdin deposit failed: {message}"),
            )),
            SupervisorResponse::Spawned(_)
            | SupervisorResponse::Waited(_)
            | SupervisorResponse::Ack(_)
            | SupervisorResponse::StdinFd(_)
            | SupervisorResponse::OutputChunks(_) => Err(supervisor_error(
                ErrorCode::Internal,
                "session supervisor returned a non-deposit result for a stdin deposit",
            )),
        }
    }

    /// Retrieve the deposited stdin write end after control reattach.
    ///
    /// Returns [`ErrorCode::Unavailable`] when no deposit remains (never
    /// deposited, already taken, or intentionally closed). Does not invent an
    /// empty writable stream.
    pub(crate) fn take_stdin(&mut self, launcher_pid: i32) -> Result<OwnedFd> {
        let mut payload = Vec::with_capacity(5);
        payload.push(MSG_TAKE_STDIN);
        payload.extend_from_slice(&launcher_pid.to_be_bytes());
        self.control.write_all(&payload).map_err(|error| {
            supervisor_error(
                ErrorCode::Internal,
                format!("failed to write session-supervisor stdin take request: {error}"),
            )
        })?;
        match read_supervisor_response(&mut self.control)? {
            SupervisorResponse::StdinFd(fd) => Ok(fd),
            SupervisorResponse::Error(message) => Err(supervisor_error(
                ErrorCode::Unavailable,
                format!("session supervisor stdin take unavailable: {message}"),
            )),
            SupervisorResponse::Spawned(_)
            | SupervisorResponse::Waited(_)
            | SupervisorResponse::Ack(_)
            | SupervisorResponse::OutputChunks(_) => Err(supervisor_error(
                ErrorCode::Internal,
                "session supervisor returned a non-take result for a stdin take",
            )),
        }
    }

    /// Drop the deposited stdin duplicate so an intentional Host close can EOF.
    ///
    /// Idempotent when no deposit remains for `launcher_pid`.
    pub(crate) fn close_deposited_stdin(&mut self, launcher_pid: i32) -> Result<()> {
        let mut payload = Vec::with_capacity(5);
        payload.push(MSG_CLOSE_DEPOSITED_STDIN);
        payload.extend_from_slice(&launcher_pid.to_be_bytes());
        self.control.write_all(&payload).map_err(|error| {
            supervisor_error(
                ErrorCode::Internal,
                format!("failed to write session-supervisor stdin close request: {error}"),
            )
        })?;
        match read_supervisor_response(&mut self.control)? {
            SupervisorResponse::Ack(MSG_DEPOSIT_CLOSED) => Ok(()),
            SupervisorResponse::Error(message) => Err(supervisor_error(
                ErrorCode::Internal,
                format!("session supervisor stdin close failed: {message}"),
            )),
            SupervisorResponse::Spawned(_)
            | SupervisorResponse::Waited(_)
            | SupervisorResponse::Ack(_)
            | SupervisorResponse::StdinFd(_)
            | SupervisorResponse::OutputChunks(_) => Err(supervisor_error(
                ErrorCode::Internal,
                "session supervisor returned a non-close result for a stdin close",
            )),
        }
    }

    /// Move exclusive capture stdout/stderr read ends to the supervisor.
    ///
    /// Passes ownership via SCM_RIGHTS, then drops the Host-local `OwnedFd`
    /// copies immediately so the supervisor is the sole reader before drain
    /// threads start. Unlike stdin, this is not `F_DUPFD`: two readers would
    /// race and split the stream. Hosts consume chunks only through
    /// [`Self::read_output`].
    pub(crate) fn deposit_output(
        &mut self,
        launcher_pid: i32,
        stdout: Option<OwnedFd>,
        stderr: Option<OwnedFd>,
    ) -> Result<()> {
        let mut flags = 0_u8;
        let mut fds = Vec::with_capacity(2);
        if let Some(descriptor) = stdout.as_ref() {
            flags |= FLAG_OUTPUT_STDOUT;
            fds.push(descriptor.as_raw_fd());
        }
        if let Some(descriptor) = stderr.as_ref() {
            flags |= FLAG_OUTPUT_STDERR;
            fds.push(descriptor.as_raw_fd());
        }
        if flags == 0 {
            return Err(supervisor_error(
                ErrorCode::InvalidArgument,
                "session supervisor output deposit requires at least one capture read end",
            ));
        }
        let mut payload = Vec::with_capacity(6);
        payload.push(MSG_DEPOSIT_OUTPUT);
        payload.extend_from_slice(&launcher_pid.to_be_bytes());
        payload.push(flags);
        self.control.write_all(&payload).map_err(|error| {
            supervisor_error(
                ErrorCode::Internal,
                format!("failed to write session-supervisor output deposit header: {error}"),
            )
        })?;
        send_with_fds(self.control.as_raw_fd(), &[0xFD], &fds)?;
        // Move, not dup: drop Host copies before the supervisor ack returns so
        // drain threads never share the pipe with a competing Host reader.
        drop(stdout);
        drop(stderr);
        match read_supervisor_response(&mut self.control)? {
            SupervisorResponse::Ack(MSG_OUTPUT_DEPOSITED) => Ok(()),
            SupervisorResponse::Error(message) => Err(supervisor_error(
                ErrorCode::Internal,
                format!("session supervisor output deposit failed: {message}"),
            )),
            SupervisorResponse::Spawned(_)
            | SupervisorResponse::Waited(_)
            | SupervisorResponse::Ack(_)
            | SupervisorResponse::StdinFd(_)
            | SupervisorResponse::OutputChunks(_) => Err(supervisor_error(
                ErrorCode::Internal,
                "session supervisor returned a non-deposit result for an output deposit",
            )),
        }
    }

    /// Poll authentic captured chunks drained exclusively by the supervisor.
    ///
    /// Returns [`ErrorCode::Unavailable`] when no output deposit exists for
    /// `launcher_pid` (never invent an empty successful stream). Stale cursors
    /// after eviction fail closed with [`ErrorCode::ResourceExhausted`].
    pub(crate) fn read_output(
        &mut self,
        launcher_pid: i32,
        after_sequence: u64,
        max_bytes: u32,
        wait_timeout_ms: Option<u64>,
    ) -> Result<Vec<OutputChunk>> {
        let wait_ms = wait_timeout_ms.unwrap_or(0);
        let wait_ms = u32::try_from(wait_ms).unwrap_or(u32::MAX);
        let mut payload = Vec::with_capacity(21);
        payload.push(MSG_READ_OUTPUT);
        payload.extend_from_slice(&launcher_pid.to_be_bytes());
        payload.extend_from_slice(&after_sequence.to_be_bytes());
        payload.extend_from_slice(&max_bytes.to_be_bytes());
        payload.extend_from_slice(&wait_ms.to_be_bytes());
        self.control.write_all(&payload).map_err(|error| {
            supervisor_error(
                ErrorCode::Internal,
                format!("failed to write session-supervisor read-output request: {error}"),
            )
        })?;
        match read_supervisor_response(&mut self.control)? {
            SupervisorResponse::OutputChunks(chunks) => Ok(chunks),
            SupervisorResponse::Error(message) => {
                let code = if message.contains("fell behind retained cursor") {
                    ErrorCode::ResourceExhausted
                } else if message.contains("ahead of latest cursor") {
                    ErrorCode::InvalidArgument
                } else {
                    ErrorCode::Unavailable
                };
                Err(supervisor_error(
                    code,
                    format!("session supervisor read-output unavailable: {message}"),
                ))
            }
            SupervisorResponse::Spawned(_)
            | SupervisorResponse::Waited(_)
            | SupervisorResponse::Ack(_)
            | SupervisorResponse::StdinFd(_) => Err(supervisor_error(
                ErrorCode::Internal,
                "session supervisor returned a non-read-output result for a read-output request",
            )),
        }
    }

    /// Reattach a replacement Host to a live supervisor after the original
    /// control channel closed.
    ///
    /// Re-executing a new supervisor is wrong: PDEATHSIG parentage and exact
    /// wait status belong to the recorded supervisor incarnation. This opens a
    /// fresh control socket on the published abstract endpoint and proves the
    /// PID + start-time identity still matches. It does not restore
    /// `PreparedProcess` by itself; call [`Self::take_stdin`] for deposited
    /// stdin and [`Self::read_output`] for exclusive capture relay after reattach.
    pub(crate) fn reattach(expected: &SessionSupervisorIdentity) -> Result<Self> {
        expected.authenticate_live()?;
        let address = SocketAddr::from_abstract_name(expected.reattach_endpoint_name().as_bytes())
            .map_err(|error| {
                supervisor_error(
                    ErrorCode::Internal,
                    format!("failed to construct session-supervisor reattach address: {error}"),
                )
            })?;
        let deadline = Instant::now() + REATTACH_CONNECT_TIMEOUT;
        let mut control = loop {
            match UnixStream::connect_addr(&address) {
                Ok(stream) => break stream,
                Err(error)
                    if Instant::now() < deadline
                        && matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionRefused
                                | io::ErrorKind::NotFound
                                | io::ErrorKind::WouldBlock
                        ) =>
                {
                    std::thread::sleep(REATTACH_POLL_INTERVAL);
                }
                Err(error) => {
                    return Err(supervisor_error(
                        ErrorCode::Unavailable,
                        format!(
                            "failed to connect session-supervisor reattach endpoint for PID {}: {error}",
                            expected.pid()
                        ),
                    )
                    .retryable(true));
                }
            }
        };
        control
            .set_read_timeout(Some(REATTACH_CONNECT_TIMEOUT))
            .and_then(|()| control.set_write_timeout(Some(REATTACH_CONNECT_TIMEOUT)))
            .map_err(|error| {
                supervisor_error(
                    ErrorCode::Internal,
                    format!("failed to bound session-supervisor reattach channel: {error}"),
                )
            })?;
        let identity = read_ready_identity(&mut control)?;
        if identity.pid() != expected.pid()
            || identity.start_time_ticks() != expected.start_time_ticks()
        {
            return Err(supervisor_error(
                ErrorCode::PermissionDenied,
                format!(
                    "session supervisor reattach identity drifted: expected PID {} start {}, observed PID {} start {}",
                    expected.pid(),
                    expected.start_time_ticks(),
                    identity.pid(),
                    identity.start_time_ticks()
                ),
            ));
        }
        identity.authenticate_live()?;
        let pidfd = PidFd::open(identity.pid())?;
        Ok(Self {
            identity,
            control,
            pidfd,
        })
    }
}

impl Drop for HostSessionSupervisor {
    fn drop(&mut self) {
        let _ = self.control.write_all(&[MSG_SHUTDOWN]);
        let _ = self.pidfd.send_signal(libc::SIGKILL);
        terminate_pid(self.identity.pid());
        let _ = wait_for_child(self.identity.pid());
    }
}

fn finish_start(mut control: UnixStream, pid: i32) -> Result<HostSessionSupervisor> {
    let pidfd = PidFd::open(pid).map_err(|error| {
        terminate_pid(pid);
        let _ = wait_for_child(pid);
        error
    })?;
    let identity = match read_ready_identity(&mut control) {
        Ok(identity) => identity,
        Err(error) => {
            terminate_pid(pid);
            let _ = wait_for_child(pid);
            return Err(error);
        }
    };
    if identity.pid() != pid {
        terminate_pid(pid);
        let _ = wait_for_child(pid);
        return Err(supervisor_error(
            ErrorCode::PermissionDenied,
            format!(
                "session supervisor identity PID {} does not match spawned PID {pid}",
                identity.pid()
            ),
        ));
    }
    identity.authenticate_live()?;
    Ok(HostSessionSupervisor {
        identity,
        control,
        pidfd,
    })
}

/// Enter the durable session-supervise service when requested by argv.
pub(crate) fn run_session_supervise_if_requested() -> Option<Result<()>> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(OsStr::new("session-supervise")) {
        return None;
    }
    if arguments.next().is_some() {
        return Some(Err(supervisor_error(
            ErrorCode::InvalidArgument,
            "session-supervise accepts no additional arguments",
        )));
    }
    Some(run_session_supervise_service())
}

fn run_session_supervise_service() -> Result<()> {
    // SAFETY: the fixed supervise FD is installed by the Host pre_exec before exec.
    let mut control = unsafe { UnixStream::from_raw_fd(SUPERVISE_CONTROL_FD) };
    // SAFETY: PR_SET_CHILD_SUBREAPER takes only integer arguments.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(last_os_error("enable session supervisor child subreaper"));
    }
    let identity = SessionSupervisorIdentity::current()?;
    write_ready_identity(&mut control, &identity)?;
    let mut deposited_stdin: BTreeMap<i32, OwnedFd> = BTreeMap::new();
    let mut deposited_output: BTreeMap<i32, Arc<SyncOutputBuffer>> = BTreeMap::new();

    loop {
        let mut header = [0_u8; 1];
        match control.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                // Host Service died or closed its channel. Remain as the durable
                // session authority. Do not reap waitable children here: exact
                // exit status must stay available for MSG_WAIT after an
                // authenticated replacement Host reattaches the control channel.
                // Re-exec / a new supervisor would break PDEATHSIG parentage.
                // Deposited stdin write ends and exclusive capture drains stay
                // open across the control gap so Host death alone neither EOFs
                // stdin nor loses buffered stdout/stderr.
                control = accept_control_reattach(&identity)?;
                continue;
            }
            Err(error) => {
                return Err(supervisor_error(
                    ErrorCode::Internal,
                    format!("failed to read session-supervisor request: {error}"),
                ));
            }
        }
        match header[0] {
            MSG_SHUTDOWN => {
                deposited_stdin.clear();
                deposited_output.clear();
                reap_children();
                return Ok(());
            }
            MSG_SPAWN => match handle_spawn_request(&mut control, identity.pid()) {
                Ok(pid) => {
                    let mut response = Vec::with_capacity(5);
                    response.push(MSG_SPAWNED);
                    response.extend_from_slice(&pid.to_be_bytes());
                    control.write_all(&response).map_err(|error| {
                        terminate_pid(pid);
                        supervisor_error(
                            ErrorCode::Internal,
                            format!("failed to publish session-supervisor spawn result: {error}"),
                        )
                    })?;
                }
                Err(error) => {
                    write_error_response(&mut control, &error.message)?;
                }
            },
            MSG_WAIT => match handle_wait_request(&mut control) {
                Ok((pid, status)) => {
                    deposited_stdin.remove(&pid);
                    // Keep output buffers after wait so Hosts can drain residual
                    // authentic chunks / EOF after the launcher exits.
                    let mut response = Vec::with_capacity(5);
                    response.push(MSG_WAITED);
                    response.extend_from_slice(&status.to_be_bytes());
                    control.write_all(&response).map_err(|error| {
                        supervisor_error(
                            ErrorCode::Internal,
                            format!("failed to publish session-supervisor wait result: {error}"),
                        )
                    })?;
                }
                Err(error) => {
                    write_error_response(&mut control, &error.message)?;
                }
            },
            MSG_DEPOSIT_STDIN => {
                match handle_deposit_stdin(&mut control, &mut deposited_stdin) {
                    Ok(()) => {
                        control.write_all(&[MSG_DEPOSITED]).map_err(|error| {
                        supervisor_error(
                            ErrorCode::Internal,
                            format!("failed to publish session-supervisor stdin deposit ack: {error}"),
                        )
                    })?;
                    }
                    Err(error) => {
                        write_error_response(&mut control, &error.message)?;
                    }
                }
            }
            MSG_TAKE_STDIN => {
                match handle_take_stdin(&mut control, &mut deposited_stdin) {
                    Ok(fd) => {
                        control.write_all(&[MSG_STDIN_TAKEN]).map_err(|error| {
                        supervisor_error(
                            ErrorCode::Internal,
                            format!("failed to publish session-supervisor stdin take header: {error}"),
                        )
                    })?;
                        send_with_fds(control.as_raw_fd(), &[0xFD], &[fd.as_raw_fd()])?;
                        // SCM_RIGHTS duplicated into the replacement Host; drop the
                        // supervisor copy so intentional Host close can deliver EOF.
                        drop(fd);
                    }
                    Err(error) => {
                        write_error_response(&mut control, &error.message)?;
                    }
                }
            }
            MSG_CLOSE_DEPOSITED_STDIN => {
                match handle_close_deposited_stdin(&mut control, &mut deposited_stdin) {
                    Ok(()) => {
                        control.write_all(&[MSG_DEPOSIT_CLOSED]).map_err(|error| {
                            supervisor_error(
                                ErrorCode::Internal,
                                format!(
                                    "failed to publish session-supervisor stdin close ack: {error}"
                                ),
                            )
                        })?;
                    }
                    Err(error) => {
                        write_error_response(&mut control, &error.message)?;
                    }
                }
            }
            MSG_DEPOSIT_OUTPUT => {
                match handle_deposit_output(&mut control, &mut deposited_output) {
                    Ok(()) => {
                        control.write_all(&[MSG_OUTPUT_DEPOSITED]).map_err(|error| {
                            supervisor_error(
                                ErrorCode::Internal,
                                format!(
                                    "failed to publish session-supervisor output deposit ack: {error}"
                                ),
                            )
                        })?;
                    }
                    Err(error) => {
                        write_error_response(&mut control, &error.message)?;
                    }
                }
            }
            MSG_READ_OUTPUT => match handle_read_output(&mut control, &deposited_output) {
                Ok(chunks) => {
                    write_output_chunks_response(&mut control, &chunks)?;
                }
                Err(error) => {
                    write_error_response(&mut control, &error.message)?;
                }
            },
            other => {
                return Err(supervisor_error(
                    ErrorCode::InvalidArgument,
                    format!("session supervisor received unknown request {other}"),
                ));
            }
        }
    }
}

fn write_ready_identity(
    control: &mut UnixStream,
    identity: &SessionSupervisorIdentity,
) -> Result<()> {
    let mut ready = Vec::with_capacity(13);
    ready.push(MSG_READY);
    ready.extend_from_slice(&identity.pid().to_be_bytes());
    ready.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
    control.write_all(&ready).map_err(|error| {
        supervisor_error(
            ErrorCode::Internal,
            format!("failed to publish session-supervisor readiness: {error}"),
        )
    })
}

fn accept_control_reattach(identity: &SessionSupervisorIdentity) -> Result<UnixStream> {
    identity.authenticate_live()?;
    let address = SocketAddr::from_abstract_name(identity.reattach_endpoint_name().as_bytes())
        .map_err(|error| {
            supervisor_error(
                ErrorCode::Internal,
                format!("failed to construct session-supervisor reattach listen address: {error}"),
            )
        })?;
    let listener = UnixListener::bind_addr(&address).map_err(|error| {
        supervisor_error(
            ErrorCode::Internal,
            format!("failed to bind session-supervisor reattach endpoint: {error}"),
        )
    })?;
    listener.set_nonblocking(true).map_err(|error| {
        supervisor_error(
            ErrorCode::Internal,
            format!("failed to make session-supervisor reattach endpoint nonblocking: {error}"),
        )
    })?;
    let deadline = Instant::now() + REATTACH_ACCEPT_TIMEOUT;
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(REATTACH_POLL_INTERVAL);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(supervisor_error(
                    ErrorCode::Unavailable,
                    format!(
                        "session supervisor PID {} timed out waiting for Host control reattach",
                        identity.pid()
                    ),
                )
                .retryable(true));
            }
            Err(error) => {
                return Err(supervisor_error(
                    ErrorCode::Internal,
                    format!("failed to accept session-supervisor reattach: {error}"),
                ));
            }
        }
    };
    drop(listener);
    stream
        .set_read_timeout(None)
        .and_then(|()| stream.set_write_timeout(None))
        .map_err(|error| {
            supervisor_error(
                ErrorCode::Internal,
                format!("failed to clear session-supervisor reattach timeouts: {error}"),
            )
        })?;
    write_ready_identity(&mut stream, identity)?;
    Ok(stream)
}

fn handle_spawn_request(control: &mut UnixStream, supervisor_pid: i32) -> Result<i32> {
    let arg_count = read_u32(control)? as usize;
    if arg_count == 0 || arg_count > MAX_SPAWN_ARGS + 1 {
        return Err(supervisor_error(
            ErrorCode::InvalidArgument,
            format!("session supervisor spawn argument count {arg_count} is invalid"),
        ));
    }
    let mut argv = Vec::with_capacity(arg_count);
    for _ in 0..arg_count {
        argv.push(read_os_string(control)?);
    }
    let flags = read_u8(control)?;
    let unknown = flags
        & !(FLAG_JOIN_CGROUP
            | FLAG_CONTROL_WORKLOAD
            | FLAG_STDIN
            | FLAG_STDOUT
            | FLAG_STDERR
            | FLAG_INHERITED);
    if unknown != 0 {
        return Err(supervisor_error(
            ErrorCode::InvalidArgument,
            format!("session supervisor spawn flags contain unsupported bits {unknown:#x}"),
        ));
    }
    let inherited_targets = if flags & FLAG_INHERITED != 0 {
        let count = usize::from(read_u8(control)?);
        if count == 0 || count > MAX_INHERITED_SPAWN_FDS {
            return Err(supervisor_error(
                ErrorCode::InvalidArgument,
                format!("session supervisor inherited descriptor count {count} is invalid"),
            ));
        }
        let mut targets = Vec::with_capacity(count);
        for _ in 0..count {
            let mut bytes = [0_u8; 4];
            control.read_exact(&mut bytes).map_err(|error| {
                supervisor_error(
                    ErrorCode::Unavailable,
                    format!("failed to read session-supervisor inherited target FD: {error}"),
                )
            })?;
            let target = i32::from_be_bytes(bytes);
            if target <= libc::STDERR_FILENO {
                return Err(supervisor_error(
                    ErrorCode::InvalidArgument,
                    format!(
                        "session supervisor inherited target FD {target} must be greater than stderr"
                    ),
                ));
            }
            targets.push(target);
        }
        targets
    } else {
        Vec::new()
    };
    let expected_fds = usize::from((flags & FLAG_JOIN_CGROUP) != 0)
        + (2 * usize::from((flags & FLAG_CONTROL_WORKLOAD) != 0))
        + usize::from((flags & FLAG_STDIN) != 0)
        + usize::from((flags & FLAG_STDOUT) != 0)
        + usize::from((flags & FLAG_STDERR) != 0)
        + inherited_targets.len();
    let fds = if expected_fds == 0 {
        Vec::new()
    } else {
        receive_fds(control.as_raw_fd(), expected_fds)?
    };
    let mut fd_iter = fds.into_iter();
    let join_cgroup = if flags & FLAG_JOIN_CGROUP != 0 {
        Some(fd_iter.next().ok_or_else(|| {
            supervisor_error(
                ErrorCode::Internal,
                "session supervisor spawn missing cgroup.procs descriptor",
            )
        })?)
    } else {
        None
    };
    let control_workload = if flags & FLAG_CONTROL_WORKLOAD != 0 {
        let control_fd = fd_iter.next().ok_or_else(|| {
            supervisor_error(
                ErrorCode::Internal,
                "session supervisor spawn missing control cgroup descriptor",
            )
        })?;
        let workload_fd = fd_iter.next().ok_or_else(|| {
            supervisor_error(
                ErrorCode::Internal,
                "session supervisor spawn missing workload cgroup descriptor",
            )
        })?;
        Some((control_fd, workload_fd))
    } else {
        None
    };
    let stdin = if flags & FLAG_STDIN != 0 {
        Some(fd_iter.next().ok_or_else(|| {
            supervisor_error(
                ErrorCode::Internal,
                "session supervisor spawn missing stdin descriptor",
            )
        })?)
    } else {
        None
    };
    let stdout = if flags & FLAG_STDOUT != 0 {
        Some(fd_iter.next().ok_or_else(|| {
            supervisor_error(
                ErrorCode::Internal,
                "session supervisor spawn missing stdout descriptor",
            )
        })?)
    } else {
        None
    };
    let stderr = if flags & FLAG_STDERR != 0 {
        Some(fd_iter.next().ok_or_else(|| {
            supervisor_error(
                ErrorCode::Internal,
                "session supervisor spawn missing stderr descriptor",
            )
        })?)
    } else {
        None
    };
    let mut inherited = Vec::with_capacity(inherited_targets.len());
    for target in inherited_targets {
        let source = fd_iter.next().ok_or_else(|| {
            supervisor_error(
                ErrorCode::Internal,
                "session supervisor spawn missing inherited descriptor",
            )
        })?;
        inherited.push((source, target));
    }

    let program = argv.first().ok_or_else(|| {
        supervisor_error(
            ErrorCode::InvalidArgument,
            "session supervisor spawn requires a program path",
        )
    })?;
    let mut command = Command::new(program);
    command
        .args(&argv[1..])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let join_raw = join_cgroup.as_ref().map(AsRawFd::as_raw_fd);
    let control_raw = control_workload
        .as_ref()
        .map(|(control_fd, workload_fd)| (control_fd.as_raw_fd(), workload_fd.as_raw_fd()));
    let stdin_raw = stdin.as_ref().map(AsRawFd::as_raw_fd);
    let stdout_raw = stdout.as_ref().map(AsRawFd::as_raw_fd);
    let stderr_raw = stderr.as_ref().map(AsRawFd::as_raw_fd);
    let inherited_raw: Vec<(RawFd, i32)> = inherited
        .iter()
        .map(|(source, target)| (source.as_raw_fd(), *target))
        .collect();
    // SAFETY: pre_exec only installs already-open descriptors and arms PDEATHSIG.
    unsafe {
        command.pre_exec(move || {
            verify_and_arm_parent_death_signal(supervisor_pid, "supervised container launcher")
                .map_err(|error| io::Error::other(error.to_string()))?;
            if let Some(descriptor) = join_raw {
                super::cgroup::join_current_process(descriptor)?;
            }
            if let Some((control_fd, workload_fd)) = control_raw {
                super::cgroup::install_control_workload_descriptors_from_pre_exec(
                    control_fd,
                    workload_fd,
                )?;
            }
            install_stdio_from_pre_exec(stdin_raw, stdout_raw, stderr_raw)?;
            install_inherited_from_pre_exec(&inherited_raw)?;
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|error| {
        supervisor_error(
            ErrorCode::Internal,
            format!("session supervisor failed to spawn launcher: {error}"),
        )
    })?;
    drop(join_cgroup);
    drop(control_workload);
    drop(stdin);
    drop(stdout);
    drop(stderr);
    drop(inherited);
    let pid = match i32::try_from(child.id()) {
        Ok(pid) => pid,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(supervisor_error(
                ErrorCode::ResourceExhausted,
                format!("supervised launcher PID does not fit the process model: {error}"),
            ));
        }
    };
    // Retain Child so MSG_WAIT can reap the exact launcher without racing an
    // opportunistic reap loop while the Host still owns the generation.
    std::mem::forget(child);
    Ok(pid)
}

fn install_stdio_from_pre_exec(
    stdin: Option<RawFd>,
    stdout: Option<RawFd>,
    stderr: Option<RawFd>,
) -> io::Result<()> {
    if let Some(descriptor) = stdin {
        if unsafe { libc::dup2(descriptor, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        clear_cloexec_raw(0)?;
    }
    if let Some(descriptor) = stdout {
        if unsafe { libc::dup2(descriptor, 1) } < 0 {
            return Err(io::Error::last_os_error());
        }
        clear_cloexec_raw(1)?;
    }
    if let Some(descriptor) = stderr {
        if unsafe { libc::dup2(descriptor, 2) } < 0 {
            return Err(io::Error::last_os_error());
        }
        clear_cloexec_raw(2)?;
    }
    Ok(())
}

fn install_inherited_from_pre_exec(inherited: &[(RawFd, i32)]) -> io::Result<()> {
    for &(source, target) in inherited {
        if unsafe { libc::dup2(source, target) } < 0 {
            return Err(io::Error::last_os_error());
        }
        clear_cloexec_raw(target)?;
    }
    Ok(())
}

fn clear_cloexec_raw(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl F_GETFD/F_SETFD operate on an open descriptor owned by us.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let flags = flags & !libc::FD_CLOEXEC;
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn handle_wait_request(control: &mut UnixStream) -> Result<(i32, i32)> {
    let mut pid_bytes = [0_u8; 4];
    control.read_exact(&mut pid_bytes).map_err(|error| {
        supervisor_error(
            ErrorCode::Unavailable,
            format!("failed to read session-supervisor wait pid: {error}"),
        )
    })?;
    let pid = i32::from_be_bytes(pid_bytes);
    if pid <= 0 {
        return Err(supervisor_error(
            ErrorCode::InvalidArgument,
            format!("session supervisor wait requires a positive PID; received {pid}"),
        ));
    }
    let outcome = wait_for_child(pid)?;
    let status = match outcome {
        ChildOutcome::Exited(code) => code << 8,
        ChildOutcome::Signaled(signal) => signal,
    };
    Ok((pid, status))
}

fn read_launcher_pid(control: &mut UnixStream, operation: &str) -> Result<i32> {
    let mut pid_bytes = [0_u8; 4];
    control.read_exact(&mut pid_bytes).map_err(|error| {
        supervisor_error(
            ErrorCode::Unavailable,
            format!("failed to read session-supervisor {operation} pid: {error}"),
        )
    })?;
    let pid = i32::from_be_bytes(pid_bytes);
    if pid <= 0 {
        return Err(supervisor_error(
            ErrorCode::InvalidArgument,
            format!("session supervisor {operation} requires a positive PID; received {pid}"),
        ));
    }
    Ok(pid)
}

fn handle_deposit_stdin(
    control: &mut UnixStream,
    deposited_stdin: &mut BTreeMap<i32, OwnedFd>,
) -> Result<()> {
    let pid = read_launcher_pid(control, "stdin deposit")?;
    let mut fds = receive_fds(control.as_raw_fd(), 1)?;
    let stdin = fds.pop().ok_or_else(|| {
        supervisor_error(
            ErrorCode::Internal,
            "session supervisor stdin deposit received no descriptor",
        )
    })?;
    if deposited_stdin.contains_key(&pid) {
        return Err(supervisor_error(
            ErrorCode::Conflict,
            format!("session supervisor already holds a stdin deposit for launcher PID {pid}"),
        ));
    }
    deposited_stdin.insert(pid, stdin);
    Ok(())
}

fn handle_take_stdin(
    control: &mut UnixStream,
    deposited_stdin: &mut BTreeMap<i32, OwnedFd>,
) -> Result<OwnedFd> {
    let pid = read_launcher_pid(control, "stdin take")?;
    deposited_stdin.remove(&pid).ok_or_else(|| {
        supervisor_error(
            ErrorCode::Unavailable,
            format!("session supervisor has no deposited stdin for launcher PID {pid}"),
        )
    })
}

fn handle_close_deposited_stdin(
    control: &mut UnixStream,
    deposited_stdin: &mut BTreeMap<i32, OwnedFd>,
) -> Result<()> {
    let pid = read_launcher_pid(control, "stdin close")?;
    // Idempotent: intentional Host close_stdin may race with take/wait cleanup.
    let _ = deposited_stdin.remove(&pid);
    Ok(())
}

fn handle_deposit_output(
    control: &mut UnixStream,
    deposited_output: &mut BTreeMap<i32, Arc<SyncOutputBuffer>>,
) -> Result<()> {
    let pid = read_launcher_pid(control, "output deposit")?;
    let flags = read_u8(control)?;
    if flags & !(FLAG_OUTPUT_STDOUT | FLAG_OUTPUT_STDERR) != 0 {
        return Err(supervisor_error(
            ErrorCode::InvalidArgument,
            format!("session supervisor output deposit flags {flags:#x} are invalid"),
        ));
    }
    let expected =
        usize::from(flags & FLAG_OUTPUT_STDOUT != 0) + usize::from(flags & FLAG_OUTPUT_STDERR != 0);
    if expected == 0 {
        return Err(supervisor_error(
            ErrorCode::InvalidArgument,
            "session supervisor output deposit requires stdout and/or stderr flags",
        ));
    }
    let mut fds = receive_fds(control.as_raw_fd(), expected)?;
    if fds.len() != expected {
        return Err(supervisor_error(
            ErrorCode::Internal,
            format!(
                "session supervisor output deposit expected {expected} descriptors; received {}",
                fds.len()
            ),
        ));
    }
    if deposited_output.contains_key(&pid) {
        return Err(supervisor_error(
            ErrorCode::FailedPrecondition,
            format!(
                "session supervisor already holds exclusive capture drains for launcher PID {pid}"
            ),
        ));
    }
    let buffer = SyncOutputBuffer::new(expected as u8);
    if flags & FLAG_OUTPUT_STDOUT != 0 {
        let stdout = fds.remove(0);
        spawn_exclusive_output_reader(stdout, OutputStream::Stdout, Arc::clone(&buffer))?;
    }
    if flags & FLAG_OUTPUT_STDERR != 0 {
        let stderr = fds.remove(0);
        spawn_exclusive_output_reader(stderr, OutputStream::Stderr, Arc::clone(&buffer))?;
    }
    deposited_output.insert(pid, buffer);
    Ok(())
}

fn handle_read_output(
    control: &mut UnixStream,
    deposited_output: &BTreeMap<i32, Arc<SyncOutputBuffer>>,
) -> Result<Vec<OutputChunk>> {
    let pid = read_launcher_pid(control, "read-output")?;
    let after_sequence = read_u64(control)?;
    let max_bytes = read_u32(control)?;
    let wait_ms = read_u32(control)?;
    let buffer = deposited_output.get(&pid).ok_or_else(|| {
        supervisor_error(
            ErrorCode::Unavailable,
            format!("session supervisor has no deposited capture output for launcher PID {pid}"),
        )
    })?;
    let wait_timeout_ms = (wait_ms > 0).then_some(u64::from(wait_ms));
    buffer.read(after_sequence, max_bytes, wait_timeout_ms)
}

fn spawn_exclusive_output_reader(
    fd: OwnedFd,
    stream: OutputStream,
    buffer: Arc<SyncOutputBuffer>,
) -> Result<()> {
    std::thread::Builder::new()
        .name(format!("a3s-oci-output-{stream:?}"))
        .spawn(move || {
            let mut reader = std::fs::File::from(fd);
            let mut bytes = vec![0_u8; OUTPUT_READER_CHUNK_BYTES];
            loop {
                match reader.read(&mut bytes) {
                    Ok(0) => {
                        buffer.finish(stream, None);
                        return;
                    }
                    Ok(length) => buffer.append(stream, bytes[..length].to_vec()),
                    Err(error) => {
                        buffer.finish(stream, Some(error));
                        return;
                    }
                }
            }
        })
        .map_err(|error| {
            supervisor_error(
                ErrorCode::ResourceExhausted,
                format!("failed to spawn session-supervisor {stream:?} drain thread: {error}"),
            )
        })?;
    Ok(())
}

fn write_output_chunks_response(control: &mut UnixStream, chunks: &[OutputChunk]) -> Result<()> {
    let count = u32::try_from(chunks.len()).map_err(|_| {
        supervisor_error(
            ErrorCode::ResourceExhausted,
            "session supervisor output chunk count does not fit the wire format",
        )
    })?;
    let mut payload = Vec::new();
    payload.push(MSG_OUTPUT_CHUNKS);
    payload.extend_from_slice(&count.to_be_bytes());
    for chunk in chunks {
        payload.extend_from_slice(&chunk.sequence.to_be_bytes());
        payload.push(match chunk.stream {
            OutputStream::Stdout => 0,
            OutputStream::Stderr => 1,
        });
        payload.push(u8::from(chunk.eof));
        let len = u32::try_from(chunk.data.len()).map_err(|_| {
            supervisor_error(
                ErrorCode::ResourceExhausted,
                "session supervisor output chunk exceeds u32 length",
            )
        })?;
        payload.extend_from_slice(&len.to_be_bytes());
        payload.extend_from_slice(&chunk.data);
    }
    control.write_all(&payload).map_err(|error| {
        supervisor_error(
            ErrorCode::Internal,
            format!("failed to publish session-supervisor output chunks: {error}"),
        )
    })
}

fn read_output_chunks_response(control: &mut UnixStream) -> Result<Vec<OutputChunk>> {
    let count = read_u32(control)? as usize;
    if count > 10_000 {
        return Err(supervisor_error(
            ErrorCode::ResourceExhausted,
            format!("session supervisor output chunk count {count} exceeds bound"),
        ));
    }
    let mut chunks = Vec::with_capacity(count);
    for _ in 0..count {
        let sequence = read_u64(control)?;
        let stream = match read_u8(control)? {
            0 => OutputStream::Stdout,
            1 => OutputStream::Stderr,
            other => {
                return Err(supervisor_error(
                    ErrorCode::Internal,
                    format!("session supervisor output stream tag {other} is invalid"),
                ));
            }
        };
        let eof = match read_u8(control)? {
            0 => false,
            1 => true,
            other => {
                return Err(supervisor_error(
                    ErrorCode::Internal,
                    format!("session supervisor output eof tag {other} is invalid"),
                ));
            }
        };
        let len = read_u32(control)? as usize;
        if len > MAX_ARG_BYTES * 64 {
            return Err(supervisor_error(
                ErrorCode::ResourceExhausted,
                format!("session supervisor output chunk length {len} exceeds bound"),
            ));
        }
        let mut data = vec![0_u8; len];
        control.read_exact(&mut data).map_err(|error| {
            supervisor_error(
                ErrorCode::Unavailable,
                format!("failed to read session-supervisor output chunk: {error}"),
            )
        })?;
        chunks.push(OutputChunk {
            sequence,
            stream,
            data,
            eof,
        });
    }
    Ok(chunks)
}

enum SupervisorResponse {
    Spawned(i32),
    Waited(i32),
    Ack(u8),
    StdinFd(OwnedFd),
    OutputChunks(Vec<OutputChunk>),
    Error(String),
}

fn read_ready_identity(control: &mut UnixStream) -> Result<SessionSupervisorIdentity> {
    let mut header = [0_u8; 1];
    control.read_exact(&mut header).map_err(|error| {
        supervisor_error(
            ErrorCode::Unavailable,
            format!("failed to read session-supervisor ready header: {error}"),
        )
    })?;
    if header[0] != MSG_READY {
        return Err(supervisor_error(
            ErrorCode::Internal,
            format!("session supervisor ready header mismatch: {}", header[0]),
        ));
    }
    let mut pid_bytes = [0_u8; 4];
    let mut start_bytes = [0_u8; 8];
    control.read_exact(&mut pid_bytes).map_err(|error| {
        supervisor_error(
            ErrorCode::Unavailable,
            format!("failed to read session-supervisor ready pid: {error}"),
        )
    })?;
    control.read_exact(&mut start_bytes).map_err(|error| {
        supervisor_error(
            ErrorCode::Unavailable,
            format!("failed to read session-supervisor ready start-time: {error}"),
        )
    })?;
    Ok(SessionSupervisorIdentity {
        schema_version: IDENTITY_SCHEMA_VERSION.to_string(),
        pid: i32::from_be_bytes(pid_bytes),
        start_time_ticks: u64::from_be_bytes(start_bytes),
    })
}

fn read_supervisor_response(control: &mut UnixStream) -> Result<SupervisorResponse> {
    let mut header = [0_u8; 1];
    control.read_exact(&mut header).map_err(|error| {
        supervisor_error(
            ErrorCode::Unavailable,
            format!("failed to read session-supervisor response: {error}"),
        )
    })?;
    match header[0] {
        MSG_SPAWNED => {
            let mut pid_bytes = [0_u8; 4];
            control.read_exact(&mut pid_bytes).map_err(|error| {
                supervisor_error(
                    ErrorCode::Unavailable,
                    format!("failed to read session-supervisor spawned pid: {error}"),
                )
            })?;
            Ok(SupervisorResponse::Spawned(i32::from_be_bytes(pid_bytes)))
        }
        MSG_WAITED => {
            let mut status_bytes = [0_u8; 4];
            control.read_exact(&mut status_bytes).map_err(|error| {
                supervisor_error(
                    ErrorCode::Unavailable,
                    format!("failed to read session-supervisor wait status: {error}"),
                )
            })?;
            Ok(SupervisorResponse::Waited(i32::from_be_bytes(status_bytes)))
        }
        MSG_DEPOSITED | MSG_DEPOSIT_CLOSED | MSG_OUTPUT_DEPOSITED => {
            Ok(SupervisorResponse::Ack(header[0]))
        }
        MSG_STDIN_TAKEN => {
            let mut fds = receive_fds(control.as_raw_fd(), 1)?;
            let fd = fds.pop().ok_or_else(|| {
                supervisor_error(
                    ErrorCode::Internal,
                    "session supervisor stdin take response contained no descriptor",
                )
            })?;
            Ok(SupervisorResponse::StdinFd(fd))
        }
        MSG_OUTPUT_CHUNKS => Ok(SupervisorResponse::OutputChunks(
            read_output_chunks_response(control)?,
        )),
        MSG_ERROR => {
            let len = read_u32(control)? as usize;
            if len > MAX_ARG_BYTES {
                return Err(supervisor_error(
                    ErrorCode::ResourceExhausted,
                    format!("session supervisor error message exceeds {MAX_ARG_BYTES} bytes"),
                ));
            }
            let mut bytes = vec![0_u8; len];
            control.read_exact(&mut bytes).map_err(|error| {
                supervisor_error(
                    ErrorCode::Unavailable,
                    format!("failed to read session-supervisor error message: {error}"),
                )
            })?;
            Ok(SupervisorResponse::Error(
                String::from_utf8_lossy(&bytes).into_owned(),
            ))
        }
        other => Err(supervisor_error(
            ErrorCode::Internal,
            format!("session supervisor returned unknown response {other}"),
        )),
    }
}

fn write_error_response(control: &mut UnixStream, message: &str) -> Result<()> {
    let bytes = message.as_bytes();
    if bytes.len() > MAX_ARG_BYTES {
        return Err(supervisor_error(
            ErrorCode::ResourceExhausted,
            format!("session supervisor error message exceeds {MAX_ARG_BYTES} bytes"),
        ));
    }
    let mut payload = Vec::with_capacity(5 + bytes.len());
    payload.push(MSG_ERROR);
    payload.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(bytes);
    control.write_all(&payload).map_err(|error| {
        supervisor_error(
            ErrorCode::Internal,
            format!("failed to publish session-supervisor error: {error}"),
        )
    })
}

fn write_os_string(payload: &mut Vec<u8>, value: &OsStr) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() > MAX_ARG_BYTES {
        return Err(supervisor_error(
            ErrorCode::InvalidArgument,
            format!("session supervisor argument exceeds {MAX_ARG_BYTES} bytes"),
        ));
    }
    payload.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(bytes);
    Ok(())
}

fn read_os_string(control: &mut UnixStream) -> Result<std::ffi::OsString> {
    let len = read_u32(control)? as usize;
    if len > MAX_ARG_BYTES {
        return Err(supervisor_error(
            ErrorCode::ResourceExhausted,
            format!("session supervisor argument exceeds {MAX_ARG_BYTES} bytes"),
        ));
    }
    let mut bytes = vec![0_u8; len];
    control.read_exact(&mut bytes).map_err(|error| {
        supervisor_error(
            ErrorCode::Unavailable,
            format!("failed to read session-supervisor argument: {error}"),
        )
    })?;
    Ok(OsStr::from_bytes(&bytes).to_os_string())
}

fn read_u32(control: &mut UnixStream) -> Result<u32> {
    let mut bytes = [0_u8; 4];
    control.read_exact(&mut bytes).map_err(|error| {
        supervisor_error(
            ErrorCode::Unavailable,
            format!("failed to read session-supervisor u32: {error}"),
        )
    })?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(control: &mut UnixStream) -> Result<u64> {
    let mut bytes = [0_u8; 8];
    control.read_exact(&mut bytes).map_err(|error| {
        supervisor_error(
            ErrorCode::Unavailable,
            format!("failed to read session-supervisor u64: {error}"),
        )
    })?;
    Ok(u64::from_be_bytes(bytes))
}

fn read_u8(control: &mut UnixStream) -> Result<u8> {
    let mut bytes = [0_u8; 1];
    control.read_exact(&mut bytes).map_err(|error| {
        supervisor_error(
            ErrorCode::Unavailable,
            format!("failed to read session-supervisor u8: {error}"),
        )
    })?;
    Ok(bytes[0])
}

fn clear_cloexec(fd: RawFd) -> Result<()> {
    // SAFETY: fcntl F_GETFD/F_SETFD operate on an open descriptor owned by us.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(last_os_error("read session-supervisor channel FD flags"));
    }
    let flags = flags & !libc::FD_CLOEXEC;
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } < 0 {
        return Err(last_os_error("clear session-supervisor channel CLOEXEC"));
    }
    Ok(())
}

fn send_with_fds(socket: RawFd, payload: &[u8], fds: &[RawFd]) -> Result<()> {
    if fds.len() > MAX_SPAWN_FDS {
        return Err(supervisor_error(
            ErrorCode::InvalidArgument,
            format!(
                "session supervisor spawn supports at most {MAX_SPAWN_FDS} FDs; received {}",
                fds.len()
            ),
        ));
    }
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut _,
        iov_len: payload.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    // Room for CMSG_SPACE(MAX_SPAWN_FDS * sizeof(RawFd)).
    let mut control = [0_u8; 512];
    if !fds.is_empty() {
        let descriptor_bytes = std::mem::size_of_val(fds);
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = unsafe { libc::CMSG_SPACE(descriptor_bytes as u32) } as _;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            if header.is_null() {
                return Err(supervisor_error(
                    ErrorCode::Internal,
                    "session supervisor SCM_RIGHTS control buffer has no header",
                ));
            }
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(descriptor_bytes as u32) as _;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(header),
                descriptor_bytes,
            );
        }
    }
    let sent = unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) };
    if sent != payload.len() as isize {
        return Err(last_os_error("send session-supervisor spawn request"));
    }
    Ok(())
}

fn receive_fds(socket: RawFd, expected: usize) -> Result<Vec<OwnedFd>> {
    if expected == 0 {
        return Ok(Vec::new());
    }
    if expected > MAX_SPAWN_FDS {
        return Err(supervisor_error(
            ErrorCode::InvalidArgument,
            format!(
                "session supervisor spawn supports at most {MAX_SPAWN_FDS} FDs; expected {expected}"
            ),
        ));
    }
    let mut payload = [0_u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    // Room for CMSG_SPACE(MAX_SPAWN_FDS * sizeof(RawFd)).
    let mut control = [0_u8; 512];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len() as _;
    let received = unsafe { libc::recvmsg(socket, &mut message, 0) };
    if received < 0 {
        return Err(last_os_error(
            "receive session-supervisor spawn descriptors",
        ));
    }
    if received != 1 || payload[0] != 0xFD {
        return Err(supervisor_error(
            ErrorCode::Internal,
            "session supervisor spawn descriptor frame marker mismatch",
        ));
    }
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err(supervisor_error(
            ErrorCode::Internal,
            "session supervisor spawn descriptor frame has no control header",
        ));
    }
    let (level, kind, len) = unsafe {
        (
            (*header).cmsg_level,
            (*header).cmsg_type,
            (*header).cmsg_len,
        )
    };
    let descriptor_bytes = expected * std::mem::size_of::<RawFd>();
    let expected_len = unsafe { libc::CMSG_LEN(descriptor_bytes as u32) } as usize;
    if level != libc::SOL_SOCKET || kind != libc::SCM_RIGHTS || len as usize != expected_len {
        return Err(supervisor_error(
            ErrorCode::Internal,
            "session supervisor spawn descriptor frame is not SCM_RIGHTS",
        ));
    }
    let mut raw = vec![0 as RawFd; expected];
    unsafe {
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(header).cast::<RawFd>(),
            raw.as_mut_ptr(),
            expected,
        );
    }
    Ok(raw
        .into_iter()
        .map(|fd| {
            // SAFETY: recvmsg transferred ownership of each descriptor.
            unsafe { OwnedFd::from_raw_fd(fd) }
        })
        .collect())
}

fn reap_children() {
    loop {
        let mut status = 0;
        // SAFETY: non-blocking wait for any child.
        let reaped = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if reaped <= 0 {
            break;
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

fn run_owner_child(ready: &mut UnixStream) -> Result<()> {
    // Supervisor must intentionally omit PDEATHSIG against the owner so it can
    // outlive Host Service death. Workload arms PDEATHSIG against supervisor.
    // SAFETY: single-threaded fork child.
    let supervisor_pid = unsafe { libc::fork() };
    if supervisor_pid < 0 {
        return Err(last_os_error("fork session supervisor"));
    }
    if supervisor_pid == 0 {
        let code = match run_supervisor_child(ready) {
            Ok(()) => 0,
            Err(_) => 72,
        };
        // SAFETY: fork child must not unwind into the harness.
        unsafe { libc::_exit(code) }
    }

    loop {
        // SAFETY: pause until SIGKILL from the test parent.
        unsafe { libc::pause() };
    }
}

fn run_supervisor_child(ready: &mut UnixStream) -> Result<()> {
    // Become a subreaper so workload orphans stay under this authenticated
    // supervisor if intermediate helpers exit.
    // SAFETY: PR_SET_CHILD_SUBREAPER takes only integer arguments.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(last_os_error("enable session supervisor child subreaper"));
    }

    let identity = SessionSupervisorIdentity::current()?;
    // SAFETY: single-threaded fork child.
    let workload_pid = unsafe { libc::fork() };
    if workload_pid < 0 {
        return Err(last_os_error("fork session-supervisor workload"));
    }
    if workload_pid == 0 {
        if verify_and_arm_parent_death_signal(identity.pid(), "session workload").is_err() {
            // SAFETY: fork child must not unwind into the harness.
            unsafe { libc::_exit(73) }
        }
        loop {
            // SAFETY: pause until supervisor death delivers SIGKILL.
            unsafe { libc::pause() };
        }
    }

    // Allow the workload to arm PDEATHSIG before publishing readiness.
    std::thread::sleep(Duration::from_millis(20));
    let mut payload = Vec::with_capacity(18);
    payload.push(READY_BYTE);
    payload.push(WORKLOAD_BYTE);
    payload.extend_from_slice(&identity.pid().to_be_bytes());
    payload.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
    payload.extend_from_slice(&workload_pid.to_be_bytes());
    ready.write_all(&payload).map_err(|error| {
        terminate_pid(workload_pid);
        let _ = wait_for_child(workload_pid);
        supervisor_error(
            ErrorCode::Internal,
            format!("failed to publish session-supervisor readiness: {error}"),
        )
    })?;

    loop {
        let mut status = 0;
        // SAFETY: non-blocking wait for any child.
        let reaped = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if reaped < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ECHILD) && err.raw_os_error() != Some(libc::EINTR) {
                return Err(supervisor_error(
                    ErrorCode::Internal,
                    format!("session supervisor waitpid failed: {err}"),
                ));
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn process_observation(pid: i32) -> Result<Option<ProcessObservation>> {
    if pid <= 0 {
        return Err(supervisor_error(
            ErrorCode::InvalidArgument,
            format!("session supervisor PID must be positive; received {pid}"),
        ));
    }
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(supervisor_error(
                ErrorCode::Internal,
                format!("failed to read {}: {error}", path.display()),
            ));
        }
    };
    if contents.len() > MAX_STAT_BYTES {
        return Err(supervisor_error(
            ErrorCode::ResourceExhausted,
            format!(
                "process identity exceeds {MAX_STAT_BYTES} bytes: {}",
                path.display()
            ),
        ));
    }
    let closing = contents.rfind(") ").ok_or_else(|| {
        supervisor_error(
            ErrorCode::FailedPrecondition,
            format!("process identity is malformed: {}", path.display()),
        )
    })?;
    let reported_pid = contents[..]
        .split_once(" (")
        .and_then(|(pid, _)| pid.parse::<i32>().ok())
        .ok_or_else(|| {
            supervisor_error(
                ErrorCode::FailedPrecondition,
                format!("process identity has no valid PID: {}", path.display()),
            )
        })?;
    if reported_pid != pid {
        return Err(supervisor_error(
            ErrorCode::PermissionDenied,
            format!(
                "process identity PID mismatch at {}: expected {pid}, observed {reported_pid}",
                path.display()
            ),
        ));
    }
    let fields: Vec<&str> = contents[closing + 2..].split_whitespace().collect();
    let state = fields
        .first()
        .and_then(|value| value.bytes().next())
        .ok_or_else(|| {
            supervisor_error(
                ErrorCode::FailedPrecondition,
                format!("process identity missing state: {}", path.display()),
            )
        })?;
    let start_time_ticks = fields.get(19).ok_or_else(|| {
        supervisor_error(
            ErrorCode::FailedPrecondition,
            format!("process identity missing starttime: {}", path.display()),
        )
    })?;
    let start_time_ticks = start_time_ticks.parse::<u64>().map_err(|error| {
        supervisor_error(
            ErrorCode::FailedPrecondition,
            format!(
                "process identity has invalid starttime {}: {error}",
                path.display()
            ),
        )
    })?;
    Ok(Some(ProcessObservation {
        start_time_ticks,
        state,
    }))
}

fn process_is_live(pid: i32) -> bool {
    process_observation(pid)
        .ok()
        .flatten()
        .is_some_and(|observation| !observation.is_terminated())
}

fn wait_until_dead(pid: i32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !process_is_live(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    !process_is_live(pid)
}

fn supervisor_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("native-linux-session-supervisor")
}

fn last_os_error(operation: &str) -> Error {
    let error = io::Error::last_os_error();
    supervisor_error(ErrorCode::Internal, format!("{operation} failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_ready(stream: &mut UnixStream) -> Result<(SessionSupervisorIdentity, i32)> {
        let mut header = [0_u8; 2];
        stream.read_exact(&mut header).map_err(|error| {
            supervisor_error(
                ErrorCode::Unavailable,
                format!("failed to read session-supervisor readiness header: {error}"),
            )
        })?;
        if header != [READY_BYTE, WORKLOAD_BYTE] {
            return Err(supervisor_error(
                ErrorCode::Internal,
                "session-supervisor readiness header mismatch",
            ));
        }
        let mut pid_bytes = [0_u8; 4];
        let mut start_bytes = [0_u8; 8];
        let mut workload_bytes = [0_u8; 4];
        stream.read_exact(&mut pid_bytes).map_err(|error| {
            supervisor_error(
                ErrorCode::Unavailable,
                format!("failed to read supervisor pid: {error}"),
            )
        })?;
        stream.read_exact(&mut start_bytes).map_err(|error| {
            supervisor_error(
                ErrorCode::Unavailable,
                format!("failed to read supervisor start-time: {error}"),
            )
        })?;
        stream.read_exact(&mut workload_bytes).map_err(|error| {
            supervisor_error(
                ErrorCode::Unavailable,
                format!("failed to read workload pid: {error}"),
            )
        })?;
        let identity = SessionSupervisorIdentity {
            schema_version: IDENTITY_SCHEMA_VERSION.to_string(),
            pid: i32::from_be_bytes(pid_bytes),
            start_time_ticks: u64::from_be_bytes(start_bytes),
        };
        Ok((identity, i32::from_be_bytes(workload_bytes)))
    }

    fn spawn_surviving_supervisor() -> (SessionSupervisorIdentity, i32, i32) {
        let (mut parent_ready, mut child_ready) =
            UnixStream::pair().expect("session-supervisor ready channel");
        // SAFETY: parent reaps the owner; child stays single-threaded.
        let owner_pid = unsafe { libc::fork() };
        assert!(owner_pid >= 0, "fork owner: {}", io::Error::last_os_error());
        if owner_pid == 0 {
            drop(parent_ready);
            let code = match run_owner_child(&mut child_ready) {
                Ok(()) => 0,
                Err(_) => 71,
            };
            // SAFETY: fork child must not unwind into the harness.
            unsafe { libc::_exit(code) }
        }
        drop(child_ready);
        let (identity, workload_pid) = read_ready(&mut parent_ready).expect("read readiness");
        let supervisor_pid = identity.pid();
        terminate_pid(owner_pid);
        let status = wait_for_child(owner_pid).expect("reap owner");
        assert!(
            matches!(
                status,
                ChildOutcome::Signaled(signal) if signal == libc::SIGKILL
            ) || matches!(status, ChildOutcome::Exited(_)),
            "owner must exit after SIGKILL: {status:?}"
        );
        (identity, supervisor_pid, workload_pid)
    }

    #[test]
    fn rejects_pid_only_authentication_when_start_time_drifts() {
        let live = SessionSupervisorIdentity::current().expect("capture current identity");
        let forged = SessionSupervisorIdentity {
            schema_version: IDENTITY_SCHEMA_VERSION.to_string(),
            pid: live.pid(),
            start_time_ticks: live.start_time_ticks().saturating_add(1),
        };
        let error = forged
            .authenticate_live()
            .expect_err("start-time drift must fail closed");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
    }

    #[test]
    fn rejects_absent_supervisor_pid() {
        let forged = SessionSupervisorIdentity {
            schema_version: IDENTITY_SCHEMA_VERSION.to_string(),
            pid: i32::MAX - 7,
            start_time_ticks: 1,
        };
        let error = forged
            .authenticate_live()
            .expect_err("absent supervisor must fail closed");
        assert_eq!(error.code, ErrorCode::Unavailable);
    }

    #[test]
    fn rejects_unknown_identity_schema() {
        let live = SessionSupervisorIdentity::current().expect("capture current identity");
        let forged = SessionSupervisorIdentity {
            schema_version: "a3s.oci.native-linux-session-supervisor-identity.v0".to_string(),
            pid: live.pid(),
            start_time_ticks: live.start_time_ticks(),
        };
        let error = forged
            .authenticate_live()
            .expect_err("unknown schema must fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
    }

    #[test]
    fn workload_survives_owner_death_when_bound_to_authenticated_supervisor() {
        let (identity, supervisor_pid, workload_pid) = spawn_surviving_supervisor();
        identity
            .authenticate_live()
            .expect("replacement Host must authenticate the surviving supervisor");
        assert!(
            process_is_live(supervisor_pid),
            "supervisor must remain live after owner death"
        );
        assert!(
            process_is_live(workload_pid),
            "workload must remain live after owner death when PDEATHSIG targets supervisor"
        );

        terminate_pid(supervisor_pid);
        assert!(
            wait_until_dead(workload_pid, Duration::from_secs(2)),
            "workload must die when its authenticated supervisor dies"
        );
        let _ = wait_for_child(supervisor_pid);
    }

    #[test]
    fn owner_death_still_kills_workload_when_pdeathsig_targets_owner() {
        let (mut parent_ready, mut child_ready) =
            UnixStream::pair().expect("contrast ready channel");
        // SAFETY: parent reaps the owner; child stays single-threaded.
        let owner_pid = unsafe { libc::fork() };
        assert!(owner_pid >= 0, "fork contrast owner");
        if owner_pid == 0 {
            drop(parent_ready);
            // SAFETY: single-threaded fork child.
            let workload_pid = unsafe { libc::fork() };
            if workload_pid < 0 {
                unsafe { libc::_exit(81) }
            }
            if workload_pid == 0 {
                let owner = unsafe { libc::getppid() };
                if verify_and_arm_parent_death_signal(owner, "contrast workload").is_err() {
                    unsafe { libc::_exit(82) }
                }
                loop {
                    unsafe { libc::pause() };
                }
            }
            std::thread::sleep(Duration::from_millis(30));
            if child_ready.write_all(&workload_pid.to_be_bytes()).is_err() {
                terminate_pid(workload_pid);
                unsafe { libc::_exit(83) }
            }
            loop {
                unsafe { libc::pause() };
            }
        }
        drop(child_ready);
        let mut workload_bytes = [0_u8; 4];
        parent_ready
            .read_exact(&mut workload_bytes)
            .expect("read contrast workload pid");
        let workload_pid = i32::from_be_bytes(workload_bytes);
        terminate_pid(owner_pid);
        let _ = wait_for_child(owner_pid);
        assert!(
            wait_until_dead(workload_pid, Duration::from_secs(2)),
            "current Host-bound PDEATHSIG model must still terminate workload on owner death"
        );
    }

    #[test]
    fn production_supervisor_can_parent_workload_that_survives_host_death() {
        let (mut parent_ready, mut child_ready) =
            UnixStream::pair().expect("production supervisor ready channel");
        // SAFETY: parent reaps the fake Host; child starts the production supervisor.
        let host_pid = unsafe { libc::fork() };
        assert!(host_pid >= 0, "fork fake host");
        if host_pid == 0 {
            drop(parent_ready);
            let mut supervisor = match HostSessionSupervisor::start_via_fork() {
                Ok(supervisor) => supervisor,
                Err(_) => unsafe { libc::_exit(91) },
            };
            let workload_pid = match supervisor.spawn_sleep_workload(30) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(92) },
            };
            let identity = supervisor.identity().clone();
            let mut payload = Vec::with_capacity(16);
            payload.extend_from_slice(&identity.pid().to_be_bytes());
            payload.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
            payload.extend_from_slice(&workload_pid.to_be_bytes());
            if child_ready.write_all(&payload).is_err() {
                unsafe { libc::_exit(93) }
            }
            // Leak supervisor so Drop does not kill it when this fake Host exits.
            std::mem::forget(supervisor);
            loop {
                unsafe { libc::pause() };
            }
        }
        drop(child_ready);
        let mut payload = [0_u8; 16];
        parent_ready
            .read_exact(&mut payload)
            .expect("read production supervisor evidence");
        let identity = SessionSupervisorIdentity {
            schema_version: IDENTITY_SCHEMA_VERSION.to_string(),
            pid: i32::from_be_bytes(payload[0..4].try_into().expect("pid bytes")),
            start_time_ticks: u64::from_be_bytes(payload[4..12].try_into().expect("start bytes")),
        };
        let workload_pid = i32::from_be_bytes(payload[12..16].try_into().expect("workload bytes"));
        terminate_pid(host_pid);
        let _ = wait_for_child(host_pid);
        identity
            .authenticate_live()
            .expect("replacement must authenticate production supervisor after Host death");
        assert!(
            process_is_live(identity.pid()),
            "production supervisor must survive Host death"
        );
        assert!(
            process_is_live(workload_pid),
            "workload parented by production supervisor must survive Host death"
        );
        terminate_pid(identity.pid());
        assert!(
            wait_until_dead(workload_pid, Duration::from_secs(2)),
            "workload must die when production supervisor dies"
        );
        let _ = wait_for_child(identity.pid());
    }

    #[test]
    fn supervised_launcher_with_stdio_survives_host_death_and_stays_authenticated() {
        let (mut parent_ready, mut child_ready) =
            UnixStream::pair().expect("stdio supervisor ready channel");
        // SAFETY: parent reaps the fake Host; child owns the production supervisor.
        let host_pid = unsafe { libc::fork() };
        assert!(host_pid >= 0, "fork fake host for stdio survival");
        if host_pid == 0 {
            drop(parent_ready);
            let mut supervisor = match HostSessionSupervisor::start_via_fork() {
                Ok(supervisor) => supervisor,
                Err(_) => unsafe { libc::_exit(101) },
            };
            let mut pipe_fds = [0, 0];
            if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
                unsafe { libc::_exit(102) }
            }
            let child_stdout = pipe_fds[1];
            let host_stdout = pipe_fds[0];
            let launcher_pid = match supervisor.spawn_launcher(
                Path::new("/bin/sleep"),
                &["30".into()],
                None,
                None,
                Some((None, Some(child_stdout), None)),
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(103) },
            };
            // Close the child write end in the fake Host; the launcher keeps its copy.
            unsafe {
                libc::close(child_stdout);
            }
            let identity = supervisor.identity().clone();
            let mut payload = Vec::with_capacity(20);
            payload.extend_from_slice(&identity.pid().to_be_bytes());
            payload.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
            payload.extend_from_slice(&launcher_pid.to_be_bytes());
            payload.extend_from_slice(&host_stdout.to_be_bytes());
            if child_ready.write_all(&payload).is_err() {
                unsafe { libc::_exit(104) }
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
            .expect("read stdio supervisor evidence");
        let identity = SessionSupervisorIdentity {
            schema_version: IDENTITY_SCHEMA_VERSION.to_string(),
            pid: i32::from_be_bytes(payload[0..4].try_into().expect("pid bytes")),
            start_time_ticks: u64::from_be_bytes(payload[4..12].try_into().expect("start bytes")),
        };
        let launcher_pid = i32::from_be_bytes(payload[12..16].try_into().expect("launcher bytes"));
        let host_stdout = i32::from_be_bytes(payload[16..20].try_into().expect("stdout bytes"));
        terminate_pid(host_pid);
        let _ = wait_for_child(host_pid);
        // The fake Host's stdout read end dies with the Host process; that is
        // intentional. The invariant under test is supervisor + launcher lifetime.
        let _ = host_stdout;
        identity
            .authenticate_live()
            .expect("replacement must authenticate supervisor after Host death with stdio spawn");
        assert!(
            process_is_live(identity.pid()),
            "supervisor must survive Host death after stdio-capable launcher spawn"
        );
        assert!(
            process_is_live(launcher_pid),
            "stdio launcher parented by supervisor must survive Host death"
        );
        // Prove the launcher is still a real child of the supervisor, not Host.
        let status = std::fs::read_to_string(format!("/proc/{launcher_pid}/status"))
            .expect("read launcher status");
        let ppid = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:\t"))
            .expect("launcher status must report PPid")
            .parse::<i32>()
            .expect("parse launcher PPid");
        assert_eq!(
            ppid,
            identity.pid(),
            "supervised launcher must remain parented by the supervisor after Host death"
        );
        terminate_pid(identity.pid());
        assert!(
            wait_until_dead(launcher_pid, Duration::from_secs(2)),
            "stdio launcher must die when its supervisor dies"
        );
        let _ = wait_for_child(identity.pid());
    }

    #[test]
    fn replacement_host_can_reattach_control_and_wait_without_inventing_status() {
        let (mut parent_ready, mut child_ready) =
            UnixStream::pair().expect("reattach ready channel");
        // SAFETY: parent reaps the fake Host; child owns the production supervisor.
        let host_pid = unsafe { libc::fork() };
        assert!(host_pid >= 0, "fork fake host for reattach");
        if host_pid == 0 {
            drop(parent_ready);
            let mut supervisor = match HostSessionSupervisor::start_via_fork() {
                Ok(supervisor) => supervisor,
                Err(_) => unsafe { libc::_exit(111) },
            };
            let launcher_pid = match supervisor.spawn_launcher(
                Path::new("/bin/sleep"),
                &["1".into()],
                None,
                None,
                None,
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(112) },
            };
            let identity = supervisor.identity().clone();
            let mut payload = Vec::with_capacity(16);
            payload.extend_from_slice(&identity.pid().to_be_bytes());
            payload.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
            payload.extend_from_slice(&launcher_pid.to_be_bytes());
            if child_ready.write_all(&payload).is_err() {
                unsafe { libc::_exit(113) }
            }
            // Leak so Drop does not SHUTDOWN/kill the supervisor on Host exit.
            std::mem::forget(supervisor);
            loop {
                unsafe { libc::pause() };
            }
        }
        drop(child_ready);
        let mut payload = [0_u8; 16];
        parent_ready
            .read_exact(&mut payload)
            .expect("read reattach supervisor evidence");
        let identity = SessionSupervisorIdentity {
            schema_version: IDENTITY_SCHEMA_VERSION.to_string(),
            pid: i32::from_be_bytes(payload[0..4].try_into().expect("pid bytes")),
            start_time_ticks: u64::from_be_bytes(payload[4..12].try_into().expect("start bytes")),
        };
        let launcher_pid = i32::from_be_bytes(payload[12..16].try_into().expect("launcher bytes"));
        terminate_pid(host_pid);
        let _ = wait_for_child(host_pid);
        identity
            .authenticate_live()
            .expect("replacement must authenticate live supervisor before reattach");
        let mut reattached = HostSessionSupervisor::reattach(&identity)
            .expect("replacement Host must reopen the supervisor control channel");
        assert_eq!(reattached.identity().pid(), identity.pid());
        assert_eq!(
            reattached.identity().start_time_ticks(),
            identity.start_time_ticks()
        );
        let status = reattached
            .wait_launcher(launcher_pid)
            .expect("reattached Host must wait the exact supervised launcher");
        assert_eq!(
            status, 0,
            "wait must return the real launcher exit status, not an invented value"
        );
        assert!(
            !process_is_live(launcher_pid),
            "launcher must be reaped after authentic wait"
        );
        // Drop reattached sends SHUTDOWN and terminates the supervisor.
    }

    #[test]
    fn deposited_stdin_survives_host_death_and_reattach_take_is_authentic() {
        use std::io::Write as _;
        use std::os::fd::IntoRawFd;

        let (mut parent_ready, mut child_ready) =
            UnixStream::pair().expect("stdin deposit ready channel");
        // SAFETY: parent reaps the fake Host; child owns the production supervisor.
        let host_pid = unsafe { libc::fork() };
        assert!(host_pid >= 0, "fork fake host for stdin deposit");
        if host_pid == 0 {
            drop(parent_ready);
            let mut supervisor = match HostSessionSupervisor::start_via_fork() {
                Ok(supervisor) => supervisor,
                Err(_) => unsafe { libc::_exit(131) },
            };
            let mut fds = [0, 0];
            if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
                unsafe { libc::_exit(132) }
            }
            let child_stdin = unsafe { OwnedFd::from_raw_fd(fds[0]) };
            let host_stdin = unsafe { OwnedFd::from_raw_fd(fds[1]) };
            let deposit = unsafe { libc::fcntl(host_stdin.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if deposit < 0 {
                unsafe { libc::_exit(133) }
            }
            let launcher_pid = match supervisor.spawn_launcher(
                Path::new("/bin/cat"),
                &[],
                None,
                None,
                Some((Some(child_stdin.as_raw_fd()), None, None)),
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(134) },
            };
            drop(child_stdin);
            if supervisor.deposit_stdin(launcher_pid, deposit).is_err() {
                unsafe { libc::_exit(135) }
            }
            // SAFETY: SCM_RIGHTS duplicated into the supervisor; close the local copy.
            unsafe {
                libc::close(deposit);
            }
            // Host keeps its write end until death; deposit must keep stdin open.
            let identity = supervisor.identity().clone();
            let mut payload = Vec::with_capacity(16);
            payload.extend_from_slice(&identity.pid().to_be_bytes());
            payload.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
            payload.extend_from_slice(&launcher_pid.to_be_bytes());
            if child_ready.write_all(&payload).is_err() {
                unsafe { libc::_exit(136) }
            }
            // Close the Host-local write end explicitly before dying so only the
            // deposited duplicate remains (simulates Host process FD teardown).
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
            .expect("read stdin-deposit supervisor evidence");
        let identity = SessionSupervisorIdentity {
            schema_version: IDENTITY_SCHEMA_VERSION.to_string(),
            pid: i32::from_be_bytes(payload[0..4].try_into().expect("pid bytes")),
            start_time_ticks: u64::from_be_bytes(payload[4..12].try_into().expect("start bytes")),
        };
        let launcher_pid = i32::from_be_bytes(payload[12..16].try_into().expect("launcher bytes"));
        terminate_pid(host_pid);
        let _ = wait_for_child(host_pid);
        assert!(
            process_is_live(launcher_pid),
            "cat must stay live: deposited stdin must prevent EOF after Host death"
        );
        let mut reattached = HostSessionSupervisor::reattach(&identity)
            .expect("replacement Host must reattach after stdin deposit");
        let taken = reattached
            .take_stdin(launcher_pid)
            .expect("reattach must restore the authentic deposited stdin write end");
        let missing = reattached
            .take_stdin(launcher_pid)
            .expect_err("second take must fail closed, not invent another stream");
        assert_eq!(missing.code, ErrorCode::Unavailable);
        let mut writer = unsafe { std::fs::File::from_raw_fd(taken.into_raw_fd()) };
        writer
            .write_all(b"reattached-stdin\n")
            .expect("write through restored stdin");
        drop(writer);
        reattached
            .close_deposited_stdin(launcher_pid)
            .expect("idempotent close after take");
        let status = reattached
            .wait_launcher(launcher_pid)
            .expect("wait must return authentic cat exit after stdin EOF");
        assert_eq!(
            status, 0,
            "cat must exit 0 after authentic EOF, not invented status"
        );
    }

    #[test]
    fn exclusive_stdout_survives_host_death_and_relay_is_authentic() {
        let (mut parent_ready, mut child_ready) =
            UnixStream::pair().expect("output deposit ready channel");
        // SAFETY: parent reaps the fake Host; child owns the production supervisor.
        let host_pid = unsafe { libc::fork() };
        assert!(host_pid >= 0, "fork fake host for output deposit");
        if host_pid == 0 {
            drop(parent_ready);
            let mut supervisor = match HostSessionSupervisor::start_via_fork() {
                Ok(supervisor) => supervisor,
                Err(_) => unsafe { libc::_exit(151) },
            };
            let mut fds = [0, 0];
            if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
                unsafe { libc::_exit(152) }
            }
            let host_stdout = unsafe { OwnedFd::from_raw_fd(fds[0]) };
            let child_stdout = unsafe { OwnedFd::from_raw_fd(fds[1]) };
            let launcher_pid = match supervisor.spawn_launcher(
                Path::new("/bin/echo"),
                &["relay-bytes".into()],
                None,
                None,
                Some((None, Some(child_stdout.as_raw_fd()), None)),
            ) {
                Ok(pid) => pid,
                Err(_) => unsafe { libc::_exit(153) },
            };
            drop(child_stdout);
            if supervisor
                .deposit_output(launcher_pid, Some(host_stdout), None)
                .is_err()
            {
                unsafe { libc::_exit(154) }
            }
            // Second deposit of the same launcher must fail closed (exclusive).
            let mut again = [0, 0];
            if unsafe { libc::pipe(again.as_mut_ptr()) } != 0 {
                unsafe { libc::_exit(155) }
            }
            let competing = unsafe { OwnedFd::from_raw_fd(again[0]) };
            unsafe {
                libc::close(again[1]);
            }
            if supervisor
                .deposit_output(launcher_pid, Some(competing), None)
                .is_ok()
            {
                unsafe { libc::_exit(156) }
            }
            let identity = supervisor.identity().clone();
            let mut payload = Vec::with_capacity(16);
            payload.extend_from_slice(&identity.pid().to_be_bytes());
            payload.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
            payload.extend_from_slice(&launcher_pid.to_be_bytes());
            if child_ready.write_all(&payload).is_err() {
                unsafe { libc::_exit(157) }
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
            .expect("read output-deposit supervisor evidence");
        let identity = SessionSupervisorIdentity {
            schema_version: IDENTITY_SCHEMA_VERSION.to_string(),
            pid: i32::from_be_bytes(payload[0..4].try_into().expect("pid bytes")),
            start_time_ticks: u64::from_be_bytes(payload[4..12].try_into().expect("start bytes")),
        };
        let launcher_pid = i32::from_be_bytes(payload[12..16].try_into().expect("launcher bytes"));
        terminate_pid(host_pid);
        let _ = wait_for_child(host_pid);
        let mut reattached = HostSessionSupervisor::reattach(&identity)
            .expect("replacement Host must reattach after exclusive output deposit");
        let mut chunks = Vec::new();
        let mut after = 0_u64;
        let mut saw_eof = false;
        for _ in 0..100 {
            let more = reattached
                .read_output(launcher_pid, after, 4096, Some(100))
                .expect("relay must return authentic chunks without inventing status");
            if more.is_empty() {
                if saw_eof {
                    break;
                }
                continue;
            }
            if let Some(seq) = more.iter().map(|chunk| chunk.sequence).max() {
                after = seq;
            }
            saw_eof |= more.iter().any(|chunk| chunk.eof);
            chunks.extend(more);
            if saw_eof {
                break;
            }
        }
        let joined: Vec<u8> = chunks
            .iter()
            .filter(|chunk| !chunk.eof)
            .flat_map(|chunk| chunk.data.iter().copied())
            .collect();
        assert!(
            joined
                .windows(b"relay-bytes".len())
                .any(|w| w == b"relay-bytes"),
            "relay must surface authentic echo bytes, got {joined:?}"
        );
        assert!(saw_eof, "exclusive drain must publish authentic EOF");
        let status = reattached
            .wait_launcher(launcher_pid)
            .expect("wait must return authentic echo status");
        assert_eq!(status, 0, "echo must exit 0, not invented status");
    }

    #[test]
    fn reattach_rejects_start_time_drift_without_opening_control() {
        let identity = SessionSupervisorIdentity {
            schema_version: IDENTITY_SCHEMA_VERSION.to_string(),
            pid: i32::try_from(std::process::id()).expect("pid fits i32"),
            start_time_ticks: 1,
        };
        let error = HostSessionSupervisor::reattach(&identity)
            .expect_err("stale start-time must not authenticate for reattach");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
    }

    #[test]
    fn host_sends_rootless_device_mounts_to_supervisor_parented_launcher() {
        use std::os::fd::AsRawFd;
        use std::process::Command as StdCommand;

        // Prefer a tiny Python receiver so the launcher is a real supervisor
        // child. Skip when python3 is absent (unit hosts without it).
        if StdCommand::new("python3")
            .arg("-c")
            .arg("import socket")
            .status()
            .map(|status| !status.success())
            .unwrap_or(true)
        {
            eprintln!("skipping: python3 unavailable for supervised device-mount receiver");
            return;
        }

        const CONTROL_TARGET_FD: i32 = 200;
        const DEVICE_MOUNTS_BYTE: u8 = 0xD1;
        let expected = crate::OCI_LINUX_DEFAULT_DEVICE_NODES.len();
        let script = format!(
            r#"
import array, socket, sys
MARKER = {marker}
EXPECTED = {expected}
fd = {fd}
sock = socket.socket(fileno=fd)
msg, ancdata, flags, _addr = sock.recvmsg(1, socket.CMSG_SPACE(max(EXPECTED, 1) * 4))
if not msg or msg[0] != MARKER:
    sys.exit(11)
received = []
for level, typ, data in ancdata:
    if level != socket.SOL_SOCKET or typ != socket.SCM_RIGHTS:
        sys.exit(12)
    fds = array.array("i")
    fds.frombytes(data[: len(data) - (len(data) % fds.itemsize)])
    received.extend(fds)
sys.exit(0 if len(received) == EXPECTED else 14)
"#,
            marker = DEVICE_MOUNTS_BYTE,
            expected = expected,
            fd = CONTROL_TARGET_FD,
        );
        let directory = tempfile::tempdir().expect("receiver script directory");
        let script_path = directory.path().join("receive_device_mounts.py");
        std::fs::write(&script_path, script).expect("write receiver script");

        let mut supervisor = match HostSessionSupervisor::start_via_fork() {
            Ok(supervisor) => supervisor,
            Err(error) => panic!("start supervisor: {error}"),
        };
        let (host_control, child_control) =
            UnixStream::pair().expect("Host↔launcher device-mount control");
        let launcher_pid = supervisor
            .spawn_launcher_with_inherited(
                Path::new("python3"),
                &[script_path.as_os_str().to_os_string()],
                None,
                None,
                None,
                &[(child_control.as_raw_fd(), CONTROL_TARGET_FD)],
            )
            .expect("spawn supervisor-parented receiver");
        drop(child_control);

        let mounts = (0..expected)
            .map(|_| OwnedFd::from(std::fs::File::open("/dev/null").expect("device fixture")))
            .collect::<Vec<_>>();
        let descriptors = mounts
            .iter()
            .map(AsRawFd::as_raw_fd)
            .collect::<Vec<_>>();
        // Mirror create: Host holds the control socket and sends mounts after
        // the supervisor-parented launcher is live — not via spawn FD lists.
        super::super::device_mount_transport::send_descriptor_frame(
            host_control.as_raw_fd(),
            DEVICE_MOUNTS_BYTE,
            &descriptors,
        )
        .expect("send mounts to supervisor-parented launcher");
        drop(mounts);
        drop(host_control);

        let status = supervisor
            .wait_launcher(launcher_pid)
            .expect("wait authentic receiver exit");
        assert_eq!(
            status, 0,
            "receiver must exit 0 after authentic SCM_RIGHTS receive, not invented status"
        );
    }
}
