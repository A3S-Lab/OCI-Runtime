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
//!    ticks before claiming any live session.
//!
//! Qualification may enable production wiring with
//! `A3S_OCI_NATIVE_SESSION_SUPERVISOR=1`. Default create keeps Host-bound
//! PDEATHSIG so stopped-only recovery gates stay green.

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use a3s_oci_sdk::{Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};

use super::pid_supervisor::{
    terminate_pid, wait_for_child, verify_and_arm_parent_death_signal, ChildOutcome,
};
use super::pidfd::PidFd;

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
const MAX_SPAWN_ARGS: usize = 64;
const MAX_ARG_BYTES: usize = 8 * 1024;
#[allow(dead_code)] // Read by session_supervisor_opt_in for create wiring.
const ENV_OPT_IN: &str = "A3S_OCI_NATIVE_SESSION_SUPERVISOR";

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
}

/// Whether Native create should attach workloads to a host-surviving supervisor.
#[allow(dead_code)] // Wired into create when launcher spawn moves under the supervisor.
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
    #[allow(dead_code)] // Create path adopts this once launcher spawn is supervised.
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
                format!("session supervisor PID {raw_pid} does not fit the identity model: {error}"),
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
        )
    }

    /// Spawn a process as a real child of the supervisor with PDEATHSIG armed.
    pub(crate) fn spawn_launcher(
        &mut self,
        program: &Path,
        args: &[std::ffi::OsString],
        join_cgroup_procs: Option<RawFd>,
        control_workload: Option<(RawFd, RawFd)>,
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
            flags |= 0b001;
            fds.push(descriptor);
        }
        if let Some((control, workload)) = control_workload {
            flags |= 0b010;
            fds.push(control);
            fds.push(workload);
        }
        payload.push(flags);
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
            SupervisorResponse::Waited(_) => Err(supervisor_error(
                ErrorCode::Internal,
                "session supervisor returned a wait result for a spawn request",
            )),
        }
    }

    /// Block until a supervised child exits and return its raw wait status.
    #[allow(dead_code)] // Used when create launcher spawn moves under the supervisor.
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
            SupervisorResponse::Spawned(_) => Err(supervisor_error(
                ErrorCode::Internal,
                "session supervisor returned a spawn result for a wait request",
            )),
        }
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
    let mut ready = Vec::with_capacity(13);
    ready.push(MSG_READY);
    ready.extend_from_slice(&identity.pid().to_be_bytes());
    ready.extend_from_slice(&identity.start_time_ticks().to_be_bytes());
    control.write_all(&ready).map_err(|error| {
        supervisor_error(
            ErrorCode::Internal,
            format!("failed to publish session-supervisor readiness: {error}"),
        )
    })?;

    loop {
        let mut header = [0_u8; 1];
        match control.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                // Host Service died or closed its channel. Remain as the durable
                // session authority until an authenticated replacement reconnects
                // or an operator kills this process. Reap only after Host is gone
                // so a live Host can wait the launcher through its pidfd.
                loop {
                    reap_children();
                    std::thread::sleep(Duration::from_millis(50));
                }
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
                Ok(status) => {
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
            other => {
                return Err(supervisor_error(
                    ErrorCode::InvalidArgument,
                    format!("session supervisor received unknown request {other}"),
                ));
            }
        }
    }
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
    let expected_fds = usize::from(flags & 0b001) + (2 * usize::from((flags & 0b010) != 0));
    let fds = if expected_fds == 0 {
        Vec::new()
    } else {
        receive_fds(control.as_raw_fd(), expected_fds)?
    };
    let mut fd_iter = fds.into_iter();
    let join_cgroup = if flags & 0b001 != 0 {
        Some(fd_iter.next().ok_or_else(|| {
            supervisor_error(
                ErrorCode::Internal,
                "session supervisor spawn missing cgroup.procs descriptor",
            )
        })?)
    } else {
        None
    };
    let control_workload = if flags & 0b010 != 0 {
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

fn handle_wait_request(control: &mut UnixStream) -> Result<i32> {
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
    Ok(match outcome {
        ChildOutcome::Exited(code) => code << 8,
        ChildOutcome::Signaled(signal) => signal,
    })
}

enum SupervisorResponse {
    Spawned(i32),
    Waited(i32),
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
    if fds.len() > 3 {
        return Err(supervisor_error(
            ErrorCode::InvalidArgument,
            format!("session supervisor spawn supports at most 3 FDs; received {}", fds.len()),
        ));
    }
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut _,
        iov_len: payload.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    let mut control = [0_u8; 256];
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
    if expected > 3 {
        return Err(supervisor_error(
            ErrorCode::InvalidArgument,
            format!("session supervisor spawn supports at most 3 FDs; expected {expected}"),
        ));
    }
    let mut payload = [0_u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut control = [0_u8; 256];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len() as _;
    let received = unsafe { libc::recvmsg(socket, &mut message, 0) };
    if received < 0 {
        return Err(last_os_error("receive session-supervisor spawn descriptors"));
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
    let (level, kind, len) = unsafe { ((*header).cmsg_level, (*header).cmsg_type, (*header).cmsg_len) };
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
            if err.raw_os_error() != Some(libc::ECHILD) && err.raw_os_error() != Some(libc::EINTR)
            {
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
}
