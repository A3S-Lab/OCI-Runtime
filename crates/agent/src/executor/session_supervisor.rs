//! Host-surviving session supervisor foundation for Native Linux live reattach.
//!
//! Current Native Linux owner-death recovery installs `PR_SET_PDEATHSIG(SIGKILL)`
//! against the Host Service owner, so a replacement process can only reconcile a
//! stopped tombstone. Box B2 / OCI R6 live process-session recovery needs a
//! different lifetime model:
//!
//! 1. a durable supervisor outlives Host Service death;
//! 2. workload helpers arm parent-death against that supervisor;
//! 3. a replacement Host authenticates the supervisor by PID **and** start-time
//!    ticks before claiming any live session.
//!
//! This module proves that identity and lifetime contract in isolation. It does
//! not yet wire the supervisor into the production executor or claim Box cutover.
#![allow(dead_code)] // Production executor wiring is the next R6 slice.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use a3s_oci_sdk::{Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};

use super::pid_supervisor::{
    terminate_pid, wait_for_child, verify_and_arm_parent_death_signal, ChildOutcome,
};

const IDENTITY_SCHEMA_VERSION: &str = "a3s.oci.native-linux-session-supervisor-identity.v1";
const MAX_STAT_BYTES: usize = 4096;
const READY_BYTE: u8 = b'R';
const WORKLOAD_BYTE: u8 = b'W';

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
}
