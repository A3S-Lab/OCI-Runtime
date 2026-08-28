use std::io::{self, Read, Write};
use std::os::fd::RawFd;
use std::os::unix::net::UnixStream;

use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::process_group::ProcessGroupLease;

const EXITED_OUTCOME_BYTE: u8 = 0x31;
const SIGNALED_OUTCOME_BYTE: u8 = 0x32;

pub(super) enum NamespaceForkRole {
    Launcher {
        child_pid: libc::pid_t,
        outcome_channel: UnixStream,
    },
    NamespaceChild {
        host_pid: libc::pid_t,
        outcome_channel: UnixStream,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PayloadForkRole {
    NamespaceInit { child_pid: libc::pid_t },
    Payload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ChildOutcome {
    Exited(i32),
    Signaled(i32),
}

pub(super) fn fork_namespace_child() -> Result<NamespaceForkRole> {
    let (mut launcher_channel, mut child_channel) = UnixStream::pair().map_err(|error| {
        supervisor_error(
            ErrorCode::Internal,
            format!("failed to create namespace child channel: {error}"),
        )
    })?;
    // SAFETY: the internal init wrapper enters this path before constructing a
    // Tokio runtime or any additional threads. Both branches immediately close
    // the socket endpoint they do not own.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(last_os_error("fork namespace child process"));
    }
    if child_pid == 0 {
        drop(launcher_channel);
        arm_parent_death_signal("namespace child")?;
        let mut encoded_pid = [0_u8; size_of::<libc::pid_t>()];
        child_channel
            .read_exact(&mut encoded_pid)
            .map_err(|error| {
                supervisor_error(
                    ErrorCode::Unavailable,
                    format!("namespace launcher closed before identifying its child: {error}"),
                )
            })?;
        let host_pid = libc::pid_t::from_be_bytes(encoded_pid);
        if host_pid <= 0 {
            return Err(supervisor_error(
                ErrorCode::Internal,
                format!("namespace launcher reported non-positive child PID {host_pid}"),
            ));
        }
        return Ok(NamespaceForkRole::NamespaceChild {
            host_pid,
            outcome_channel: child_channel,
        });
    }

    drop(child_channel);
    if let Err(error) = launcher_channel.write_all(&child_pid.to_be_bytes()) {
        terminate_pid(child_pid);
        let _ = wait_for_child(child_pid);
        return Err(supervisor_error(
            ErrorCode::Internal,
            format!("failed to identify namespace child process: {error}"),
        ));
    }
    Ok(NamespaceForkRole::Launcher {
        child_pid,
        outcome_channel: launcher_channel,
    })
}

pub(super) fn fork_payload(namespace_init_pid: libc::pid_t) -> Result<PayloadForkRole> {
    if namespace_init_pid <= 0 {
        return Err(supervisor_error(
            ErrorCode::Internal,
            format!("namespace init has non-positive PID {namespace_init_pid}"),
        ));
    }
    // SAFETY: the namespace init is a dedicated single-threaded process. The
    // parent remains a reaper and the child immediately arms a parent-death
    // signal before entering the prepared start barrier.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(last_os_error("fork prepared container payload"));
    }
    if child_pid == 0 {
        arm_parent_death_signal("container payload")?;
        // SAFETY: `getppid` has no preconditions. The payload must remain a
        // direct child of namespace PID 1 until it replaces its image.
        let actual_parent = unsafe { libc::getppid() };
        if actual_parent != namespace_init_pid {
            return Err(supervisor_error(
                ErrorCode::Unavailable,
                format!(
                    "container payload parent changed from namespace init {namespace_init_pid} \
                     to {actual_parent} before preparation"
                ),
            ));
        }
        Ok(PayloadForkRole::Payload)
    } else {
        Ok(PayloadForkRole::NamespaceInit { child_pid })
    }
}

pub(super) fn wait_for_child(pid: libc::pid_t) -> Result<ChildOutcome> {
    loop {
        let mut status = 0;
        // SAFETY: `status` points to writable storage and `pid` is the
        // positive child PID returned by `fork`.
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == pid {
            return decode_wait_status(status);
        }
        if waited < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(last_os_error("reap namespace child process"));
    }
}

pub(super) fn supervise_payload(
    payload_pid: libc::pid_t,
    process_group: &ProcessGroupLease,
) -> Result<ChildOutcome> {
    let payload_outcome = loop {
        let (waited, outcome) = wait_for_any_child_without_reaping()?;
        if waited == payload_pid {
            break outcome;
        }
        let reaped = wait_for_child(waited)?;
        if reaped != outcome {
            return Err(supervisor_error(
                ErrorCode::Internal,
                format!(
                    "peeked namespace child {waited} outcome {outcome:?} changed to {reaped:?} \
                     while reaping"
                ),
            ));
        }
    };
    let lease = process_group.lock_for_reap()?;
    terminate_visible_descendants()?;
    let reaped = wait_for_child(payload_pid)?;
    if reaped != payload_outcome {
        return Err(supervisor_error(
            ErrorCode::Internal,
            format!(
                "peeked configured payload outcome {payload_outcome:?} changed to {reaped:?} \
                 while reaping"
            ),
        ));
    }
    terminate_and_reap_remaining_children()?;
    lease.unlock()?;
    Ok(payload_outcome)
}

pub(super) fn supervise_process_group(
    payload_pid: libc::pid_t,
    process_group: &ProcessGroupLease,
) -> Result<ChildOutcome> {
    let outcome = wait_for_child_without_reaping(payload_pid)?;
    let lease = process_group.lock_for_reap()?;
    terminate_process_group(payload_pid);
    let reaped = wait_for_child(payload_pid)?;
    if reaped != outcome {
        return Err(supervisor_error(
            ErrorCode::Internal,
            format!(
                "peeked configured payload outcome {outcome:?} changed to {reaped:?} while reaping"
            ),
        ));
    }
    lease.unlock()?;
    Ok(outcome)
}

pub(super) fn supervise_exec_payload(
    payload_pid: libc::pid_t,
    init_pidfd: RawFd,
    process_group: &ProcessGroupLease,
) -> Result<ChildOutcome> {
    if payload_pid <= 0 || init_pidfd < 0 {
        return Err(supervisor_error(
            ErrorCode::Internal,
            format!(
                "exec supervision requires a positive payload PID and live init pidfd; received \
                 PID {payload_pid}, fd {init_pidfd}"
            ),
        ));
    }
    loop {
        if let Some(outcome) = peek_child_outcome(payload_pid)? {
            // Keep the exited leader as a zombie while signaling its process
            // group. This is the same WNOWAIT ownership pattern used by the
            // A3S Box PID 1 reaper and prevents the kernel from reusing the
            // leader PID/PGID before descendant cleanup.
            let lease = process_group.lock_for_reap()?;
            terminate_process_group(payload_pid);
            let reaped = wait_for_child(payload_pid)?;
            if reaped != outcome {
                return Err(supervisor_error(
                    ErrorCode::Internal,
                    format!(
                        "peeked exec payload outcome {outcome:?} changed to {reaped:?} while reaping"
                    ),
                ));
            }
            lease.unlock()?;
            return Ok(outcome);
        }

        let mut descriptor = libc::pollfd {
            fd: init_pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `descriptor` points to one initialized pollfd and remains
        // writable for the call. A bounded timeout keeps payload observation
        // responsive without a busy loop.
        let polled = unsafe { libc::poll(&mut descriptor, 1, 10) };
        if polled < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            let lease = process_group.lock_for_reap()?;
            terminate_process_group(payload_pid);
            terminate_pid(payload_pid);
            let _ = wait_for_child(payload_pid);
            lease.unlock()?;
            return Err(supervisor_error(
                error_code(&error),
                format!("monitor configured-process pidfd failed: {error}"),
            ));
        }
        let fatal_events = libc::POLLERR | libc::POLLHUP | libc::POLLNVAL;
        if descriptor.revents & (libc::POLLIN | fatal_events) != 0 {
            let lease = process_group.lock_for_reap()?;
            terminate_process_group(payload_pid);
            terminate_pid(payload_pid);
            let outcome = wait_for_child(payload_pid)?;
            lease.unlock()?;
            return Ok(outcome);
        }
    }
}

pub(super) fn report_supervised_outcome(
    channel: &mut UnixStream,
    outcome: ChildOutcome,
) -> Result<()> {
    let (kind, value) = match outcome {
        ChildOutcome::Exited(exit_code) => (EXITED_OUTCOME_BYTE, exit_code),
        ChildOutcome::Signaled(signal) => (SIGNALED_OUTCOME_BYTE, signal),
    };
    channel
        .write_all(&[kind])
        .and_then(|()| channel.write_all(&value.to_be_bytes()))
        .map_err(|error| {
            supervisor_error(
                ErrorCode::Unavailable,
                format!("failed to report supervised payload outcome: {error}"),
            )
        })
}

pub(super) fn read_supervised_outcome(channel: &mut UnixStream) -> Result<Option<ChildOutcome>> {
    let mut kind = [0_u8; 1];
    let read = channel.read(&mut kind).map_err(|error| {
        supervisor_error(
            ErrorCode::Unavailable,
            format!("failed to read supervised payload outcome: {error}"),
        )
    })?;
    if read == 0 {
        return Ok(None);
    }
    let mut encoded_value = [0_u8; size_of::<i32>()];
    channel.read_exact(&mut encoded_value).map_err(|error| {
        supervisor_error(
            ErrorCode::Unavailable,
            format!("supervised payload outcome was truncated: {error}"),
        )
    })?;
    let value = i32::from_be_bytes(encoded_value);
    match kind[0] {
        EXITED_OUTCOME_BYTE if (0..=255).contains(&value) => Ok(Some(ChildOutcome::Exited(value))),
        SIGNALED_OUTCOME_BYTE if is_valid_signal(value) => Ok(Some(ChildOutcome::Signaled(value))),
        other => Err(supervisor_error(
            ErrorCode::FailedPrecondition,
            format!("supervised payload returned invalid outcome kind {other:#04x} value {value}"),
        )),
    }
}

pub(super) fn mirror_child_outcome(outcome: ChildOutcome) -> ! {
    match outcome {
        ChildOutcome::Exited(exit_code) => {
            // SAFETY: `_exit` has no memory-safety preconditions and bypasses
            // Rust destructors intentionally in this dedicated wrapper.
            unsafe { libc::_exit(exit_code) }
        }
        ChildOutcome::Signaled(signal) => mirror_signal(signal),
    }
}

pub(super) fn terminate_pid(pid: libc::pid_t) {
    if pid > 0 {
        // SAFETY: `pid` is a positive child PID and SIGKILL has no pointer
        // preconditions.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
}

pub(super) fn establish_process_group() -> Result<()> {
    // SAFETY: getpid and getpgrp have no preconditions.
    let (pid, process_group) = unsafe { (libc::getpid(), libc::getpgrp()) };
    if pid <= 0 {
        return Err(supervisor_error(
            ErrorCode::Internal,
            format!("configured workload reported invalid PID {pid}"),
        ));
    }
    if process_group == pid {
        return Ok(());
    }
    // Linux reports PGID 0 when the inherited process-group leader is not
    // visible in the current PID namespace. Treat that as requiring a local
    // group rather than rejecting a valid namespace child.
    // SAFETY: zero selects the current process and requests a new process
    // group led by that process before untrusted workload code is released.
    if unsafe { libc::setpgid(0, 0) } == 0 {
        Ok(())
    } else {
        Err(last_os_error("create configured workload process group"))
    }
}

pub(super) fn establish_process_session() -> Result<()> {
    // SAFETY: getpid, getpgrp, and getsid with PID zero have no pointer
    // arguments and inspect only the calling process.
    let (pid, process_group, session) =
        unsafe { (libc::getpid(), libc::getpgrp(), libc::getsid(0)) };
    if pid <= 0 || process_group < 0 || session < 0 {
        return Err(last_os_error("inspect configured workload session"));
    }
    if process_group == pid && session == pid {
        return Ok(());
    }
    if process_group == pid {
        return Err(supervisor_error(
            ErrorCode::FailedPrecondition,
            format!(
                "configured workload PID {pid} is already a process-group leader in external session {session}"
            ),
        ));
    }
    // SAFETY: the configured non-terminal payload is a freshly forked child
    // that has not yet executed untrusted code. A new session also creates the
    // PID-led process group used by exact descendant signaling and prevents a
    // Host controlling terminal from entering a portable checkpoint image.
    let created = unsafe { libc::setsid() };
    if created == pid {
        Ok(())
    } else if created < 0 {
        Err(last_os_error("create configured workload session"))
    } else {
        Err(supervisor_error(
            ErrorCode::Internal,
            format!("setsid returned unexpected session ID {created} for workload PID {pid}"),
        ))
    }
}

pub(super) fn signal_process_group(leader_pid: libc::pid_t, signal: i32) -> Result<()> {
    if leader_pid <= 0 {
        return Err(supervisor_error(
            ErrorCode::InvalidArgument,
            format!("process-group leader PID must be positive; received {leader_pid}"),
        ));
    }
    validate_process_group_signal(signal)?;
    // SAFETY: a negative PID targets the process group whose leader identity
    // the caller retains through a pidfd or non-reaping wait ownership.
    if unsafe { libc::kill(-leader_pid, signal) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    let code = match error.raw_os_error() {
        Some(libc::ESRCH) => ErrorCode::FailedPrecondition,
        Some(libc::EPERM) | Some(libc::EACCES) => ErrorCode::PermissionDenied,
        Some(libc::EINVAL) => ErrorCode::InvalidArgument,
        _ => ErrorCode::Internal,
    };
    Err(supervisor_error(
        code,
        format!("signal process group {leader_pid} with signal {signal} failed: {error}"),
    ))
}

pub(super) fn validate_process_group_signal(signal: i32) -> Result<()> {
    if is_valid_signal(signal) {
        Ok(())
    } else {
        Err(supervisor_error(
            ErrorCode::InvalidArgument,
            format!(
                "process-group signal must be a valid positive Linux signal; received {signal}"
            ),
        ))
    }
}

pub(super) fn terminate_process_group(leader_pid: libc::pid_t) {
    let _ = signal_process_group(leader_pid, libc::SIGKILL);
}

pub(super) fn arm_parent_death_signal(role: &str) -> Result<()> {
    // SAFETY: `prctl` receives only integer arguments. A fatal parent-death
    // signal prevents either internal wrapper from becoming detached from its
    // authenticated owner.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } == 0 {
        Ok(())
    } else {
        Err(last_os_error(&format!("arm {role} parent-death signal")))
    }
}

pub(super) fn verify_and_arm_parent_death_signal(
    expected_parent: libc::pid_t,
    role: &str,
) -> Result<()> {
    if expected_parent <= 0 {
        return Err(supervisor_error(
            ErrorCode::InvalidArgument,
            format!("{role} expected a positive parent PID; received {expected_parent}"),
        ));
    }
    // SAFETY: `getppid` has no preconditions. Checking before and after
    // `prctl` closes both sides of the inspection-to-arm race: a child never
    // authenticates a reaper as its owner, and a death between the first
    // check and `prctl` is detected even though PDEATHSIG is not retroactive.
    let observed_parent = unsafe { libc::getppid() };
    if observed_parent != expected_parent {
        return Err(supervisor_error(
            ErrorCode::PermissionDenied,
            format!(
                "{role} parent changed from authenticated PID {expected_parent} to {observed_parent} before supervision was armed"
            ),
        ));
    }
    arm_parent_death_signal(role)?;
    // SAFETY: `getppid` has no preconditions.
    let observed_parent = unsafe { libc::getppid() };
    if observed_parent != expected_parent {
        return Err(supervisor_error(
            ErrorCode::Unavailable,
            format!(
                "{role} parent changed from authenticated PID {expected_parent} to {observed_parent} while supervision was armed"
            ),
        ));
    }
    Ok(())
}

fn wait_for_child_without_reaping(pid: libc::pid_t) -> Result<ChildOutcome> {
    loop {
        // SAFETY: an all-zero siginfo_t is the required input sentinel and
        // waitid initializes it for the exact selected child.
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        // SAFETY: `info` points to writable storage and `pid` is the positive
        // direct child retained by this supervisor. WNOWAIT preserves its PID
        // and process-group identity until descendant cleanup is complete.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if result == 0 {
            // SAFETY: successful waitid initialized the child identity.
            let reported_pid = unsafe { info.si_pid() };
            if reported_pid != pid {
                return Err(supervisor_error(
                    ErrorCode::PermissionDenied,
                    format!(
                        "waitid reported configured payload PID {reported_pid}, expected {pid}"
                    ),
                ));
            }
            return decode_siginfo(&info);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(supervisor_error(
            error_code(&error),
            format!("inspect configured payload without reaping failed: {error}"),
        ));
    }
}

fn wait_for_any_child_without_reaping() -> Result<(libc::pid_t, ChildOutcome)> {
    loop {
        // SAFETY: an all-zero siginfo_t is the required input sentinel and
        // waitid initializes it for one waitable child. WNOWAIT retains the
        // child PID so its identity cannot be reused before cleanup.
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        // SAFETY: `info` points to writable storage. P_ALL with id zero waits
        // for one child owned by this namespace init.
        let result =
            unsafe { libc::waitid(libc::P_ALL, 0, &mut info, libc::WEXITED | libc::WNOWAIT) };
        if result == 0 {
            // SAFETY: successful waitid initialized the child identity.
            let pid = unsafe { info.si_pid() };
            if pid <= 0 {
                return Err(supervisor_error(
                    ErrorCode::Internal,
                    format!("waitid reported non-positive namespace child PID {pid}"),
                ));
            }
            return decode_siginfo(&info).map(|outcome| (pid, outcome));
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(supervisor_error(
            error_code(&error),
            format!("inspect namespace child without reaping failed: {error}"),
        ));
    }
}

fn peek_child_outcome(pid: libc::pid_t) -> Result<Option<ChildOutcome>> {
    // SAFETY: an all-zero siginfo_t is the required sentinel for WNOHANG;
    // waitid initializes it when the selected child has changed state.
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    // SAFETY: `info` points to writable storage and `pid` identifies the
    // direct child retained by this supervisor. WNOWAIT leaves the child
    // waitable so its PID and process-group identity cannot be reused yet.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(None);
        }
        return Err(supervisor_error(
            error_code(&error),
            format!("inspect supervised exec payload failed: {error}"),
        ));
    }
    // SAFETY: waitid initialized the child identity when si_pid is non-zero.
    let reported_pid = unsafe { info.si_pid() };
    if reported_pid == 0 {
        return Ok(None);
    }
    if reported_pid != pid {
        return Err(supervisor_error(
            ErrorCode::PermissionDenied,
            format!(
                "waitid reported exec payload PID {reported_pid}, expected supervised child {pid}"
            ),
        ));
    }
    decode_siginfo(&info).map(Some)
}

fn decode_siginfo(info: &libc::siginfo_t) -> Result<ChildOutcome> {
    // SAFETY: the caller received this record from a successful waitid call.
    let status = unsafe { info.si_status() };
    match info.si_code {
        libc::CLD_EXITED if (0..=255).contains(&status) => Ok(ChildOutcome::Exited(status)),
        libc::CLD_KILLED | libc::CLD_DUMPED if is_valid_signal(status) => {
            Ok(ChildOutcome::Signaled(status))
        }
        code => Err(supervisor_error(
            ErrorCode::Internal,
            format!("child produced unsupported waitid code {code} status {status}"),
        )),
    }
}

fn terminate_visible_descendants() -> Result<()> {
    // SAFETY: from namespace PID 1, PID -1 addresses only visible descendants
    // and excludes the caller.
    let killed = unsafe { libc::kill(-1, libc::SIGKILL) };
    if killed == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(supervisor_error(
            error_code(&error),
            format!("terminate remaining PID namespace processes failed: {error}"),
        ))
    }
}

fn terminate_and_reap_remaining_children() -> Result<()> {
    loop {
        // Repeating the signal after every reap closes races with descendants
        // that fork while teardown begins.
        terminate_visible_descendants()?;

        let mut status = 0;
        // SAFETY: `status` points to writable storage. PID -1 waits for one
        // remaining adopted descendant.
        let waited = unsafe { libc::waitpid(-1, &mut status, 0) };
        if waited > 0 {
            decode_wait_status(status)?;
            continue;
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.raw_os_error() == Some(libc::ECHILD) {
            return Ok(());
        }
        return Err(supervisor_error(
            error_code(&error),
            format!("reap remaining PID namespace processes failed: {error}"),
        ));
    }
}

fn decode_wait_status(status: i32) -> Result<ChildOutcome> {
    if libc::WIFEXITED(status) {
        return Ok(ChildOutcome::Exited(libc::WEXITSTATUS(status)));
    }
    if libc::WIFSIGNALED(status) {
        return Ok(ChildOutcome::Signaled(libc::WTERMSIG(status)));
    }
    Err(supervisor_error(
        ErrorCode::Internal,
        format!("namespace child produced unsupported wait status {status:#x}"),
    ))
}

fn mirror_signal(signal: i32) -> ! {
    if !matches!(signal, libc::SIGKILL | libc::SIGSTOP) {
        // SAFETY: `signal` came from `waitpid`; SIG_DFL is a valid disposition.
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
        }
        // SAFETY: the signal-set pointer is initialized before it is supplied
        // to `sigprocmask`, and the old mask is intentionally not retained.
        unsafe {
            let mut set = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, signal);
            libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        }
    }
    // SAFETY: `getpid` has no preconditions and `signal` is the positive value
    // reported by `waitpid`.
    unsafe {
        libc::kill(libc::getpid(), signal);
        libc::_exit(128_i32.saturating_add(signal).min(255));
    }
}

fn is_valid_signal(signal: i32) -> bool {
    (1..=libc::SIGRTMAX()).contains(&signal)
}

fn error_code(error: &io::Error) -> ErrorCode {
    if matches!(error.raw_os_error(), Some(libc::EACCES) | Some(libc::EPERM)) {
        ErrorCode::PermissionDenied
    } else {
        ErrorCode::Internal
    }
}

fn last_os_error(operation: &str) -> Error {
    let error = io::Error::last_os_error();
    supervisor_error(error_code(&error), format!("{operation} failed: {error}"))
}

fn supervisor_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("run-container-init")
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    use super::{
        decode_wait_status, establish_process_session, peek_child_outcome, read_supervised_outcome,
        report_supervised_outcome, terminate_pid, wait_for_child, ChildOutcome,
        EXITED_OUTCOME_BYTE,
    };

    #[test]
    fn supervised_outcome_round_trip_preserves_exit_and_signal_results() {
        for outcome in [
            ChildOutcome::Exited(42),
            ChildOutcome::Signaled(libc::SIGKILL),
        ] {
            let (mut writer, mut reader) = UnixStream::pair().expect("outcome channel");
            report_supervised_outcome(&mut writer, outcome).expect("report outcome");
            drop(writer);
            assert_eq!(
                read_supervised_outcome(&mut reader).expect("read outcome"),
                Some(outcome)
            );
        }
    }

    #[test]
    fn supervised_outcome_distinguishes_clean_eof_from_truncation() {
        let (writer, mut reader) = UnixStream::pair().expect("empty outcome channel");
        drop(writer);
        assert_eq!(
            read_supervised_outcome(&mut reader).expect("read clean EOF"),
            None
        );

        let (mut writer, mut reader) = UnixStream::pair().expect("truncated outcome channel");
        writer
            .write_all(&[EXITED_OUTCOME_BYTE, 0])
            .expect("write truncated outcome");
        drop(writer);
        assert!(read_supervised_outcome(&mut reader).is_err());
    }

    #[test]
    fn decodes_normal_and_signal_wait_statuses() {
        assert_eq!(
            decode_wait_status(42 << 8).expect("normal exit status"),
            ChildOutcome::Exited(42)
        );
        assert_eq!(
            decode_wait_status(libc::SIGKILL).expect("signal status"),
            ChildOutcome::Signaled(libc::SIGKILL)
        );
    }

    #[test]
    fn non_terminal_workload_gets_an_idempotent_private_session() {
        // SAFETY: the child performs only bounded libc identity calls before
        // exiting; the parent retains and reaps the exact returned PID.
        let pid = unsafe { libc::fork() };
        assert!(
            pid >= 0,
            "fork session test child: {}",
            std::io::Error::last_os_error()
        );
        if pid == 0 {
            let valid = establish_process_session().is_ok()
                && establish_process_session().is_ok()
                // SAFETY: these identity syscalls have no preconditions.
                && unsafe { libc::getsid(0) } == unsafe { libc::getpid() }
                // SAFETY: these identity syscalls have no preconditions.
                && unsafe { libc::getpgrp() } == unsafe { libc::getpid() };
            // SAFETY: bypassing destructors is intentional in the fork child.
            unsafe { libc::_exit(if valid { 0 } else { 101 }) }
        }
        assert_eq!(
            wait_for_child(pid).expect("reap session test child"),
            ChildOutcome::Exited(0)
        );
    }

    #[test]
    fn peeks_exec_child_outcome_without_reaping_or_releasing_its_pid() {
        // SAFETY: the test child exits immediately without touching shared
        // state; the parent retains and reaps the exact returned PID.
        let pid = unsafe { libc::fork() };
        assert!(
            pid >= 0,
            "fork test child: {}",
            std::io::Error::last_os_error()
        );
        if pid == 0 {
            // SAFETY: bypassing destructors is intentional in the fork child.
            unsafe { libc::_exit(23) }
        }

        let started = Instant::now();
        let outcome = loop {
            match peek_child_outcome(pid).expect("peek child outcome") {
                Some(outcome) => break outcome,
                None if started.elapsed() < Duration::from_secs(2) => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                None => {
                    terminate_pid(pid);
                    let _ = wait_for_child(pid);
                    panic!("test child did not become waitable");
                }
            }
        };
        assert_eq!(outcome, ChildOutcome::Exited(23));
        assert_eq!(
            wait_for_child(pid).expect("child must remain reapable after WNOWAIT"),
            outcome
        );
    }
}
