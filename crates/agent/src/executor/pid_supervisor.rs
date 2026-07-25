use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use a3s_oci_sdk::{Error, ErrorCode, Result};

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

pub(super) fn supervise_payload(payload_pid: libc::pid_t) -> Result<ChildOutcome> {
    let payload_outcome = loop {
        let (waited, outcome) = wait_for_any_child()?;
        if waited == payload_pid {
            break outcome;
        }
    };
    terminate_and_reap_remaining_children()?;
    Ok(payload_outcome)
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

fn arm_parent_death_signal(role: &str) -> Result<()> {
    // SAFETY: `prctl` receives only integer arguments. A fatal parent-death
    // signal prevents either internal wrapper from becoming detached from its
    // authenticated owner.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } == 0 {
        Ok(())
    } else {
        Err(last_os_error(&format!("arm {role} parent-death signal")))
    }
}

fn wait_for_any_child() -> Result<(libc::pid_t, ChildOutcome)> {
    loop {
        let mut status = 0;
        // SAFETY: `status` points to writable storage. PID -1 waits for one
        // child owned by this namespace init.
        let waited = unsafe { libc::waitpid(-1, &mut status, 0) };
        if waited > 0 {
            return decode_wait_status(status).map(|outcome| (waited, outcome));
        }
        if waited < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(last_os_error("reap namespace child"));
    }
}

fn terminate_and_reap_remaining_children() -> Result<()> {
    loop {
        // SAFETY: from namespace PID 1, PID -1 addresses only visible
        // descendants and excludes the caller. Repeating the signal after
        // every reap closes races with descendants that fork while teardown
        // begins.
        let killed = unsafe { libc::kill(-1, libc::SIGKILL) };
        if killed != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(supervisor_error(
                    error_code(&error),
                    format!("terminate remaining PID namespace processes failed: {error}"),
                ));
            }
        }

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
    if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) {
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

    use super::{
        decode_wait_status, read_supervised_outcome, report_supervised_outcome, ChildOutcome,
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
}
