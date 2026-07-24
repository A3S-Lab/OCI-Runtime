use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use a3s_oci_sdk::{Error, ErrorCode, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SignalOutcome {
    Delivered,
    Exited,
}

#[derive(Debug)]
pub(super) struct PidFd {
    descriptor: OwnedFd,
    pid: i32,
}

impl PidFd {
    pub(super) fn open(pid: i32) -> Result<Self> {
        if pid <= 0 {
            return Err(pidfd_error(
                ErrorCode::InvalidArgument,
                format!("pidfd requires a positive process ID; received {pid}"),
            ));
        }
        // SAFETY: `pidfd_open` takes only integer arguments. Flags are zero as
        // required by the current Linux ABI.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
        if descriptor < 0 {
            return Err(last_pidfd_error("open", pid, None));
        }
        let descriptor = i32::try_from(descriptor).map_err(|error| {
            pidfd_error(
                ErrorCode::ResourceExhausted,
                format!("pidfd descriptor does not fit the process descriptor model: {error}"),
            )
        })?;
        // SAFETY: the successful `pidfd_open` call returned one new owned file
        // descriptor. `OwnedFd` closes it exactly once.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        Ok(Self { descriptor, pid })
    }

    pub(super) fn send_signal(&self, signal: i32) -> Result<SignalOutcome> {
        if signal < 0 {
            return Err(pidfd_error(
                ErrorCode::InvalidArgument,
                format!("pidfd signal must be non-negative; received {signal}"),
            ));
        }
        // SAFETY: the descriptor is a live pidfd owned by this value. A null
        // siginfo pointer asks the kernel to synthesize ordinary kill(2)
        // semantics, and flags must be zero for the current ABI.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.descriptor.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0_u32,
            )
        };
        if result == 0 {
            return Ok(SignalOutcome::Delivered);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(SignalOutcome::Exited)
        } else {
            Err(map_pidfd_error(
                "send signal through",
                Some(self.pid),
                Some(signal),
                error,
            ))
        }
    }
}

pub(crate) fn verify_support() -> Result<()> {
    let pid = i32::try_from(std::process::id()).map_err(|error| {
        pidfd_error(
            ErrorCode::ResourceExhausted,
            format!("current process ID does not fit the pidfd process model: {error}"),
        )
    })?;
    let pidfd = PidFd::open(pid)?;
    match pidfd.send_signal(0)? {
        SignalOutcome::Delivered => Ok(()),
        SignalOutcome::Exited => Err(pidfd_error(
            ErrorCode::Internal,
            "current process disappeared while probing pidfd signaling",
        )),
    }
}

fn last_pidfd_error(operation: &str, pid: i32, signal: Option<i32>) -> Error {
    map_pidfd_error(operation, Some(pid), signal, io::Error::last_os_error())
}

fn map_pidfd_error(
    operation: &str,
    pid: Option<i32>,
    signal: Option<i32>,
    error: io::Error,
) -> Error {
    let code = match error.raw_os_error() {
        Some(libc::ENOSYS) => ErrorCode::Unsupported,
        Some(libc::EINVAL) if signal.is_none() => ErrorCode::Unsupported,
        Some(libc::EINVAL) => ErrorCode::InvalidArgument,
        Some(libc::ESRCH) => ErrorCode::FailedPrecondition,
        Some(libc::EPERM) | Some(libc::EACCES) => ErrorCode::PermissionDenied,
        Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOMEM) => {
            ErrorCode::ResourceExhausted
        }
        _ => ErrorCode::Internal,
    };
    let target = pid.map_or_else(String::new, |pid| format!(" for PID {pid}"));
    let signal = signal.map_or_else(String::new, |signal| format!(" with signal {signal}"));
    pidfd_error(
        code,
        format!("failed to {operation} pidfd{target}{signal}: {error}"),
    )
}

fn pidfd_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("linux-pidfd")
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Child, Command};

    use a3s_oci_sdk::ErrorCode;

    use super::{PidFd, SignalOutcome};

    #[test]
    fn current_process_supports_pidfd_signaling() {
        let pid = i32::try_from(std::process::id()).expect("process ID fits i32");
        let pidfd = PidFd::open(pid).expect("open pidfd for current process");
        assert_eq!(
            pidfd
                .send_signal(0)
                .expect("probe current process through pidfd"),
            SignalOutcome::Delivered
        );
    }

    #[test]
    fn rejects_non_positive_process_ids_before_syscall() {
        for pid in [0, -1] {
            let error = PidFd::open(pid).expect_err("non-positive PID must fail");
            assert_eq!(error.code, ErrorCode::InvalidArgument);
        }
    }

    #[test]
    fn rejects_negative_signals_before_syscall() {
        let pid = i32::try_from(std::process::id()).expect("process ID fits i32");
        let pidfd = PidFd::open(pid).expect("open pidfd for current process");
        let error = pidfd
            .send_signal(-1)
            .expect_err("negative signal must fail");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn signals_the_opened_process_and_detects_its_exit() {
        struct ChildGuard(Child);

        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let mut child = ChildGuard(
            Command::new("/bin/sleep")
                .arg("30")
                .spawn()
                .expect("spawn test process"),
        );
        let pid = i32::try_from(child.0.id()).expect("child PID fits i32");
        let pidfd = PidFd::open(pid).expect("open child pidfd");
        assert_eq!(
            pidfd
                .send_signal(libc::SIGKILL)
                .expect("signal exact child"),
            SignalOutcome::Delivered
        );
        let status = child.0.wait().expect("reap signaled child");
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert_eq!(
            pidfd
                .send_signal(0)
                .expect("inspect exited child through retained pidfd"),
            SignalOutcome::Exited
        );
    }
}
