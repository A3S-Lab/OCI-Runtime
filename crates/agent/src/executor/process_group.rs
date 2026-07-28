use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::Path;

use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::pid_supervisor;
use super::pidfd::{PidFd, SignalOutcome};

#[derive(Debug)]
pub(super) struct ProcessGroupLease {
    directory: File,
}

impl ProcessGroupLease {
    pub(super) async fn open_for_snapshot(snapshot: &Path) -> Result<Self> {
        let directory = snapshot_directory(snapshot)?;
        let file = tokio::fs::File::open(directory).await.map_err(|error| {
            lease_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to open process-group lease directory {}: {error}",
                    directory.display()
                ),
            )
        })?;
        Self::validated(file.into_std().await)
    }

    pub(super) fn open_for_snapshot_sync(snapshot: &Path) -> Result<Self> {
        let directory = snapshot_directory(snapshot)?;
        let directory = File::open(directory).map_err(|error| {
            lease_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to open process-group lease directory {}: {error}",
                    directory.display()
                ),
            )
        })?;
        Self::validated(directory)
    }

    pub(super) fn signal(&self, pidfd: &PidFd, signal: i32) -> Result<SignalOutcome> {
        pid_supervisor::validate_process_group_signal(signal)?;
        let Some(guard) = self.try_lock()? else {
            // A supervisor takes this lock only after the exact leader is
            // waitable and before it can be reaped. It owns descendant cleanup,
            // so a concurrent caller must not resolve the numeric PGID again.
            return Ok(SignalOutcome::Exited);
        };
        let outcome = match pidfd.send_signal(0) {
            Ok(SignalOutcome::Delivered) => {
                pid_supervisor::signal_process_group(pidfd.pid(), signal)
                    .map(|()| SignalOutcome::Delivered)
            }
            Ok(SignalOutcome::Exited) => Ok(SignalOutcome::Exited),
            Err(error) => Err(error),
        };
        let unlocked = guard.unlock();
        match (outcome, unlocked) {
            (Ok(outcome), Ok(())) => Ok(outcome),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(unlock)) => Err(Error::new(
                error.code,
                format!("{error}; additionally failed to release process-group lease: {unlock}"),
            )
            .for_operation("signal-process-group")
            .retryable(error.retryable)),
        }
    }

    pub(super) fn lock_for_reap(&self) -> Result<ProcessGroupLeaseGuard<'_>> {
        self.lock(false)?.ok_or_else(|| {
            lease_error(
                ErrorCode::Internal,
                "blocking process-group lease acquisition returned no guard",
            )
        })
    }

    fn validated(directory: File) -> Result<Self> {
        ensure_close_on_exec(&directory)?;
        let lease = Self { directory };
        let guard = lease.try_lock()?.ok_or_else(|| {
            lease_error(
                ErrorCode::Conflict,
                "new process-group lease directory is already locked",
            )
        })?;
        guard.unlock()?;
        Ok(lease)
    }

    fn try_lock(&self) -> Result<Option<ProcessGroupLeaseGuard<'_>>> {
        self.lock(true)
    }

    fn lock(&self, nonblocking: bool) -> Result<Option<ProcessGroupLeaseGuard<'_>>> {
        let operation = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
        loop {
            // SAFETY: `directory` is a live descriptor owned by this lease;
            // flock changes only the advisory lock associated with it.
            if unsafe { libc::flock(self.directory.as_raw_fd(), operation) } == 0 {
                return Ok(Some(ProcessGroupLeaseGuard {
                    lease: self,
                    locked: true,
                }));
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if nonblocking && error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Ok(None);
            }
            return Err(lock_error("acquire", error));
        }
    }
}

fn ensure_close_on_exec(file: &File) -> Result<()> {
    // SAFETY: F_GETFD reads flags from this live owned descriptor.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(lock_error(
            "inspect close-on-exec on",
            io::Error::last_os_error(),
        ));
    }
    if flags & libc::FD_CLOEXEC != 0 {
        return Ok(());
    }
    // SAFETY: F_SETFD changes only descriptor flags for this owned file.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } == 0 {
        Ok(())
    } else {
        Err(lock_error(
            "set close-on-exec on",
            io::Error::last_os_error(),
        ))
    }
}

pub(super) struct ProcessGroupLeaseGuard<'a> {
    lease: &'a ProcessGroupLease,
    locked: bool,
}

impl ProcessGroupLeaseGuard<'_> {
    pub(super) fn unlock(mut self) -> Result<()> {
        self.unlock_inner()?;
        self.locked = false;
        Ok(())
    }

    fn unlock_inner(&self) -> Result<()> {
        // SAFETY: this guard was created only after locking the live lease
        // descriptor and releases that exact advisory lock.
        if unsafe { libc::flock(self.lease.directory.as_raw_fd(), libc::LOCK_UN) } == 0 {
            Ok(())
        } else {
            Err(lock_error("release", io::Error::last_os_error()))
        }
    }
}

impl Drop for ProcessGroupLeaseGuard<'_> {
    fn drop(&mut self) {
        if self.locked {
            let _ = self.unlock_inner();
        }
    }
}

fn snapshot_directory(snapshot: &Path) -> Result<&Path> {
    snapshot.parent().ok_or_else(|| {
        lease_error(
            ErrorCode::InvalidArgument,
            format!(
                "process-group snapshot has no owning directory: {}",
                snapshot.display()
            ),
        )
    })
}

fn lock_error(operation: &str, error: io::Error) -> Error {
    let code = match error.raw_os_error() {
        Some(libc::EACCES) | Some(libc::EPERM) => ErrorCode::PermissionDenied,
        Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => ErrorCode::Unsupported,
        _ => ErrorCode::Internal,
    };
    lease_error(
        code,
        format!("failed to {operation} process-group lease: {error}"),
    )
}

fn lease_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("process-group-lease")
}
