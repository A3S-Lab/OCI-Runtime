use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::sync::Arc;

use a3s_oci_agent::InheritedDescriptorPlan;
use a3s_oci_sdk::{Error, ErrorCode, Result};

/// Exec listener descriptor consumed by A3S Box guest init.
pub const EXEC_LISTENER_FD: i32 = 3;
/// PTY listener descriptor consumed by A3S Box guest init.
pub const PTY_LISTENER_FD: i32 = 4;
/// Dedicated init-log descriptor consumed by A3S Box guest init.
pub const INIT_LOG_FD: i32 = 5;

/// Native A3S Box control resources attached to one OCI create.
///
/// The runtime validates both listeners as bound Unix stream listeners and the
/// log as a writable regular file. It then exposes them only to the configured
/// init process as descriptors 3, 4, and 5. Clones share the same host handles
/// and are intended only for exact create retries.
#[derive(Debug, Clone)]
pub struct NativeControlDescriptors {
    exec_listener: Arc<UnixListener>,
    pty_listener: Arc<UnixListener>,
    init_log: Arc<File>,
}

impl NativeControlDescriptors {
    /// Own and validate the exact A3S Box listener and log resources.
    pub fn new(
        exec_listener: UnixListener,
        pty_listener: UnixListener,
        init_log: File,
    ) -> Result<Self> {
        let descriptors = Self {
            exec_listener: Arc::new(exec_listener),
            pty_listener: Arc::new(pty_listener),
            init_log: Arc::new(init_log),
        };
        descriptors.descriptor_plan()?;
        Ok(descriptors)
    }

    /// Duplicate and own inherited A3S Box control descriptor roles.
    ///
    /// The source descriptors remain owned by the caller. Each duplicate is
    /// revalidated as a bound Unix stream listener or writable regular file
    /// before it can be attached to a native create request.
    pub fn try_clone_from_fds(
        exec_listener: BorrowedFd<'_>,
        pty_listener: BorrowedFd<'_>,
        init_log: BorrowedFd<'_>,
    ) -> Result<Self> {
        let clone = |descriptor: BorrowedFd<'_>, role: &str| {
            descriptor.try_clone_to_owned().map_err(|error| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("failed to duplicate inherited {role} descriptor: {error}"),
                )
                .for_operation("open-native-control-descriptors")
            })
        };
        Self::new(
            UnixListener::from(clone(exec_listener, "exec listener")?),
            UnixListener::from(clone(pty_listener, "PTY listener")?),
            File::from(clone(init_log, "init log")?),
        )
    }

    /// Safely duplicate inherited raw descriptor numbers before validation.
    ///
    /// Unlike [`Self::try_clone_from_fds`], this entry point accepts descriptor
    /// numbers that may be closed. Invalid handles return a typed error without
    /// requiring the caller to construct an invalid [`BorrowedFd`].
    pub fn try_clone_from_raw_fds(
        exec_listener: RawFd,
        pty_listener: RawFd,
        init_log: RawFd,
    ) -> Result<Self> {
        let clone = |descriptor: RawFd, role: &str| {
            // SAFETY: fcntl reads the descriptor table and either returns a new
            // independently owned descriptor or -1 without taking ownership.
            let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 0) };
            if duplicate == -1 {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "failed to duplicate inherited {role} descriptor {descriptor}: {}",
                        std::io::Error::last_os_error()
                    ),
                )
                .for_operation("open-native-control-descriptors"));
            }
            // SAFETY: a successful F_DUPFD_CLOEXEC result is a fresh descriptor
            // whose ownership is transferred into this OwnedFd exactly once.
            Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
        };
        Self::new(
            UnixListener::from(clone(exec_listener, "exec listener")?),
            UnixListener::from(clone(pty_listener, "PTY listener")?),
            File::from(clone(init_log, "init log")?),
        )
    }

    pub(crate) fn descriptor_plan(&self) -> Result<InheritedDescriptorPlan> {
        InheritedDescriptorPlan::a3s_box_control(
            self.exec_listener.as_fd(),
            self.pty_listener.as_fd(),
            self.init_log.as_fd(),
        )
    }
}

impl PartialEq for NativeControlDescriptors {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.exec_listener, &other.exec_listener)
            && Arc::ptr_eq(&self.pty_listener, &other.pty_listener)
            && Arc::ptr_eq(&self.init_log, &other.init_log)
    }
}

impl Eq for NativeControlDescriptors {}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixListener;

    use a3s_oci_sdk::ErrorCode;

    use super::NativeControlDescriptors;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn native_control_descriptors_are_send_sync_and_validate_roles() {
        assert_send_sync::<NativeControlDescriptors>();
        let temporary = tempfile::tempdir().expect("temporary directory");
        let exec = UnixListener::bind(temporary.path().join("exec.sock")).expect("exec listener");
        let pty = UnixListener::bind(temporary.path().join("pty.sock")).expect("PTY listener");
        let log = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(temporary.path().join("init.log"))
            .expect("init log");
        let descriptors = NativeControlDescriptors::new(exec, pty, log)
            .expect("valid native control descriptors");
        assert_eq!(descriptors, descriptors.clone());

        let exec =
            UnixListener::bind(temporary.path().join("exec-2.sock")).expect("second exec listener");
        let pty =
            UnixListener::bind(temporary.path().join("pty-2.sock")).expect("second PTY listener");
        let readonly = OpenOptions::new()
            .read(true)
            .open(temporary.path().join("init.log"))
            .expect("readonly init log");
        let error = NativeControlDescriptors::new(exec, pty, readonly)
            .expect_err("readonly init log must fail");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("writable"));
    }

    #[test]
    fn native_control_descriptors_clone_inherited_roles_without_aliasing_sources() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let exec = UnixListener::bind(temporary.path().join("exec.sock")).expect("exec listener");
        let pty = UnixListener::bind(temporary.path().join("pty.sock")).expect("PTY listener");
        let log = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(temporary.path().join("init.log"))
            .expect("init log");

        let descriptors =
            NativeControlDescriptors::try_clone_from_fds(exec.as_fd(), pty.as_fd(), log.as_fd())
                .expect("clone inherited descriptor roles");
        drop((exec, pty, log));
        descriptors
            .descriptor_plan()
            .expect("cloned descriptors must own independent live handles");
    }

    #[test]
    fn raw_descriptor_clone_rejects_closed_roles_without_borrowing_them() {
        let error = NativeControlDescriptors::try_clone_from_raw_fds(-1, -1, -1)
            .expect_err("closed raw descriptor must fail");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("exec listener descriptor -1"));
    }
}
