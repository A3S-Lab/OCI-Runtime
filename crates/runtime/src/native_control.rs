use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::net::UnixListener;
use std::sync::Arc;

use a3s_oci_agent::InheritedDescriptorPlan;
use a3s_oci_sdk::Result;

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
}
