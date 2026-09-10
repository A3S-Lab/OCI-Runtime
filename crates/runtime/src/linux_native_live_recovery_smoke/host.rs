//! Spawn / SIGKILL / reclaim helpers for `native-linux-host-service`.

use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use a3s_oci_sdk::{LocalIpcEndpoint, RuntimeClient};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout, Instant};

use crate::native_hook_recovery_smoke::{
    capture_native_process_identity, NativeLinuxProcessIdentity,
};

const START_TIMEOUT: Duration = Duration::from_secs(20);
const STOP_TIMEOUT: Duration = Duration::from_secs(45);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const SESSION_SUPERVISOR_ENV: &str = "A3S_OCI_NATIVE_SESSION_SUPERVISOR";

pub(super) struct HostServiceProcess {
    child: Child,
    socket: PathBuf,
}

impl HostServiceProcess {
    pub(super) async fn spawn(
        executable: &Path,
        root: &Path,
        agent: &Path,
        stdout: &Path,
        stderr: &Path,
    ) -> Result<Self, String> {
        let stdout = create_private_log(stdout, "native Host Service stdout")?;
        let stderr = create_private_log(stderr, "native Host Service stderr")?;
        let child = Command::new(executable)
            .arg("native-linux-host-service")
            .arg("--root")
            .arg(root)
            .arg("--agent")
            .arg(agent)
            .env(SESSION_SUPERVISOR_ENV, "1")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| format!("failed to start native-linux-host-service: {error}"))?;
        let mut process = Self {
            child,
            socket: root.join("runtime.sock"),
        };
        match process.wait_for_private_socket().await {
            Ok(()) => Ok(process),
            Err(primary) => {
                process.emergency_stop().await;
                Err(primary)
            }
        }
    }

    pub(super) fn pid(&self) -> Result<u32, String> {
        self.child
            .id()
            .ok_or_else(|| "native Host Service has no live PID".to_string())
    }

    pub(super) fn identity(&self) -> Result<NativeLinuxProcessIdentity, String> {
        capture_native_process_identity(self.pid()?)
    }

    pub(super) fn socket_path(&self) -> &Path {
        &self.socket
    }

    pub(super) async fn connect(&self) -> Result<RuntimeClient, String> {
        let endpoint = LocalIpcEndpoint::unix_socket(&self.socket)
            .map_err(|error| format!("failed to configure native Host endpoint: {error}"))?;
        timeout(START_TIMEOUT, RuntimeClient::connect(&endpoint))
            .await
            .map_err(|_| "timed out connecting to native Host Service".to_string())?
            .map_err(|error| format!("failed to connect native Host Service: {error}"))
    }

    pub(super) async fn sigkill(&mut self) -> Result<(), String> {
        let pid = libc::pid_t::try_from(self.pid()?)
            .map_err(|error| format!("native Host Service PID is invalid: {error}"))?;
        // SAFETY: pid identifies the exact retained child; SIGKILL is the
        // qualification's deliberate uncatchable owner-death boundary.
        if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
            return Err(format!(
                "failed to SIGKILL native Host Service: {}",
                io::Error::last_os_error()
            ));
        }
        let status = timeout(STOP_TIMEOUT, self.child.wait())
            .await
            .map_err(|_| "timed out reaping SIGKILLed native Host Service".to_string())?
            .map_err(|error| format!("failed to reap SIGKILLed native Host Service: {error}"))?;
        if status.signal() != Some(libc::SIGKILL) {
            return Err(format!(
                "native Host Service exited with {status}, expected SIGKILL"
            ));
        }
        Ok(())
    }

    pub(super) async fn terminate(&mut self) -> Result<bool, String> {
        let pid = libc::pid_t::try_from(self.pid()?)
            .map_err(|error| format!("native Host Service PID is invalid: {error}"))?;
        // SAFETY: pid identifies the exact retained child; SIGTERM is the
        // normal graceful Host Service shutdown request.
        if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(format!("failed to terminate native Host Service: {error}"));
            }
        }
        match timeout(STOP_TIMEOUT, self.child.wait()).await {
            Ok(Ok(status)) => Ok(status.success()),
            Ok(Err(error)) => Err(format!("failed to reap native Host Service: {error}")),
            Err(_) => {
                let _ = self.child.kill().await;
                let _ = self.child.wait().await;
                Err("native Host Service did not stop after SIGTERM".to_string())
            }
        }
    }

    pub(super) async fn emergency_stop(&mut self) {
        if self.child.id().is_none() {
            return;
        }
        let _ = self.child.kill().await;
        let _ = timeout(STOP_TIMEOUT, self.child.wait()).await;
    }

    async fn wait_for_private_socket(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|error| format!("failed to inspect native Host Service: {error}"))?
            {
                return Err(format!(
                    "native Host Service exited before publishing its socket: {status}"
                ));
            }
            match std::fs::symlink_metadata(&self.socket) {
                Ok(metadata) => {
                    // SAFETY: geteuid has no preconditions or failure result.
                    let uid = unsafe { libc::geteuid() };
                    if !metadata.file_type().is_socket()
                        || metadata.uid() != uid
                        || metadata.mode() & 0o777 != 0o600
                    {
                        return Err(format!(
                            "native Host Service endpoint is not a same-UID mode-0600 socket: {}",
                            self.socket.display()
                        ));
                    }
                    if tokio::net::UnixStream::connect(&self.socket).await.is_ok() {
                        return Ok(());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "failed to inspect native Host Service socket {}: {error}",
                        self.socket.display()
                    ));
                }
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for native Host Service socket".to_string());
            }
            sleep(POLL_INTERVAL).await;
        }
    }
}

/// Reclaim a verified dead owner socket so a replacement Host can bind the same root.
pub(super) fn reclaim_dead_owner_socket(path: &Path) -> Result<(), String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "failed to inspect stale native Host socket {}: {error}",
                path.display()
            ));
        }
    };
    // SAFETY: geteuid has no preconditions or failure result.
    let uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_socket() || metadata.uid() != uid {
        return Err(format!(
            "refusing to remove stale native Host path {}; expected same-UID socket",
            path.display()
        ));
    }
    // Prove the listener is gone (ConnectionRefused / NotFound) before unlink.
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => {
            return Err(format!(
                "native Host socket still has a live listener: {}",
                path.display()
            ));
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) => {}
        Err(error) => {
            return Err(format!(
                "could not prove native Host socket {} is stale: {error}",
                path.display()
            ));
        }
    }
    std::fs::remove_file(path).map_err(|error| {
        format!(
            "failed to remove stale native Host socket {}: {error}",
            path.display()
        )
    })
}

pub(super) fn process_still_live(identity: &NativeLinuxProcessIdentity) -> Result<bool, String> {
    match capture_native_process_identity(identity.pid) {
        Ok(observed) => Ok(observed.start_time_ticks == identity.start_time_ticks),
        Err(_) => Ok(false),
    }
}

fn create_private_log(path: &Path, label: &str) -> Result<std::fs::File, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            format!("failed to create {label} parent {}: {error}", parent.display())
        })?;
    }
    let mut options = std::fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    options
        .open(path)
        .map_err(|error| format!("failed to create {label} {}: {error}", path.display()))
}
