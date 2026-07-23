use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr as StdSocketAddr, UnixListener as StdUnixListener};
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use a3s_oci_agent_protocol::AgentVsockEndpoint;
use a3s_oci_sdk::{Error, ErrorCode, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::time::timeout;

use super::plan::InitPlan;

pub(super) const READY_BYTE: u8 = 0xA3;
pub(super) const START_BYTE: u8 = 0x5A;
const INIT_READY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub(super) struct PreparedProcess {
    child: Child,
    control: Option<UnixStream>,
    pid: i32,
}

impl PreparedProcess {
    pub(super) async fn spawn(plan: &InitPlan, config_snapshot: &Path) -> Result<Self> {
        let (listener, control_name) = bind_control_listener()?;
        let executable = std::env::current_exe().map_err(|error| {
            process_error(
                ErrorCode::Internal,
                format!("failed to resolve guest-agent executable: {error}"),
            )
        })?;
        let mut command = Command::new(executable);
        command
            .arg("container-init")
            .arg(config_snapshot)
            .arg(&plan.bundle_directory)
            .arg(&control_name)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|error| {
            process_error(
                ErrorCode::Internal,
                format!("failed to spawn prepared container init: {error}"),
            )
        })?;
        let Some(raw_pid) = child.id() else {
            terminate(&mut child).await;
            return Err(process_error(
                ErrorCode::Internal,
                "spawned container init has no live process ID",
            ));
        };
        let pid = match i32::try_from(raw_pid) {
            Ok(pid) => pid,
            Err(_) => {
                terminate(&mut child).await;
                return Err(process_error(
                    ErrorCode::ResourceExhausted,
                    format!("container init PID {raw_pid} does not fit the OCI state model"),
                ));
            }
        };

        enum ReadyOutcome {
            Connected(io::Result<(UnixStream, tokio::net::unix::SocketAddr)>),
            Exited(io::Result<ExitStatus>),
        }
        let ready = timeout(INIT_READY_TIMEOUT, async {
            tokio::select! {
                accepted = listener.accept() => ReadyOutcome::Connected(accepted),
                status = child.wait() => ReadyOutcome::Exited(status),
            }
        })
        .await;
        let mut control = match ready {
            Ok(ReadyOutcome::Connected(Ok((control, _)))) => control,
            Ok(ReadyOutcome::Connected(Err(error))) => {
                terminate(&mut child).await;
                return Err(process_error(
                    ErrorCode::Internal,
                    format!("failed to accept prepared init control connection: {error}"),
                ));
            }
            Ok(ReadyOutcome::Exited(Ok(status))) => {
                return Err(process_error(
                    ErrorCode::FailedPrecondition,
                    format!("container init rejected its plan and exited with {status}"),
                ));
            }
            Ok(ReadyOutcome::Exited(Err(error))) => {
                return Err(process_error(
                    ErrorCode::Internal,
                    format!("failed to wait for prepared container init: {error}"),
                ));
            }
            Err(_) => {
                terminate(&mut child).await;
                return Err(process_error(
                    ErrorCode::DeadlineExceeded,
                    "timed out waiting for the prepared container init",
                ));
            }
        };
        let peer = match control.peer_cred() {
            Ok(peer) => peer,
            Err(error) => {
                terminate(&mut child).await;
                return Err(process_error(
                    ErrorCode::Internal,
                    format!("failed to read prepared init peer credentials: {error}"),
                ));
            }
        };
        if peer.pid() != Some(pid) {
            terminate(&mut child).await;
            return Err(process_error(
                ErrorCode::PermissionDenied,
                format!(
                    "init control peer PID {:?} does not match spawned PID {pid}",
                    peer.pid()
                ),
            ));
        }
        let mut ready_byte = [0_u8; 1];
        match timeout(INIT_READY_TIMEOUT, control.read_exact(&mut ready_byte)).await {
            Ok(Ok(_)) if ready_byte[0] == READY_BYTE => {}
            Ok(Ok(_)) => {
                terminate(&mut child).await;
                return Err(process_error(
                    ErrorCode::FailedPrecondition,
                    "prepared container init returned an invalid readiness byte",
                ));
            }
            Ok(Err(error)) => {
                terminate(&mut child).await;
                return Err(process_error(
                    ErrorCode::FailedPrecondition,
                    format!("prepared container init closed before readiness: {error}"),
                ));
            }
            Err(_) => {
                terminate(&mut child).await;
                return Err(process_error(
                    ErrorCode::DeadlineExceeded,
                    "timed out reading prepared container init readiness",
                ));
            }
        }
        drop(listener);

        Ok(Self {
            child,
            control: Some(control),
            pid,
        })
    }

    pub(super) const fn pid(&self) -> i32 {
        self.pid
    }

    pub(super) async fn release(&mut self) -> Result<()> {
        let control = self.control.as_mut().ok_or_else(|| {
            process_error(
                ErrorCode::FailedPrecondition,
                "container init has already crossed the start barrier",
            )
        })?;
        control.write_all(&[START_BYTE]).await.map_err(|error| {
            process_error(
                ErrorCode::Unavailable,
                format!("failed to release prepared container init: {error}"),
            )
        })?;
        let control = self.control.take();
        drop(control);
        Ok(())
    }

    pub(super) fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        self.child.try_wait().map_err(|error| {
            process_error(
                ErrorCode::Internal,
                format!("failed to inspect container init state: {error}"),
            )
        })
    }

    pub(super) fn signal(&self, signal: i32) -> Result<()> {
        // SAFETY: `pid` is the positive process ID returned by Tokio and the
        // signal has already passed the SDK's positive-integer validation.
        if unsafe { libc::kill(self.pid, signal) } == 0 {
            Ok(())
        } else {
            Err(process_error(
                ErrorCode::Unavailable,
                format!(
                    "failed to signal container init PID {}: {}",
                    self.pid,
                    io::Error::last_os_error()
                ),
            ))
        }
    }

    pub(super) async fn force_stop(&mut self) -> Result<()> {
        match self.child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(error) => {
                return Err(process_error(
                    ErrorCode::Internal,
                    format!("failed to inspect container init before cleanup: {error}"),
                ));
            }
        }
        self.child.kill().await.map_err(|error| {
            process_error(
                ErrorCode::Internal,
                format!("failed to terminate container init during cleanup: {error}"),
            )
        })?;
        self.child.wait().await.map_err(|error| {
            process_error(
                ErrorCode::Internal,
                format!("failed to reap container init during cleanup: {error}"),
            )
        })?;
        Ok(())
    }
}

fn bind_control_listener() -> Result<(UnixListener, String)> {
    let endpoint = AgentVsockEndpoint::generate()?;
    let control_name = format!("a3s-oci-init-{}", endpoint.pipe_name());
    let address = StdSocketAddr::from_abstract_name(control_name.as_bytes()).map_err(|error| {
        process_error(
            ErrorCode::Internal,
            format!("failed to construct abstract init control address: {error}"),
        )
    })?;
    let listener = StdUnixListener::bind_addr(&address).map_err(|error| {
        process_error(
            ErrorCode::Internal,
            format!("failed to bind abstract init control socket: {error}"),
        )
    })?;
    listener.set_nonblocking(true).map_err(|error| {
        process_error(
            ErrorCode::Internal,
            format!("failed to make init control socket nonblocking: {error}"),
        )
    })?;
    let listener = UnixListener::from_std(listener).map_err(|error| {
        process_error(
            ErrorCode::Internal,
            format!("failed to register init control socket with Tokio: {error}"),
        )
    })?;
    Ok((listener, control_name))
}

async fn terminate(child: &mut Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

fn process_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("run-container-init")
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixStream};

    use tokio::io::AsyncReadExt;

    use super::{bind_control_listener, READY_BYTE};

    #[tokio::test(flavor = "current_thread")]
    async fn abstract_control_listener_reports_the_kernel_peer_pid() {
        let (listener, name) = bind_control_listener().expect("bind abstract control listener");
        tokio::task::spawn_blocking(move || {
            let address =
                SocketAddr::from_abstract_name(name.as_bytes()).expect("abstract address");
            let mut stream = UnixStream::connect_addr(&address).expect("connect control socket");
            stream.write_all(&[READY_BYTE]).expect("write ready byte");
        })
        .await
        .expect("control client task");

        let (mut stream, _) = listener.accept().await.expect("accept control client");
        assert_eq!(
            stream.peer_cred().expect("read peer credentials").pid(),
            i32::try_from(std::process::id()).ok()
        );
        let mut ready = [0_u8; 1];
        stream
            .read_exact(&mut ready)
            .await
            .expect("read ready byte");
        assert_eq!(ready[0], READY_BYTE);
    }
}
