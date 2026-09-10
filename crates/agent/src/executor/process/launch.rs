use std::fs::File;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr as StdSocketAddr, UnixListener as StdUnixListener};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus as ProcessExitStatus;
use std::sync::Arc;

use a3s_oci_agent_protocol::AgentVsockEndpoint;
use a3s_oci_sdk::{Error, ErrorCode, IoMode, ProcessIo, Result};
use tokio::net::UnixListener;
use tokio::process::Child;

use super::super::bundle_scope::{PinnedBundleDirectory, PinnedRootfsDirectory};
use super::super::cgroup::CgroupHandle;
use super::super::plan::InitPlan;
use super::{append_cleanup_error, process_error};

pub(crate) use super::super::session_supervisor::SharedSessionSupervisor;

/// Local Host-parented child or supervisor-parented launcher.
#[derive(Debug)]
pub(in crate::executor) enum LauncherChild {
    Local(Child),
    Supervised {
        pid: u32,
        supervisor: SharedSessionSupervisor,
        status: Option<ProcessExitStatus>,
    },
}

impl LauncherChild {
    pub(super) fn id(&self) -> Option<u32> {
        match self {
            Self::Local(child) => child.id(),
            Self::Supervised { pid, .. } => Some(*pid),
        }
    }

    pub(super) fn try_wait(&mut self) -> std::io::Result<Option<ProcessExitStatus>> {
        match self {
            Self::Local(child) => child.try_wait(),
            Self::Supervised { pid, status, .. } => {
                if let Some(status) = status.clone() {
                    return Ok(Some(status));
                }
                if supervised_pid_is_alive(*pid) {
                    return Ok(None);
                }
                // Process is gone; fall through to authentic wait_launcher on wait().
                Ok(None)
            }
        }
    }

    pub(super) async fn wait(&mut self) -> std::io::Result<ProcessExitStatus> {
        match self {
            Self::Local(child) => child.wait().await,
            Self::Supervised {
                pid,
                supervisor,
                status,
            } => {
                if let Some(status) = status.clone() {
                    return Ok(status);
                }
                let supervisor = Arc::clone(supervisor);
                let pid = i32::try_from(*pid).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "supervised launcher PID does not fit i32",
                    )
                })?;
                let raw = tokio::task::spawn_blocking(move || {
                    supervisor
                        .lock()
                        .map_err(|_| std::io::Error::other("session supervisor lock is poisoned"))?
                        .wait_launcher(pid)
                        .map_err(|error| std::io::Error::other(error.to_string()))
                })
                .await
                .map_err(std::io::Error::other)??;
                let waited = ProcessExitStatus::from_raw(raw);
                *status = Some(waited.clone());
                Ok(waited)
            }
        }
    }

    /// Observe launcher exit without holding the session-supervisor mutex.
    ///
    /// The create ready-race must not call [`Self::wait`] for supervised
    /// children: `wait_launcher` holds the supervisor lock for the whole
    /// MSG_WAIT round-trip, so a cancelled `select!` arm leaves cleanup unable
    /// to kill/deposit and deadlocks create in `prepared`.
    pub(super) async fn wait_for_ready_race_exit(&mut self) -> std::io::Result<ProcessExitStatus> {
        match self {
            Self::Local(_) => self.wait().await,
            Self::Supervised { pid, status, .. } => {
                if let Some(status) = status.clone() {
                    return Ok(status);
                }
                let watched = *pid;
                loop {
                    if !supervised_pid_is_alive(watched) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                self.wait().await
            }
        }
    }
}

fn supervised_pid_is_alive(pid: u32) -> bool {
    std::path::Path::new("/proc").join(pid.to_string()).exists()
}

/// Host-retained stdio pipe ends for a supervised launcher.
pub(in crate::executor) struct SupervisedIoPipes {
    pub(in crate::executor) stdin: Option<OwnedFd>,
    pub(in crate::executor) stdout: Option<OwnedFd>,
    pub(in crate::executor) stderr: Option<OwnedFd>,
}

/// Child-side stdio descriptors that must stay open until SCM_RIGHTS send completes.
pub(in crate::executor) struct SupervisedChildStdio {
    pub(in crate::executor) stdin: Option<OwnedFd>,
    pub(in crate::executor) stdout: Option<OwnedFd>,
    pub(in crate::executor) stderr: Option<OwnedFd>,
}

/// Remaining supervised-create Unsupported gates.
///
/// Rootless device mounts are deliberately absent: Host still sends prepared
/// mount descriptors over the authenticated create-control socket after the
/// supervisor-parented launcher connects (`send_device_mounts` / SCM_RIGHTS).
/// Empty and nonempty frames share that path; spawn_launcher does not carry them.
pub(super) fn supervised_create_unsupported_reason(
    pinned_bundle: bool,
    inherited_workload_descriptors: bool,
    io: &ProcessIo,
) -> Option<&'static str> {
    if pinned_bundle {
        return Some(
            "session-supervisor create does not support descriptor-pinned utility-VM bundles yet",
        );
    }
    if inherited_workload_descriptors {
        return Some(
            "session-supervisor create does not support inherited workload descriptors yet",
        );
    }
    if matches!(io.stdin, IoMode::Terminal)
        || matches!(io.stdout, IoMode::Terminal)
        || matches!(io.stderr, IoMode::Terminal)
        || io.terminal_size.is_some()
    {
        return Some("session-supervisor create does not support terminal process I/O yet");
    }
    if matches!(io.stdin, IoMode::Inherit)
        || matches!(io.stdout, IoMode::Inherit)
        || matches!(io.stderr, IoMode::Inherit)
    {
        return Some("session-supervisor create does not support inherited process I/O yet");
    }
    None
}

/// Prepare Host/child stdio pipe ends for supervised spawn.
pub(in crate::executor) fn prepare_supervised_stdio(
    io: &ProcessIo,
) -> Result<(SupervisedIoPipes, SupervisedChildStdio)> {
    if matches!(io.stdin, IoMode::Terminal)
        || matches!(io.stdout, IoMode::Terminal)
        || matches!(io.stderr, IoMode::Terminal)
        || io.terminal_size.is_some()
    {
        return Err(process_error(
            ErrorCode::Unsupported,
            "session-supervisor create does not support terminal process I/O yet",
        ));
    }
    if matches!(io.stdin, IoMode::Inherit)
        || matches!(io.stdout, IoMode::Inherit)
        || matches!(io.stderr, IoMode::Inherit)
    {
        return Err(process_error(
            ErrorCode::Unsupported,
            "session-supervisor create does not support inherited process I/O yet",
        ));
    }

    let mut host = SupervisedIoPipes {
        stdin: None,
        stdout: None,
        stderr: None,
    };
    let mut child = SupervisedChildStdio {
        stdin: None,
        stdout: None,
        stderr: None,
    };

    if matches!(io.stdin, IoMode::Pipe) {
        let (read, write) = create_pipe()?;
        child.stdin = Some(read);
        host.stdin = Some(write);
    }
    if matches!(io.stdout, IoMode::Capture) {
        let (read, write) = create_pipe()?;
        host.stdout = Some(read);
        child.stdout = Some(write);
    }
    if matches!(io.stderr, IoMode::Capture) {
        let (read, write) = create_pipe()?;
        host.stderr = Some(read);
        child.stderr = Some(write);
    }

    Ok((host, child))
}

fn create_pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0, 0];
    // SAFETY: pipe writes two open descriptors into the stack array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(process_error(
            ErrorCode::Internal,
            format!(
                "failed to create session-supervisor stdio pipe: {}",
                std::io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: successful pipe returns two owned descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

pub(super) fn validate_rootless_device_mounts(
    mounts: &[OwnedFd],
    rootless: bool,
    devices_required: bool,
) -> Result<()> {
    let expected = if rootless && devices_required {
        super::super::device::ROOTLESS_DEVICE_MOUNT_COUNT
    } else {
        0
    };
    if mounts.len() != expected {
        return Err(process_error(
            ErrorCode::PermissionDenied,
            format!(
                "prepared rootless device mount count {} does not match expected {expected}",
                mounts.len()
            ),
        ));
    }
    Ok(())
}

pub(super) async fn retain_original_rootfs(
    plan: &InitPlan,
    pinned_bundle: Option<&PinnedBundleDirectory>,
) -> Result<(File, Option<PinnedRootfsDirectory>)> {
    if let Some(bundle) = pinned_bundle {
        let relative = plan.rootfs.strip_prefix(&plan.bundle_directory).map_err(|_| {
            process_error(
                ErrorCode::PermissionDenied,
                format!(
                    "container rootfs must be relative to its descriptor-pinned utility-VM bundle: {}",
                    plan.rootfs.display()
                ),
            )
        })?;
        let rootfs = bundle
            .open_rootfs(relative, "run-container-init")?
            .ok_or_else(|| {
                process_error(
                    ErrorCode::InvalidArgument,
                    format!("container rootfs does not exist: {}", plan.rootfs.display()),
                )
            })?;
        let child_rootfs = bundle.prepare_rootfs_for_child(&rootfs)?;
        return Ok((rootfs, Some(child_rootfs)));
    }
    let path = &plan.rootfs;
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|error| {
            process_error(
                ErrorCode::InvalidArgument,
                format!(
                    "failed to retain container rootfs {} before init launch: {error}",
                    path.display()
                ),
            )
        })?
        .into_std()
        .await;
    Ok((file, None))
}

pub(in crate::executor) fn bind_control_listener() -> Result<(UnixListener, String)> {
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

pub(in crate::executor) async fn terminate_host_child(child: &mut Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

pub(in crate::executor) async fn terminate(child: &mut LauncherChild) {
    match child {
        LauncherChild::Local(child) => {
            terminate_host_child(child).await;
        }
        LauncherChild::Supervised {
            pid,
            supervisor,
            status,
        } => {
            if status.is_some() {
                return;
            }
            let Ok(pid) = i32::try_from(*pid) else {
                return;
            };
            super::super::pid_supervisor::terminate_pid(pid);
            if let Ok(mut guard) = supervisor.lock() {
                if let Ok(raw) = guard.wait_launcher(pid) {
                    *status = Some(ProcessExitStatus::from_raw(raw));
                }
            }
        }
    }
}

pub(super) fn cleanup_unstarted_cgroup(
    cgroup: &mut Option<CgroupHandle>,
    mut primary: Error,
) -> Error {
    if let Some(mut cgroup) = cgroup.take() {
        if let Err(error) = cgroup.cleanup() {
            append_cleanup_error(
                &mut primary,
                "remove the unstarted container cgroup",
                &error,
            );
        }
    }
    primary
}

pub(super) async fn cleanup_uncommitted_create(
    child: &mut LauncherChild,
    cgroup: &mut Option<CgroupHandle>,
    mut primary: Error,
) -> Error {
    let termination = match cgroup.as_ref() {
        Some(cgroup) => cgroup.terminate_all().await,
        None => Ok(()),
    };
    terminate(child).await;
    if let Err(error) = termination {
        append_cleanup_error(&mut primary, "terminate the container cgroup", &error);
    }
    if let Some(mut cgroup) = cgroup.take() {
        if let Err(error) = cgroup.cleanup() {
            append_cleanup_error(&mut primary, "remove the container cgroup", &error);
        }
    }
    primary
}
