use std::io;
use std::os::fd::RawFd;
use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::{Error, ErrorCode, ExitStatus, ProcessIo, Result};
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::time::timeout;

use super::capability::report_capability_warnings;
use super::control::{read_outcome, read_start_result, InitOutcome, START_BYTE};
use super::io::ProcessIoHandle;
use super::namespace::RetainedNamespaceArgument;
use super::pid;
use super::pidfd::{PidFd, SignalOutcome};
use super::process::{bind_control_listener, convert_exit_status, terminate};
use super::process_group::ProcessGroupLease;

mod helper;

const EXEC_READY_TIMEOUT: Duration = Duration::from_secs(10);
const EXEC_MODE: &str = "container-exec";

#[derive(Debug)]
pub(super) struct ExecProcess {
    child: Child,
    pid: i32,
    pidfd: PidFd,
    process_group: ProcessGroupLease,
    terminal: bool,
    io: ProcessIoHandle,
    exit_status: Option<ExitStatus>,
}

impl ExecProcess {
    pub(super) async fn spawn(
        snapshot: &Path,
        init_executable: &Path,
        init_process: &super::process::PreparedProcess,
        terminal: bool,
        io: &ProcessIo,
    ) -> Result<Self> {
        let context = init_process.execution_context();
        let process_group = ProcessGroupLease::open_for_snapshot(snapshot).await?;
        let init_pidfd = init_process.pidfd_descriptor();
        let cgroup_procs = init_process.workload_cgroup_procs_descriptor();
        let inherited = context.inherited_descriptors(init_pidfd, cgroup_procs)?;
        let namespace_arguments = context.namespace_arguments();
        let (listener, control_name) = bind_control_listener()?;

        let mut command = Command::new(init_executable);
        command
            .arg(EXEC_MODE)
            .arg(snapshot)
            .arg(&control_name)
            .arg(context.root_descriptor().to_string())
            .arg(init_pidfd.to_string())
            .arg(std::process::id().to_string())
            .arg(
                cgroup_procs
                    .map(|descriptor| descriptor.to_string())
                    .unwrap_or_else(|| "none".to_string()),
            );
        append_namespace_arguments(&mut command, &namespace_arguments);
        command.env_clear().kill_on_drop(true);
        let io_setup = ProcessIoHandle::configure(&mut command, io)?;
        let terminal_io = io_setup.uses_terminal();
        // SAFETY: the callback runs in the freshly forked command child and
        // changes descriptor flags only in the child-side descriptor table.
        // The authenticated helper applies initial affinity, enters the
        // workload cgroup, and applies final affinity before forking payload.
        unsafe {
            command.pre_exec(move || {
                super::fd_boundary::mark_private_descriptors_close_on_exec()?;
                make_descriptors_inheritable(&inherited)?;
                super::terminal::prepare_child_terminal(terminal_io)
            });
        }
        let mut child = command.spawn().map_err(|error| {
            exec_error(
                ErrorCode::Internal,
                format!("failed to spawn container exec helper: {error}"),
            )
        })?;
        let process_io = match ProcessIoHandle::attach(io_setup, &mut child, io) {
            Ok(process_io) => process_io,
            Err(error) => {
                terminate(&mut child).await;
                return Err(error);
            }
        };
        let Some(raw_launcher_pid) = child.id() else {
            terminate(&mut child).await;
            return Err(exec_error(
                ErrorCode::Internal,
                "spawned container exec helper has no live process ID",
            ));
        };
        let launcher_pid = match i32::try_from(raw_launcher_pid) {
            Ok(pid) => pid,
            Err(error) => {
                terminate(&mut child).await;
                return Err(exec_error(
                    ErrorCode::ResourceExhausted,
                    format!(
                        "exec helper PID {raw_launcher_pid} does not fit the process model: {error}"
                    ),
                ));
            }
        };

        enum ReadyOutcome {
            Connected(io::Result<(tokio::net::UnixStream, tokio::net::unix::SocketAddr)>),
            Exited(io::Result<std::process::ExitStatus>),
        }
        let ready = timeout(EXEC_READY_TIMEOUT, async {
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
                return Err(exec_error(
                    ErrorCode::Internal,
                    format!("failed to accept container exec control connection: {error}"),
                ));
            }
            Ok(ReadyOutcome::Exited(Ok(status))) => {
                return Err(exec_error(
                    ErrorCode::FailedPrecondition,
                    format!("container exec helper rejected its plan and exited with {status}"),
                ));
            }
            Ok(ReadyOutcome::Exited(Err(error))) => {
                return Err(exec_error(
                    ErrorCode::Internal,
                    format!("failed to wait for container exec helper: {error}"),
                ));
            }
            Err(_) => {
                terminate(&mut child).await;
                return Err(exec_error(
                    ErrorCode::DeadlineExceeded,
                    "timed out waiting for the container exec helper",
                ));
            }
        };
        let peer = match control.peer_cred() {
            Ok(peer) => peer,
            Err(error) => {
                terminate(&mut child).await;
                return Err(exec_error(
                    ErrorCode::Internal,
                    format!("failed to read container exec helper credentials: {error}"),
                ));
            }
        };
        if peer.pid() != Some(launcher_pid) {
            terminate(&mut child).await;
            return Err(exec_error(
                ErrorCode::PermissionDenied,
                format!(
                    "exec control peer PID {:?} does not match spawned helper {launcher_pid}",
                    peer.pid()
                ),
            ));
        }

        let runtime_pid = match timeout(EXEC_READY_TIMEOUT, read_outcome(&mut control)).await {
            Ok(Ok(InitOutcome::Ready {
                pid,
                namespace_init_pid: None,
            })) => pid,
            Ok(Ok(InitOutcome::Ready {
                namespace_init_pid: Some(pid),
                ..
            })) => {
                terminate(&mut child).await;
                return Err(exec_error(
                    ErrorCode::PermissionDenied,
                    format!("exec helper unexpectedly reported namespace init PID {pid}"),
                ));
            }
            Ok(Ok(InitOutcome::Rejected(error))) => {
                terminate(&mut child).await;
                return Err(error);
            }
            Ok(Ok(InitOutcome::UserMappingRequired)) => {
                terminate(&mut child).await;
                return Err(exec_error(
                    ErrorCode::PermissionDenied,
                    "exec helper requested an unexpected user mapping",
                ));
            }
            Ok(Ok(InitOutcome::OrderedIdmapRequired { .. })) => {
                terminate(&mut child).await;
                return Err(exec_error(
                    ErrorCode::PermissionDenied,
                    "exec helper requested an unexpected ordered ID-mapped mount",
                ));
            }
            Ok(Ok(InitOutcome::CreateHooksReady { .. })) => {
                terminate(&mut child).await;
                return Err(exec_error(
                    ErrorCode::PermissionDenied,
                    "exec helper reported an unexpected create-hook barrier",
                ));
            }
            Ok(Err(error)) => {
                terminate(&mut child).await;
                return Err(error);
            }
            Err(_) => {
                terminate(&mut child).await;
                return Err(exec_error(
                    ErrorCode::DeadlineExceeded,
                    "timed out reading container exec readiness",
                ));
            }
        };
        let pidfd = match PidFd::open(runtime_pid) {
            Ok(pidfd) => pidfd,
            Err(error) => {
                terminate(&mut child).await;
                return Err(error);
            }
        };
        if let Err(error) = pid::validate_exec_runtime_pid(launcher_pid, runtime_pid, context).await
        {
            terminate(&mut child).await;
            return Err(error);
        }
        match init_process.signal(0) {
            Ok(SignalOutcome::Delivered) => {}
            Ok(SignalOutcome::Exited) => {
                terminate(&mut child).await;
                return Err(exec_error(
                    ErrorCode::FailedPrecondition,
                    "configured container process exited before exec release",
                ));
            }
            Err(error) => {
                terminate(&mut child).await;
                return Err(error);
            }
        }
        if let Err(error) = control.write_all(&[START_BYTE]).await {
            terminate(&mut child).await;
            return Err(exec_error(
                ErrorCode::Unavailable,
                format!("failed to release prepared exec process: {error}"),
            ));
        }
        let started = match timeout(EXEC_READY_TIMEOUT, read_start_result(&mut control)).await {
            Ok(result) => result,
            Err(_) => Err(exec_error(
                ErrorCode::DeadlineExceeded,
                "timed out waiting for the exec process to cross exec",
            )),
        };
        drop(control);
        drop(listener);
        let warnings = match started {
            Ok(warnings) => warnings,
            Err(error) => {
                terminate(&mut child).await;
                return Err(error);
            }
        };
        report_capability_warnings(&warnings);

        Ok(Self {
            child,
            pid: runtime_pid,
            pidfd,
            process_group,
            terminal,
            io: process_io,
            exit_status: None,
        })
    }

    pub(super) const fn pid(&self) -> i32 {
        self.pid
    }

    pub(super) const fn terminal(&self) -> bool {
        self.terminal
    }

    pub(super) fn io_handle(&self) -> ProcessIoHandle {
        self.io.clone()
    }

    pub(super) fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        if let Some(status) = &self.exit_status {
            return Ok(Some(status.clone()));
        }
        let status = self.child.try_wait().map_err(|error| {
            exec_error(
                ErrorCode::Internal,
                format!("failed to inspect exec process state: {error}"),
            )
        })?;
        status
            .map(|status| self.cache_exit_status(status))
            .transpose()
    }

    pub(super) fn signal(&self, signal: i32) -> Result<SignalOutcome> {
        self.pidfd.send_signal(signal)
    }

    pub(super) fn signal_all(&self, signal: i32) -> Result<SignalOutcome> {
        self.process_group.signal(&self.pidfd, signal)
    }

    pub(super) async fn force_stop(&mut self) -> Result<()> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        match self.signal_all(libc::SIGKILL) {
            Ok(SignalOutcome::Delivered | SignalOutcome::Exited) => {}
            Err(error) => {
                terminate(&mut self.child).await;
                return Err(error);
            }
        }
        match timeout(EXEC_READY_TIMEOUT, self.child.wait()).await {
            Ok(Ok(status)) => {
                self.cache_exit_status(status)?;
            }
            Ok(Err(error)) => {
                return Err(exec_error(
                    ErrorCode::Internal,
                    format!("failed to reap exec helper during cleanup: {error}"),
                ));
            }
            Err(_) => {
                terminate(&mut self.child).await;
                return Err(exec_error(
                    ErrorCode::DeadlineExceeded,
                    "timed out reaping exec helper during cleanup",
                ));
            }
        }
        Ok(())
    }

    fn cache_exit_status(&mut self, status: std::process::ExitStatus) -> Result<ExitStatus> {
        let status = convert_exit_status(status)?;
        self.exit_status = Some(status.clone());
        Ok(status)
    }
}

pub(crate) fn run_container_exec_if_requested() -> Option<Result<()>> {
    helper::run_container_exec_if_requested()
}

fn append_namespace_arguments(command: &mut Command, namespaces: &[RetainedNamespaceArgument]) {
    for namespace in namespaces {
        command.arg(format!(
            "{}:{}:{}",
            namespace.name, namespace.clone_flag, namespace.descriptor
        ));
    }
}

fn make_descriptors_inheritable(descriptors: &[RawFd]) -> io::Result<()> {
    for descriptor in descriptors {
        // SAFETY: each descriptor is live in the child descriptor table.
        let flags = unsafe { libc::fcntl(*descriptor, libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `F_SETFD` changes only the close-on-exec bit for this child.
        if unsafe { libc::fcntl(*descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn exec_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("run-container-exec")
}
