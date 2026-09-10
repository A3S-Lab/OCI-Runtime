use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitStatus as ProcessExitStatus;
use std::sync::Arc;
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
use super::pid_supervisor::terminate_pid;
use super::pidfd::{PidFd, SignalOutcome};
use super::process::{
    bind_control_listener, convert_exit_status, prepare_supervised_stdio, terminate_host_child,
    SharedSessionSupervisor,
};
use super::process_group::ProcessGroupLease;

mod helper;

const EXEC_READY_TIMEOUT: Duration = Duration::from_secs(10);
const EXEC_MODE: &str = "container-exec";

#[derive(Debug)]
enum ExecChild {
    Host(Child),
    Supervised {
        helper_pid: u32,
        supervisor: SharedSessionSupervisor,
        status: Option<ProcessExitStatus>,
    },
}

#[derive(Debug)]
pub(super) struct ExecProcess {
    child: ExecChild,
    pid: i32,
    pidfd: PidFd,
    process_group: ProcessGroupLease,
    terminal: bool,
    io: ProcessIoHandle,
    exit_status: Option<ExitStatus>,
}

/// Minimum authentic spawn inputs for container-exec (live Host or Host reopen).
///
/// Built from a live [`PreparedProcess`] or rebuilt after Host reopen from the
/// durable recovery config snapshot plus the authenticated live init identity.
/// Never invents namespace/rootfs evidence.
pub(super) struct ExecSpawnContext<'a> {
    pub(super) execution_context: &'a super::namespace::RetainedExecutionContext,
    pub(super) init_pidfd: RawFd,
    pub(super) workload_cgroup_procs: Option<RawFd>,
    pub(super) init_signal: &'a PidFd,
}

impl ExecProcess {
    pub(super) async fn spawn(
        snapshot: &Path,
        init_executable: &Path,
        init_process: &super::process::PreparedProcess,
        terminal: bool,
        io: &ProcessIo,
        session_supervisor: Option<SharedSessionSupervisor>,
    ) -> Result<Self> {
        let context = ExecSpawnContext {
            execution_context: init_process.execution_context(),
            init_pidfd: init_process.pidfd_descriptor(),
            workload_cgroup_procs: init_process.workload_cgroup_procs_descriptor(),
            init_signal: init_process.pidfd(),
        };
        Self::spawn_with_context(
            snapshot,
            init_executable,
            &context,
            terminal,
            io,
            session_supervisor,
        )
        .await
    }

    /// Spawn using an authentic retained context (live create or Host-reopen rebuild).
    pub(super) async fn spawn_with_context(
        snapshot: &Path,
        init_executable: &Path,
        context: &ExecSpawnContext<'_>,
        terminal: bool,
        io: &ProcessIo,
        session_supervisor: Option<SharedSessionSupervisor>,
    ) -> Result<Self> {
        let process_group = ProcessGroupLease::open_for_snapshot(snapshot).await?;
        let inherited = context.execution_context.inherited_descriptors(
            context.init_pidfd,
            context.workload_cgroup_procs,
        )?;
        let namespace_arguments = context.execution_context.namespace_arguments();
        let (listener, control_name) = bind_control_listener()?;

        let (mut child, process_io) = if let Some(supervisor) = session_supervisor {
            spawn_supervised_exec(
                init_executable,
                snapshot,
                &control_name,
                context.execution_context,
                context.init_pidfd,
                context.workload_cgroup_procs,
                &inherited,
                &namespace_arguments,
                io,
                &supervisor,
            )
            .await?
        } else {
            spawn_host_exec(
                init_executable,
                snapshot,
                &control_name,
                context.execution_context,
                context.init_pidfd,
                context.workload_cgroup_procs,
                &inherited,
                &namespace_arguments,
                io,
            )
            .await?
        };

        let runtime_pid =
            complete_exec_handshake(&mut child, &listener, context.init_signal, context.execution_context)
                .await?;

        let pidfd = PidFd::open(runtime_pid)?;
        let terminal = child_terminal(&child, terminal);
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

    pub(super) fn helper_pid(&self) -> i32 {
        match &self.child {
            ExecChild::Host(child) => child
                .id()
                .and_then(|pid| i32::try_from(pid).ok())
                .unwrap_or(-1),
            ExecChild::Supervised { helper_pid, .. } => i32::try_from(*helper_pid).unwrap_or(-1),
        }
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
        let status = match &mut self.child {
            ExecChild::Host(child) => child.try_wait().map_err(|error| {
                exec_error(
                    ErrorCode::Internal,
                    format!("failed to inspect exec process state: {error}"),
                )
            })?,
            ExecChild::Supervised { status, .. } => status.clone(),
        };
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
                terminate_exec_child(&mut self.child).await;
                return Err(error);
            }
        }
        match timeout(EXEC_READY_TIMEOUT, wait_exec_child(&mut self.child)).await {
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
                terminate_exec_child(&mut self.child).await;
                return Err(exec_error(
                    ErrorCode::DeadlineExceeded,
                    "timed out reaping exec helper during cleanup",
                ));
            }
        }
        Ok(())
    }

    fn cache_exit_status(&mut self, status: ProcessExitStatus) -> Result<ExitStatus> {
        let status = convert_exit_status(status)?;
        self.exit_status = Some(status.clone());
        Ok(status)
    }
}

async fn spawn_host_exec(
    init_executable: &Path,
    snapshot: &Path,
    control_name: &str,
    context: &super::namespace::RetainedExecutionContext,
    init_pidfd: RawFd,
    cgroup_procs: Option<RawFd>,
    inherited: &[RawFd],
    namespace_arguments: &[RetainedNamespaceArgument],
    io: &ProcessIo,
) -> Result<(ExecChild, ProcessIoHandle)> {
    let mut command = Command::new(init_executable);
    append_exec_arguments(
        &mut command,
        snapshot,
        control_name,
        context,
        init_pidfd,
        std::process::id(),
        false,
        cgroup_procs,
        namespace_arguments,
    );
    command.env_clear().kill_on_drop(true);
    let io_setup = ProcessIoHandle::configure(&mut command, io)?;
    let terminal_io = io_setup.uses_terminal();
    let inherited = inherited.to_vec();
    // SAFETY: the callback runs in the freshly forked command child and
    // changes descriptor flags only in the child-side descriptor table.
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
            terminate_host_child(&mut child).await;
            return Err(error);
        }
    };
    Ok((ExecChild::Host(child), process_io))
}

async fn spawn_supervised_exec(
    init_executable: &Path,
    snapshot: &Path,
    control_name: &str,
    context: &super::namespace::RetainedExecutionContext,
    init_pidfd: RawFd,
    cgroup_procs: Option<RawFd>,
    inherited: &[RawFd],
    namespace_arguments: &[RetainedNamespaceArgument],
    io: &ProcessIo,
    supervisor: &SharedSessionSupervisor,
) -> Result<(ExecChild, ProcessIoHandle)> {
    let supervisor_pid = {
        let guard = supervisor.lock().map_err(|_| {
            exec_error(
                ErrorCode::Internal,
                "session supervisor lock is poisoned during exec spawn",
            )
        })?;
        guard.identity().pid()
    };
    let (host_pipes, child_stdio) = prepare_supervised_stdio(io).map_err(|error| {
        exec_error(
            error.code,
            format!(
                "session-supervisor exec does not support this process I/O layout: {}",
                error.message
            ),
        )
    })?;
    let stdio = Some((
        child_stdio.stdin.as_ref().map(AsRawFd::as_raw_fd),
        child_stdio.stdout.as_ref().map(AsRawFd::as_raw_fd),
        child_stdio.stderr.as_ref().map(AsRawFd::as_raw_fd),
    ));
    let mut args: Vec<std::ffi::OsString> = Vec::new();
    append_exec_os_arguments(
        &mut args,
        snapshot,
        control_name,
        context,
        init_pidfd,
        supervisor_pid,
        true,
        cgroup_procs,
        namespace_arguments,
    );
    let inherited_pairs: Vec<(RawFd, i32)> = inherited.iter().copied().map(|fd| (fd, fd)).collect();
    let helper_pid = {
        let mut guard = supervisor.lock().map_err(|_| {
            exec_error(
                ErrorCode::Internal,
                "session supervisor lock is poisoned during exec spawn",
            )
        })?;
        guard.spawn_launcher_with_inherited(
            init_executable,
            &args,
            cgroup_procs,
            None,
            stdio,
            &inherited_pairs,
        )
    };
    drop(child_stdio);
    let helper_pid = match helper_pid {
        Ok(pid) => pid,
        Err(error) => return Err(error),
    };
    let raw_helper_pid = match u32::try_from(helper_pid) {
        Ok(pid) => pid,
        Err(error) => {
            terminate_supervised_helper(supervisor, helper_pid).await;
            return Err(exec_error(
                ErrorCode::ResourceExhausted,
                format!(
                    "supervised exec helper PID {helper_pid} does not fit the process model: {error}"
                ),
            ));
        }
    };
    let process_io = ProcessIoHandle::attach_supervised(io, host_pipes.stdin, None).map_err(
        |error| {
            exec_error(
                error.code,
                format!(
                    "failed to attach supervised exec process I/O: {}",
                    error.message
                ),
            )
        },
    )?;
    Ok((
        ExecChild::Supervised {
            helper_pid: raw_helper_pid,
            supervisor: Arc::clone(supervisor),
            status: None,
        },
        process_io,
    ))
}

async fn complete_exec_handshake(
    child: &mut ExecChild,
    listener: &tokio::net::UnixListener,
    init_signal: &PidFd,
    context: &super::namespace::RetainedExecutionContext,
) -> Result<i32> {
    let launcher_pid = helper_pid_for_handshake(child)?;

    enum ReadyOutcome {
        Connected(io::Result<(tokio::net::UnixStream, tokio::net::unix::SocketAddr)>),
        Exited(io::Result<ProcessExitStatus>),
    }
    let ready = timeout(EXEC_READY_TIMEOUT, async {
        tokio::select! {
            accepted = listener.accept() => ReadyOutcome::Connected(accepted),
            status = wait_exec_child(child) => ReadyOutcome::Exited(status),
        }
    })
    .await;
    let mut control = match ready {
        Ok(ReadyOutcome::Connected(Ok((control, _)))) => control,
        Ok(ReadyOutcome::Connected(Err(error))) => {
            terminate_exec_child(child).await;
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
            terminate_exec_child(child).await;
            return Err(exec_error(
                ErrorCode::DeadlineExceeded,
                "timed out waiting for the container exec helper",
            ));
        }
    };
    let peer = match control.peer_cred() {
        Ok(peer) => peer,
        Err(error) => {
            terminate_exec_child(child).await;
            return Err(exec_error(
                ErrorCode::Internal,
                format!("failed to read container exec helper credentials: {error}"),
            ));
        }
    };
    if peer.pid() != Some(launcher_pid) {
        terminate_exec_child(child).await;
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
            terminate_exec_child(child).await;
            return Err(exec_error(
                ErrorCode::PermissionDenied,
                format!("exec helper unexpectedly reported namespace init PID {pid}"),
            ));
        }
        Ok(Ok(InitOutcome::Rejected(error))) => {
            terminate_exec_child(child).await;
            return Err(error);
        }
        Ok(Ok(InitOutcome::UserMappingRequired)) => {
            terminate_exec_child(child).await;
            return Err(exec_error(
                ErrorCode::PermissionDenied,
                "exec helper requested an unexpected user mapping",
            ));
        }
        Ok(Ok(InitOutcome::OrderedIdmapRequired { .. })) => {
            terminate_exec_child(child).await;
            return Err(exec_error(
                ErrorCode::PermissionDenied,
                "exec helper requested an unexpected ordered ID-mapped mount",
            ));
        }
        Ok(Ok(InitOutcome::CreateHooksReady { .. })) => {
            terminate_exec_child(child).await;
            return Err(exec_error(
                ErrorCode::PermissionDenied,
                "exec helper reported an unexpected create-hook barrier",
            ));
        }
        Ok(Err(error)) => {
            terminate_exec_child(child).await;
            return Err(error);
        }
        Err(_) => {
            terminate_exec_child(child).await;
            return Err(exec_error(
                ErrorCode::DeadlineExceeded,
                "timed out reading container exec readiness",
            ));
        }
    };
    if let Err(error) = pid::validate_exec_runtime_pid(launcher_pid, runtime_pid, context).await {
        terminate_exec_child(child).await;
        return Err(error);
    }
    match init_signal.send_signal(0) {
        Ok(SignalOutcome::Delivered) => {}
        Ok(SignalOutcome::Exited) => {
            terminate_exec_child(child).await;
            return Err(exec_error(
                ErrorCode::FailedPrecondition,
                "configured container process exited before exec release",
            ));
        }
        Err(error) => {
            terminate_exec_child(child).await;
            return Err(error);
        }
    }
    if let Err(error) = control.write_all(&[START_BYTE]).await {
        terminate_exec_child(child).await;
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
    let warnings = match started {
        Ok(warnings) => warnings,
        Err(error) => {
            terminate_exec_child(child).await;
            return Err(error);
        }
    };
    report_capability_warnings(&warnings);
    Ok(runtime_pid)
}

fn helper_pid_for_handshake(child: &ExecChild) -> Result<i32> {
    match child {
        ExecChild::Host(child) => {
            let Some(raw_launcher_pid) = child.id() else {
                return Err(exec_error(
                    ErrorCode::Internal,
                    "spawned container exec helper has no live process ID",
                ));
            };
            i32::try_from(raw_launcher_pid).map_err(|error| {
                exec_error(
                    ErrorCode::ResourceExhausted,
                    format!(
                        "exec helper PID {raw_launcher_pid} does not fit the process model: {error}"
                    ),
                )
            })
        }
        ExecChild::Supervised { helper_pid, .. } => i32::try_from(*helper_pid).map_err(|error| {
            exec_error(
                ErrorCode::ResourceExhausted,
                format!("supervised exec helper PID {helper_pid} does not fit i32: {error}"),
            )
        }),
    }
}

fn child_terminal(child: &ExecChild, requested: bool) -> bool {
    match child {
        ExecChild::Host(_) => requested,
        ExecChild::Supervised { .. } => false,
    }
}

async fn wait_exec_child(child: &mut ExecChild) -> io::Result<ProcessExitStatus> {
    match child {
        ExecChild::Host(child) => child.wait().await,
        ExecChild::Supervised {
            helper_pid,
            supervisor,
            status,
        } => {
            if let Some(status) = status.clone() {
                return Ok(status);
            }
            let supervisor = Arc::clone(supervisor);
            let pid = i32::try_from(*helper_pid).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "supervised exec helper PID does not fit i32",
                )
            })?;
            let raw = tokio::task::spawn_blocking(move || {
                supervisor
                    .lock()
                    .map_err(|_| io::Error::other("session supervisor lock is poisoned"))?
                    .wait_launcher(pid)
                    .map_err(|error| io::Error::other(error.to_string()))
            })
            .await
            .map_err(io::Error::other)??;
            let waited = ProcessExitStatus::from_raw(raw);
            *status = Some(waited.clone());
            Ok(waited)
        }
    }
}

async fn terminate_exec_child(child: &mut ExecChild) {
    match child {
        ExecChild::Host(child) => terminate_host_child(child).await,
        ExecChild::Supervised {
            helper_pid,
            supervisor,
            ..
        } => {
            let pid = i32::try_from(*helper_pid).unwrap_or(-1);
            if pid > 0 {
                terminate_supervised_helper(supervisor, pid).await;
            }
        }
    }
}

async fn terminate_supervised_helper(supervisor: &SharedSessionSupervisor, helper_pid: i32) {
    terminate_pid(helper_pid);
    let _ = tokio::task::spawn_blocking({
        let supervisor = Arc::clone(supervisor);
        move || {
            supervisor
                .lock()
                .ok()
                .and_then(|mut guard| guard.wait_launcher(helper_pid).ok())
        }
    })
    .await;
}

fn append_exec_arguments(
    command: &mut Command,
    snapshot: &Path,
    control_name: &str,
    context: &super::namespace::RetainedExecutionContext,
    init_pidfd: RawFd,
    parent_pid: u32,
    survive_host_death: bool,
    cgroup_procs: Option<RawFd>,
    namespace_arguments: &[RetainedNamespaceArgument],
) {
    command
        .arg(EXEC_MODE)
        .arg(snapshot)
        .arg(control_name)
        .arg(context.root_descriptor().to_string())
        .arg(init_pidfd.to_string())
        .arg(parent_pid.to_string())
        .arg(if survive_host_death { "1" } else { "0" })
        .arg(
            cgroup_procs
                .map(|descriptor| descriptor.to_string())
                .unwrap_or_else(|| "none".to_string()),
        );
    append_namespace_arguments(command, namespace_arguments);
}

fn append_exec_os_arguments(
    args: &mut Vec<std::ffi::OsString>,
    snapshot: &Path,
    control_name: &str,
    context: &super::namespace::RetainedExecutionContext,
    init_pidfd: RawFd,
    parent_pid: i32,
    survive_host_death: bool,
    cgroup_procs: Option<RawFd>,
    namespace_arguments: &[RetainedNamespaceArgument],
) {
    args.push(EXEC_MODE.into());
    args.push(snapshot.as_os_str().to_os_string());
    args.push(control_name.into());
    args.push(context.root_descriptor().to_string().into());
    args.push(init_pidfd.to_string().into());
    args.push(parent_pid.to_string().into());
    args.push(if survive_host_death { "1" } else { "0" }.into());
    args.push(
        cgroup_procs
            .map(|descriptor| descriptor.to_string())
            .unwrap_or_else(|| "none".to_string())
            .into(),
    );
    for namespace in namespace_arguments {
        args.push(format!(
            "{}:{}:{}",
            namespace.name, namespace.clone_flag, namespace.descriptor
        ).into());
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
