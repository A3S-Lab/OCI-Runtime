use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr as StdSocketAddr, UnixListener as StdUnixListener};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitStatus as ProcessExitStatus;
use std::time::Duration;

use a3s_oci_agent_protocol::AgentVsockEndpoint;
use a3s_oci_sdk::oci_spec::runtime::LinuxResources;
use a3s_oci_sdk::{
    ContainerStats, ContainerTarget, Error, ErrorCode, ExitStatus, ProcessIo, Result,
    CONTROL_CGROUP_PROCS_FD, WORKLOAD_CGROUP_PROCS_FD,
};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::time::timeout;

use super::capability::CapabilityPlan;
use super::cgroup::{self, CgroupHandle, CgroupManager};
use super::control::{
    acknowledge_user_mapping, continue_create, read_outcome, read_start_result, send_device_mounts,
    InitOutcome, START_BYTE,
};
use super::hook::{HookPhase, HookSet, HookStateTemplate};
use super::inherited_descriptor::InheritedDescriptorPlan;
use super::io::ProcessIoHandle;
use super::namespace::{self, RetainedExecutionContext, UserMappingRuntime};
use super::pid;
use super::pid_supervisor;
use super::pidfd::{PidFd, SignalOutcome};
use super::plan::InitPlan;
use super::process_group::ProcessGroupLease;
use super::seccomp::SeccompPlan;
use super::RootfsScope;

const INIT_READY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub(super) struct PreparedProcess {
    child: Child,
    control: Option<UnixStream>,
    pid: i32,
    pidfd: PidFd,
    process_group: ProcessGroupLease,
    execution_context: RetainedExecutionContext,
    capabilities: CapabilityPlan,
    seccomp: SeccompPlan,
    cgroup: Option<CgroupHandle>,
    io: ProcessIoHandle,
    exit_status: Option<ExitStatus>,
    hooks: HookSet,
    hook_state: HookStateTemplate,
}

pub(super) struct ProcessSpawnContext<'a> {
    pub(super) inherited_descriptors: InheritedDescriptorPlan,
    pub(super) rootless_device_mounts: Vec<OwnedFd>,
    pub(super) rootfs_scope: RootfsScope,
    pub(super) user_mapping_runtime: &'a UserMappingRuntime,
    pub(super) device_source_directory: &'a Path,
}

impl PreparedProcess {
    pub(super) async fn spawn(
        plan: &InitPlan,
        config_snapshot: &Path,
        init_executable: &Path,
        cgroup_manager: Option<&CgroupManager>,
        io: &ProcessIo,
        hook_state: &HookStateTemplate,
        context: ProcessSpawnContext<'_>,
    ) -> Result<Self> {
        let ProcessSpawnContext {
            inherited_descriptors,
            rootless_device_mounts,
            rootfs_scope,
            user_mapping_runtime,
            device_source_directory,
        } = context;
        let rootless = user_mapping_runtime.is_rootless();
        let original_rootfs = retain_original_rootfs(&plan.rootfs).await?;
        let process_group = ProcessGroupLease::open_for_snapshot(config_snapshot).await?;
        if plan.cgroup.uses_control_workload_layout() {
            inherited_descriptors
                .ensure_targets_available(&[CONTROL_CGROUP_PROCS_FD, WORKLOAD_CGROUP_PROCS_FD])?;
        }
        validate_rootless_device_mounts(
            &rootless_device_mounts,
            rootless,
            plan.devices.has_node_setup(),
        )?;
        let mut cgroup = CgroupHandle::create(&plan.cgroup, &plan.devices, cgroup_manager)?;
        let init_cgroup_procs = cgroup.as_ref().map(CgroupHandle::init_procs_descriptor);
        let control_workload_descriptors = cgroup
            .as_ref()
            .and_then(CgroupHandle::control_workload_descriptors);
        if plan.cgroup.uses_control_workload_layout() && control_workload_descriptors.is_none() {
            return Err(process_error(
                ErrorCode::Internal,
                "control/workload cgroup descriptors were not prepared",
            ));
        }
        let (listener, control_name) = bind_control_listener()?;
        // SAFETY: getpid has no preconditions and cannot fail.
        let expected_owner_pid = unsafe { libc::getpid() };
        let process_io_json = serde_json::to_string(io).map_err(|error| {
            process_error(
                ErrorCode::Internal,
                format!("failed to encode prepared init process I/O: {error}"),
            )
        })?;
        if process_io_json.len() > super::MAX_INTERNAL_PROCESS_IO_BYTES {
            return Err(process_error(
                ErrorCode::Internal,
                format!(
                    "encoded prepared init process I/O is {} bytes; maximum is {}",
                    process_io_json.len(),
                    super::MAX_INTERNAL_PROCESS_IO_BYTES
                ),
            ));
        }
        let mut command = Command::new(init_executable);
        command
            .arg("container-init")
            .arg(config_snapshot)
            .arg(&plan.bundle_directory)
            .arg(&control_name)
            .arg(hook_state.id())
            .arg(rootfs_scope.internal_argument())
            .arg(expected_owner_pid.to_string())
            .arg(if rootless { "rootless" } else { "privileged" })
            .arg(device_source_directory)
            .arg(process_io_json)
            .env_clear()
            .kill_on_drop(true);
        let io_setup = ProcessIoHandle::configure(&mut command, io)?;
        let terminal = io_setup.uses_terminal();
        // SAFETY: the callback runs in the freshly forked command child and
        // performs one bounded write to the already-open outer cgroup.procs
        // file, installs fixed control/workload descriptors, establishes the
        // configured controlling terminal when present, and installs the
        // already-validated caller descriptors with bounded dup2.
        unsafe {
            command.pre_exec(move || {
                pid_supervisor::verify_and_arm_parent_death_signal(
                    expected_owner_pid,
                    "container launcher",
                )
                .map_err(|error| io::Error::other(error.to_string()))?;
                if let Some(descriptor) = init_cgroup_procs {
                    cgroup::join_current_process(descriptor)?;
                }
                if let Some((control, workload)) = control_workload_descriptors {
                    cgroup::install_control_workload_descriptors_from_pre_exec(control, workload)?;
                }
                super::terminal::prepare_child_terminal(terminal)?;
                inherited_descriptors.install_in_child()
            });
        }
        let mut child = command.spawn().map_err(|error| {
            process_error(
                ErrorCode::Internal,
                format!("failed to spawn prepared container init: {error}"),
            )
        })?;
        let process_io = match ProcessIoHandle::attach(io_setup, &mut child, io) {
            Ok(process_io) => process_io,
            Err(error) => {
                terminate(&mut child).await;
                return Err(error);
            }
        };
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
            Exited(io::Result<ProcessExitStatus>),
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
        if let Err(error) = send_device_mounts(&control, &rootless_device_mounts) {
            terminate(&mut child).await;
            return Err(error);
        }
        drop(rootless_device_mounts);
        let mut user_mapping_installed = false;
        let mut create_hooks_ready = None;
        let runtime_pid = loop {
            match timeout(INIT_READY_TIMEOUT, read_outcome(&mut control)).await {
                Ok(Ok(InitOutcome::UserMappingRequired)) => {
                    if !plan.namespaces.new_user()
                        || user_mapping_installed
                        || create_hooks_ready.is_some()
                    {
                        terminate(&mut child).await;
                        return Err(process_error(
                            ErrorCode::PermissionDenied,
                            "container init sent an unexpected user namespace mapping request",
                        ));
                    }
                    match timeout(
                        INIT_READY_TIMEOUT,
                        namespace::install_user_mappings(
                            &plan.namespaces,
                            pid,
                            user_mapping_runtime,
                            &plan.additional_gids,
                        ),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            terminate(&mut child).await;
                            return Err(error);
                        }
                        Err(_) => {
                            terminate(&mut child).await;
                            return Err(process_error(
                                ErrorCode::DeadlineExceeded,
                                "timed out installing container user namespace mappings",
                            ));
                        }
                    }
                    if let Err(error) = acknowledge_user_mapping(&mut control).await {
                        terminate(&mut child).await;
                        return Err(error);
                    }
                    user_mapping_installed = true;
                }
                Ok(Ok(InitOutcome::CreateHooksReady {
                    pid: runtime_pid,
                    namespace_init_pid,
                })) => {
                    if create_hooks_ready.is_some()
                        || (plan.namespaces.new_user() && !user_mapping_installed)
                    {
                        let error = process_error(
                            ErrorCode::PermissionDenied,
                            "container init reported an invalid create-hook barrier",
                        );
                        cleanup_failed_create(&mut child, &mut cgroup, &plan.hooks, hook_state)
                            .await;
                        return Err(error);
                    }
                    if let Err(error) =
                        pid::validate_runtime_pid(plan, pid, runtime_pid, namespace_init_pid).await
                    {
                        cleanup_failed_create(&mut child, &mut cgroup, &plan.hooks, hook_state)
                            .await;
                        return Err(error);
                    }
                    if plan.cgroup.uses_control_workload_layout() {
                        let finalized = match (cgroup.as_mut(), cgroup_manager) {
                            (Some(cgroup), Some(manager)) => {
                                cgroup.finalize_control_workload(&plan.cgroup, manager)
                            }
                            _ => Err(process_error(
                                ErrorCode::Internal,
                                "control/workload cgroup finalization lost its runtime manager",
                            )),
                        };
                        if let Err(error) = finalized {
                            cleanup_failed_create(&mut child, &mut cgroup, &plan.hooks, hook_state)
                                .await;
                            return Err(error);
                        }
                    }
                    let creating = match hook_state.encode(
                        a3s_oci_sdk::oci_spec::runtime::ContainerState::Creating,
                        Some(runtime_pid),
                    ) {
                        Ok(state) => state,
                        Err(error) => {
                            cleanup_failed_create(&mut child, &mut cgroup, &plan.hooks, hook_state)
                                .await;
                            return Err(error);
                        }
                    };
                    for phase in [HookPhase::Prestart, HookPhase::CreateRuntime] {
                        if let Err(error) = plan.hooks.run(phase, &creating).await {
                            cleanup_failed_create(&mut child, &mut cgroup, &plan.hooks, hook_state)
                                .await;
                            return Err(error);
                        }
                    }
                    if let Err(error) = continue_create(&mut control).await {
                        cleanup_failed_create(&mut child, &mut cgroup, &plan.hooks, hook_state)
                            .await;
                        return Err(error);
                    }
                    create_hooks_ready = Some((runtime_pid, namespace_init_pid));
                }
                Ok(Ok(InitOutcome::Ready {
                    pid: runtime_pid,
                    namespace_init_pid,
                })) => {
                    if plan.namespaces.new_user() && !user_mapping_installed {
                        cleanup_failed_create(&mut child, &mut cgroup, &plan.hooks, hook_state)
                            .await;
                        return Err(process_error(
                            ErrorCode::PermissionDenied,
                            "container init bypassed required user namespace mappings",
                        ));
                    }
                    if let Err(error) =
                        pid::validate_runtime_pid(plan, pid, runtime_pid, namespace_init_pid).await
                    {
                        cleanup_failed_create(&mut child, &mut cgroup, &plan.hooks, hook_state)
                            .await;
                        return Err(error);
                    }
                    if create_hooks_ready != Some((runtime_pid, namespace_init_pid)) {
                        let error = process_error(
                            ErrorCode::PermissionDenied,
                            "container init final readiness did not match its create-hook barrier",
                        );
                        cleanup_failed_create(&mut child, &mut cgroup, &plan.hooks, hook_state)
                            .await;
                        return Err(error);
                    }
                    break runtime_pid;
                }
                Ok(Ok(InitOutcome::Rejected(error))) => {
                    if create_hooks_ready.is_some() {
                        cleanup_failed_create(&mut child, &mut cgroup, &plan.hooks, hook_state)
                            .await;
                    } else {
                        terminate(&mut child).await;
                    }
                    return Err(error);
                }
                Ok(Err(error)) => {
                    if create_hooks_ready.is_some() {
                        cleanup_failed_create(&mut child, &mut cgroup, &plan.hooks, hook_state)
                            .await;
                    } else {
                        terminate(&mut child).await;
                    }
                    return Err(error);
                }
                Err(_) => {
                    if create_hooks_ready.is_some() {
                        cleanup_failed_create(&mut child, &mut cgroup, &plan.hooks, hook_state)
                            .await;
                    } else {
                        terminate(&mut child).await;
                    }
                    return Err(process_error(
                        ErrorCode::DeadlineExceeded,
                        "timed out reading prepared container init readiness",
                    ));
                }
            }
        };
        let pidfd = match PidFd::open(runtime_pid) {
            Ok(pidfd) => pidfd,
            Err(error) => {
                cleanup_failed_create(&mut child, &mut cgroup, &plan.hooks, hook_state).await;
                return Err(error);
            }
        };
        let execution_context =
            match RetainedExecutionContext::capture(&plan.namespaces, runtime_pid, original_rootfs)
                .await
            {
                Ok(context) => context,
                Err(error) => {
                    cleanup_failed_create(&mut child, &mut cgroup, &plan.hooks, hook_state).await;
                    return Err(error);
                }
            };
        drop(listener);

        Ok(Self {
            child,
            control: Some(control),
            pid: runtime_pid,
            pidfd,
            process_group,
            execution_context,
            capabilities: plan.capabilities,
            seccomp: plan.seccomp.clone(),
            cgroup,
            io: process_io,
            exit_status: None,
            hooks: plan.hooks.clone(),
            hook_state: hook_state.clone(),
        })
    }

    pub(super) const fn pid(&self) -> i32 {
        self.pid
    }

    pub(super) fn launcher_pid(&self) -> Result<i32> {
        let raw = self.child.id().ok_or_else(|| {
            process_error(
                ErrorCode::FailedPrecondition,
                "container launcher exited before recovery evidence was persisted",
            )
        })?;
        i32::try_from(raw).map_err(|error| {
            process_error(
                ErrorCode::ResourceExhausted,
                format!("container launcher PID {raw} does not fit the recovery model: {error}"),
            )
        })
    }

    pub(super) fn recovery_cgroup_paths(&self) -> Option<(&Path, &[std::path::PathBuf])> {
        self.cgroup
            .as_ref()
            .map(super::cgroup::CgroupHandle::recovery_paths)
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
        let started = match timeout(INIT_READY_TIMEOUT, read_start_result(control)).await {
            Ok(result) => result,
            Err(_) => Err(process_error(
                ErrorCode::DeadlineExceeded,
                "timed out waiting for the configured process to cross exec",
            )),
        };
        drop(self.control.take());
        if let Err(error) = started {
            let _ = self.force_stop().await;
            return Err(error);
        }
        let state = self.hook_state.encode(
            a3s_oci_sdk::oci_spec::runtime::ContainerState::Running,
            Some(self.pid),
        )?;
        if let Err(error) = self.hooks.run(HookPhase::Poststart, &state).await {
            let _ = self.force_stop().await;
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn poststop_plan(&self) -> Result<(HookSet, Vec<u8>)> {
        let state = self.hook_state.encode(
            a3s_oci_sdk::oci_spec::runtime::ContainerState::Stopped,
            None,
        )?;
        Ok((self.hooks.clone(), state))
    }

    pub(super) fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        if let Some(status) = &self.exit_status {
            return Ok(Some(status.clone()));
        }
        let status = self.child.try_wait().map_err(|error| {
            process_error(
                ErrorCode::Internal,
                format!("failed to inspect container init state: {error}"),
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

    pub(super) const fn execution_context(&self) -> &RetainedExecutionContext {
        &self.execution_context
    }

    pub(super) const fn seccomp(&self) -> &SeccompPlan {
        &self.seccomp
    }

    pub(super) const fn capabilities(&self) -> CapabilityPlan {
        self.capabilities
    }

    pub(super) fn io_handle(&self) -> ProcessIoHandle {
        self.io.clone()
    }

    pub(super) fn pidfd_descriptor(&self) -> std::os::fd::RawFd {
        self.pidfd.raw_descriptor()
    }

    pub(super) fn workload_cgroup_procs_descriptor(&self) -> Option<std::os::fd::RawFd> {
        self.cgroup
            .as_ref()
            .map(CgroupHandle::workload_procs_descriptor)
    }

    pub(super) async fn set_frozen(&self, frozen: bool) -> Result<()> {
        self.cgroup
            .as_ref()
            .ok_or_else(|| {
                process_error(
                    ErrorCode::Unsupported,
                    "container pause requires an explicit cgroup v2 path",
                )
            })?
            .set_frozen(frozen)
            .await
    }

    pub(super) async fn update_resources(&mut self, resources: &LinuxResources) -> Result<()> {
        self.cgroup
            .as_mut()
            .ok_or_else(|| {
                process_error(
                    ErrorCode::Unsupported,
                    "container resource update requires an explicit cgroup v2 path",
                )
            })?
            .update(resources)
            .await
    }

    pub(super) async fn stats(&self, target: ContainerTarget) -> Result<ContainerStats> {
        self.cgroup
            .as_ref()
            .ok_or_else(|| {
                process_error(
                    ErrorCode::Unsupported,
                    "container stats require an explicit cgroup v2 path",
                )
            })?
            .stats(target)
            .await
    }

    pub(super) async fn force_stop(&mut self) -> Result<()> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        match self.signal_all(libc::SIGKILL) {
            Ok(SignalOutcome::Delivered | SignalOutcome::Exited) => {}
            Err(error) => {
                terminate(&mut self.child).await;
                return Err(Error::new(
                    error.code,
                    format!(
                        "failed to terminate container init PID {} during cleanup: {error}",
                        self.pid
                    ),
                )
                .for_operation("run-container-init")
                .retryable(error.retryable));
            }
        }
        match timeout(INIT_READY_TIMEOUT, self.child.wait()).await {
            Ok(Ok(status)) => {
                self.cache_exit_status(status)?;
            }
            Ok(Err(error)) => {
                return Err(process_error(
                    ErrorCode::Internal,
                    format!("failed to reap container init supervisor during cleanup: {error}"),
                ));
            }
            Err(_) => {
                terminate(&mut self.child).await;
                return Err(process_error(
                    ErrorCode::DeadlineExceeded,
                    "timed out reaping container init supervisor during cleanup",
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

fn validate_rootless_device_mounts(
    mounts: &[OwnedFd],
    rootless: bool,
    devices_required: bool,
) -> Result<()> {
    let expected = if rootless && devices_required {
        super::device::ROOTLESS_DEVICE_MOUNT_COUNT
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

async fn retain_original_rootfs(path: &Path) -> Result<File> {
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
    Ok(file)
}

pub(super) fn bind_control_listener() -> Result<(UnixListener, String)> {
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

pub(super) async fn terminate(child: &mut Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

async fn cleanup_failed_create(
    child: &mut Child,
    cgroup: &mut Option<CgroupHandle>,
    hooks: &HookSet,
    hook_state: &HookStateTemplate,
) {
    terminate(child).await;
    drop(cgroup.take());
    match hook_state.encode(
        a3s_oci_sdk::oci_spec::runtime::ContainerState::Stopped,
        None,
    ) {
        Ok(state) => hooks.run_poststop(&state).await,
        Err(error) => eprintln!("a3s-oci-agent: failed-create poststop state warning: {error}"),
    }
}

fn process_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("run-container-init")
}

pub(super) fn convert_exit_status(status: ProcessExitStatus) -> Result<ExitStatus> {
    if let Some(exit_code) = status.code() {
        return ExitStatus::exited(exit_code);
    }
    if let Some(signal) = status.signal() {
        return ExitStatus::signaled(signal, false);
    }
    Err(process_error(
        ErrorCode::Internal,
        format!("container init returned an unsupported process status {status}"),
    ))
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixStream};

    use tokio::io::AsyncReadExt;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus as ProcessExitStatus;

    use super::{bind_control_listener, convert_exit_status};
    use crate::executor::control::READY_BYTE;

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

    #[test]
    fn converts_normal_and_signal_process_results() {
        assert_eq!(
            convert_exit_status(ProcessExitStatus::from_raw(42 << 8)).expect("normal result"),
            a3s_oci_sdk::ExitStatus::exited(42).expect("normal SDK result")
        );
        assert_eq!(
            convert_exit_status(ProcessExitStatus::from_raw(libc::SIGKILL)).expect("signal result"),
            a3s_oci_sdk::ExitStatus::signaled(libc::SIGKILL, false).expect("signal SDK result")
        );
    }
}
