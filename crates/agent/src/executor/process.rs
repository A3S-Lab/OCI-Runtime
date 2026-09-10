mod launch;
mod restore;
#[cfg(test)]
mod tests;

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus as ProcessExitStatus;
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::LinuxResources;
use a3s_oci_sdk::{
    ContainerStats, ContainerTarget, Error, ErrorCode, ExitStatus, IoMode, ProcessIo, Result,
    CONTROL_CGROUP_PROCS_FD, WORKLOAD_CGROUP_PROCS_FD,
};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::time::timeout;

use super::bundle_scope::{PinnedBundleDirectory, UTILITY_VM_BUNDLE_FD, UTILITY_VM_ROOTFS_FD};
use super::capability::{report_capability_warnings, CapabilityPlan};
use super::cgroup::{self, CgroupHandle, CgroupManager};
use super::control::{
    acknowledge_ordered_idmap, acknowledge_user_mapping, continue_create, read_outcome,
    read_start_result, receive_ordered_idmap_descriptors, send_device_mounts, InitOutcome,
    START_BYTE,
};
use super::hook::{HookPhase, HookSet, HookStateTemplate};
use super::inherited_descriptor::InheritedDescriptorPlan;
use super::intel_rdt::{IntelRdtHandle, IntelRdtRecovery};
use super::io::ProcessIoHandle;
use super::mount;
use super::namespace::{self, RetainedExecutionContext, UserMappingRuntime};
use super::network_device::NetworkDeviceLease;
use super::pid;
use super::pid_supervisor;
use super::pidfd::{PidFd, SignalOutcome};
use super::plan::InitPlan;
use super::process_group::ProcessGroupLease;
use super::seccomp::SeccompPlan;
use super::RootfsScope;
pub(in crate::executor) use launch::prepare_supervised_stdio;
pub(super) use launch::{
    bind_control_listener, terminate, terminate_host_child, SharedSessionSupervisor,
};
use launch::{
    cleanup_uncommitted_create, cleanup_unstarted_cgroup, retain_original_rootfs,
    supervised_create_unsupported_reason, validate_rootless_device_mounts, LauncherChild,
};

const INIT_READY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub(super) struct PreparedProcess {
    child: LauncherChild,
    control: Option<UnixStream>,
    pid: i32,
    namespace_init_pid: Option<i32>,
    pidfd: PidFd,
    process_group: ProcessGroupLease,
    has_process: bool,
    execution_context: RetainedExecutionContext,
    capabilities: CapabilityPlan,
    seccomp: SeccompPlan,
    cgroup: Option<CgroupHandle>,
    intel_rdt: Option<IntelRdtHandle>,
    network_devices: Option<NetworkDeviceLease>,
    io: ProcessIoHandle,
    exit_status: Option<ExitStatus>,
    hooks: HookSet,
    hook_state: HookStateTemplate,
    checkpoint_external_mounts: Vec<(String, PathBuf)>,
}

pub(super) struct ProcessSpawnContext<'a> {
    pub(super) inherited_descriptors: InheritedDescriptorPlan,
    pub(super) rootless_device_mounts: Vec<OwnedFd>,
    pub(super) pinned_bundle: Option<PinnedBundleDirectory>,
    pub(super) rootfs_scope: RootfsScope,
    pub(super) user_mapping_runtime: &'a UserMappingRuntime,
    pub(super) device_source_directory: &'a Path,
    pub(super) vm_storage_sources: &'a crate::vm_attachment::UtilityVmStorageSources,
    pub(super) session_supervisor: Option<SharedSessionSupervisor>,
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
            pinned_bundle,
            rootfs_scope,
            user_mapping_runtime,
            device_source_directory,
            vm_storage_sources,
            session_supervisor,
        } = context;
        let rootless = user_mapping_runtime.is_rootless();
        let supervised = session_supervisor.is_some();
        if supervised {
            // Rootless device mounts are intentionally allowed: after the
            // supervised launcher connects to the Host create-control socket,
            // Host still authenticates peer PID and sends mounts via SCM_RIGHTS
            // (`send_device_mounts`). Parentage is Supervisor→Launcher; the
            // mount frame never needs to ride spawn_launcher FD lists.
            if let Some(reason) = supervised_create_unsupported_reason(
                pinned_bundle.is_some(),
                inherited_descriptors.schema().is_some(),
                io,
            ) {
                return Err(process_error(ErrorCode::Unsupported, reason));
            }
        }
        let (original_rootfs, pinned_rootfs) =
            retain_original_rootfs(plan, pinned_bundle.as_ref()).await?;
        let process_group = ProcessGroupLease::open_for_snapshot(config_snapshot).await?;
        if pinned_bundle.is_some() {
            inherited_descriptors
                .ensure_targets_available(&[UTILITY_VM_BUNDLE_FD, UTILITY_VM_ROOTFS_FD])?;
        }
        if plan.cgroup.uses_control_workload_layout() {
            inherited_descriptors
                .ensure_targets_available(&[CONTROL_CGROUP_PROCS_FD, WORKLOAD_CGROUP_PROCS_FD])?;
        }
        validate_rootless_device_mounts(
            &rootless_device_mounts,
            rootless,
            plan.devices.has_node_setup(),
        )?;
        let mut intel_rdt = IntelRdtHandle::create(plan.intel_rdt.as_ref(), hook_state.id())?;
        let (listener, control_name) = bind_control_listener()?;
        let expected_owner_pid = if let Some(supervisor) = session_supervisor.as_ref() {
            let guard = supervisor.lock().map_err(|_| {
                process_error(
                    ErrorCode::Internal,
                    "session supervisor lock is poisoned before launcher spawn",
                )
            })?;
            guard.identity().pid()
        } else {
            // SAFETY: getpid has no preconditions and cannot fail.
            unsafe { libc::getpid() }
        };
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
        let vm_storage_sources_json = vm_storage_sources.to_json()?;
        let mut cgroup = CgroupHandle::create(
            &plan.cgroup,
            &plan.cgroup_ownership,
            &plan.devices,
            cgroup_manager,
        )?;
        let init_cgroup_procs = cgroup.as_ref().map(CgroupHandle::init_procs_descriptor);
        let control_workload_descriptors = cgroup
            .as_ref()
            .and_then(CgroupHandle::control_workload_descriptors);
        if plan.cgroup.uses_control_workload_layout() && control_workload_descriptors.is_none() {
            let error = process_error(
                ErrorCode::Internal,
                "control/workload cgroup descriptors were not prepared",
            );
            return Err(cleanup_unstarted_cgroup(&mut cgroup, error));
        }

        let (mut child, process_io) = if let Some(supervisor) = session_supervisor {
            let init_args: Vec<OsString> = vec![
                "container-init".into(),
                config_snapshot.as_os_str().to_os_string(),
                plan.bundle_directory.as_os_str().to_os_string(),
                control_name.clone().into(),
                hook_state.id().into(),
                rootfs_scope.internal_argument().into(),
                "bundle-path".into(),
                expected_owner_pid.to_string().into(),
                if rootless {
                    "rootless".into()
                } else {
                    "privileged".into()
                },
                device_source_directory.as_os_str().to_os_string(),
                vm_storage_sources_json.clone().into(),
                process_io_json.clone().into(),
            ];
            let (mut host_pipes, child_stdio) = match prepare_supervised_stdio(io) {
                Ok(pipes) => pipes,
                Err(error) => return Err(cleanup_unstarted_cgroup(&mut cgroup, error)),
            };
            let stdio = Some((
                child_stdio.stdin.as_ref().map(AsRawFd::as_raw_fd),
                child_stdio.stdout.as_ref().map(AsRawFd::as_raw_fd),
                child_stdio.stderr.as_ref().map(AsRawFd::as_raw_fd),
            ));
            let spawned = {
                let mut guard = match supervisor.lock() {
                    Ok(guard) => guard,
                    Err(_) => {
                        let error = process_error(
                            ErrorCode::Internal,
                            "session supervisor lock is poisoned during launcher spawn",
                        );
                        return Err(cleanup_unstarted_cgroup(&mut cgroup, error));
                    }
                };
                guard.spawn_launcher(
                    init_executable,
                    &init_args,
                    init_cgroup_procs,
                    control_workload_descriptors,
                    stdio,
                )
            };
            // Child-side pipe ends must outlive SCM_RIGHTS + supervised spawn.
            drop(child_stdio);
            let pid = match spawned {
                Ok(pid) => pid,
                Err(error) => {
                    return Err(cleanup_unstarted_cgroup(&mut cgroup, error));
                }
            };
            let raw_pid = match u32::try_from(pid) {
                Ok(pid) => pid,
                Err(_) => {
                    let error = process_error(
                        ErrorCode::ResourceExhausted,
                        format!("supervised launcher PID {pid} does not fit the process model"),
                    );
                    let mut child = LauncherChild::Supervised {
                        pid: pid.max(0) as u32,
                        supervisor: Arc::clone(&supervisor),
                        status: None,
                    };
                    return Err(cleanup_uncommitted_create(&mut child, &mut cgroup, error).await);
                }
            };
            if let Some(stdin) = host_pipes.stdin.as_ref() {
                // Duplicate the Host write end into the supervisor so Host death
                // does not EOF the child. Capture stdout/stderr use exclusive
                // move deposit instead (two readers would split the stream).
                let deposit = unsafe { libc::fcntl(stdin.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
                if deposit < 0 {
                    let error = process_error(
                        ErrorCode::Internal,
                        format!(
                            "failed to duplicate supervised stdin for session-supervisor deposit: {}",
                            io::Error::last_os_error()
                        ),
                    );
                    let mut child = LauncherChild::Supervised {
                        pid: raw_pid,
                        supervisor: Arc::clone(&supervisor),
                        status: None,
                    };
                    return Err(cleanup_uncommitted_create(&mut child, &mut cgroup, error).await);
                }
                // Drop the supervisor MutexGuard before any .await (Send).
                let deposit_result = match supervisor.lock() {
                    Ok(mut guard) => {
                        let result = guard.deposit_stdin(pid, deposit);
                        drop(guard);
                        Some(result)
                    }
                    Err(_) => None,
                };
                // SAFETY: SCM_RIGHTS transferred a copy (or deposit failed); close
                // the local duplicate either way.
                unsafe {
                    libc::close(deposit);
                }
                let deposit_error = match deposit_result {
                    Some(Ok(())) => None,
                    Some(Err(error)) => Some(error),
                    None => Some(process_error(
                        ErrorCode::Internal,
                        "session supervisor lock is poisoned during stdin deposit",
                    )),
                };
                if let Some(error) = deposit_error {
                    let mut child = LauncherChild::Supervised {
                        pid: raw_pid,
                        supervisor: Arc::clone(&supervisor),
                        status: None,
                    };
                    return Err(cleanup_uncommitted_create(&mut child, &mut cgroup, error).await);
                }
            }
            let capture_stdout = host_pipes.stdout.is_some();
            let capture_stderr = host_pipes.stderr.is_some();
            if capture_stdout || capture_stderr {
                let stdout = host_pipes.stdout.take();
                let stderr = host_pipes.stderr.take();
                let deposit_result = match supervisor.lock() {
                    Ok(mut guard) => {
                        let result = guard.deposit_output(pid, stdout, stderr);
                        drop(guard);
                        Some(result)
                    }
                    Err(_) => None,
                };
                let deposit_error = match deposit_result {
                    Some(Ok(())) => None,
                    Some(Err(error)) => Some(error),
                    None => Some(process_error(
                        ErrorCode::Internal,
                        "session supervisor lock is poisoned during output deposit",
                    )),
                };
                if let Some(error) = deposit_error {
                    let mut child = LauncherChild::Supervised {
                        pid: raw_pid,
                        supervisor: Arc::clone(&supervisor),
                        status: None,
                    };
                    return Err(cleanup_uncommitted_create(&mut child, &mut cgroup, error).await);
                }
            }
            let output_relay =
                (capture_stdout || capture_stderr).then(|| (Arc::clone(&supervisor), pid));
            let process_io =
                match ProcessIoHandle::attach_supervised(io, host_pipes.stdin, output_relay) {
                    Ok(process_io) => process_io,
                    Err(error) => {
                        let mut child = LauncherChild::Supervised {
                            pid: raw_pid,
                            supervisor: Arc::clone(&supervisor),
                            status: None,
                        };
                        return Err(
                            cleanup_uncommitted_create(&mut child, &mut cgroup, error).await
                        );
                    }
                };
            if matches!(io.stdin, IoMode::Pipe) {
                if let Err(error) = process_io.bind_stdin_deposit(Arc::clone(&supervisor), pid) {
                    let mut child = LauncherChild::Supervised {
                        pid: raw_pid,
                        supervisor: Arc::clone(&supervisor),
                        status: None,
                    };
                    return Err(cleanup_uncommitted_create(&mut child, &mut cgroup, error).await);
                }
            }
            (
                LauncherChild::Supervised {
                    pid: raw_pid,
                    supervisor,
                    status: None,
                },
                process_io,
            )
        } else {
            let mut command = Command::new(init_executable);
            command
                .arg("container-init")
                .arg(config_snapshot)
                .arg(&plan.bundle_directory)
                .arg(&control_name)
                .arg(hook_state.id())
                .arg(rootfs_scope.internal_argument())
                .arg(if pinned_bundle.is_some() {
                    "pinned-bundle-fd"
                } else {
                    "bundle-path"
                })
                .arg(expected_owner_pid.to_string())
                .arg(if rootless { "rootless" } else { "privileged" })
                .arg(device_source_directory)
                .arg(vm_storage_sources_json)
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
                    super::fd_boundary::mark_private_descriptors_close_on_exec()?;
                    pid_supervisor::verify_and_arm_parent_death_signal(
                        expected_owner_pid,
                        "container launcher",
                    )
                    .map_err(|error| io::Error::other(error.to_string()))?;
                    if let Some(descriptor) = init_cgroup_procs {
                        cgroup::join_current_process(descriptor)?;
                    }
                    if let Some((control, workload)) = control_workload_descriptors {
                        cgroup::install_control_workload_descriptors_from_pre_exec(
                            control, workload,
                        )?;
                    }
                    if let Some(bundle) = pinned_bundle.as_ref() {
                        bundle.install_in_child()?;
                    }
                    if let Some(rootfs) = pinned_rootfs.as_ref() {
                        rootfs.install_in_child()?;
                    }
                    super::terminal::prepare_child_terminal(terminal)?;
                    inherited_descriptors.install_in_child()
                });
            }
            let mut local = match command.spawn() {
                Ok(child) => child,
                Err(error) => {
                    let error = process_error(
                        ErrorCode::Internal,
                        format!("failed to spawn prepared container init: {error}"),
                    );
                    return Err(cleanup_unstarted_cgroup(&mut cgroup, error));
                }
            };
            let process_io = match ProcessIoHandle::attach(io_setup, &mut local, io) {
                Ok(process_io) => process_io,
                Err(error) => {
                    let mut child = LauncherChild::Local(local);
                    return Err(cleanup_uncommitted_create(&mut child, &mut cgroup, error).await);
                }
            };
            (LauncherChild::Local(local), process_io)
        };
        let Some(raw_pid) = child.id() else {
            let error = process_error(
                ErrorCode::Internal,
                "spawned container init has no live process ID",
            );
            return Err(cleanup_uncommitted_create(&mut child, &mut cgroup, error).await);
        };
        let pid = match i32::try_from(raw_pid) {
            Ok(pid) => pid,
            Err(_) => {
                let error = process_error(
                    ErrorCode::ResourceExhausted,
                    format!("container init PID {raw_pid} does not fit the OCI state model"),
                );
                return Err(cleanup_uncommitted_create(&mut child, &mut cgroup, error).await);
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
                let error = process_error(
                    ErrorCode::Internal,
                    format!("failed to accept prepared init control connection: {error}"),
                );
                return Err(cleanup_uncommitted_create(&mut child, &mut cgroup, error).await);
            }
            Ok(ReadyOutcome::Exited(Ok(status))) => {
                let error = process_error(
                    ErrorCode::FailedPrecondition,
                    format!("container init rejected its plan and exited with {status}"),
                );
                return Err(cleanup_uncommitted_create(&mut child, &mut cgroup, error).await);
            }
            Ok(ReadyOutcome::Exited(Err(error))) => {
                let error = process_error(
                    ErrorCode::Internal,
                    format!("failed to wait for prepared container init: {error}"),
                );
                return Err(cleanup_uncommitted_create(&mut child, &mut cgroup, error).await);
            }
            Err(_) => {
                let error = process_error(
                    ErrorCode::DeadlineExceeded,
                    "timed out waiting for the prepared container init",
                );
                return Err(cleanup_uncommitted_create(&mut child, &mut cgroup, error).await);
            }
        };
        let peer = match control.peer_cred() {
            Ok(peer) => peer,
            Err(error) => {
                let error = process_error(
                    ErrorCode::Internal,
                    format!("failed to read prepared init peer credentials: {error}"),
                );
                return Err(cleanup_uncommitted_create(&mut child, &mut cgroup, error).await);
            }
        };
        if peer.pid() != Some(pid) {
            let error = process_error(
                ErrorCode::PermissionDenied,
                format!(
                    "init control peer PID {:?} does not match spawned PID {pid}",
                    peer.pid()
                ),
            );
            return Err(cleanup_uncommitted_create(&mut child, &mut cgroup, error).await);
        }
        if let Err(error) = send_device_mounts(&control, &rootless_device_mounts) {
            return Err(cleanup_uncommitted_create(&mut child, &mut cgroup, error).await);
        }
        drop(rootless_device_mounts);
        let mut user_mapping_installed = false;
        let mut create_hooks_ready = None;
        let ordered_idmap_mounts = plan
            .mounts
            .iter()
            .filter(|mount| mount.ordered_source.is_some() && mount.idmap.is_some())
            .collect::<Vec<_>>();
        let mut ordered_idmaps_applied = 0_usize;
        let (runtime_pid, namespace_init_pid) = loop {
            match timeout(INIT_READY_TIMEOUT, read_outcome(&mut control)).await {
                Ok(Ok(InitOutcome::UserMappingRequired)) => {
                    if !plan.namespaces.new_user()
                        || user_mapping_installed
                        || create_hooks_ready.is_some()
                    {
                        let error = process_error(
                            ErrorCode::PermissionDenied,
                            "container init sent an unexpected user namespace mapping request",
                        );
                        return Err(if create_hooks_ready.is_some() {
                            cleanup_failed_create(
                                &mut child,
                                &mut cgroup,
                                &plan.hooks,
                                hook_state,
                                error,
                            )
                            .await
                        } else {
                            cleanup_uncommitted_create(&mut child, &mut cgroup, error).await
                        });
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
                            return Err(
                                cleanup_uncommitted_create(&mut child, &mut cgroup, error).await
                            );
                        }
                        Err(_) => {
                            let error = process_error(
                                ErrorCode::DeadlineExceeded,
                                "timed out installing container user namespace mappings",
                            );
                            return Err(
                                cleanup_uncommitted_create(&mut child, &mut cgroup, error).await
                            );
                        }
                    }
                    if let Err(error) = acknowledge_user_mapping(&mut control).await {
                        return Err(
                            cleanup_uncommitted_create(&mut child, &mut cgroup, error).await
                        );
                    }
                    user_mapping_installed = true;
                }
                Ok(Ok(InitOutcome::OrderedIdmapRequired { mount_index })) => {
                    let expected = ordered_idmap_mounts.get(ordered_idmaps_applied).copied();
                    if create_hooks_ready.is_some()
                        || (plan.namespaces.new_user() && !user_mapping_installed)
                        || expected.map(|mount| mount.index) != Some(mount_index)
                    {
                        let expected_index = expected.map(|mount| mount.index);
                        let error = process_error(
                            ErrorCode::PermissionDenied,
                            format!(
                                "container init requested ordered ID-map for mount index \
                                 {mount_index}; expected {expected_index:?}"
                            ),
                        );
                        return Err(
                            cleanup_uncommitted_create(&mut child, &mut cgroup, error).await
                        );
                    }
                    let descriptors = match timeout(
                        INIT_READY_TIMEOUT,
                        receive_ordered_idmap_descriptors(&control),
                    )
                    .await
                    {
                        Ok(Ok(descriptors)) => descriptors,
                        Ok(Err(error)) => {
                            return Err(
                                cleanup_uncommitted_create(&mut child, &mut cgroup, error).await
                            );
                        }
                        Err(_) => {
                            let error = process_error(
                                ErrorCode::DeadlineExceeded,
                                format!(
                                    "timed out receiving descriptors for ordered ID-mapped \
                                         mount {mount_index}"
                                ),
                            );
                            return Err(
                                cleanup_uncommitted_create(&mut child, &mut cgroup, error).await
                            );
                        }
                    };
                    let Some(expected) = expected else {
                        let error = process_error(
                            ErrorCode::Internal,
                            "validated ordered ID-map request lost its mount plan",
                        );
                        return Err(
                            cleanup_uncommitted_create(&mut child, &mut cgroup, error).await
                        );
                    };
                    if let Err(error) = mount::apply_ordered_idmap_from_parent(
                        expected,
                        &descriptors.0,
                        &descriptors.1,
                    ) {
                        return Err(
                            cleanup_uncommitted_create(&mut child, &mut cgroup, error).await
                        );
                    }
                    ordered_idmaps_applied += 1;
                    if let Err(error) = acknowledge_ordered_idmap(&mut control).await {
                        return Err(
                            cleanup_uncommitted_create(&mut child, &mut cgroup, error).await
                        );
                    }
                }
                Ok(Ok(InitOutcome::CreateHooksReady {
                    pid: runtime_pid,
                    namespace_init_pid,
                })) => {
                    if create_hooks_ready.is_some()
                        || (plan.namespaces.new_user() && !user_mapping_installed)
                        || ordered_idmaps_applied != ordered_idmap_mounts.len()
                    {
                        let error = process_error(
                            ErrorCode::PermissionDenied,
                            "container init reported an invalid create-hook barrier",
                        );
                        return Err(cleanup_failed_create(
                            &mut child,
                            &mut cgroup,
                            &plan.hooks,
                            hook_state,
                            error,
                        )
                        .await);
                    }
                    if let Err(error) =
                        pid::validate_runtime_pid(plan, pid, runtime_pid, namespace_init_pid).await
                    {
                        return Err(cleanup_failed_create(
                            &mut child,
                            &mut cgroup,
                            &plan.hooks,
                            hook_state,
                            error,
                        )
                        .await);
                    }
                    let device_filter_activated = cgroup
                        .as_mut()
                        .map_or(Ok(()), CgroupHandle::activate_device_filter);
                    if let Err(error) = device_filter_activated {
                        return Err(cleanup_failed_create(
                            &mut child,
                            &mut cgroup,
                            &plan.hooks,
                            hook_state,
                            error,
                        )
                        .await);
                    }
                    if let Some(handle) = intel_rdt.as_mut() {
                        if let Err(error) = handle.assign(runtime_pid) {
                            return Err(cleanup_failed_create(
                                &mut child,
                                &mut cgroup,
                                &plan.hooks,
                                hook_state,
                                error,
                            )
                            .await);
                        }
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
                            return Err(cleanup_failed_create(
                                &mut child,
                                &mut cgroup,
                                &plan.hooks,
                                hook_state,
                                error,
                            )
                            .await);
                        }
                    }
                    let creating = match hook_state.encode(
                        a3s_oci_sdk::oci_spec::runtime::ContainerState::Creating,
                        Some(runtime_pid),
                    ) {
                        Ok(state) => state,
                        Err(error) => {
                            return Err(cleanup_failed_create(
                                &mut child,
                                &mut cgroup,
                                &plan.hooks,
                                hook_state,
                                error,
                            )
                            .await);
                        }
                    };
                    for phase in [HookPhase::Prestart, HookPhase::CreateRuntime] {
                        if let Err(error) = plan.hooks.run(phase, &creating).await {
                            return Err(cleanup_failed_create(
                                &mut child,
                                &mut cgroup,
                                &plan.hooks,
                                hook_state,
                                error,
                            )
                            .await);
                        }
                    }
                    if let Err(error) = continue_create(&mut control).await {
                        return Err(cleanup_failed_create(
                            &mut child,
                            &mut cgroup,
                            &plan.hooks,
                            hook_state,
                            error,
                        )
                        .await);
                    }
                    create_hooks_ready = Some((runtime_pid, namespace_init_pid));
                }
                Ok(Ok(InitOutcome::Ready {
                    pid: runtime_pid,
                    namespace_init_pid,
                })) => {
                    if plan.namespaces.new_user() && !user_mapping_installed {
                        let error = process_error(
                            ErrorCode::PermissionDenied,
                            "container init bypassed required user namespace mappings",
                        );
                        return Err(cleanup_failed_create(
                            &mut child,
                            &mut cgroup,
                            &plan.hooks,
                            hook_state,
                            error,
                        )
                        .await);
                    }
                    if let Err(error) =
                        pid::validate_runtime_pid(plan, pid, runtime_pid, namespace_init_pid).await
                    {
                        return Err(cleanup_failed_create(
                            &mut child,
                            &mut cgroup,
                            &plan.hooks,
                            hook_state,
                            error,
                        )
                        .await);
                    }
                    if create_hooks_ready != Some((runtime_pid, namespace_init_pid)) {
                        let error = process_error(
                            ErrorCode::PermissionDenied,
                            "container init final readiness did not match its create-hook barrier",
                        );
                        return Err(cleanup_failed_create(
                            &mut child,
                            &mut cgroup,
                            &plan.hooks,
                            hook_state,
                            error,
                        )
                        .await);
                    }
                    break (runtime_pid, namespace_init_pid);
                }
                Ok(Ok(InitOutcome::Rejected(error))) => {
                    return Err(if create_hooks_ready.is_some() {
                        cleanup_failed_create(
                            &mut child,
                            &mut cgroup,
                            &plan.hooks,
                            hook_state,
                            error,
                        )
                        .await
                    } else {
                        cleanup_uncommitted_create(&mut child, &mut cgroup, error).await
                    });
                }
                Ok(Err(error)) => {
                    return Err(if create_hooks_ready.is_some() {
                        cleanup_failed_create(
                            &mut child,
                            &mut cgroup,
                            &plan.hooks,
                            hook_state,
                            error,
                        )
                        .await
                    } else {
                        cleanup_uncommitted_create(&mut child, &mut cgroup, error).await
                    });
                }
                Err(_) => {
                    let error = process_error(
                        ErrorCode::DeadlineExceeded,
                        "timed out reading prepared container init readiness",
                    );
                    return Err(if create_hooks_ready.is_some() {
                        cleanup_failed_create(
                            &mut child,
                            &mut cgroup,
                            &plan.hooks,
                            hook_state,
                            error,
                        )
                        .await
                    } else {
                        cleanup_uncommitted_create(&mut child, &mut cgroup, error).await
                    });
                }
            }
        };
        let pidfd = match PidFd::open(runtime_pid) {
            Ok(pidfd) => pidfd,
            Err(error) => {
                return Err(cleanup_failed_create(
                    &mut child,
                    &mut cgroup,
                    &plan.hooks,
                    hook_state,
                    error,
                )
                .await);
            }
        };
        let execution_context =
            match RetainedExecutionContext::capture(&plan.namespaces, runtime_pid, original_rootfs)
                .await
            {
                Ok(context) => context,
                Err(error) => {
                    return Err(cleanup_failed_create(
                        &mut child,
                        &mut cgroup,
                        &plan.hooks,
                        hook_state,
                        error,
                    )
                    .await);
                }
            };
        let network_devices = if plan.network_devices.is_empty() {
            None
        } else {
            let target_namespace = match execution_context.duplicate_network_namespace() {
                Ok(namespace) => namespace,
                Err(error) => {
                    return Err(cleanup_failed_create(
                        &mut child,
                        &mut cgroup,
                        &plan.hooks,
                        hook_state,
                        error,
                    )
                    .await);
                }
            };
            match NetworkDeviceLease::apply(&plan.network_devices, target_namespace).await {
                Ok(lease) => lease,
                Err(error) => {
                    return Err(cleanup_failed_create(
                        &mut child,
                        &mut cgroup,
                        &plan.hooks,
                        hook_state,
                        error,
                    )
                    .await);
                }
            }
        };
        drop(listener);

        Ok(Self {
            child,
            control: Some(control),
            pid: runtime_pid,
            namespace_init_pid,
            pidfd,
            process_group,
            has_process: plan.has_process,
            execution_context,
            capabilities: plan.capabilities,
            seccomp: plan.seccomp.clone(),
            cgroup,
            intel_rdt,
            network_devices,
            io: process_io,
            exit_status: None,
            hooks: plan.hooks.clone(),
            hook_state: hook_state.clone(),
            checkpoint_external_mounts: plan.devices.checkpoint_external_mounts(),
        })
    }

    pub(super) const fn pid(&self) -> i32 {
        self.pid
    }

    pub(super) const fn checkpoint_root_pid(&self) -> i32 {
        self.pid
    }

    pub(super) const fn has_pid_namespace_supervisor(&self) -> bool {
        self.namespace_init_pid.is_some()
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

    pub(super) fn checkpoint_cgroup_path(&self) -> Option<&Path> {
        self.cgroup
            .as_ref()
            .map(super::cgroup::CgroupHandle::checkpoint_path)
    }

    pub(super) fn checkpoint_external_mounts(&self) -> &[(String, PathBuf)] {
        &self.checkpoint_external_mounts
    }

    pub(super) fn has_isolated_checkpoint_workload(&self) -> bool {
        self.cgroup
            .as_ref()
            .is_some_and(super::cgroup::CgroupHandle::has_isolated_workload)
    }

    pub(super) async fn require_checkpoint_membership(&self) -> Result<()> {
        self.cgroup
            .as_ref()
            .ok_or_else(|| {
                process_error(
                    ErrorCode::FailedPrecondition,
                    "native checkpoint requires an explicit cgroup-v2 path",
                )
            })?
            .require_checkpoint_member(self.pid)
            .await
    }

    pub(super) fn recovery_intel_rdt(&self) -> Option<IntelRdtRecovery> {
        self.intel_rdt.as_ref().and_then(IntelRdtHandle::recovery)
    }

    pub(super) fn cleanup_intel_rdt(&mut self) -> Result<()> {
        if let Some(handle) = self.intel_rdt.as_mut() {
            handle.cleanup()?;
        }
        self.intel_rdt.take();
        Ok(())
    }

    pub(super) async fn rollback_network_devices(&mut self) -> Result<()> {
        match self.network_devices.take() {
            Some(lease) => lease.rollback().await,
            None => Ok(()),
        }
    }

    pub(super) fn commit_network_devices(&mut self) {
        if let Some(lease) = self.network_devices.as_mut() {
            lease.commit();
        }
    }

    pub(super) async fn release(&mut self) -> Result<()> {
        if self.control.is_none() {
            return Err(process_error(
                ErrorCode::FailedPrecondition,
                "container init has already crossed the start barrier",
            ));
        }
        if !self.has_process {
            drop(self.control.take());
            let mut error = process_error(
                ErrorCode::FailedPrecondition,
                "config.process is required before OCI start",
            );
            if let Err(cleanup) = self.force_stop().await {
                error.message = format!(
                    "{}; failed to stop the processless created container: {cleanup}",
                    error.message
                );
                error.retryable |= cleanup.retryable;
            }
            return Err(error);
        }
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
        let warnings = match started {
            Ok(warnings) => warnings,
            Err(error) => {
                let _ = self.force_stop().await;
                return Err(error);
            }
        };
        report_capability_warnings(&warnings);
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

    pub(super) fn has_configured_network_namespace(&self) -> bool {
        self.execution_context.has_configured_network_namespace()
    }

    pub(super) fn has_configured_user_namespace(&self) -> bool {
        self.execution_context.has_configured_user_namespace()
    }

    pub(super) fn uses_terminal(&self) -> bool {
        self.io.uses_terminal()
    }

    pub(super) const fn has_intel_rdt(&self) -> bool {
        self.intel_rdt.is_some()
    }

    pub(super) const fn has_network_devices(&self) -> bool {
        self.network_devices.is_some()
    }

    pub(super) fn has_hooks(&self) -> bool {
        self.hooks != HookSet::default()
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

    /// Authenticated init pidfd for exec handshake liveness checks.
    pub(super) const fn pidfd(&self) -> &PidFd {
        &self.pidfd
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

async fn cleanup_failed_create(
    child: &mut LauncherChild,
    cgroup: &mut Option<CgroupHandle>,
    hooks: &HookSet,
    hook_state: &HookStateTemplate,
    primary: Error,
) -> Error {
    let mut primary = cleanup_uncommitted_create(child, cgroup, primary).await;
    match hook_state.encode(
        a3s_oci_sdk::oci_spec::runtime::ContainerState::Stopped,
        None,
    ) {
        Ok(state) => hooks.run_poststop(&state).await,
        Err(error) => append_cleanup_error(&mut primary, "encode the poststop hook state", &error),
    }
    primary
}

fn append_cleanup_error(primary: &mut Error, action: &str, cleanup: &Error) {
    primary.message = format!(
        "{}; failed-create cleanup could not {action}: {cleanup}",
        primary.message
    );
    primary.retryable |= cleanup.retryable;
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
