use std::fs::File;
use std::io;
use std::path::Path;
use std::process::ExitStatus as ProcessExitStatus;
use std::time::Duration;

use a3s_oci_sdk::{Error, ErrorCode, Result};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::timeout;

use super::super::cgroup::{self, CgroupHandle, CgroupManager};
use super::super::hook::{HookSet, HookStateTemplate};
use super::super::io::ProcessIoHandle;
use super::super::namespace::RetainedExecutionContext;
use super::super::pid;
use super::super::pid_supervisor;
use super::super::pidfd::PidFd;
use super::super::plan::InitPlan;
use super::super::process_group::ProcessGroupLease;
use super::super::restore::{
    LinuxRestoreSpawnRequest, LinuxRestoreSpawner, RestoreExternalMount, RestoreRootfsMount,
};
use super::super::{restore_cgroup_namespace, restore_supervisor};
use super::launch::{
    bind_control_listener, cleanup_uncommitted_create, cleanup_unstarted_cgroup,
    retain_original_rootfs,
};
use super::{append_cleanup_error, process_error, PreparedProcess, INIT_READY_TIMEOUT};

const RESTORE_READY_TIMEOUT: Duration = Duration::from_secs(5 * 60);

impl PreparedProcess {
    pub(in crate::executor) async fn restore(
        plan: &InitPlan,
        config_snapshot: &Path,
        supervisor_executable: &Path,
        cgroup_manager: Option<&CgroupManager>,
        hook_state: &HookStateTemplate,
        external_mounts: Vec<RestoreExternalMount>,
        spawner: &dyn LinuxRestoreSpawner,
    ) -> Result<Self> {
        let (original_rootfs, pinned_rootfs) = retain_original_rootfs(plan, None).await?;
        if pinned_rootfs.is_some() {
            return Err(process_error(
                ErrorCode::Unsupported,
                "native restore cannot use a utility-VM pinned rootfs",
            ));
        }
        let process_group = ProcessGroupLease::open_for_snapshot(config_snapshot).await?;
        let mut cgroup = CgroupHandle::create(
            &plan.cgroup,
            &plan.cgroup_ownership,
            &plan.devices,
            cgroup_manager,
        )?;
        // SAFETY: getpid has no preconditions and cannot fail.
        let expected_owner_pid = unsafe { libc::getpid() };
        let management_cgroup_procs = match cgroup
            .as_ref()
            .ok_or_else(|| {
                process_error(
                    ErrorCode::FailedPrecondition,
                    "native restore requires an explicit cgroup-v2 path",
                )
            })
            .and_then(CgroupHandle::restore_management_procs)
        {
            Ok(descriptor) => descriptor,
            Err(error) => return Err(cleanup_unstarted_cgroup(&mut cgroup, error)),
        };
        let cgroup_namespace = match prepare_restore_cgroup_namespace(
            supervisor_executable,
            expected_owner_pid,
            management_cgroup_procs,
            cgroup.as_ref().ok_or_else(|| {
                process_error(ErrorCode::Internal, "native restore lost its cgroup handle")
            })?,
        )
        .await
        {
            Ok(namespace) => namespace,
            Err(error) => return Err(cleanup_unstarted_cgroup(&mut cgroup, error)),
        };
        let finalized = match (cgroup.as_mut(), cgroup_manager) {
            (Some(cgroup), Some(manager)) => {
                cgroup.finalize_control_workload(&plan.cgroup, manager)
            }
            _ => Err(process_error(
                ErrorCode::FailedPrecondition,
                "native restore requires an initialized cgroup manager",
            )),
        };
        if let Err(error) = finalized {
            return Err(cleanup_unstarted_cgroup(&mut cgroup, error));
        }
        let control_cgroup_procs = match cgroup
            .as_ref()
            .ok_or_else(|| {
                process_error(
                    ErrorCode::FailedPrecondition,
                    "native restore requires an explicit cgroup-v2 path",
                )
            })
            .and_then(CgroupHandle::restore_control_procs)
        {
            Ok(descriptor) => descriptor,
            Err(error) => return Err(cleanup_unstarted_cgroup(&mut cgroup, error)),
        };
        let (listener, control_name) = match bind_control_listener() {
            Ok(listener) => listener,
            Err(error) => return Err(cleanup_unstarted_cgroup(&mut cgroup, error)),
        };
        let mut rootfs_mount = match RestoreRootfsMount::bind(&plan.rootfs) {
            Ok(mount) => mount,
            Err(error) => return Err(cleanup_unstarted_cgroup(&mut cgroup, error)),
        };
        let spawn_request = LinuxRestoreSpawnRequest {
            supervisor_executable: supervisor_executable.to_path_buf(),
            config_snapshot: config_snapshot.to_path_buf(),
            control_name,
            expected_owner_pid,
            rootfs: plan.rootfs.clone(),
            cgroup_namespace,
            control_cgroup_procs,
            external_mounts,
        };
        let mut child = match spawner.spawn(spawn_request).await {
            Ok(child) => child,
            Err(mut error) => {
                if let Err(cleanup) = rootfs_mount.cleanup() {
                    append_cleanup_error(&mut error, "release the restore rootfs mount", &cleanup);
                }
                return Err(cleanup_unstarted_cgroup(&mut cgroup, error));
            }
        };
        let supervisor_pid = match child.id().and_then(|pid| i32::try_from(pid).ok()) {
            Some(pid) if pid > 0 => pid,
            _ => {
                let error = process_error(
                    ErrorCode::Internal,
                    "spawned restore supervisor has no representable live PID",
                );
                return Err(cleanup_failed_restore(
                    &mut child,
                    &mut cgroup,
                    &mut rootfs_mount,
                    error,
                )
                .await);
            }
        };

        enum ReadyOutcome {
            Connected(io::Result<(UnixStream, tokio::net::unix::SocketAddr)>),
            Exited(io::Result<ProcessExitStatus>),
        }
        let ready = timeout(RESTORE_READY_TIMEOUT, async {
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
                    format!("failed to accept restored supervisor control connection: {error}"),
                );
                return Err(cleanup_failed_restore(
                    &mut child,
                    &mut cgroup,
                    &mut rootfs_mount,
                    error,
                )
                .await);
            }
            Ok(ReadyOutcome::Exited(Ok(status))) => {
                let error = process_error(
                    ErrorCode::FailedPrecondition,
                    format!("CRIU restore supervisor exited before readiness with {status}"),
                );
                return Err(cleanup_failed_restore(
                    &mut child,
                    &mut cgroup,
                    &mut rootfs_mount,
                    error,
                )
                .await);
            }
            Ok(ReadyOutcome::Exited(Err(error))) => {
                let error = process_error(
                    ErrorCode::Internal,
                    format!("failed to wait for CRIU restore supervisor: {error}"),
                );
                return Err(cleanup_failed_restore(
                    &mut child,
                    &mut cgroup,
                    &mut rootfs_mount,
                    error,
                )
                .await);
            }
            Err(_) => {
                let error = process_error(
                    ErrorCode::DeadlineExceeded,
                    "timed out waiting for CRIU restore readiness",
                );
                return Err(cleanup_failed_restore(
                    &mut child,
                    &mut cgroup,
                    &mut rootfs_mount,
                    error,
                )
                .await);
            }
        };
        let peer = match control.peer_cred() {
            Ok(peer) => peer,
            Err(error) => {
                let error = process_error(
                    ErrorCode::Internal,
                    format!("failed to read restored supervisor peer credentials: {error}"),
                );
                return Err(cleanup_failed_restore(
                    &mut child,
                    &mut cgroup,
                    &mut rootfs_mount,
                    error,
                )
                .await);
            }
        };
        if peer.pid() != Some(supervisor_pid) {
            let error = process_error(
                ErrorCode::PermissionDenied,
                format!(
                    "restore control peer PID {:?} does not match supervisor {supervisor_pid}",
                    peer.pid()
                ),
            );
            return Err(
                cleanup_failed_restore(&mut child, &mut cgroup, &mut rootfs_mount, error).await,
            );
        }
        let runtime_pid = match timeout(
            INIT_READY_TIMEOUT,
            restore_supervisor::read_ready(&mut control),
        )
        .await
        {
            Ok(Ok(pid)) => pid,
            Ok(Err(error)) => {
                return Err(cleanup_failed_restore(
                    &mut child,
                    &mut cgroup,
                    &mut rootfs_mount,
                    error,
                )
                .await);
            }
            Err(_) => {
                let error = process_error(
                    ErrorCode::DeadlineExceeded,
                    "timed out reading restored init readiness",
                );
                return Err(cleanup_failed_restore(
                    &mut child,
                    &mut cgroup,
                    &mut rootfs_mount,
                    error,
                )
                .await);
            }
        };
        if let Err(error) =
            pid::validate_restored_runtime_pid(plan, supervisor_pid, runtime_pid).await
        {
            return Err(
                cleanup_failed_restore(&mut child, &mut cgroup, &mut rootfs_mount, error).await,
            );
        }
        let pidfd = match PidFd::open(runtime_pid) {
            Ok(pidfd) => pidfd,
            Err(error) => {
                return Err(cleanup_failed_restore(
                    &mut child,
                    &mut cgroup,
                    &mut rootfs_mount,
                    error,
                )
                .await);
            }
        };
        let frozen = match cgroup.as_ref() {
            Some(handle) => handle.set_frozen(true).await,
            None => Err(process_error(
                ErrorCode::Internal,
                "native restore lost its prepared cgroup",
            )),
        };
        if let Err(error) = frozen {
            return Err(
                cleanup_failed_restore(&mut child, &mut cgroup, &mut rootfs_mount, error).await,
            );
        }
        let adopted = match cgroup.as_ref() {
            Some(handle) => {
                handle
                    .adopt_restored_members(supervisor_pid, runtime_pid)
                    .await
            }
            None => Err(process_error(
                ErrorCode::Internal,
                "native restore lost its prepared cgroup",
            )),
        };
        if let Err(error) = adopted {
            return Err(
                cleanup_failed_restore(&mut child, &mut cgroup, &mut rootfs_mount, error).await,
            );
        }
        let device_filter_activated = cgroup
            .as_mut()
            .ok_or_else(|| {
                process_error(
                    ErrorCode::Internal,
                    "native restore lost its prepared cgroup",
                )
            })
            .and_then(CgroupHandle::activate_device_filter);
        if let Err(error) = device_filter_activated {
            return Err(
                cleanup_failed_restore(&mut child, &mut cgroup, &mut rootfs_mount, error).await,
            );
        }
        let execution_context =
            match RetainedExecutionContext::capture(&plan.namespaces, runtime_pid, original_rootfs)
                .await
            {
                Ok(context) => context,
                Err(error) => {
                    return Err(cleanup_failed_restore(
                        &mut child,
                        &mut cgroup,
                        &mut rootfs_mount,
                        error,
                    )
                    .await);
                }
            };
        let continued = match cgroup.as_ref() {
            Some(handle) => handle.continue_stopped_restore_members(runtime_pid).await,
            None => Err(process_error(
                ErrorCode::Internal,
                "native restore lost its prepared cgroup",
            )),
        };
        if let Err(error) = continued {
            return Err(
                cleanup_failed_restore(&mut child, &mut cgroup, &mut rootfs_mount, error).await,
            );
        }
        if let Err(error) = rootfs_mount.cleanup() {
            return Err(
                cleanup_failed_restore(&mut child, &mut cgroup, &mut rootfs_mount, error).await,
            );
        }
        if let Err(error) = restore_supervisor::acknowledge(&mut control).await {
            return Err(
                cleanup_failed_restore(&mut child, &mut cgroup, &mut rootfs_mount, error).await,
            );
        }
        drop(control);
        drop(listener);

        Ok(Self {
            child,
            control: None,
            pid: runtime_pid,
            namespace_init_pid: None,
            pidfd,
            process_group,
            has_process: plan.has_process,
            execution_context,
            capabilities: plan.capabilities,
            seccomp: plan.seccomp.clone(),
            cgroup,
            intel_rdt: None,
            network_devices: None,
            io: ProcessIoHandle::restored_null(),
            exit_status: None,
            hooks: HookSet::default(),
            hook_state: hook_state.clone(),
            checkpoint_external_mounts: plan.devices.checkpoint_external_mounts(),
        })
    }
}

async fn cleanup_failed_restore(
    child: &mut Child,
    cgroup: &mut Option<CgroupHandle>,
    rootfs_mount: &mut RestoreRootfsMount,
    primary: Error,
) -> Error {
    let mut primary = cleanup_uncommitted_create(child, cgroup, primary).await;
    if let Err(error) = rootfs_mount.cleanup() {
        append_cleanup_error(&mut primary, "release the restore rootfs mount", &error);
    }
    primary
}

async fn prepare_restore_cgroup_namespace(
    supervisor_executable: &Path,
    expected_owner_pid: i32,
    management_cgroup_procs: File,
    cgroup: &CgroupHandle,
) -> Result<File> {
    let (listener, control_name) = bind_control_listener()?;
    let mut command = Command::new(supervisor_executable);
    command
        .arg(restore_cgroup_namespace::MODE)
        .arg(control_name)
        .arg(expected_owner_pid.to_string())
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    // SAFETY: the callback runs in the freshly forked helper and performs only
    // the established parent-death check and one retained cgroup.procs write.
    unsafe {
        command.pre_exec(move || {
            pid_supervisor::verify_and_arm_parent_death_signal(
                expected_owner_pid,
                "restore cgroup namespace launcher",
            )
            .map_err(|error| io::Error::other(error.to_string()))?;
            cgroup::join_current_process(std::os::fd::AsRawFd::as_raw_fd(&management_cgroup_procs))
        });
    }
    let mut child = command.spawn().map_err(|error| {
        process_error(
            ErrorCode::Unavailable,
            format!("failed to spawn restore cgroup namespace helper: {error}"),
        )
    })?;
    let helper_pid = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| {
            process_error(
                ErrorCode::Internal,
                "restore cgroup namespace helper has no representable PID",
            )
        });
    let helper_pid = match helper_pid {
        Ok(pid) => pid,
        Err(error) => return Err(cleanup_restore_namespace_helper(&mut child, error).await),
    };

    enum NamespaceReady {
        Connected(io::Result<(UnixStream, tokio::net::unix::SocketAddr)>),
        Exited(io::Result<ProcessExitStatus>),
    }
    let ready = timeout(INIT_READY_TIMEOUT, async {
        tokio::select! {
            accepted = listener.accept() => NamespaceReady::Connected(accepted),
            status = child.wait() => NamespaceReady::Exited(status),
        }
    })
    .await;
    let mut control = match ready {
        Ok(NamespaceReady::Connected(Ok((control, _)))) => control,
        Ok(NamespaceReady::Connected(Err(error))) => {
            let error = process_error(
                ErrorCode::Internal,
                format!("failed to accept restore cgroup namespace connection: {error}"),
            );
            return Err(cleanup_restore_namespace_helper(&mut child, error).await);
        }
        Ok(NamespaceReady::Exited(Ok(status))) => {
            return Err(process_error(
                ErrorCode::FailedPrecondition,
                format!("restore cgroup namespace helper exited before readiness with {status}"),
            ));
        }
        Ok(NamespaceReady::Exited(Err(error))) => {
            return Err(process_error(
                ErrorCode::Internal,
                format!("failed to wait for restore cgroup namespace helper: {error}"),
            ));
        }
        Err(_) => {
            let error = process_error(
                ErrorCode::DeadlineExceeded,
                "timed out preparing restore cgroup namespace",
            );
            return Err(cleanup_restore_namespace_helper(&mut child, error).await);
        }
    };
    let peer = control.peer_cred().map_err(|error| {
        process_error(
            ErrorCode::Internal,
            format!("failed to inspect restore cgroup namespace peer: {error}"),
        )
    });
    match peer {
        Ok(peer) if peer.pid() == Some(helper_pid) => {}
        Ok(peer) => {
            let error = process_error(
                ErrorCode::PermissionDenied,
                format!(
                    "restore cgroup namespace peer PID {:?} does not match helper {helper_pid}",
                    peer.pid()
                ),
            );
            return Err(cleanup_restore_namespace_helper(&mut child, error).await);
        }
        Err(error) => return Err(cleanup_restore_namespace_helper(&mut child, error).await),
    }
    match timeout(
        INIT_READY_TIMEOUT,
        restore_cgroup_namespace::read_ready(&mut control),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(cleanup_restore_namespace_helper(&mut child, error).await),
        Err(_) => {
            let error = process_error(
                ErrorCode::DeadlineExceeded,
                "timed out reading restore cgroup namespace readiness",
            );
            return Err(cleanup_restore_namespace_helper(&mut child, error).await);
        }
    }
    let namespace_path = std::path::PathBuf::from(format!("/proc/{helper_pid}/ns/cgroup"));
    let namespace = match File::open(&namespace_path) {
        Ok(namespace) => namespace,
        Err(error) => {
            let error = process_error(
                ErrorCode::PermissionDenied,
                format!(
                    "failed to retain restore cgroup namespace {}: {error}",
                    namespace_path.display()
                ),
            );
            return Err(cleanup_restore_namespace_helper(&mut child, error).await);
        }
    };
    if let Err(error) = cgroup.move_restore_helper_to_control(helper_pid) {
        return Err(cleanup_restore_namespace_helper(&mut child, error).await);
    }
    if let Err(error) = restore_cgroup_namespace::acknowledge(&mut control).await {
        return Err(cleanup_restore_namespace_helper(&mut child, error).await);
    }
    drop(control);
    drop(listener);
    match timeout(INIT_READY_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) if status.success() => Ok(namespace),
        Ok(Ok(status)) => Err(process_error(
            ErrorCode::FailedPrecondition,
            format!("restore cgroup namespace helper exited with {status}"),
        )),
        Ok(Err(error)) => Err(process_error(
            ErrorCode::Internal,
            format!("failed to reap restore cgroup namespace helper: {error}"),
        )),
        Err(_) => {
            let error = process_error(
                ErrorCode::DeadlineExceeded,
                "timed out reaping restore cgroup namespace helper",
            );
            Err(cleanup_restore_namespace_helper(&mut child, error).await)
        }
    }
}

async fn cleanup_restore_namespace_helper(child: &mut Child, mut primary: Error) -> Error {
    let _ = child.start_kill();
    match timeout(INIT_READY_TIMEOUT, child.wait()).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            primary.message = format!(
                "{}; failed to reap restore cgroup namespace helper: {error}",
                primary.message
            );
        }
        Err(_) => {
            primary.message = format!(
                "{}; timed out reaping restore cgroup namespace helper",
                primary.message
            );
        }
    }
    primary
}
