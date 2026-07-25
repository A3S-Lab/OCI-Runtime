use std::fs::File;
use std::os::unix::net::UnixStream;
use std::path::Path;

use a3s_oci_sdk::{ErrorCode, Result};

use super::{init_error, prepare_create_environment, reject_before_ready, wait_for_start_and_exec};
use crate::executor::control::write_ready;
use crate::executor::mount::IdmappedMountSources;
use crate::executor::pid;
use crate::executor::pid_supervisor::{self, ChildOutcome, NamespaceForkRole, PayloadForkRole};
use crate::executor::plan::InitPlan;

pub(super) fn run_namespaced_init(
    plan: &InitPlan,
    bundle_directory: &Path,
    rootfs: &Path,
    rootfs_file: &File,
    host_proc: &File,
    mut idmapped_sources: IdmappedMountSources,
    mut control: UnixStream,
) -> Result<()> {
    match pid_supervisor::fork_namespace_child() {
        Ok(NamespaceForkRole::Launcher {
            child_pid,
            mut outcome_channel,
        }) => {
            drop(control);
            drop(idmapped_sources);
            if plan.namespaces.new_pid() {
                match pid_supervisor::read_supervised_outcome(&mut outcome_channel) {
                    Ok(Some(payload_outcome)) => {
                        let namespace_init_outcome = pid_supervisor::wait_for_child(child_pid)?;
                        if namespace_init_outcome != ChildOutcome::Exited(0) {
                            pid_supervisor::mirror_child_outcome(namespace_init_outcome);
                        }
                        pid_supervisor::mirror_child_outcome(payload_outcome)
                    }
                    Ok(None) => {
                        let outcome = pid_supervisor::wait_for_child(child_pid)?;
                        pid_supervisor::mirror_child_outcome(outcome)
                    }
                    Err(error) => {
                        pid_supervisor::terminate_pid(child_pid);
                        let _ = pid_supervisor::wait_for_child(child_pid);
                        Err(error)
                    }
                }
            } else {
                drop(outcome_channel);
                let outcome = pid_supervisor::wait_for_child(child_pid)?;
                pid_supervisor::mirror_child_outcome(outcome)
            }
        }
        Ok(NamespaceForkRole::NamespaceChild {
            host_pid,
            outcome_channel,
        }) => {
            if plan.namespaces.new_pid() {
                return run_pid_namespace_init(
                    plan,
                    bundle_directory,
                    rootfs,
                    rootfs_file,
                    host_proc,
                    host_pid,
                    idmapped_sources,
                    control,
                    outcome_channel,
                );
            }
            drop(outcome_channel);
            if let Err(error) =
                prepare_create_environment(plan, bundle_directory, rootfs, &mut idmapped_sources)
            {
                return reject_before_ready(&mut control, error);
            }
            drop(idmapped_sources);
            write_ready(&mut control, host_pid, None)?;
            wait_for_start_and_exec(plan, rootfs_file, control)
        }
        Err(error) => reject_before_ready(&mut control, error),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_pid_namespace_init(
    plan: &InitPlan,
    bundle_directory: &Path,
    rootfs: &Path,
    rootfs_file: &File,
    host_proc: &File,
    namespace_init_host_pid: libc::pid_t,
    mut idmapped_sources: IdmappedMountSources,
    mut control: UnixStream,
    mut outcome_channel: UnixStream,
) -> Result<()> {
    if let Err(error) =
        prepare_create_environment(plan, bundle_directory, rootfs, &mut idmapped_sources)
    {
        return reject_before_ready(&mut control, error);
    }
    drop(idmapped_sources);
    // SAFETY: `getpid` has no preconditions. This branch is the first child
    // created after `CLONE_NEWPID` and must therefore be namespace PID 1.
    let namespace_init_pid = unsafe { libc::getpid() };
    if namespace_init_pid != 1 {
        return reject_before_ready(
            &mut control,
            init_error(
                ErrorCode::PermissionDenied,
                format!("new PID namespace init has PID {namespace_init_pid}, expected 1"),
            ),
        );
    }
    match pid_supervisor::fork_payload(namespace_init_pid) {
        Ok(PayloadForkRole::NamespaceInit { child_pid }) => {
            drop(control);
            let outcome = pid_supervisor::supervise_payload(child_pid)?;
            pid_supervisor::report_supervised_outcome(&mut outcome_channel, outcome)
        }
        Ok(PayloadForkRole::Payload) => {
            drop(outcome_channel);
            let runtime_pid = match pid::host_visible_pid(host_proc) {
                Ok(pid) => pid,
                Err(error) => return reject_before_ready(&mut control, error),
            };
            write_ready(&mut control, runtime_pid, Some(namespace_init_host_pid))?;
            wait_for_start_and_exec(plan, rootfs_file, control)
        }
        Err(error) => reject_before_ready(&mut control, error),
    }
}
