use std::fs::File;
use std::os::unix::net::UnixStream;

use a3s_oci_sdk::{ErrorCode, Result};

use super::{complete_create_and_wait_for_start, init_error, reject_before_ready, CreateContext};
use crate::executor::mount::DetachedMountSources;
use crate::executor::pid;
use crate::executor::pid_supervisor::{self, ChildOutcome, NamespaceForkRole, PayloadForkRole};
use crate::executor::process_group::ProcessGroupLease;

pub(super) fn run_supervised_init(
    create: &CreateContext<'_>,
    host_proc: &File,
    detached_sources: DetachedMountSources,
    mut control: UnixStream,
    process_group: ProcessGroupLease,
) -> Result<()> {
    match pid_supervisor::fork_namespace_child() {
        Ok(NamespaceForkRole::Launcher {
            child_pid,
            mut outcome_channel,
        }) => {
            drop(control);
            drop(detached_sources);
            if create.plan.namespaces.new_pid() {
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
                let outcome = pid_supervisor::supervise_process_group(child_pid, &process_group)?;
                pid_supervisor::mirror_child_outcome(outcome)
            }
        }
        Ok(NamespaceForkRole::NamespaceChild {
            host_pid,
            outcome_channel,
        }) => {
            if create.plan.namespaces.new_pid() {
                return run_pid_namespace_init(
                    create,
                    host_proc,
                    host_pid,
                    detached_sources,
                    control,
                    outcome_channel,
                    &process_group,
                );
            }
            drop(outcome_channel);
            complete_create_and_wait_for_start(
                create,
                host_proc,
                detached_sources,
                host_pid,
                None,
                control,
            )
        }
        Err(error) => reject_before_ready(&mut control, error),
    }
}

fn run_pid_namespace_init(
    create: &CreateContext<'_>,
    host_proc: &File,
    namespace_init_host_pid: libc::pid_t,
    detached_sources: DetachedMountSources,
    mut control: UnixStream,
    mut outcome_channel: UnixStream,
    process_group: &ProcessGroupLease,
) -> Result<()> {
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
            let outcome = pid_supervisor::supervise_payload(child_pid, process_group)?;
            pid_supervisor::report_supervised_outcome(&mut outcome_channel, outcome)
        }
        Ok(PayloadForkRole::Payload) => {
            drop(outcome_channel);
            let runtime_pid = match pid::host_visible_pid(host_proc) {
                Ok(pid) => pid,
                Err(error) => return reject_before_ready(&mut control, error),
            };
            complete_create_and_wait_for_start(
                create,
                host_proc,
                detached_sources,
                runtime_pid,
                Some(namespace_init_host_pid),
                control,
            )
        }
        Err(error) => reject_before_ready(&mut control, error),
    }
}
