use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::plan::InitPlan;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ForkRole {
    Supervisor { child_pid: libc::pid_t },
    Init { runtime_pid: libc::pid_t },
}

pub(super) fn fork_namespace_init() -> Result<ForkRole> {
    let (mut supervisor_channel, mut init_channel) = UnixStream::pair().map_err(|error| {
        pid_error(
            ErrorCode::Internal,
            format!("failed to create PID namespace supervisor channel: {error}"),
        )
    })?;
    // SAFETY: the internal init wrapper enters this path before constructing a
    // Tokio runtime or any additional threads. Both branches immediately close
    // the socket endpoint they do not own.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(last_os_error("fork PID namespace init process"));
    }
    if child_pid == 0 {
        drop(supervisor_channel);
        // SAFETY: `prctl` receives only integer arguments. Arming a fatal
        // parent-death signal ensures that killing the authenticated
        // supervisor cannot orphan the namespace init.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
            return Err(last_os_error("arm PID namespace init parent-death signal"));
        }
        let mut encoded_pid = [0_u8; size_of::<libc::pid_t>()];
        init_channel.read_exact(&mut encoded_pid).map_err(|error| {
            pid_error(
                ErrorCode::Unavailable,
                format!("PID namespace supervisor closed before identifying init: {error}"),
            )
        })?;
        let runtime_pid = libc::pid_t::from_be_bytes(encoded_pid);
        if runtime_pid <= 0 {
            return Err(pid_error(
                ErrorCode::Internal,
                format!("PID namespace supervisor reported non-positive init PID {runtime_pid}"),
            ));
        }
        drop(init_channel);
        return Ok(ForkRole::Init { runtime_pid });
    }

    drop(init_channel);
    if let Err(error) = supervisor_channel.write_all(&child_pid.to_be_bytes()) {
        terminate_pid(child_pid);
        let _ = wait_for_child(child_pid);
        return Err(pid_error(
            ErrorCode::Internal,
            format!("failed to identify PID namespace init process: {error}"),
        ));
    }
    drop(supervisor_channel);
    Ok(ForkRole::Supervisor { child_pid })
}

pub(super) fn wait_for_child(pid: libc::pid_t) -> Result<()> {
    loop {
        let mut status = 0;
        // SAFETY: `status` points to writable storage and `pid` is the
        // positive child PID returned by `fork`.
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == pid {
            return Ok(());
        }
        if waited < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(last_os_error("reap PID namespace init process"));
    }
}

pub(super) async fn validate_runtime_pid(
    plan: &InitPlan,
    supervisor_pid: i32,
    runtime_pid: i32,
) -> Result<()> {
    if !plan.new_pid_namespace {
        if runtime_pid == supervisor_pid {
            return Ok(());
        }
        return Err(pid_error(
            ErrorCode::PermissionDenied,
            format!(
                "container init reported PID {runtime_pid}, but authenticated supervisor PID is \
                 {supervisor_pid}"
            ),
        ));
    }
    if runtime_pid == supervisor_pid {
        return Err(pid_error(
            ErrorCode::PermissionDenied,
            "PID namespace init must differ from its authenticated supervisor",
        ));
    }

    let status = tokio::fs::read_to_string(format!("/proc/{runtime_pid}/status"))
        .await
        .map_err(|error| {
            pid_error(
                ErrorCode::PermissionDenied,
                format!("failed to inspect reported PID namespace init {runtime_pid}: {error}"),
            )
        })?;
    let identity = parse_pid_identity(&status)?;
    if identity.parent_pid != supervisor_pid {
        return Err(pid_error(
            ErrorCode::PermissionDenied,
            format!(
                "reported PID namespace init {runtime_pid} has parent {}, expected authenticated \
                 supervisor {supervisor_pid}",
                identity.parent_pid
            ),
        ));
    }
    if identity.namespace_pids.first() != Some(&runtime_pid)
        || identity.namespace_pids.last() != Some(&1)
        || identity.namespace_pids.len() < 2
    {
        return Err(pid_error(
            ErrorCode::PermissionDenied,
            format!("reported PID namespace init {runtime_pid} does not map to namespace PID 1"),
        ));
    }

    let init_namespace = tokio::fs::read_link(format!("/proc/{runtime_pid}/ns/pid"))
        .await
        .map_err(|error| {
            pid_error(
                ErrorCode::PermissionDenied,
                format!("failed to inspect PID namespace for init {runtime_pid}: {error}"),
            )
        })?;
    let runtime_namespace = tokio::fs::read_link("/proc/self/ns/pid")
        .await
        .map_err(|error| {
            pid_error(
                ErrorCode::Internal,
                format!("failed to inspect guest-agent PID namespace: {error}"),
            )
        })?;
    let intended_namespace =
        tokio::fs::read_link(format!("/proc/{supervisor_pid}/ns/pid_for_children"))
            .await
            .map_err(|error| {
                pid_error(
                    ErrorCode::PermissionDenied,
                    format!(
                        "failed to inspect authenticated supervisor PID namespace target: {error}"
                    ),
                )
            })?;
    if init_namespace == runtime_namespace || init_namespace != intended_namespace {
        return Err(pid_error(
            ErrorCode::PermissionDenied,
            format!(
                "reported init {runtime_pid} is not in the authenticated supervisor's new PID \
                 namespace"
            ),
        ));
    }
    Ok(())
}

fn terminate_pid(pid: libc::pid_t) {
    if pid > 0 {
        // SAFETY: `pid` is a positive child PID and SIGKILL has no pointer
        // preconditions.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PidIdentity {
    parent_pid: i32,
    namespace_pids: Vec<i32>,
}

fn parse_pid_identity(status: &str) -> Result<PidIdentity> {
    let parent_pid = parse_status_pids(status, "PPid:")?
        .into_iter()
        .next()
        .ok_or_else(|| {
            pid_error(
                ErrorCode::FailedPrecondition,
                "container init status contains an empty PPid field",
            )
        })?;
    let namespace_pids = parse_status_pids(status, "NSpid:")?;
    if namespace_pids.is_empty() {
        return Err(pid_error(
            ErrorCode::FailedPrecondition,
            "container init status contains an empty NSpid field",
        ));
    }
    Ok(PidIdentity {
        parent_pid,
        namespace_pids,
    })
}

fn parse_status_pids(status: &str, field: &str) -> Result<Vec<i32>> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .ok_or_else(|| {
            pid_error(
                ErrorCode::FailedPrecondition,
                format!("container init status is missing {field}"),
            )
        })?;
    value
        .split_ascii_whitespace()
        .map(|value| {
            value.parse::<i32>().map_err(|error| {
                pid_error(
                    ErrorCode::FailedPrecondition,
                    format!("container init status has invalid {field} value `{value}`: {error}"),
                )
            })
        })
        .collect()
}

fn last_os_error(operation: &str) -> Error {
    pid_error(
        ErrorCode::Internal,
        format!("{operation} failed: {}", io::Error::last_os_error()),
    )
}

fn pid_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("run-container-init")
}

#[cfg(test)]
mod tests {
    use super::{parse_pid_identity, PidIdentity};

    #[test]
    fn parses_supervisor_and_nested_pid_namespace_identity() {
        let status = "Name:\tsh\nPid:\t413\nPPid:\t407\nNSpid:\t413\t1\n";
        assert_eq!(
            parse_pid_identity(status).expect("parse PID identity"),
            PidIdentity {
                parent_pid: 407,
                namespace_pids: vec![413, 1],
            }
        );
    }

    #[test]
    fn rejects_missing_or_malformed_pid_namespace_identity() {
        for status in [
            "PPid:\t407\n",
            "PPid:\tnot-a-pid\nNSpid:\t413\t1\n",
            "PPid:\t407\nNSpid:\t\n",
        ] {
            let error = parse_pid_identity(status).expect_err("invalid PID identity must fail");
            assert_eq!(error.code, a3s_oci_sdk::ErrorCode::FailedPrecondition);
        }
    }
}
