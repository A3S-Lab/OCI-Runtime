use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};

use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::plan::InitPlan;

const MAX_PROC_STATUS_BYTES: u64 = 64 * 1024;

pub(super) fn host_visible_pid(host_proc: &File) -> Result<libc::pid_t> {
    let path = CString::new("self/status").map_err(|error| {
        pid_error(
            ErrorCode::Internal,
            format!("retained proc status path is invalid: {error}"),
        )
    })?;
    // SAFETY: `host_proc` is an open directory descriptor for the procfs
    // retained before PID namespace entry. The relative path is
    // NUL-terminated and ownership of a successful descriptor is transferred
    // exactly once to `File`.
    let status_fd = unsafe {
        libc::openat(
            host_proc.as_raw_fd(),
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if status_fd < 0 {
        return Err(last_os_error(
            "open payload status through retained host procfs",
        ));
    }
    // SAFETY: `status_fd` is a new owned descriptor returned by `openat`.
    let status_file = unsafe { File::from_raw_fd(status_fd) };
    let mut bytes = Vec::new();
    status_file
        .take(MAX_PROC_STATUS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            pid_error(
                ErrorCode::Internal,
                format!("failed to read payload status through retained host procfs: {error}"),
            )
        })?;
    if bytes.len() as u64 > MAX_PROC_STATUS_BYTES {
        return Err(pid_error(
            ErrorCode::ResourceExhausted,
            format!("payload proc status exceeds {MAX_PROC_STATUS_BYTES} bytes"),
        ));
    }
    let status = std::str::from_utf8(&bytes).map_err(|error| {
        pid_error(
            ErrorCode::FailedPrecondition,
            format!("payload proc status is not UTF-8: {error}"),
        )
    })?;
    parse_pid_identity(status)?
        .namespace_pids
        .first()
        .copied()
        .ok_or_else(|| {
            pid_error(
                ErrorCode::FailedPrecondition,
                "payload proc status contains no host-visible PID",
            )
        })
}

pub(super) async fn validate_runtime_pid(
    plan: &InitPlan,
    launcher_pid: i32,
    runtime_pid: i32,
    namespace_init_pid: Option<i32>,
) -> Result<()> {
    if plan.namespaces.new_pid() {
        let namespace_init_pid = namespace_init_pid.ok_or_else(|| {
            pid_error(
                ErrorCode::PermissionDenied,
                "new PID namespace payload omitted its namespace init PID",
            )
        })?;
        if runtime_pid == launcher_pid
            || namespace_init_pid == launcher_pid
            || runtime_pid == namespace_init_pid
        {
            return Err(pid_error(
                ErrorCode::PermissionDenied,
                "authenticated launcher, namespace init, and payload PIDs must be distinct",
            ));
        }
        let namespace_init_identity =
            read_pid_identity(namespace_init_pid, "namespace init").await?;
        let payload_identity = read_pid_identity(runtime_pid, "container payload").await?;
        validate_new_pid_identity_chain(
            launcher_pid,
            namespace_init_pid,
            runtime_pid,
            &namespace_init_identity,
            &payload_identity,
        )?;
        validate_new_pid_namespace_links(launcher_pid, namespace_init_pid, runtime_pid).await?;
        return validate_created_namespace_identities(plan, launcher_pid, runtime_pid).await;
    }

    if namespace_init_pid.is_some() {
        return Err(pid_error(
            ErrorCode::PermissionDenied,
            "container payload reported a namespace init without creating a PID namespace",
        ));
    }
    if !plan.namespaces.requires_child_process() {
        if runtime_pid == launcher_pid {
            return validate_created_namespace_identities(plan, launcher_pid, runtime_pid).await;
        }
        return Err(pid_error(
            ErrorCode::PermissionDenied,
            format!(
                "container payload reported PID {runtime_pid}, but authenticated launcher PID is \
                 {launcher_pid}"
            ),
        ));
    }
    if runtime_pid == launcher_pid {
        return Err(pid_error(
            ErrorCode::PermissionDenied,
            "namespace child must differ from its authenticated launcher",
        ));
    }

    let identity = read_pid_identity(runtime_pid, "container payload").await?;
    if identity.parent_pid != launcher_pid {
        return Err(pid_error(
            ErrorCode::PermissionDenied,
            format!(
                "reported container payload {runtime_pid} has parent {}, expected authenticated \
                 launcher {launcher_pid}",
                identity.parent_pid
            ),
        ));
    }
    validate_created_namespace_identities(plan, launcher_pid, runtime_pid).await
}

async fn read_pid_identity(pid: i32, role: &str) -> Result<PidIdentity> {
    let status = tokio::fs::read_to_string(format!("/proc/{pid}/status"))
        .await
        .map_err(|error| {
            pid_error(
                ErrorCode::PermissionDenied,
                format!("failed to inspect reported {role} {pid}: {error}"),
            )
        })?;
    parse_pid_identity(&status)
}

fn validate_new_pid_identity_chain(
    launcher_pid: i32,
    namespace_init_pid: i32,
    runtime_pid: i32,
    namespace_init: &PidIdentity,
    payload: &PidIdentity,
) -> Result<()> {
    if namespace_init.parent_pid != launcher_pid {
        return Err(pid_error(
            ErrorCode::PermissionDenied,
            format!(
                "reported namespace init {namespace_init_pid} has parent {}, expected \
                 authenticated launcher {launcher_pid}",
                namespace_init.parent_pid
            ),
        ));
    }
    if payload.parent_pid != namespace_init_pid {
        return Err(pid_error(
            ErrorCode::PermissionDenied,
            format!(
                "reported container payload {runtime_pid} has parent {}, expected namespace init \
                 {namespace_init_pid}",
                payload.parent_pid
            ),
        ));
    }
    if namespace_init.namespace_pids.first() != Some(&namespace_init_pid)
        || namespace_init.namespace_pids.last() != Some(&1)
        || namespace_init.namespace_pids.len() < 2
    {
        return Err(pid_error(
            ErrorCode::PermissionDenied,
            format!("reported namespace init {namespace_init_pid} does not map to namespace PID 1"),
        ));
    }
    if payload.namespace_pids.first() != Some(&runtime_pid)
        || payload.namespace_pids.last().is_none_or(|pid| *pid <= 1)
        || payload.namespace_pids.len() != namespace_init.namespace_pids.len()
    {
        return Err(pid_error(
            ErrorCode::PermissionDenied,
            format!(
                "reported container payload {runtime_pid} does not map to a PID above 1 in the \
                 namespace init's PID namespace"
            ),
        ));
    }
    Ok(())
}

async fn validate_new_pid_namespace_links(
    launcher_pid: i32,
    namespace_init_pid: i32,
    runtime_pid: i32,
) -> Result<()> {
    let namespace_init = read_namespace_link(
        &format!("/proc/{namespace_init_pid}/ns/pid"),
        "namespace init PID namespace",
        ErrorCode::PermissionDenied,
    )
    .await?;
    let payload = read_namespace_link(
        &format!("/proc/{runtime_pid}/ns/pid"),
        "container payload PID namespace",
        ErrorCode::PermissionDenied,
    )
    .await?;
    let agent = read_namespace_link(
        "/proc/self/ns/pid",
        "guest-agent PID namespace",
        ErrorCode::Internal,
    )
    .await?;
    let intended = read_namespace_link(
        &format!("/proc/{launcher_pid}/ns/pid_for_children"),
        "authenticated launcher's PID namespace target",
        ErrorCode::PermissionDenied,
    )
    .await?;
    if namespace_init != payload || namespace_init == agent || namespace_init != intended {
        return Err(pid_error(
            ErrorCode::PermissionDenied,
            "namespace init and container payload did not enter the authenticated new PID namespace",
        ));
    }
    Ok(())
}

async fn read_namespace_link(
    path: &str,
    description: &str,
    code: ErrorCode,
) -> Result<std::path::PathBuf> {
    tokio::fs::read_link(path)
        .await
        .map_err(|error| pid_error(code, format!("failed to inspect {description}: {error}")))
}

async fn validate_created_namespace_identities(
    plan: &InitPlan,
    supervisor_pid: i32,
    runtime_pid: i32,
) -> Result<()> {
    if plan.namespaces.new_user() {
        validate_namespace_identity(
            "user",
            &format!("/proc/{supervisor_pid}/ns/user"),
            &format!("/proc/{runtime_pid}/ns/user"),
            "/proc/self/ns/user",
        )
        .await?;
    }
    if plan.namespaces.new_time() {
        validate_namespace_identity(
            "time",
            &format!("/proc/{supervisor_pid}/ns/time_for_children"),
            &format!("/proc/{runtime_pid}/ns/time"),
            "/proc/self/ns/time",
        )
        .await?;
    }
    Ok(())
}

async fn validate_namespace_identity(
    namespace: &str,
    intended_path: &str,
    actual_path: &str,
    runtime_path: &str,
) -> Result<()> {
    let intended = tokio::fs::read_link(intended_path).await.map_err(|error| {
        pid_error(
            ErrorCode::PermissionDenied,
            format!("failed to inspect intended {namespace} namespace: {error}"),
        )
    })?;
    let actual = tokio::fs::read_link(actual_path).await.map_err(|error| {
        pid_error(
            ErrorCode::PermissionDenied,
            format!("failed to inspect container init {namespace} namespace: {error}"),
        )
    })?;
    let runtime = tokio::fs::read_link(runtime_path).await.map_err(|error| {
        pid_error(
            ErrorCode::Internal,
            format!("failed to inspect runtime {namespace} namespace: {error}"),
        )
    })?;
    if actual != intended || actual == runtime {
        Err(pid_error(
            ErrorCode::PermissionDenied,
            format!("container init did not enter the authenticated new {namespace} namespace"),
        ))
    } else {
        Ok(())
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
    use std::fs::File;

    use super::{
        host_visible_pid, parse_pid_identity, validate_new_pid_identity_chain, PidIdentity,
    };

    #[test]
    fn parses_parent_and_nested_pid_namespace_identity() {
        let status = "Name:\ta3s-oci-agent\nPid:\t413\nPPid:\t407\nNSpid:\t413\t1\n";
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

    #[test]
    fn validates_launcher_pid1_payload_identity_chain() {
        validate_new_pid_identity_chain(
            407,
            413,
            419,
            &PidIdentity {
                parent_pid: 407,
                namespace_pids: vec![413, 1],
            },
            &PidIdentity {
                parent_pid: 413,
                namespace_pids: vec![419, 2],
            },
        )
        .expect("valid PID supervision chain");
    }

    #[test]
    fn rejects_broken_launcher_pid1_payload_identity_chain() {
        for (namespace_init, payload) in [
            (
                PidIdentity {
                    parent_pid: 999,
                    namespace_pids: vec![413, 1],
                },
                PidIdentity {
                    parent_pid: 413,
                    namespace_pids: vec![419, 2],
                },
            ),
            (
                PidIdentity {
                    parent_pid: 407,
                    namespace_pids: vec![413, 1],
                },
                PidIdentity {
                    parent_pid: 999,
                    namespace_pids: vec![419, 2],
                },
            ),
            (
                PidIdentity {
                    parent_pid: 407,
                    namespace_pids: vec![413, 2],
                },
                PidIdentity {
                    parent_pid: 413,
                    namespace_pids: vec![419, 3],
                },
            ),
            (
                PidIdentity {
                    parent_pid: 407,
                    namespace_pids: vec![413, 1],
                },
                PidIdentity {
                    parent_pid: 413,
                    namespace_pids: vec![419, 1],
                },
            ),
        ] {
            let error = validate_new_pid_identity_chain(407, 413, 419, &namespace_init, &payload)
                .expect_err("broken PID supervision chain must fail");
            assert_eq!(error.code, a3s_oci_sdk::ErrorCode::PermissionDenied);
        }
    }

    #[test]
    fn retained_procfs_reports_the_current_host_visible_pid() {
        let host_proc = File::open("/proc").expect("open procfs");
        assert_eq!(
            host_visible_pid(&host_proc).expect("read host-visible PID"),
            i32::try_from(std::process::id()).expect("test PID fits i32")
        );
    }
}
