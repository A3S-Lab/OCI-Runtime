use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::{SocketAddr, UnixStream as StdUnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use a3s_oci_sdk::{Error, ErrorCode, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::pid_supervisor;
use super::process_group::ProcessGroupLease;

const MODE: &str = "container-restore-supervisor";
const READY_BYTE: u8 = 0x52;
const ACKNOWLEDGE_BYTE: u8 = 0x41;
const MAX_PIDFILE_BYTES: u64 = 32;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) fn run_if_requested() -> Option<Result<()>> {
    let mut arguments = std::env::args_os();
    let _executable = arguments.next();
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new(MODE)) {
        return None;
    }
    Some(run(arguments.collect()))
}

fn run(arguments: Vec<OsString>) -> Result<()> {
    if arguments.len() != 4 {
        return Err(supervisor_error(
            ErrorCode::InvalidArgument,
            format!(
                "restore supervisor requires snapshot, control endpoint, pidfile, and owner PID; received {} arguments",
                arguments.len()
            ),
        ));
    }
    let snapshot = absolute_path(&arguments[0], "configuration snapshot")?;
    let control_name = arguments[1].to_str().ok_or_else(|| {
        supervisor_error(
            ErrorCode::InvalidArgument,
            "restore supervisor control endpoint is not valid UTF-8",
        )
    })?;
    if control_name.is_empty() || control_name.len() > 255 {
        return Err(supervisor_error(
            ErrorCode::InvalidArgument,
            "restore supervisor control endpoint is empty or oversized",
        ));
    }
    let pidfile = absolute_path(&arguments[2], "restored PID file")?;
    let expected_owner_pid = arguments[3]
        .to_str()
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| {
            supervisor_error(
                ErrorCode::InvalidArgument,
                "restore supervisor owner PID must be a positive integer",
            )
        })?;

    pid_supervisor::verify_and_arm_parent_death_signal(
        expected_owner_pid,
        "restored container supervisor",
    )?;
    let init_pid = read_restored_pid(&pidfile)?;
    if let Err(error) = verify_direct_child(init_pid) {
        cleanup_restored_child(init_pid);
        return Err(error);
    }
    let process_group = match ProcessGroupLease::open_for_snapshot_sync(&snapshot) {
        Ok(lease) => lease,
        Err(error) => {
            cleanup_restored_child(init_pid);
            return Err(error);
        }
    };
    if let Err(error) = report_ready(control_name, init_pid) {
        cleanup_restored_child(init_pid);
        return Err(error);
    }
    let outcome = match pid_supervisor::supervise_process_group(init_pid, &process_group) {
        Ok(outcome) => outcome,
        Err(error) => {
            cleanup_restored_child(init_pid);
            return Err(error);
        }
    };
    pid_supervisor::mirror_child_outcome(outcome)
}

pub(super) async fn read_ready(control: &mut UnixStream) -> Result<i32> {
    let mut message = [0_u8; 1 + size_of::<i32>()];
    control.read_exact(&mut message).await.map_err(|error| {
        supervisor_error(
            ErrorCode::Unavailable,
            format!("failed to read restored supervisor readiness: {error}"),
        )
    })?;
    let pid = i32::from_be_bytes(message[1..].try_into().map_err(|_| {
        supervisor_error(
            ErrorCode::Internal,
            "restored supervisor PID message has an invalid width",
        )
    })?);
    if message[0] != READY_BYTE || pid <= 0 {
        return Err(supervisor_error(
            ErrorCode::PermissionDenied,
            "restored supervisor sent an invalid readiness message",
        ));
    }
    Ok(pid)
}

pub(super) async fn acknowledge(control: &mut UnixStream) -> Result<()> {
    control
        .write_all(&[ACKNOWLEDGE_BYTE])
        .await
        .map_err(|error| {
            supervisor_error(
                ErrorCode::Unavailable,
                format!("failed to acknowledge restored supervisor readiness: {error}"),
            )
        })
}

fn report_ready(control_name: &str, init_pid: i32) -> Result<()> {
    let address = SocketAddr::from_abstract_name(control_name.as_bytes()).map_err(|error| {
        supervisor_error(
            ErrorCode::Internal,
            format!("failed to construct restore control address: {error}"),
        )
    })?;
    let mut control = StdUnixStream::connect_addr(&address).map_err(|error| {
        supervisor_error(
            ErrorCode::Unavailable,
            format!("failed to connect restored supervisor control channel: {error}"),
        )
    })?;
    control
        .set_read_timeout(Some(CONTROL_TIMEOUT))
        .and_then(|()| control.set_write_timeout(Some(CONTROL_TIMEOUT)))
        .map_err(|error| {
            supervisor_error(
                ErrorCode::Internal,
                format!("failed to bound restored supervisor control channel: {error}"),
            )
        })?;
    control
        .write_all(&[READY_BYTE])
        .and_then(|()| control.write_all(&init_pid.to_be_bytes()))
        .map_err(|error| {
            supervisor_error(
                ErrorCode::Unavailable,
                format!("failed to report restored supervisor readiness: {error}"),
            )
        })?;
    let mut acknowledgement = [0_u8; 1];
    control.read_exact(&mut acknowledgement).map_err(|error| {
        supervisor_error(
            ErrorCode::Unavailable,
            format!("restore owner closed before accepting the restored process: {error}"),
        )
    })?;
    if acknowledgement != [ACKNOWLEDGE_BYTE] {
        return Err(supervisor_error(
            ErrorCode::PermissionDenied,
            "restore owner sent an invalid readiness acknowledgement",
        ));
    }
    Ok(())
}

fn read_restored_pid(path: &Path) -> Result<i32> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|error| {
        supervisor_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to open restored PID file {}: {error}",
                path.display()
            ),
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        supervisor_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect restored PID file {}: {error}",
                path.display()
            ),
        )
    })?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_PIDFILE_BYTES {
        return Err(supervisor_error(
            ErrorCode::FailedPrecondition,
            "restored PID file is not a bounded non-empty regular file",
        ));
    }
    let mut encoded = String::new();
    file.take(MAX_PIDFILE_BYTES + 1)
        .read_to_string(&mut encoded)
        .map_err(|error| {
            supervisor_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to read restored PID file {}: {error}",
                    path.display()
                ),
            )
        })?;
    encoded
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| {
            supervisor_error(
                ErrorCode::FailedPrecondition,
                "restored PID file does not contain one positive decimal PID",
            )
        })
}

fn verify_direct_child(pid: i32) -> Result<()> {
    // SAFETY: getpid has no preconditions and cannot fail.
    let supervisor_pid = unsafe { libc::getpid() };
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|error| {
        supervisor_error(
            ErrorCode::PermissionDenied,
            format!("failed to inspect restored init PID {pid}: {error}"),
        )
    })?;
    let suffix = stat
        .rsplit_once(')')
        .map(|(_, suffix)| suffix.trim())
        .ok_or_else(|| {
            supervisor_error(
                ErrorCode::FailedPrecondition,
                "restored init proc stat is malformed",
            )
        })?;
    let mut fields = suffix.split_whitespace();
    let _state = fields.next();
    let parent_pid = fields
        .next()
        .and_then(|value| value.parse::<i32>().ok())
        .ok_or_else(|| {
            supervisor_error(
                ErrorCode::FailedPrecondition,
                "restored init proc stat omits a valid parent PID",
            )
        })?;
    if pid == supervisor_pid || parent_pid != supervisor_pid {
        return Err(supervisor_error(
            ErrorCode::PermissionDenied,
            format!(
                "restored init PID {pid} has parent {parent_pid}, expected supervisor {supervisor_pid}"
            ),
        ));
    }
    Ok(())
}

fn cleanup_restored_child(pid: i32) {
    pid_supervisor::terminate_process_group(pid);
    pid_supervisor::terminate_pid(pid);
    let _ = pid_supervisor::wait_for_child(pid);
}

fn absolute_path(value: &std::ffi::OsStr, label: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(supervisor_error(
            ErrorCode::InvalidArgument,
            format!(
                "restore supervisor {label} must be absolute: {}",
                path.display()
            ),
        ));
    }
    Ok(path)
}

fn supervisor_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("supervise-restored-container")
}
