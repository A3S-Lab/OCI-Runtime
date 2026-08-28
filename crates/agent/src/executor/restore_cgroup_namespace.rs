use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixStream as StdUnixStream};
use std::time::Duration;

use a3s_oci_sdk::{Error, ErrorCode, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::pid_supervisor;

pub(super) const MODE: &str = "container-restore-cgroup-namespace";
const READY_BYTE: u8 = 0x4e;
const ACKNOWLEDGE_BYTE: u8 = 0x41;
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
    if arguments.len() != 2 {
        return Err(namespace_error(
            ErrorCode::InvalidArgument,
            format!(
                "restore cgroup namespace helper requires a control endpoint and owner PID; received {} arguments",
                arguments.len()
            ),
        ));
    }
    let control_name = arguments[0].to_str().ok_or_else(|| {
        namespace_error(
            ErrorCode::InvalidArgument,
            "restore cgroup namespace control endpoint is not valid UTF-8",
        )
    })?;
    if control_name.is_empty() || control_name.len() > 255 {
        return Err(namespace_error(
            ErrorCode::InvalidArgument,
            "restore cgroup namespace control endpoint is empty or oversized",
        ));
    }
    let expected_owner_pid = arguments[1]
        .to_str()
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| {
            namespace_error(
                ErrorCode::InvalidArgument,
                "restore cgroup namespace owner PID must be a positive integer",
            )
        })?;
    pid_supervisor::verify_and_arm_parent_death_signal(
        expected_owner_pid,
        "restore cgroup namespace helper",
    )?;
    // SAFETY: unshare receives one supported namespace flag and no pointers.
    if unsafe { libc::unshare(libc::CLONE_NEWCGROUP) } != 0 {
        return Err(namespace_error(
            ErrorCode::PermissionDenied,
            format!(
                "failed to create restore cgroup namespace: {}",
                std::io::Error::last_os_error()
            ),
        ));
    }
    report_ready(control_name)
}

pub(super) async fn read_ready(control: &mut UnixStream) -> Result<()> {
    let mut ready = [0_u8; 1];
    control.read_exact(&mut ready).await.map_err(|error| {
        namespace_error(
            ErrorCode::Unavailable,
            format!("failed to read restore cgroup namespace readiness: {error}"),
        )
    })?;
    if ready != [READY_BYTE] {
        return Err(namespace_error(
            ErrorCode::PermissionDenied,
            "restore cgroup namespace helper sent invalid readiness",
        ));
    }
    Ok(())
}

pub(super) async fn acknowledge(control: &mut UnixStream) -> Result<()> {
    control
        .write_all(&[ACKNOWLEDGE_BYTE])
        .await
        .map_err(|error| {
            namespace_error(
                ErrorCode::Unavailable,
                format!("failed to acknowledge restore cgroup namespace: {error}"),
            )
        })
}

fn report_ready(control_name: &str) -> Result<()> {
    let address = SocketAddr::from_abstract_name(control_name.as_bytes()).map_err(|error| {
        namespace_error(
            ErrorCode::Internal,
            format!("failed to construct restore cgroup namespace address: {error}"),
        )
    })?;
    let mut control = StdUnixStream::connect_addr(&address).map_err(|error| {
        namespace_error(
            ErrorCode::Unavailable,
            format!("failed to connect restore cgroup namespace channel: {error}"),
        )
    })?;
    control
        .set_read_timeout(Some(CONTROL_TIMEOUT))
        .and_then(|()| control.set_write_timeout(Some(CONTROL_TIMEOUT)))
        .map_err(|error| {
            namespace_error(
                ErrorCode::Internal,
                format!("failed to bound restore cgroup namespace channel: {error}"),
            )
        })?;
    control.write_all(&[READY_BYTE]).map_err(|error| {
        namespace_error(
            ErrorCode::Unavailable,
            format!("failed to report restore cgroup namespace readiness: {error}"),
        )
    })?;
    let mut acknowledgement = [0_u8; 1];
    control.read_exact(&mut acknowledgement).map_err(|error| {
        namespace_error(
            ErrorCode::Unavailable,
            format!("restore owner closed the cgroup namespace channel: {error}"),
        )
    })?;
    if acknowledgement != [ACKNOWLEDGE_BYTE] {
        return Err(namespace_error(
            ErrorCode::PermissionDenied,
            "restore owner sent an invalid cgroup namespace acknowledgement",
        ));
    }
    Ok(())
}

fn namespace_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("prepare-restore-cgroup-namespace")
}
