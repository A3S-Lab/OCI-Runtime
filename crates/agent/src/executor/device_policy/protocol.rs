use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use a3s_oci_sdk::{Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};

use super::{policy_error, DevicePlan, MAX_DEVICE_POLICY_MESSAGE_BYTES};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "operation", deny_unknown_fields)]
pub(super) enum DevicePolicyRequest {
    Hello {
        schema_version: String,
        expected_helper_pid: libc::pid_t,
    },
    Install {
        key: String,
        relative_cgroup: PathBuf,
        plan: DevicePlan,
    },
    Replace {
        key: String,
        plan: DevicePlan,
    },
    Remove {
        key: String,
    },
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    tag = "outcome",
    content = "error",
    deny_unknown_fields
)]
pub(super) enum DevicePolicyResponse {
    Applied,
    Rejected(Error),
}

pub(super) fn write_message<T: Serialize>(transport: &mut UnixStream, message: &T) -> Result<()> {
    let payload = serde_json::to_vec(message).map_err(|error| {
        policy_error(
            ErrorCode::Internal,
            format!("failed to encode rootless device-policy message: {error}"),
        )
    })?;
    if payload.len() > MAX_DEVICE_POLICY_MESSAGE_BYTES {
        return Err(policy_error(
            ErrorCode::ResourceExhausted,
            format!(
                "rootless device-policy message is {} bytes; maximum is {MAX_DEVICE_POLICY_MESSAGE_BYTES}",
                payload.len()
            ),
        ));
    }
    let length = u32::try_from(payload.len()).map_err(|error| {
        policy_error(
            ErrorCode::ResourceExhausted,
            format!("device-policy message length does not fit u32: {error}"),
        )
    })?;
    transport
        .write_all(&length.to_be_bytes())
        .and_then(|()| transport.write_all(&payload))
        .map_err(|error| {
            policy_error(
                ErrorCode::Unavailable,
                format!("failed to write rootless device-policy message: {error}"),
            )
            .retryable(true)
        })
}

pub(super) fn read_message<T: for<'de> Deserialize<'de>>(transport: &mut UnixStream) -> Result<T> {
    let mut encoded_length = [0_u8; size_of::<u32>()];
    if let Err(error) = transport.read_exact(&mut encoded_length) {
        let message = if error.kind() == ErrorKind::UnexpectedEof {
            "rootless device-policy channel closed before the next message".to_string()
        } else {
            format!("failed to read rootless device-policy message length: {error}")
        };
        return Err(policy_error(ErrorCode::Unavailable, message).retryable(true));
    }
    let length = usize::try_from(u32::from_be_bytes(encoded_length)).map_err(|error| {
        policy_error(
            ErrorCode::ResourceExhausted,
            format!("device-policy message length does not fit usize: {error}"),
        )
    })?;
    if length == 0 || length > MAX_DEVICE_POLICY_MESSAGE_BYTES {
        return Err(policy_error(
            ErrorCode::ResourceExhausted,
            format!(
                "rootless device-policy message length {length} is outside 1..={MAX_DEVICE_POLICY_MESSAGE_BYTES}"
            ),
        ));
    }
    let mut payload = vec![0_u8; length];
    transport.read_exact(&mut payload).map_err(|error| {
        policy_error(
            ErrorCode::Unavailable,
            format!("failed to read rootless device-policy message payload: {error}"),
        )
        .retryable(true)
    })?;
    serde_json::from_slice(&payload).map_err(|error| {
        policy_error(
            ErrorCode::PermissionDenied,
            format!("rootless device-policy message is invalid: {error}"),
        )
    })
}
