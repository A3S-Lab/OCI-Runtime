use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;

use a3s_oci_sdk::{Error, ErrorCode, Result};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

use super::capability::CapabilityWarning;

pub(super) const READY_BYTE: u8 = 0xA3;
pub(super) const START_BYTE: u8 = 0x5A;
const CREATE_HOOKS_READY_BYTE: u8 = 0xC1;
pub(super) const CREATE_CONTINUE_BYTE: u8 = 0xC2;
const USER_MAPPING_REQUIRED_BYTE: u8 = 0xB1;
const USER_MAPPING_APPLIED_BYTE: u8 = 0xB2;
const ORDERED_IDMAP_REQUIRED_BYTE: u8 = 0xB3;
const ORDERED_IDMAP_DESCRIPTORS_BYTE: u8 = 0xB4;
const ORDERED_IDMAP_APPLIED_BYTE: u8 = 0xB5;
const REJECTED_BYTE: u8 = 0xE1;
const DEVICE_MOUNTS_BYTE: u8 = 0xD1;
const CAPABILITY_WARNING_BYTE: u8 = 0xD2;
const MAX_REJECTION_BYTES: usize = 64 * 1024;
const MAX_CAPABILITY_WARNING_BYTES: usize = 4 * 1024;
const MAX_CAPABILITY_WARNINGS: usize = a3s_oci_sdk::OCI_LINUX_CAPABILITY_NAMES.len();

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum InitOutcome {
    UserMappingRequired,
    OrderedIdmapRequired {
        mount_index: usize,
    },
    CreateHooksReady {
        pid: i32,
        namespace_init_pid: Option<i32>,
    },
    Ready {
        pid: i32,
        namespace_init_pid: Option<i32>,
    },
    Rejected(Error),
}

pub(super) fn request_ordered_idmap(
    stream: &mut StdUnixStream,
    mount_index: usize,
    mount: RawFd,
    user_namespace: RawFd,
) -> Result<()> {
    let mount_index = u32::try_from(mount_index).map_err(|error| {
        control_error(
            ErrorCode::ResourceExhausted,
            format!("ordered ID-mapped mount index does not fit the control protocol: {error}"),
        )
    })?;
    stream
        .write_all(&[ORDERED_IDMAP_REQUIRED_BYTE])
        .and_then(|()| stream.write_all(&mount_index.to_be_bytes()))
        .map_err(|error| {
            control_error(
                ErrorCode::Unavailable,
                format!("failed to request ordered ID-mapped mount preparation: {error}"),
            )
        })?;
    super::device_mount_transport::send_descriptor_frame(
        stream.as_raw_fd(),
        ORDERED_IDMAP_DESCRIPTORS_BYTE,
        &[mount, user_namespace],
    )
    .map_err(|error| {
        control_error(
            ErrorCode::Unavailable,
            format!("failed to send ordered ID-mapped mount descriptors: {error}"),
        )
    })?;
    let mut acknowledgement = [0_u8; 1];
    stream.read_exact(&mut acknowledgement).map_err(|error| {
        control_error(
            ErrorCode::Unavailable,
            format!("ordered ID-mapped mount acknowledgement failed: {error}"),
        )
    })?;
    if acknowledgement[0] == ORDERED_IDMAP_APPLIED_BYTE {
        Ok(())
    } else {
        Err(control_error(
            ErrorCode::FailedPrecondition,
            format!(
                "ordered ID-mapped mount returned unknown acknowledgement byte {:#04x}",
                acknowledgement[0]
            ),
        ))
    }
}

pub(super) async fn receive_ordered_idmap_descriptors(
    stream: &UnixStream,
) -> Result<(OwnedFd, OwnedFd)> {
    let descriptors = stream
        .async_io(tokio::io::Interest::READABLE, || {
            super::device_mount_transport::receive_descriptor_frame(
                stream.as_raw_fd(),
                ORDERED_IDMAP_DESCRIPTORS_BYTE,
                2,
            )
        })
        .await
        .map_err(|error| {
            let code = if error.kind() == std::io::ErrorKind::InvalidData {
                ErrorCode::PermissionDenied
            } else {
                ErrorCode::Unavailable
            };
            control_error(
                code,
                format!("failed to receive ordered ID-mapped mount descriptors: {error}"),
            )
        })?;
    let mut descriptors = descriptors.into_iter();
    let mount = descriptors.next().ok_or_else(|| {
        control_error(
            ErrorCode::Internal,
            "ordered ID-mapped mount descriptor frame lost its mount descriptor",
        )
    })?;
    let user_namespace = descriptors.next().ok_or_else(|| {
        control_error(
            ErrorCode::Internal,
            "ordered ID-mapped mount descriptor frame lost its user namespace descriptor",
        )
    })?;
    Ok((mount, user_namespace))
}

pub(super) async fn acknowledge_ordered_idmap(stream: &mut UnixStream) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    stream
        .write_all(&[ORDERED_IDMAP_APPLIED_BYTE])
        .await
        .map_err(|error| {
            control_error(
                ErrorCode::Unavailable,
                format!("failed to acknowledge ordered ID-mapped mount: {error}"),
            )
        })
}

pub(super) fn receive_device_mounts(
    stream: &StdUnixStream,
    expected_count: usize,
) -> Result<Vec<OwnedFd>> {
    super::device_mount_transport::receive_descriptor_frame(
        stream.as_raw_fd(),
        DEVICE_MOUNTS_BYTE,
        expected_count,
    )
    .map_err(|error| {
        let code = if error.kind() == std::io::ErrorKind::InvalidData {
            ErrorCode::PermissionDenied
        } else {
            ErrorCode::Unavailable
        };
        control_error(
            code,
            format!("failed to receive prepared rootless device mounts: {error}"),
        )
    })
}

pub(super) fn send_device_mounts(stream: &UnixStream, mounts: &[OwnedFd]) -> Result<()> {
    let descriptors = mounts.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
    super::device_mount_transport::send_descriptor_frame(
        stream.as_raw_fd(),
        DEVICE_MOUNTS_BYTE,
        &descriptors,
    )
    .map_err(|error| {
        control_error(
            ErrorCode::Unavailable,
            format!("failed to send prepared rootless device mounts: {error}"),
        )
    })
}

pub(super) fn write_create_hooks_ready(
    stream: &mut StdUnixStream,
    pid: i32,
    namespace_init_pid: Option<i32>,
) -> Result<()> {
    write_pids(
        stream,
        CREATE_HOOKS_READY_BYTE,
        pid,
        namespace_init_pid,
        "create-hook readiness",
    )
}

pub(super) fn request_user_mapping(stream: &mut StdUnixStream) -> Result<()> {
    stream
        .write_all(&[USER_MAPPING_REQUIRED_BYTE])
        .map_err(|write| {
            control_error(
                ErrorCode::Unavailable,
                format!("failed to request user namespace mappings: {write}"),
            )
        })?;
    let mut acknowledgement = [0_u8; 1];
    stream.read_exact(&mut acknowledgement).map_err(|read| {
        control_error(
            ErrorCode::Unavailable,
            format!("user namespace mapping acknowledgement failed: {read}"),
        )
    })?;
    if acknowledgement[0] == USER_MAPPING_APPLIED_BYTE {
        Ok(())
    } else {
        Err(control_error(
            ErrorCode::FailedPrecondition,
            format!(
                "user namespace mapping returned unknown acknowledgement byte {:#04x}",
                acknowledgement[0]
            ),
        ))
    }
}

pub(super) async fn acknowledge_user_mapping(stream: &mut UnixStream) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    stream
        .write_all(&[USER_MAPPING_APPLIED_BYTE])
        .await
        .map_err(|write| {
            control_error(
                ErrorCode::Unavailable,
                format!("failed to acknowledge user namespace mappings: {write}"),
            )
        })
}

pub(super) fn write_ready(
    stream: &mut StdUnixStream,
    pid: i32,
    namespace_init_pid: Option<i32>,
) -> Result<()> {
    write_pids(stream, READY_BYTE, pid, namespace_init_pid, "readiness")
}

fn write_pids(
    stream: &mut StdUnixStream,
    discriminator: u8,
    pid: i32,
    namespace_init_pid: Option<i32>,
    description: &str,
) -> Result<()> {
    if pid <= 0 {
        return Err(control_error(
            ErrorCode::InvalidArgument,
            format!("container payload reported non-positive PID {pid}"),
        ));
    }
    let namespace_init_pid = namespace_init_pid.unwrap_or_default();
    if namespace_init_pid < 0 || namespace_init_pid == pid {
        return Err(control_error(
            ErrorCode::InvalidArgument,
            format!("container payload reported invalid namespace init PID {namespace_init_pid}"),
        ));
    }
    stream
        .write_all(&[discriminator])
        .and_then(|()| stream.write_all(&pid.to_be_bytes()))
        .and_then(|()| stream.write_all(&namespace_init_pid.to_be_bytes()))
        .map_err(|write| {
            control_error(
                ErrorCode::Unavailable,
                format!("failed to report prepared container payload {description}: {write}"),
            )
        })
}

pub(super) fn write_rejection(stream: &mut StdUnixStream, error: &Error) -> Result<()> {
    let payload = serde_json::to_vec(error).map_err(|serialize| {
        control_error(
            ErrorCode::Internal,
            format!("failed to encode container init rejection: {serialize}"),
        )
    })?;
    if payload.is_empty() || payload.len() > MAX_REJECTION_BYTES {
        return Err(control_error(
            ErrorCode::ResourceExhausted,
            format!(
                "container init rejection contains {} bytes; maximum is {MAX_REJECTION_BYTES}",
                payload.len()
            ),
        ));
    }
    let length = u32::try_from(payload.len()).map_err(|_| {
        control_error(
            ErrorCode::ResourceExhausted,
            "container init rejection length does not fit the control protocol",
        )
    })?;
    stream
        .write_all(&[REJECTED_BYTE])
        .and_then(|()| stream.write_all(&length.to_be_bytes()))
        .and_then(|()| stream.write_all(&payload))
        .map_err(|write| {
            control_error(
                ErrorCode::Unavailable,
                format!("failed to report container init rejection: {write}"),
            )
        })
}

pub(super) fn write_capability_warning(
    stream: &mut StdUnixStream,
    warning: &CapabilityWarning,
) -> Result<()> {
    warning.validate()?;
    let payload = serde_json::to_vec(warning).map_err(|serialize| {
        control_error(
            ErrorCode::Internal,
            format!("failed to encode process capability warning: {serialize}"),
        )
    })?;
    if payload.is_empty() || payload.len() > MAX_CAPABILITY_WARNING_BYTES {
        return Err(control_error(
            ErrorCode::ResourceExhausted,
            format!(
                "process capability warning contains {} bytes; maximum is {MAX_CAPABILITY_WARNING_BYTES}",
                payload.len()
            ),
        ));
    }
    let length = u32::try_from(payload.len()).map_err(|_| {
        control_error(
            ErrorCode::ResourceExhausted,
            "process capability warning length does not fit the control protocol",
        )
    })?;
    stream
        .write_all(&[CAPABILITY_WARNING_BYTE])
        .and_then(|()| stream.write_all(&length.to_be_bytes()))
        .and_then(|()| stream.write_all(&payload))
        .map_err(|write| {
            control_error(
                ErrorCode::Unavailable,
                format!("failed to report process capability warning: {write}"),
            )
        })
}

pub(super) fn write_capability_warnings(
    stream: &mut StdUnixStream,
    warnings: &[CapabilityWarning],
) -> Result<()> {
    for warning in warnings {
        write_capability_warning(stream, warning)?;
    }
    Ok(())
}

pub(super) async fn read_outcome(stream: &mut UnixStream) -> Result<InitOutcome> {
    let mut discriminator = [0_u8; 1];
    stream
        .read_exact(&mut discriminator)
        .await
        .map_err(|read| {
            control_error(
                ErrorCode::FailedPrecondition,
                format!("prepared container init closed before an outcome: {read}"),
            )
        })?;
    match discriminator[0] {
        USER_MAPPING_REQUIRED_BYTE => Ok(InitOutcome::UserMappingRequired),
        ORDERED_IDMAP_REQUIRED_BYTE => {
            let mut encoded_index = [0_u8; size_of::<u32>()];
            stream
                .read_exact(&mut encoded_index)
                .await
                .map_err(|read| {
                    control_error(
                        ErrorCode::FailedPrecondition,
                        format!("ordered ID-mapped mount index was truncated: {read}"),
                    )
                })?;
            Ok(InitOutcome::OrderedIdmapRequired {
                mount_index: u32::from_be_bytes(encoded_index) as usize,
            })
        }
        CREATE_HOOKS_READY_BYTE => {
            read_ready_pids(stream)
                .await
                .map(|(pid, namespace_init_pid)| InitOutcome::CreateHooksReady {
                    pid,
                    namespace_init_pid,
                })
        }
        READY_BYTE => read_ready_pids(stream)
            .await
            .map(|(pid, namespace_init_pid)| InitOutcome::Ready {
                pid,
                namespace_init_pid,
            }),
        REJECTED_BYTE => read_rejection(stream).await.map(InitOutcome::Rejected),
        other => Err(control_error(
            ErrorCode::FailedPrecondition,
            format!("prepared container init returned unknown outcome byte {other:#04x}"),
        )),
    }
}

pub(super) async fn continue_create(stream: &mut UnixStream) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    stream
        .write_all(&[CREATE_CONTINUE_BYTE])
        .await
        .map_err(|error| {
            control_error(
                ErrorCode::Unavailable,
                format!("failed to release prepared create hooks: {error}"),
            )
        })
}

/// Wait until exec closes the close-on-exec control descriptor, retaining any
/// structured warning frames that precede it, or reports an exact rejection.
pub(super) async fn read_start_result(stream: &mut UnixStream) -> Result<Vec<CapabilityWarning>> {
    let mut warnings = Vec::new();
    loop {
        let mut discriminator = [0_u8; 1];
        match stream.read(&mut discriminator).await {
            Ok(0) => return Ok(warnings),
            Ok(1) if discriminator[0] == CAPABILITY_WARNING_BYTE => {
                if warnings.len() == MAX_CAPABILITY_WARNINGS {
                    return Err(control_error(
                        ErrorCode::ResourceExhausted,
                        format!(
                            "prepared container start returned more than {MAX_CAPABILITY_WARNINGS} capability warnings"
                        ),
                    ));
                }
                let warning = read_capability_warning(stream).await?;
                if warnings.iter().any(|existing: &CapabilityWarning| {
                    existing.capability() == warning.capability()
                }) {
                    return Err(control_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "prepared container start returned duplicate warning for {}",
                            warning.capability()
                        ),
                    ));
                }
                eprintln!(
                    "a3s-oci-agent: OCI process capability warning: {}",
                    warning.message()
                );
                warnings.push(warning);
            }
            Ok(1) if discriminator[0] == REJECTED_BYTE => {
                return read_rejection(stream).await.and_then(Err);
            }
            Ok(1) => {
                return Err(control_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "prepared container start returned unknown outcome byte {:#04x}",
                        discriminator[0]
                    ),
                ));
            }
            Ok(_) => unreachable!("one-byte control read returned more than one byte"),
            Err(error) => {
                return Err(control_error(
                    ErrorCode::Unavailable,
                    format!("failed to read prepared container start outcome: {error}"),
                ));
            }
        }
    }
}

async fn read_ready_pids(stream: &mut UnixStream) -> Result<(i32, Option<i32>)> {
    let mut encoded_pid = [0_u8; size_of::<i32>()];
    stream.read_exact(&mut encoded_pid).await.map_err(|read| {
        control_error(
            ErrorCode::FailedPrecondition,
            format!("container payload readiness PID was truncated: {read}"),
        )
    })?;
    let pid = i32::from_be_bytes(encoded_pid);
    if pid <= 0 {
        return Err(control_error(
            ErrorCode::FailedPrecondition,
            format!("container payload reported non-positive PID {pid}"),
        ));
    }
    let mut encoded_namespace_init_pid = [0_u8; size_of::<i32>()];
    stream
        .read_exact(&mut encoded_namespace_init_pid)
        .await
        .map_err(|read| {
            control_error(
                ErrorCode::FailedPrecondition,
                format!("namespace init readiness PID was truncated: {read}"),
            )
        })?;
    let namespace_init_pid = i32::from_be_bytes(encoded_namespace_init_pid);
    if namespace_init_pid < 0 || namespace_init_pid == pid {
        Err(control_error(
            ErrorCode::FailedPrecondition,
            format!("container payload reported invalid namespace init PID {namespace_init_pid}"),
        ))
    } else {
        Ok((pid, (namespace_init_pid != 0).then_some(namespace_init_pid)))
    }
}

async fn read_rejection(stream: &mut UnixStream) -> Result<Error> {
    let mut encoded_length = [0_u8; size_of::<u32>()];
    stream
        .read_exact(&mut encoded_length)
        .await
        .map_err(|read| {
            control_error(
                ErrorCode::FailedPrecondition,
                format!("container init rejection length was truncated: {read}"),
            )
        })?;
    let length = u32::from_be_bytes(encoded_length) as usize;
    if length == 0 || length > MAX_REJECTION_BYTES {
        return Err(control_error(
            ErrorCode::ResourceExhausted,
            format!(
                "container init rejection contains {length} bytes; maximum is {MAX_REJECTION_BYTES}"
            ),
        ));
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await.map_err(|read| {
        control_error(
            ErrorCode::FailedPrecondition,
            format!("container init rejection payload was truncated: {read}"),
        )
    })?;
    serde_json::from_slice(&payload).map_err(|decode| {
        control_error(
            ErrorCode::FailedPrecondition,
            format!("container init rejection was invalid: {decode}"),
        )
    })
}

async fn read_capability_warning(stream: &mut UnixStream) -> Result<CapabilityWarning> {
    let mut encoded_length = [0_u8; size_of::<u32>()];
    stream
        .read_exact(&mut encoded_length)
        .await
        .map_err(|read| {
            control_error(
                ErrorCode::FailedPrecondition,
                format!("process capability warning length was truncated: {read}"),
            )
        })?;
    let length = u32::from_be_bytes(encoded_length) as usize;
    if length == 0 || length > MAX_CAPABILITY_WARNING_BYTES {
        return Err(control_error(
            ErrorCode::ResourceExhausted,
            format!(
                "process capability warning contains {length} bytes; maximum is {MAX_CAPABILITY_WARNING_BYTES}"
            ),
        ));
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await.map_err(|read| {
        control_error(
            ErrorCode::FailedPrecondition,
            format!("process capability warning payload was truncated: {read}"),
        )
    })?;
    let warning: CapabilityWarning = serde_json::from_slice(&payload).map_err(|decode| {
        control_error(
            ErrorCode::FailedPrecondition,
            format!("process capability warning was invalid: {decode}"),
        )
    })?;
    warning.validate().map_err(|error| {
        control_error(
            ErrorCode::FailedPrecondition,
            format!("process capability warning failed validation: {error}"),
        )
    })?;
    Ok(warning)
}

fn control_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("run-container-init")
}

#[cfg(test)]
mod tests;
