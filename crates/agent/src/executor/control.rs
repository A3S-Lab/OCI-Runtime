use std::io::{Read, Write};
use std::os::unix::net::UnixStream as StdUnixStream;

use a3s_oci_sdk::{Error, ErrorCode, Result};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

pub(super) const READY_BYTE: u8 = 0xA3;
pub(super) const START_BYTE: u8 = 0x5A;
const CREATE_HOOKS_READY_BYTE: u8 = 0xC1;
pub(super) const CREATE_CONTINUE_BYTE: u8 = 0xC2;
const USER_MAPPING_REQUIRED_BYTE: u8 = 0xB1;
const USER_MAPPING_APPLIED_BYTE: u8 = 0xB2;
const REJECTED_BYTE: u8 = 0xE1;
const MAX_REJECTION_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum InitOutcome {
    UserMappingRequired,
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

/// Wait until exec closes the close-on-exec control descriptor or reports an
/// exact start-time rejection.
pub(super) async fn read_start_result(stream: &mut UnixStream) -> Result<()> {
    let mut discriminator = [0_u8; 1];
    match stream.read(&mut discriminator).await {
        Ok(0) => Ok(()),
        Ok(1) if discriminator[0] == REJECTED_BYTE => read_rejection(stream).await.and_then(Err),
        Ok(1) => Err(control_error(
            ErrorCode::FailedPrecondition,
            format!(
                "prepared container start returned unknown outcome byte {:#04x}",
                discriminator[0]
            ),
        )),
        Ok(_) => unreachable!("one-byte control read returned more than one byte"),
        Err(error) => Err(control_error(
            ErrorCode::Unavailable,
            format!("failed to read prepared container start outcome: {error}"),
        )),
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

fn control_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("run-container-init")
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream as StdUnixStream;

    use a3s_oci_sdk::{Error, ErrorCode};

    use super::{
        acknowledge_user_mapping, read_outcome, read_start_result, request_user_mapping,
        write_create_hooks_ready, write_ready, write_rejection, InitOutcome,
    };

    #[tokio::test(flavor = "current_thread")]
    async fn user_mapping_handshake_blocks_until_the_parent_acknowledges() {
        let (mut child, parent) = StdUnixStream::pair().expect("create control socket pair");
        parent
            .set_nonblocking(true)
            .expect("make control parent nonblocking");
        let child = tokio::task::spawn_blocking(move || {
            request_user_mapping(&mut child).expect("mapping handshake");
        });
        let mut parent = tokio::net::UnixStream::from_std(parent).expect("register control parent");

        assert_eq!(
            read_outcome(&mut parent)
                .await
                .expect("read mapping request"),
            InitOutcome::UserMappingRequired
        );
        acknowledge_user_mapping(&mut parent)
            .await
            .expect("acknowledge mappings");
        child.await.expect("mapping child");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ready_round_trip_carries_the_runtime_and_optional_namespace_init_pids() {
        for namespace_init_pid in [Some(41_999), None] {
            let (mut writer, reader) = StdUnixStream::pair().expect("create control socket pair");
            reader
                .set_nonblocking(true)
                .expect("make control reader nonblocking");
            let writer = tokio::task::spawn_blocking(move || {
                write_ready(&mut writer, 42_001, namespace_init_pid).expect("write readiness");
            });
            let mut reader =
                tokio::net::UnixStream::from_std(reader).expect("register control reader");

            assert_eq!(
                read_outcome(&mut reader).await.expect("read readiness"),
                InitOutcome::Ready {
                    pid: 42_001,
                    namespace_init_pid,
                }
            );
            writer.await.expect("control writer task");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn create_hook_barrier_is_distinct_from_final_readiness() {
        let (mut writer, reader) = StdUnixStream::pair().expect("create control socket pair");
        reader
            .set_nonblocking(true)
            .expect("make control reader nonblocking");
        let writer = tokio::task::spawn_blocking(move || {
            write_create_hooks_ready(&mut writer, 42_001, Some(41_999))
                .expect("write create-hook readiness");
        });
        let mut reader = tokio::net::UnixStream::from_std(reader).expect("register control reader");

        assert_eq!(
            read_outcome(&mut reader)
                .await
                .expect("read create-hook readiness"),
            InitOutcome::CreateHooksReady {
                pid: 42_001,
                namespace_init_pid: Some(41_999),
            }
        );
        writer.await.expect("control writer task");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn readiness_reader_rejects_non_positive_or_truncated_pids() {
        use std::io::Write;

        for payload in [
            [0_i32.to_be_bytes(), 0_i32.to_be_bytes()].concat(),
            vec![0, 1],
            42_001_i32.to_be_bytes().to_vec(),
            [42_001_i32.to_be_bytes(), (-1_i32).to_be_bytes()].concat(),
            [42_001_i32.to_be_bytes(), 42_001_i32.to_be_bytes()].concat(),
        ] {
            let (mut writer, reader) = StdUnixStream::pair().expect("create control socket pair");
            reader
                .set_nonblocking(true)
                .expect("make control reader nonblocking");
            let writer = tokio::task::spawn_blocking(move || {
                writer.write_all(&[super::READY_BYTE]).expect("kind");
                writer.write_all(&payload).expect("PID payload");
            });
            let mut reader =
                tokio::net::UnixStream::from_std(reader).expect("register control reader");

            let error = read_outcome(&mut reader)
                .await
                .expect_err("invalid readiness PID must fail");
            assert_eq!(error.code, ErrorCode::FailedPrecondition);
            writer.await.expect("control writer task");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejection_round_trip_preserves_the_typed_error() {
        let (mut writer, reader) = StdUnixStream::pair().expect("create control socket pair");
        reader
            .set_nonblocking(true)
            .expect("make control reader nonblocking");
        let expected = Error::new(ErrorCode::PermissionDenied, "pivot root denied")
            .for_operation("prepare-container-rootfs");
        let reported = expected.clone();
        let writer = tokio::task::spawn_blocking(move || {
            write_rejection(&mut writer, &reported).expect("write rejection");
        });
        let mut reader = tokio::net::UnixStream::from_std(reader).expect("register control reader");

        assert_eq!(
            read_outcome(&mut reader).await.expect("read rejection"),
            InitOutcome::Rejected(expected)
        );
        writer.await.expect("control writer task");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn start_result_distinguishes_exec_close_from_typed_rejection() {
        let (writer, reader) = StdUnixStream::pair().expect("create exec-close socket pair");
        reader
            .set_nonblocking(true)
            .expect("make exec-close reader nonblocking");
        drop(writer);
        let mut reader = tokio::net::UnixStream::from_std(reader).expect("register close reader");
        read_start_result(&mut reader)
            .await
            .expect("control close proves successful exec");

        let (mut writer, reader) = StdUnixStream::pair().expect("create rejection socket pair");
        reader
            .set_nonblocking(true)
            .expect("make rejection reader nonblocking");
        let expected = Error::new(ErrorCode::FailedPrecondition, "start hook failed")
            .for_operation("run-oci-hook");
        let reported = expected.clone();
        let writer = tokio::task::spawn_blocking(move || {
            write_rejection(&mut writer, &reported).expect("write start rejection");
        });
        let mut reader = tokio::net::UnixStream::from_std(reader).expect("register reject reader");
        assert_eq!(
            read_start_result(&mut reader)
                .await
                .expect_err("typed start rejection must fail"),
            expected
        );
        writer.await.expect("start rejection writer");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejection_reader_rejects_an_unbounded_frame() {
        use std::io::Write;

        let (mut writer, reader) = StdUnixStream::pair().expect("create control socket pair");
        reader
            .set_nonblocking(true)
            .expect("make control reader nonblocking");
        let writer = tokio::task::spawn_blocking(move || {
            writer.write_all(&[super::REJECTED_BYTE]).expect("kind");
            writer
                .write_all(&u32::MAX.to_be_bytes())
                .expect("oversized length");
        });
        let mut reader = tokio::net::UnixStream::from_std(reader).expect("register control reader");

        let error = read_outcome(&mut reader)
            .await
            .expect_err("oversized rejection must fail");
        assert_eq!(error.code, ErrorCode::ResourceExhausted);
        writer.await.expect("control writer task");
    }
}
