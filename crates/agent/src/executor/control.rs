use std::io::Write;
use std::os::unix::net::UnixStream as StdUnixStream;

use a3s_oci_sdk::{Error, ErrorCode, Result};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

pub(super) const READY_BYTE: u8 = 0xA3;
pub(super) const START_BYTE: u8 = 0x5A;
const REJECTED_BYTE: u8 = 0xE1;
const MAX_REJECTION_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum InitOutcome {
    Ready { pid: i32 },
    Rejected(Error),
}

pub(super) fn write_ready(stream: &mut StdUnixStream, pid: i32) -> Result<()> {
    if pid <= 0 {
        return Err(control_error(
            ErrorCode::InvalidArgument,
            format!("container init reported non-positive PID {pid}"),
        ));
    }
    stream
        .write_all(&[READY_BYTE])
        .and_then(|()| stream.write_all(&pid.to_be_bytes()))
        .map_err(|write| {
            control_error(
                ErrorCode::Unavailable,
                format!("failed to report prepared container init readiness: {write}"),
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
        READY_BYTE => read_ready_pid(stream)
            .await
            .map(|pid| InitOutcome::Ready { pid }),
        REJECTED_BYTE => read_rejection(stream).await.map(InitOutcome::Rejected),
        other => Err(control_error(
            ErrorCode::FailedPrecondition,
            format!("prepared container init returned unknown outcome byte {other:#04x}"),
        )),
    }
}

async fn read_ready_pid(stream: &mut UnixStream) -> Result<i32> {
    let mut encoded_pid = [0_u8; size_of::<i32>()];
    stream.read_exact(&mut encoded_pid).await.map_err(|read| {
        control_error(
            ErrorCode::FailedPrecondition,
            format!("container init readiness PID was truncated: {read}"),
        )
    })?;
    let pid = i32::from_be_bytes(encoded_pid);
    if pid <= 0 {
        Err(control_error(
            ErrorCode::FailedPrecondition,
            format!("container init reported non-positive PID {pid}"),
        ))
    } else {
        Ok(pid)
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

    use super::{read_outcome, write_ready, write_rejection, InitOutcome};

    #[tokio::test(flavor = "current_thread")]
    async fn ready_round_trip_carries_the_runtime_visible_pid() {
        let (mut writer, reader) = StdUnixStream::pair().expect("create control socket pair");
        reader
            .set_nonblocking(true)
            .expect("make control reader nonblocking");
        let writer = tokio::task::spawn_blocking(move || {
            write_ready(&mut writer, 42_001).expect("write readiness");
        });
        let mut reader = tokio::net::UnixStream::from_std(reader).expect("register control reader");

        assert_eq!(
            read_outcome(&mut reader).await.expect("read readiness"),
            InitOutcome::Ready { pid: 42_001 }
        );
        writer.await.expect("control writer task");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn readiness_reader_rejects_non_positive_or_truncated_pids() {
        use std::io::Write;

        for payload in [0_i32.to_be_bytes().to_vec(), vec![0, 1]] {
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
