use std::io;

use a3s_oci_sdk::{Error, ErrorCode, Result};
use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::AGENT_MAX_FRAME_BYTES;

pub(crate) async fn write_frame<T, W>(writer: &mut W, value: &T) -> Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(value).map_err(|error| {
        protocol_wire_error(
            ErrorCode::Internal,
            "encode-agent-frame",
            format!("failed to encode agent frame: {error}"),
        )
    })?;
    let length =
        u32::try_from(payload.len()).map_err(|_| frame_too_large(payload.len(), u32::MAX))?;
    if length == 0 || length > AGENT_MAX_FRAME_BYTES {
        return Err(frame_too_large(payload.len(), AGENT_MAX_FRAME_BYTES));
    }

    writer
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|error| io_error("write-agent-frame-header", error))?;
    writer
        .write_all(&payload)
        .await
        .map_err(|error| io_error("write-agent-frame-payload", error))?;
    writer
        .flush()
        .await
        .map_err(|error| io_error("flush-agent-frame", error))
}

pub(crate) async fn read_frame<T, R>(reader: &mut R) -> Result<Option<T>>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin,
{
    read_frame_with_limit(reader, AGENT_MAX_FRAME_BYTES).await
}

async fn read_frame_with_limit<T, R>(reader: &mut R, maximum: u32) -> Result<Option<T>>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    let first = reader
        .read(&mut header[..1])
        .await
        .map_err(|error| io_error("read-agent-frame-header", error))?;
    if first == 0 {
        return Ok(None);
    }
    reader
        .read_exact(&mut header[1..])
        .await
        .map_err(|error| io_error("read-agent-frame-header", error))?;
    let length = u32::from_be_bytes(header);
    if length == 0 || length > maximum {
        return Err(protocol_wire_error(
            ErrorCode::ResourceExhausted,
            "read-agent-frame",
            format!("agent frame length {length} is outside 1..={maximum} bytes"),
        ));
    }

    let mut payload = vec![0_u8; length as usize];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|error| io_error("read-agent-frame-payload", error))?;
    serde_json::from_slice(&payload).map(Some).map_err(|error| {
        protocol_wire_error(
            ErrorCode::InvalidArgument,
            "decode-agent-frame",
            format!("invalid agent frame JSON: {error}"),
        )
    })
}

fn frame_too_large(actual: usize, maximum: u32) -> Error {
    protocol_wire_error(
        ErrorCode::ResourceExhausted,
        "encode-agent-frame",
        format!("agent frame is {actual} bytes; maximum is {maximum}"),
    )
}

fn io_error(operation: &'static str, error: io::Error) -> Error {
    protocol_wire_error(
        ErrorCode::Unavailable,
        operation,
        format!("agent transport I/O failed: {error}"),
    )
    .retryable(true)
}

fn protocol_wire_error(
    code: ErrorCode,
    operation: &'static str,
    message: impl Into<String>,
) -> Error {
    Error::new(code, message).for_operation(operation)
}

#[cfg(test)]
pub(crate) async fn read_frame_for_test<T, R>(reader: &mut R, maximum: u32) -> Result<Option<T>>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin,
{
    read_frame_with_limit(reader, maximum).await
}
