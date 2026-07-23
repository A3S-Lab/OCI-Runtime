use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    CheckpointRequest, CloseStdinRequest, ContainerOperationRequest, ContainerRecord,
    ContainerStats, CreateRequest, DeleteRequest, Error, EventBatch, EventsRequest, ExecRequest,
    ExitStatus, KillRequest, ListRequest, OutputChunk, ProcessRecord, ProcessesRequest,
    ReadOutputRequest, ResizeRequest, RestoreRequest, RuntimeInfo, SignalProcessRequest,
    StartRequest, StateRequest, StatsRequest, UpdateRequest, WaitProcessRequest, WaitRequest,
    WriteStdinRequest,
};

use super::{protocol_error, transport_error};

pub(super) const MAX_FRAME_BYTES: u32 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub(super) enum ClientMessage {
    Hello {
        protocol_min: u16,
        protocol_max: u16,
    },
    Request {
        protocol: u16,
        request_id: u64,
        request: Box<WireRequest>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub(super) enum ServerMessage {
    Welcome {
        protocol: u16,
    },
    Reject {
        protocol_min: u16,
        protocol_max: u16,
        message: String,
    },
    Response {
        protocol: u16,
        request_id: u64,
        result: Box<WireResult>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub(super) enum WireResult {
    Ok { response: Box<WireResponse> },
    Error { error: Error },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "request", rename_all = "kebab-case")]
pub(super) enum WireRequest {
    Features,
    Create(CreateRequest),
    State(StateRequest),
    Start(StartRequest),
    Kill(KillRequest),
    Delete(DeleteRequest),
    Exec(ExecRequest),
    Wait(WaitRequest),
    List(ListRequest),
    Pause(ContainerOperationRequest),
    Resume(ContainerOperationRequest),
    Update(UpdateRequest),
    Processes(ProcessesRequest),
    Stats(StatsRequest),
    Events(EventsRequest),
    ReadOutput(ReadOutputRequest),
    WriteStdin(WriteStdinRequest),
    CloseStdin(CloseStdinRequest),
    Resize(ResizeRequest),
    SignalProcess(SignalProcessRequest),
    WaitProcess(WaitProcessRequest),
    Checkpoint(CheckpointRequest),
    Restore(RestoreRequest),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "response", rename_all = "kebab-case")]
pub(super) enum WireResponse {
    Features(Box<RuntimeInfo>),
    Create(ContainerRecord),
    State(ContainerRecord),
    Start(ContainerRecord),
    Kill(ContainerRecord),
    Delete,
    Exec(ProcessRecord),
    Wait(ExitStatus),
    List(Vec<ContainerRecord>),
    Pause(ContainerRecord),
    Resume(ContainerRecord),
    Update(ContainerRecord),
    Processes(Vec<ProcessRecord>),
    Stats(ContainerStats),
    Events(EventBatch),
    ReadOutput(Vec<OutputChunk>),
    WriteStdin,
    CloseStdin,
    Resize,
    SignalProcess,
    WaitProcess(ExitStatus),
    Checkpoint(ContainerRecord),
    Restore(ContainerRecord),
}

pub(super) async fn write_frame<T>(
    io: &mut (impl AsyncWrite + Unpin + ?Sized),
    value: &T,
) -> crate::Result<()>
where
    T: Serialize,
{
    let payload = serde_json::to_vec(value).map_err(|error| {
        protocol_error(format!("failed to encode SDK transport frame: {error}"))
    })?;
    let length = u32::try_from(payload.len()).map_err(|_| {
        Error::new(
            crate::ErrorCode::ResourceExhausted,
            format!(
                "SDK transport frame is {} bytes; maximum is {MAX_FRAME_BYTES}",
                payload.len()
            ),
        )
        .for_operation("sdk-transport-write")
    })?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(Error::new(
            crate::ErrorCode::ResourceExhausted,
            format!("SDK transport frame is {length} bytes; maximum is {MAX_FRAME_BYTES}"),
        )
        .for_operation("sdk-transport-write"));
    }

    io.write_all(&length.to_be_bytes()).await.map_err(|error| {
        transport_error(
            "sdk-transport-write",
            format!("failed to write SDK frame length: {error}"),
        )
    })?;
    io.write_all(&payload).await.map_err(|error| {
        transport_error(
            "sdk-transport-write",
            format!("failed to write SDK frame payload: {error}"),
        )
    })?;
    io.flush().await.map_err(|error| {
        transport_error(
            "sdk-transport-write",
            format!("failed to flush SDK frame: {error}"),
        )
    })
}

pub(super) async fn read_frame<T>(
    io: &mut (impl AsyncRead + Unpin + ?Sized),
) -> crate::Result<Option<T>>
where
    T: DeserializeOwned,
{
    let mut length_bytes = [0_u8; 4];
    let first = io.read(&mut length_bytes[..1]).await.map_err(|error| {
        transport_error(
            "sdk-transport-read",
            format!("failed to read SDK frame length: {error}"),
        )
    })?;
    if first == 0 {
        return Ok(None);
    }
    io.read_exact(&mut length_bytes[1..])
        .await
        .map_err(|error| {
            transport_error(
                "sdk-transport-read",
                format!("truncated SDK frame length: {error}"),
            )
        })?;
    let length = u32::from_be_bytes(length_bytes);
    if length == 0 {
        return Err(protocol_error("SDK transport frame must not be empty"));
    }
    if length > MAX_FRAME_BYTES {
        return Err(Error::new(
            crate::ErrorCode::ResourceExhausted,
            format!("SDK transport frame is {length} bytes; maximum is {MAX_FRAME_BYTES}"),
        )
        .for_operation("sdk-transport-read"));
    }

    let mut payload = vec![0_u8; length as usize];
    io.read_exact(&mut payload).await.map_err(|error| {
        transport_error(
            "sdk-transport-read",
            format!("truncated SDK frame payload: {error}"),
        )
    })?;
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|error| protocol_error(format!("invalid SDK transport frame: {error}")))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt, DuplexStream};

    use crate::ErrorCode;

    use super::{read_frame, ClientMessage, MAX_FRAME_BYTES};

    async fn read_raw_prefix(prefix: [u8; 4]) -> crate::Error {
        let (mut writer, mut reader) = tokio::io::duplex(8);
        writer
            .write_all(&prefix)
            .await
            .expect("write raw frame prefix");
        drop(writer);
        read_frame::<ClientMessage>(&mut reader)
            .await
            .expect_err("invalid frame prefix must fail")
    }

    #[tokio::test]
    async fn rejects_empty_and_oversized_frames_before_allocating_payload() {
        let empty = read_raw_prefix(0_u32.to_be_bytes()).await;
        assert_eq!(empty.code, ErrorCode::Internal);

        let oversized = read_raw_prefix((MAX_FRAME_BYTES + 1).to_be_bytes()).await;
        assert_eq!(oversized.code, ErrorCode::ResourceExhausted);
    }

    #[tokio::test]
    async fn rejects_truncated_frame_payload() {
        let (mut writer, mut reader): (DuplexStream, DuplexStream) = tokio::io::duplex(16);
        writer
            .write_all(&8_u32.to_be_bytes())
            .await
            .expect("write frame length");
        writer
            .write_all(b"short")
            .await
            .expect("write partial frame");
        drop(writer);

        let error = read_frame::<ClientMessage>(&mut reader)
            .await
            .expect_err("truncated payload must fail");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(error.retryable);
    }
}
