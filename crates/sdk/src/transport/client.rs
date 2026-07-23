use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::{
    CheckpointRequest, CloseStdinRequest, ContainerOperationRequest, ContainerRecord,
    ContainerStats, CreateRequest, DeleteRequest, EventBatch, EventsRequest, ExecRequest,
    ExitStatus, KillRequest, ListRequest, OciRuntimeService, OutputChunk, ProcessRecord,
    ProcessesRequest, ReadOutputRequest, ResizeRequest, RestoreRequest, Result, RuntimeInfo,
    SignalProcessRequest, StartRequest, StateRequest, StatsRequest, UpdateRequest,
    WaitProcessRequest, WaitRequest, WriteStdinRequest,
};

use super::wire::{
    read_frame, write_frame, ClientMessage, ServerMessage, WireRequest, WireResponse,
};
use super::{protocol_error, SDK_PROTOCOL_VERSION_MAX, SDK_PROTOCOL_VERSION_MIN};

trait AsyncTransportIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncTransportIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Cloneable SDK service client over a negotiated framed byte stream.
#[derive(Clone)]
pub struct RuntimeTransportClient {
    inner: Arc<TransportClientInner>,
}

struct TransportClientInner {
    connection: Mutex<Option<Box<dyn AsyncTransportIo>>>,
    protocol: u16,
    next_request_id: AtomicU64,
}

impl fmt::Debug for RuntimeTransportClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTransportClient")
            .field("protocol", &self.inner.protocol)
            .finish_non_exhaustive()
    }
}

impl RuntimeTransportClient {
    /// Negotiate the SDK protocol over an already connected byte stream.
    pub async fn from_io<T>(io: T) -> Result<Self>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut io: Box<dyn AsyncTransportIo> = Box::new(io);
        write_frame(
            &mut *io,
            &ClientMessage::Hello {
                protocol_min: SDK_PROTOCOL_VERSION_MIN,
                protocol_max: SDK_PROTOCOL_VERSION_MAX,
            },
        )
        .await?;
        let response = read_frame::<ServerMessage>(&mut *io)
            .await?
            .ok_or_else(|| protocol_error("SDK transport closed during protocol negotiation"))?;
        let protocol = match response {
            ServerMessage::Welcome { protocol }
                if (SDK_PROTOCOL_VERSION_MIN..=SDK_PROTOCOL_VERSION_MAX).contains(&protocol) =>
            {
                protocol
            }
            ServerMessage::Welcome { protocol } => {
                return Err(protocol_error(format!(
                    "server selected unsupported SDK protocol version {protocol}"
                )));
            }
            ServerMessage::Reject {
                protocol_min,
                protocol_max,
                message,
            } => {
                return Err(crate::Error::new(
                    crate::ErrorCode::Unsupported,
                    format!(
                        "SDK protocol negotiation failed; server supports \
                         {protocol_min} through {protocol_max}: {message}"
                    ),
                )
                .for_operation("sdk-handshake"));
            }
            ServerMessage::Response { .. } => {
                return Err(protocol_error(
                    "server sent an SDK response before protocol negotiation",
                ));
            }
        };

        Ok(Self {
            inner: Arc::new(TransportClientInner {
                connection: Mutex::new(Some(io)),
                protocol,
                next_request_id: AtomicU64::new(1),
            }),
        })
    }

    /// Negotiated wire protocol version.
    #[must_use]
    pub fn protocol_version(&self) -> u16 {
        self.inner.protocol
    }

    async fn call(&self, request: WireRequest) -> Result<WireResponse> {
        request.validate()?;
        let request_id = self
            .inner
            .next_request_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| protocol_error("SDK transport request ID space exhausted"))?;

        let mut connection_guard = self.inner.connection.lock().await;
        let connection = connection_guard.as_mut().ok_or_else(|| {
            super::transport_error(
                "sdk-transport",
                "SDK transport connection is closed after a prior failure",
            )
        })?;
        if let Err(error) = write_frame(
            &mut **connection,
            &ClientMessage::Request {
                protocol: self.inner.protocol,
                request_id,
                request: Box::new(request),
            },
        )
        .await
        {
            *connection_guard = None;
            return Err(error);
        }
        let response = match read_frame::<ServerMessage>(&mut **connection).await {
            Ok(Some(response)) => response,
            Ok(None) => {
                *connection_guard = None;
                return Err(protocol_error(
                    "SDK transport closed while awaiting a response",
                ));
            }
            Err(error) => {
                *connection_guard = None;
                return Err(error);
            }
        };
        match response {
            ServerMessage::Response {
                protocol,
                request_id: response_id,
                result,
            } if protocol == self.inner.protocol && response_id == request_id => match *result {
                super::wire::WireResult::Ok { response } => Ok(*response),
                super::wire::WireResult::Error { error } => Err(error),
            },
            ServerMessage::Response {
                protocol,
                request_id: response_id,
                ..
            } => {
                *connection_guard = None;
                Err(protocol_error(format!(
                    "SDK response correlation mismatch: expected protocol {} request {}, \
                     received protocol {protocol} request {response_id}",
                    self.inner.protocol, request_id
                )))
            }
            ServerMessage::Welcome { .. } | ServerMessage::Reject { .. } => {
                *connection_guard = None;
                Err(protocol_error(
                    "server sent a handshake message after SDK negotiation",
                ))
            }
        }
    }
}

macro_rules! typed_call {
    ($self:ident, $request:expr, $expected:ident) => {
        match $self.call($request).await? {
            WireResponse::$expected(response) => Ok(response),
            response => Err(protocol_error(format!(
                "unexpected SDK response for {}: {response:?}",
                stringify!($expected)
            ))),
        }
    };
}

macro_rules! empty_call {
    ($self:ident, $request:expr, $expected:ident) => {
        match $self.call($request).await? {
            WireResponse::$expected => Ok(()),
            response => Err(protocol_error(format!(
                "unexpected SDK response for {}: {response:?}",
                stringify!($expected)
            ))),
        }
    };
}

#[async_trait]
impl OciRuntimeService for RuntimeTransportClient {
    async fn features(&self) -> Result<RuntimeInfo> {
        match self.call(WireRequest::Features).await? {
            WireResponse::Features(response) => Ok(*response),
            response => Err(protocol_error(format!(
                "unexpected SDK response for Features: {response:?}"
            ))),
        }
    }

    async fn create(&self, request: CreateRequest) -> Result<ContainerRecord> {
        typed_call!(self, WireRequest::Create(request), Create)
    }

    async fn state(&self, request: StateRequest) -> Result<ContainerRecord> {
        typed_call!(self, WireRequest::State(request), State)
    }

    async fn start(&self, request: StartRequest) -> Result<ContainerRecord> {
        typed_call!(self, WireRequest::Start(request), Start)
    }

    async fn kill(&self, request: KillRequest) -> Result<ContainerRecord> {
        typed_call!(self, WireRequest::Kill(request), Kill)
    }

    async fn delete(&self, request: DeleteRequest) -> Result<()> {
        empty_call!(self, WireRequest::Delete(request), Delete)
    }

    async fn exec(&self, request: ExecRequest) -> Result<ProcessRecord> {
        typed_call!(self, WireRequest::Exec(request), Exec)
    }

    async fn wait(&self, request: WaitRequest) -> Result<ExitStatus> {
        typed_call!(self, WireRequest::Wait(request), Wait)
    }

    async fn list(&self, request: ListRequest) -> Result<Vec<ContainerRecord>> {
        typed_call!(self, WireRequest::List(request), List)
    }

    async fn pause(&self, request: ContainerOperationRequest) -> Result<ContainerRecord> {
        typed_call!(self, WireRequest::Pause(request), Pause)
    }

    async fn resume(&self, request: ContainerOperationRequest) -> Result<ContainerRecord> {
        typed_call!(self, WireRequest::Resume(request), Resume)
    }

    async fn update(&self, request: UpdateRequest) -> Result<ContainerRecord> {
        typed_call!(self, WireRequest::Update(request), Update)
    }

    async fn processes(&self, request: ProcessesRequest) -> Result<Vec<ProcessRecord>> {
        typed_call!(self, WireRequest::Processes(request), Processes)
    }

    async fn stats(&self, request: StatsRequest) -> Result<ContainerStats> {
        typed_call!(self, WireRequest::Stats(request), Stats)
    }

    async fn events(&self, request: EventsRequest) -> Result<EventBatch> {
        typed_call!(self, WireRequest::Events(request), Events)
    }

    async fn read_output(&self, request: ReadOutputRequest) -> Result<Vec<OutputChunk>> {
        typed_call!(self, WireRequest::ReadOutput(request), ReadOutput)
    }

    async fn write_stdin(&self, request: WriteStdinRequest) -> Result<()> {
        empty_call!(self, WireRequest::WriteStdin(request), WriteStdin)
    }

    async fn close_stdin(&self, request: CloseStdinRequest) -> Result<()> {
        empty_call!(self, WireRequest::CloseStdin(request), CloseStdin)
    }

    async fn resize(&self, request: ResizeRequest) -> Result<()> {
        empty_call!(self, WireRequest::Resize(request), Resize)
    }

    async fn signal_process(&self, request: SignalProcessRequest) -> Result<()> {
        empty_call!(self, WireRequest::SignalProcess(request), SignalProcess)
    }

    async fn wait_process(&self, request: WaitProcessRequest) -> Result<ExitStatus> {
        typed_call!(self, WireRequest::WaitProcess(request), WaitProcess)
    }

    async fn checkpoint(&self, request: CheckpointRequest) -> Result<ContainerRecord> {
        typed_call!(self, WireRequest::Checkpoint(request), Checkpoint)
    }

    async fn restore(&self, request: RestoreRequest) -> Result<ContainerRecord> {
        typed_call!(self, WireRequest::Restore(request), Restore)
    }
}
