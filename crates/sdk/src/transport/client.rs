use std::fmt;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::{
    CheckpointRequest, CheckpointResponse, CloseStdinRequest, ContainerOperationRequest,
    ContainerRecord, ContainerStats, CreateRequest, DeleteRequest, Error, ErrorCode, EventBatch,
    EventsRequest, ExecRequest, ExitStatus, FileRequest, FileResponse, FilesystemRequest,
    FilesystemResponse, KillRequest, ListRequest, OciRuntimeService, OutputChunk, ProcessRecord,
    ProcessesRequest, ReadOutputRequest, ResizeRequest, RestoreRequest, RestoreResponse, Result,
    RuntimeInfo, SignalProcessRequest, StartRequest, StateRequest, StatsRequest,
    TeeAttestationRequest, TeeAttestationResponse, UpdateRequest, WaitProcessRequest, WaitRequest,
    WriteStdinRequest,
};

use super::wire::{
    read_frame, write_frame, ClientMessage, ServerMessage, WireRequest, WireResponse,
};
use super::{protocol_error, SDK_PROTOCOL_VERSION_MAX, SDK_PROTOCOL_VERSION_MIN};

pub(super) trait AsyncTransportIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncTransportIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Reopen one transport connection without replaying an in-flight request.
#[async_trait]
pub(super) trait TransportConnector: Send + Sync {
    async fn connect(&self) -> Result<Box<dyn AsyncTransportIo>>;
}

/// Cloneable SDK service client over a negotiated framed byte stream.
#[derive(Clone)]
pub struct RuntimeTransportClient {
    inner: Arc<TransportClientInner>,
}

struct TransportClientInner {
    connection: Mutex<Option<Box<dyn AsyncTransportIo>>>,
    connector: Option<Arc<dyn TransportConnector>>,
    protocol: AtomicU16,
    next_request_id: AtomicU64,
}

impl fmt::Debug for RuntimeTransportClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTransportClient")
            .field("protocol", &self.protocol_version())
            .field("reconnectable", &self.inner.connector.is_some())
            .finish_non_exhaustive()
    }
}

impl RuntimeTransportClient {
    /// Negotiate the SDK protocol over an already connected byte stream.
    pub async fn from_io<T>(io: T) -> Result<Self>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (io, protocol) = negotiate_transport(Box::new(io)).await?;
        Ok(Self::from_negotiated(io, protocol, None))
    }

    pub(super) async fn from_connector(connector: Arc<dyn TransportConnector>) -> Result<Self> {
        let io = connector.connect().await?;
        let (io, protocol) = negotiate_transport(io).await?;
        Ok(Self::from_negotiated(io, protocol, Some(connector)))
    }

    fn from_negotiated(
        io: Box<dyn AsyncTransportIo>,
        protocol: u16,
        connector: Option<Arc<dyn TransportConnector>>,
    ) -> Self {
        Self {
            inner: Arc::new(TransportClientInner {
                connection: Mutex::new(Some(io)),
                connector,
                protocol: AtomicU16::new(protocol),
                next_request_id: AtomicU64::new(1),
            }),
        }
    }

    async fn reconnect_locked(
        &self,
        connection: &mut Option<Box<dyn AsyncTransportIo>>,
    ) -> Result<()> {
        if connection.is_some() {
            return Ok(());
        }
        let connector = self.inner.connector.as_ref().ok_or_else(|| {
            super::transport_error(
                "sdk-transport",
                "SDK transport connection is closed after a prior failure",
            )
        })?;
        let io = connector.connect().await?;
        let (io, protocol) = negotiate_transport(io).await?;
        self.inner.protocol.store(protocol, Ordering::Release);
        *connection = Some(io);
        Ok(())
    }

    /// Negotiated wire protocol version for the current or most recent connection.
    #[must_use]
    pub fn protocol_version(&self) -> u16 {
        self.inner.protocol.load(Ordering::Acquire)
    }

    async fn call(&self, request: WireRequest) -> Result<WireResponse> {
        request.validate()?;
        let minimum_protocol = request.minimum_protocol();
        let request_id = self
            .inner
            .next_request_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| protocol_error("SDK transport request ID space exhausted"))?;

        let mut connection_guard = self.inner.connection.lock().await;
        self.reconnect_locked(&mut connection_guard).await?;
        let protocol = self.inner.protocol.load(Ordering::Acquire);
        if protocol < minimum_protocol {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "SDK operation requires protocol {minimum_protocol}, but the local service \
                     negotiated protocol {protocol}"
                ),
            )
            .for_operation("sdk-transport"));
        }
        let connection = connection_guard
            .as_mut()
            .expect("reconnect_locked publishes a negotiated connection");
        if let Err(error) = write_frame(
            &mut **connection,
            &ClientMessage::Request {
                protocol,
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
                return Err(super::transport_error(
                    "sdk-transport",
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
                protocol: response_protocol,
                request_id: response_id,
                result,
            } if response_protocol == protocol && response_id == request_id => match *result {
                super::wire::WireResult::Ok { response } => Ok(*response),
                super::wire::WireResult::Error { error } => Err(error),
            },
            ServerMessage::Response {
                protocol: response_protocol,
                request_id: response_id,
                ..
            } => {
                *connection_guard = None;
                Err(protocol_error(format!(
                    "SDK response correlation mismatch: expected protocol {protocol} request {request_id}, \
                     received protocol {response_protocol} request {response_id}",
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

async fn negotiate_transport(
    mut io: Box<dyn AsyncTransportIo>,
) -> Result<(Box<dyn AsyncTransportIo>, u16)> {
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
        .ok_or_else(|| {
            super::transport_error(
                "sdk-handshake",
                "SDK transport closed during protocol negotiation",
            )
        })?;
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

    Ok((io, protocol))
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
        typed_call!(self, WireRequest::Create(Box::new(request)), Create)
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

    async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        typed_call!(self, WireRequest::File(request), File)
    }

    async fn filesystem(&self, request: FilesystemRequest) -> Result<FilesystemResponse> {
        typed_call!(self, WireRequest::Filesystem(request), Filesystem)
    }

    async fn checkpoint(&self, request: CheckpointRequest) -> Result<CheckpointResponse> {
        let expected = request.clone();
        let response = typed_call!(self, WireRequest::Checkpoint(request), Checkpoint)?;
        response.validate_for_request(&expected)?;
        Ok(response)
    }

    async fn restore(&self, request: RestoreRequest) -> Result<RestoreResponse> {
        let expected = request.clone();
        let response = typed_call!(self, WireRequest::Restore(Box::new(request)), Restore)?;
        response.validate_for_request(&expected)?;
        Ok(response)
    }

    async fn attest(&self, request: TeeAttestationRequest) -> Result<TeeAttestationResponse> {
        let expected = request.clone();
        let response = typed_call!(self, WireRequest::Attest(request), Attest)?;
        response.validate_for_request(&expected)?;
        Ok(response)
    }
}
