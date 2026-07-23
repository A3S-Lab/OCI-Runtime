use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::{Error, ErrorCode, OciRuntimeService, Result};

use super::wire::{
    read_frame, write_frame, ClientMessage, ServerMessage, WireRequest, WireResponse, WireResult,
};
use super::{protocol_error, SDK_PROTOCOL_VERSION_MAX, SDK_PROTOCOL_VERSION_MIN};

/// Serve one negotiated SDK connection until the peer closes it.
pub async fn serve_transport_connection<T>(
    service: Arc<dyn OciRuntimeService>,
    mut io: T,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    let hello = read_frame::<ClientMessage>(&mut io)
        .await?
        .ok_or_else(|| protocol_error("SDK transport closed before protocol negotiation"))?;
    let (client_min, client_max) = match hello {
        ClientMessage::Hello {
            protocol_min,
            protocol_max,
        } => (protocol_min, protocol_max),
        ClientMessage::Request { .. } => {
            return Err(protocol_error(
                "client sent an SDK request before protocol negotiation",
            ));
        }
    };

    let Some(protocol) = select_protocol(client_min, client_max) else {
        write_frame(
            &mut io,
            &ServerMessage::Reject {
                protocol_min: SDK_PROTOCOL_VERSION_MIN,
                protocol_max: SDK_PROTOCOL_VERSION_MAX,
                message: format!(
                    "client supports {client_min} through {client_max}; no common version"
                ),
            },
        )
        .await?;
        return Ok(());
    };
    write_frame(&mut io, &ServerMessage::Welcome { protocol }).await?;

    loop {
        let Some(message) = read_frame::<ClientMessage>(&mut io).await? else {
            return Ok(());
        };
        let (request_protocol, request_id, request) = match message {
            ClientMessage::Request {
                protocol,
                request_id,
                request,
            } => (protocol, request_id, *request),
            ClientMessage::Hello { .. } => {
                return Err(protocol_error(
                    "client repeated SDK protocol negotiation on an active connection",
                ));
            }
        };
        if request_id == 0 {
            return Err(protocol_error(
                "client sent the reserved zero SDK request ID",
            ));
        }

        let result = if request_protocol == protocol {
            match dispatch(service.as_ref(), request).await {
                Ok(response) => WireResult::Ok {
                    response: Box::new(response),
                },
                Err(error) => WireResult::Error { error },
            }
        } else {
            WireResult::Error {
                error: Error::new(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "SDK request uses protocol {request_protocol}; negotiated protocol is \
                         {protocol}"
                    ),
                )
                .for_operation("sdk-transport"),
            }
        };
        write_frame(
            &mut io,
            &ServerMessage::Response {
                protocol,
                request_id,
                result: Box::new(result),
            },
        )
        .await?;
    }
}

const fn select_protocol(client_min: u16, client_max: u16) -> Option<u16> {
    if client_min > client_max {
        return None;
    }
    let minimum = if client_min > SDK_PROTOCOL_VERSION_MIN {
        client_min
    } else {
        SDK_PROTOCOL_VERSION_MIN
    };
    let maximum = if client_max < SDK_PROTOCOL_VERSION_MAX {
        client_max
    } else {
        SDK_PROTOCOL_VERSION_MAX
    };
    if minimum > maximum {
        None
    } else {
        Some(maximum)
    }
}

async fn dispatch(service: &dyn OciRuntimeService, request: WireRequest) -> Result<WireResponse> {
    match request {
        WireRequest::Features => service
            .features()
            .await
            .map(Box::new)
            .map(WireResponse::Features),
        WireRequest::Create(request) => service.create(request).await.map(WireResponse::Create),
        WireRequest::State(request) => service.state(request).await.map(WireResponse::State),
        WireRequest::Start(request) => service.start(request).await.map(WireResponse::Start),
        WireRequest::Kill(request) => service.kill(request).await.map(WireResponse::Kill),
        WireRequest::Delete(request) => {
            service.delete(request).await.map(|()| WireResponse::Delete)
        }
        WireRequest::Exec(request) => service.exec(request).await.map(WireResponse::Exec),
        WireRequest::Wait(request) => service.wait(request).await.map(WireResponse::Wait),
        WireRequest::List(request) => service.list(request).await.map(WireResponse::List),
        WireRequest::Pause(request) => service.pause(request).await.map(WireResponse::Pause),
        WireRequest::Resume(request) => service.resume(request).await.map(WireResponse::Resume),
        WireRequest::Update(request) => service.update(request).await.map(WireResponse::Update),
        WireRequest::Processes(request) => service
            .processes(request)
            .await
            .map(WireResponse::Processes),
        WireRequest::Stats(request) => service.stats(request).await.map(WireResponse::Stats),
        WireRequest::Events(request) => service.events(request).await.map(WireResponse::Events),
        WireRequest::ReadOutput(request) => service
            .read_output(request)
            .await
            .map(WireResponse::ReadOutput),
        WireRequest::WriteStdin(request) => service
            .write_stdin(request)
            .await
            .map(|()| WireResponse::WriteStdin),
        WireRequest::CloseStdin(request) => service
            .close_stdin(request)
            .await
            .map(|()| WireResponse::CloseStdin),
        WireRequest::Resize(request) => {
            service.resize(request).await.map(|()| WireResponse::Resize)
        }
        WireRequest::SignalProcess(request) => service
            .signal_process(request)
            .await
            .map(|()| WireResponse::SignalProcess),
        WireRequest::WaitProcess(request) => service
            .wait_process(request)
            .await
            .map(WireResponse::WaitProcess),
        WireRequest::Checkpoint(request) => service
            .checkpoint(request)
            .await
            .map(WireResponse::Checkpoint),
        WireRequest::Restore(request) => service.restore(request).await.map(WireResponse::Restore),
    }
}

#[cfg(test)]
mod tests {
    use super::select_protocol;

    #[test]
    fn negotiation_selects_highest_common_version() {
        assert_eq!(select_protocol(1, 1), Some(1));
        assert_eq!(select_protocol(0, 1), Some(1));
        assert_eq!(select_protocol(2, 3), None);
        assert_eq!(select_protocol(2, 1), None);
    }
}
