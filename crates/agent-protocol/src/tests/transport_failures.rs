use super::*;

#[derive(Debug)]
struct FailAfterNegotiationWriteStream {
    inner: DuplexStream,
    negotiation_flushed: bool,
    dropped: Arc<AtomicBool>,
}

impl FailAfterNegotiationWriteStream {
    fn new(inner: DuplexStream, dropped: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            negotiation_flushed: false,
            dropped,
        }
    }
}

impl Drop for FailAfterNegotiationWriteStream {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl AsyncRead for FailAfterNegotiationWriteStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for FailAfterNegotiationWriteStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let stream = self.get_mut();
        if stream.negotiation_flushed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected request write failure",
            )));
        }
        Pin::new(&mut stream.inner).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let stream = self.get_mut();
        match Pin::new(&mut stream.inner).poll_flush(context) {
            Poll::Ready(Ok(())) => {
                stream.negotiation_flushed = true;
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

#[tokio::test]
async fn response_disconnect_releases_the_transport_while_client_clones_remain() {
    let (host, mut guest) = tokio::io::duplex(1024 * 1024);
    let dropped = Arc::new(AtomicBool::new(false));
    let host = DropObservedStream::new(host, Arc::clone(&dropped));
    let peer = tokio::spawn(async move {
        let _hello: HostHello = read_frame(&mut guest)
            .await?
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "missing hello"))?;
        write_frame(
            &mut guest,
            &HelloOutcome::Accepted {
                hello: AgentHello::new(
                    1,
                    AgentCapabilities::core("disconnect-test", std::env::consts::ARCH)?,
                ),
            },
        )
        .await?;
        let _request: RequestEnvelope = read_frame(&mut guest)
            .await?
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "missing request"))?;
        drop(guest);
        Ok::<_, Error>(())
    });

    let client = AgentClient::connect(host, token(34))
        .await
        .expect("connect disconnecting peer");
    let clone = client.clone();
    let error = client
        .create(create_request())
        .await
        .expect_err("missing response must fail");
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert!(error.retryable);
    assert!(
        dropped.load(Ordering::SeqCst),
        "terminal response failure must release the transport even while clones remain"
    );

    let error = clone
        .create(create_request())
        .await
        .expect_err("connection must stay poisoned");
    assert_eq!(error.code, ErrorCode::Unavailable);
    clone.close().await.expect("close poisoned client");
    peer.await
        .expect("disconnecting peer task")
        .expect("disconnecting peer completed");
}

#[tokio::test]
async fn request_write_failure_releases_the_transport_while_client_clones_remain() {
    let (host, guest) = tokio::io::duplex(1024 * 1024);
    let dropped = Arc::new(AtomicBool::new(false));
    let host = FailAfterNegotiationWriteStream::new(host, Arc::clone(&dropped));
    let server = spawn_server(guest, token(35));
    let client = AgentClient::connect(host, token(35))
        .await
        .expect("connect request-failure peer");
    let clone = client.clone();

    let error = client
        .create(create_request())
        .await
        .expect_err("injected request write must fail");
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert!(error.retryable);
    assert!(
        dropped.load(Ordering::SeqCst),
        "terminal request failure must release the transport even while clones remain"
    );

    let error = clone
        .create(create_request())
        .await
        .expect_err("connection must stay poisoned");
    assert_eq!(error.code, ErrorCode::Unavailable);
    clone.close().await.expect("close poisoned client");
    server
        .await
        .expect("request-failure server task")
        .expect("request-failure server observed transport release");
}
