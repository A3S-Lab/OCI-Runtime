use std::fmt;
use std::sync::Arc;

#[cfg(unix)]
use std::path::{Path, PathBuf};

use async_trait::async_trait;

use crate::{Error, ErrorCode, Result};

use super::client::{AsyncTransportIo, TransportConnector};
use super::RuntimeTransportClient;

/// Validated platform-local IPC endpoint for the SDK transport.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalIpcEndpoint {
    kind: LocalIpcEndpointKind,
}

#[derive(Clone, PartialEq, Eq)]
enum LocalIpcEndpointKind {
    #[cfg(unix)]
    UnixSocket(PathBuf),
    #[cfg(windows)]
    WindowsNamedPipe(String),
}

impl fmt::Debug for LocalIpcEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            #[cfg(unix)]
            LocalIpcEndpointKind::UnixSocket(path) => {
                formatter.debug_tuple("UnixSocket").field(path).finish()
            }
            #[cfg(windows)]
            LocalIpcEndpointKind::WindowsNamedPipe(name) => formatter
                .debug_tuple("WindowsNamedPipe")
                .field(name)
                .finish(),
        }
    }
}

impl LocalIpcEndpoint {
    /// Construct an absolute Unix-domain socket endpoint.
    #[cfg(unix)]
    pub fn unix_socket(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("SDK Unix socket path must be absolute: {}", path.display()),
            )
            .for_operation("sdk-connect"));
        }
        std::os::unix::net::SocketAddr::from_pathname(&path).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "SDK Unix socket path cannot be represented by this platform; shorten its parent directory: {}: {error}",
                    path.display()
                ),
            )
            .for_operation("sdk-connect")
        })?;
        Ok(Self {
            kind: LocalIpcEndpointKind::UnixSocket(path),
        })
    }

    /// Borrow the Unix-domain socket path.
    #[cfg(unix)]
    #[must_use]
    pub fn as_unix_socket(&self) -> &Path {
        match &self.kind {
            LocalIpcEndpointKind::UnixSocket(path) => path,
        }
    }

    /// Construct a Windows local named-pipe endpoint.
    #[cfg(windows)]
    pub fn windows_named_pipe(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let normalized = name.to_ascii_lowercase();
        if !normalized.starts_with(r"\\.\pipe\") || name.len() <= r"\\.\pipe\".len() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                r"SDK named pipe must use a non-empty \\.\pipe\ endpoint",
            )
            .for_operation("sdk-connect"));
        }
        if name.as_bytes().contains(&0) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "SDK named pipe contains an embedded NUL byte",
            )
            .for_operation("sdk-connect"));
        }
        Ok(Self {
            kind: LocalIpcEndpointKind::WindowsNamedPipe(name),
        })
    }

    /// Borrow the Windows named-pipe path.
    #[cfg(windows)]
    #[must_use]
    pub fn as_windows_named_pipe(&self) -> &str {
        match &self.kind {
            LocalIpcEndpointKind::WindowsNamedPipe(name) => name,
        }
    }
}

impl RuntimeTransportClient {
    /// Connect and negotiate over a validated platform-local IPC endpoint.
    pub async fn connect(endpoint: &LocalIpcEndpoint) -> Result<Self> {
        let connector: Arc<dyn TransportConnector> = Arc::new(endpoint.clone());
        Self::from_connector(connector).await
    }
}

#[async_trait]
impl TransportConnector for LocalIpcEndpoint {
    async fn connect(&self) -> Result<Box<dyn AsyncTransportIo>> {
        match &self.kind {
            #[cfg(unix)]
            LocalIpcEndpointKind::UnixSocket(path) => {
                let stream = tokio::net::UnixStream::connect(path)
                    .await
                    .map_err(|error| {
                        super::transport_error(
                            "sdk-connect",
                            format!(
                                "failed to connect SDK Unix socket {}: {error}",
                                path.display()
                            ),
                        )
                    })?;
                Ok(Box::new(stream))
            }
            #[cfg(windows)]
            LocalIpcEndpointKind::WindowsNamedPipe(name) => {
                let pipe = tokio::net::windows::named_pipe::ClientOptions::new()
                    .open(name)
                    .map_err(|error| {
                        super::transport_error(
                            "sdk-connect",
                            format!("failed to connect SDK named pipe {name}: {error}"),
                        )
                    })?;
                Ok(Box::new(pipe))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use oci_spec::runtime::Features;
    use serde_json::json;
    use tokio::io::{AsyncRead, AsyncWrite};

    use super::LocalIpcEndpoint;
    #[cfg(windows)]
    use super::RuntimeTransportClient;
    use crate::{
        AttachmentCapabilities, ErrorCode, RuntimeClient, RuntimeFeatures, RuntimeInfo,
        RuntimeOperation,
    };

    use super::super::wire::{
        read_frame, write_frame, ClientMessage, ServerMessage, WireRequest, WireResponse,
        WireResult,
    };

    async fn serve_handshake(mut io: impl AsyncRead + AsyncWrite + Unpin) {
        let hello = read_frame::<ClientMessage>(&mut io)
            .await
            .expect("read client hello")
            .expect("client hello frame");
        assert!(matches!(hello, ClientMessage::Hello { .. }));
        write_frame(&mut io, &ServerMessage::Welcome { protocol: 3 })
            .await
            .expect("write server welcome");
    }

    async fn serve_features(mut io: impl AsyncRead + AsyncWrite + Unpin, calls: Arc<AtomicUsize>) {
        let hello = read_frame::<ClientMessage>(&mut io)
            .await
            .expect("read client hello")
            .expect("client hello frame");
        assert!(matches!(hello, ClientMessage::Hello { .. }));
        write_frame(&mut io, &ServerMessage::Welcome { protocol: 3 })
            .await
            .expect("write server welcome");

        while let Some(message) = read_frame::<ClientMessage>(&mut io)
            .await
            .expect("read SDK request")
        {
            let ClientMessage::Request {
                protocol,
                request_id,
                request,
            } = message
            else {
                panic!("client repeated SDK handshake");
            };
            assert_eq!(protocol, 3);
            assert!(matches!(*request, WireRequest::Features));
            calls.fetch_add(1, Ordering::Relaxed);
            let oci: Features = serde_json::from_value(json!({
                "ociVersionMin": "1.0.0",
                "ociVersionMax": "1.3.0"
            }))
            .expect("build OCI features");
            let info = RuntimeInfo {
                oci,
                drivers: RuntimeFeatures::current(Vec::new()),
                operations: vec![RuntimeOperation::Features],
                attachments: AttachmentCapabilities::base_v1(),
                extensions: Default::default(),
            };
            write_frame(
                &mut io,
                &ServerMessage::Response {
                    protocol: 3,
                    request_id,
                    result: Box::new(WireResult::Ok {
                        response: Box::new(WireResponse::Features(Box::new(info))),
                    }),
                },
            )
            .await
            .expect("write features response");
        }
    }

    async fn require_observed_disconnect(client: &RuntimeClient) {
        let error = client
            .features()
            .await
            .expect_err("the first call after server loss must expose ambiguity");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(error.retryable);
    }

    #[cfg(windows)]
    #[test]
    fn named_pipe_endpoint_is_local_and_non_empty() {
        assert!(LocalIpcEndpoint::windows_named_pipe(r"\\.\pipe\a3s-oci").is_ok());
        assert!(LocalIpcEndpoint::windows_named_pipe(r"\\server\pipe\a3s-oci").is_err());
        assert!(LocalIpcEndpoint::windows_named_pipe(r"\\.\pipe\").is_err());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn connects_over_a_real_windows_named_pipe() {
        use std::sync::atomic::{AtomicU64, Ordering};

        use tokio::net::windows::named_pipe::ServerOptions;

        static NEXT_PIPE: AtomicU64 = AtomicU64::new(1);
        let pipe_name = format!(
            r"\\.\pipe\a3s-oci-sdk-test-{}-{}",
            std::process::id(),
            NEXT_PIPE.fetch_add(1, Ordering::Relaxed)
        );
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_name)
            .expect("create named-pipe server");
        let server_task = tokio::spawn(async move {
            server.connect().await.expect("accept named-pipe client");
            serve_handshake(server).await;
        });

        let endpoint =
            LocalIpcEndpoint::windows_named_pipe(pipe_name).expect("valid named-pipe endpoint");
        let client = RuntimeTransportClient::connect(&endpoint)
            .await
            .expect("connect SDK transport over named pipe");
        assert_eq!(client.protocol_version(), 3);
        drop(client);
        server_task.await.expect("server task must join");
    }

    #[cfg(windows)]
    fn spawn_windows_feature_server(
        pipe_name: &str,
        calls: Arc<AtomicUsize>,
    ) -> tokio::task::JoinHandle<()> {
        use tokio::net::windows::named_pipe::ServerOptions;

        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(pipe_name)
            .expect("create named-pipe server");
        tokio::spawn(async move {
            server.connect().await.expect("accept named-pipe client");
            serve_features(server, calls).await;
        })
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn runtime_client_reconnects_after_named_pipe_server_restart() {
        use std::sync::atomic::AtomicU64;

        static NEXT_PIPE: AtomicU64 = AtomicU64::new(10_000);
        let pipe_name = format!(
            r"\\.\pipe\a3s-oci-sdk-reconnect-test-{}-{}",
            std::process::id(),
            NEXT_PIPE.fetch_add(1, Ordering::Relaxed)
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let first_server = spawn_windows_feature_server(&pipe_name, calls.clone());
        let endpoint =
            LocalIpcEndpoint::windows_named_pipe(pipe_name.clone()).expect("valid named pipe");
        let client = RuntimeClient::connect(&endpoint)
            .await
            .expect("connect first runtime service");

        client.features().await.expect("first features request");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        first_server.abort();
        assert!(first_server
            .await
            .expect_err("server must be aborted")
            .is_cancelled());
        require_observed_disconnect(&client).await;

        let second_server = spawn_windows_feature_server(&pipe_name, calls.clone());
        let info = client
            .features()
            .await
            .expect("next call must reconnect and renegotiate");
        assert_eq!(info.operations, [RuntimeOperation::Features]);
        assert_eq!(calls.load(Ordering::Relaxed), 2);

        drop(client);
        second_server.await.expect("replacement server must join");
    }

    #[cfg(unix)]
    #[test]
    fn unix_endpoint_requires_an_absolute_path() {
        assert!(LocalIpcEndpoint::unix_socket("/run/a3s/oci.sock").is_ok());
        assert!(LocalIpcEndpoint::unix_socket("oci.sock").is_err());
        let too_long = std::path::Path::new("/private/tmp")
            .join("x".repeat(256))
            .join("runtime.sock");
        let error = LocalIpcEndpoint::unix_socket(too_long)
            .expect_err("an unrepresentable Unix endpoint must fail during configuration");
        assert_eq!(error.code, crate::ErrorCode::InvalidArgument);
        assert!(error.message.contains("shorten its parent directory"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runtime_client_connects_over_a_real_unix_socket() {
        let temporary = tempfile::tempdir().expect("create temporary directory");
        let socket_path = temporary.path().join("a3s-oci.sock");
        let listener =
            tokio::net::UnixListener::bind(&socket_path).expect("bind temporary Unix socket");
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept Unix client");
            serve_handshake(stream).await;
        });

        let endpoint = LocalIpcEndpoint::unix_socket(socket_path).expect("valid Unix endpoint");
        let client = RuntimeClient::connect(&endpoint)
            .await
            .expect("connect SDK client over Unix socket");
        drop(client);
        server_task.await.expect("server task must join");
    }

    #[cfg(unix)]
    fn spawn_unix_feature_server(
        socket_path: &std::path::Path,
        calls: Arc<AtomicUsize>,
    ) -> tokio::task::JoinHandle<()> {
        let listener =
            tokio::net::UnixListener::bind(socket_path).expect("bind temporary Unix socket");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept Unix client");
            serve_features(stream, calls).await;
        })
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runtime_client_reconnects_after_unix_socket_server_restart() {
        let temporary = tempfile::tempdir().expect("create temporary directory");
        let socket_path = temporary.path().join("a3s-oci-reconnect.sock");
        let calls = Arc::new(AtomicUsize::new(0));
        let first_server = spawn_unix_feature_server(&socket_path, calls.clone());
        let endpoint =
            LocalIpcEndpoint::unix_socket(socket_path.clone()).expect("valid Unix endpoint");
        let client = RuntimeClient::connect(&endpoint)
            .await
            .expect("connect first runtime service");

        client.features().await.expect("first features request");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        first_server.abort();
        assert!(first_server
            .await
            .expect_err("server must be aborted")
            .is_cancelled());
        require_observed_disconnect(&client).await;

        std::fs::remove_file(&socket_path).expect("remove stale Unix socket");
        let second_server = spawn_unix_feature_server(&socket_path, calls.clone());
        let info = client
            .features()
            .await
            .expect("next call must reconnect and renegotiate");
        assert_eq!(info.operations, [RuntimeOperation::Features]);
        assert_eq!(calls.load(Ordering::Relaxed), 2);

        drop(client);
        second_server.await.expect("replacement server must join");
    }
}
