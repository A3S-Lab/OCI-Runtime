use std::fmt;

#[cfg(unix)]
use std::path::{Path, PathBuf};

use crate::{Error, ErrorCode, Result};

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
        match &endpoint.kind {
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
                Self::from_io(stream).await
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
                Self::from_io(pipe).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncRead, AsyncWrite};

    use super::LocalIpcEndpoint;
    #[cfg(windows)]
    use super::RuntimeTransportClient;
    #[cfg(unix)]
    use crate::RuntimeClient;

    use super::super::wire::{read_frame, write_frame, ClientMessage, ServerMessage};

    async fn serve_handshake(mut io: impl AsyncRead + AsyncWrite + Unpin) {
        let hello = read_frame::<ClientMessage>(&mut io)
            .await
            .expect("read client hello")
            .expect("client hello frame");
        assert!(matches!(hello, ClientMessage::Hello { .. }));
        write_frame(&mut io, &ServerMessage::Welcome { protocol: 1 })
            .await
            .expect("write server welcome");
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
        assert_eq!(client.protocol_version(), 1);
        drop(client);
        server_task.await.expect("server task must join");
    }

    #[cfg(unix)]
    #[test]
    fn unix_endpoint_requires_an_absolute_path() {
        assert!(LocalIpcEndpoint::unix_socket("/run/a3s/oci.sock").is_ok());
        assert!(LocalIpcEndpoint::unix_socket("oci.sock").is_err());
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
}
