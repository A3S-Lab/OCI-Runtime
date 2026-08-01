use std::ffi::c_void;
use std::future::Future;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;
use std::sync::Arc;

use a3s_oci_sdk::{
    serve_transport_connection, Error, ErrorCode, LocalIpcEndpoint, OciRuntimeService, Result,
};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::task::JoinSet;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY, HANDLE};

use crate::windows_security::PrivateSecurityDescriptor;
use crate::HostRuntimeService;

const MAX_CLIENT_CONNECTIONS: usize = 32;

/// Protected Windows SDK endpoint around one durable host runtime service.
///
/// The named pipe is local-only, non-inheritable, and protected by a verified
/// DACL that grants access only to the current runtime principal and
/// LocalSystem. Binding the first pipe instance also prevents another process
/// from pre-creating the endpoint before the runtime starts.
#[derive(Debug)]
pub struct WindowsHostService {
    endpoint: LocalIpcEndpoint,
    pending: NamedPipeServer,
    service: Arc<HostRuntimeService>,
}

impl WindowsHostService {
    /// Bind a protected local named pipe after the durable service is ready.
    pub fn bind(endpoint: LocalIpcEndpoint, service: HostRuntimeService) -> Result<Self> {
        let pending = create_pipe_instance(endpoint.as_windows_named_pipe(), true)?;
        Ok(Self {
            endpoint,
            pending,
            service: Arc::new(service),
        })
    }

    /// Exact endpoint accepted by [`a3s_oci_sdk::RuntimeClient::connect`].
    #[must_use]
    pub const fn endpoint(&self) -> &LocalIpcEndpoint {
        &self.endpoint
    }

    /// Serve authenticated local clients until the shutdown future resolves.
    pub async fn serve_until<F>(mut self, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        tokio::pin!(shutdown);
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    connections.abort_all();
                    while connections.join_next().await.is_some() {}
                    return Ok(());
                }
                completed = connections.join_next(), if !connections.is_empty() => {
                    match completed {
                        Some(Ok(Ok(()))) => {}
                        Some(Ok(Err(error))) => {
                            connections.abort_all();
                            while connections.join_next().await.is_some() {}
                            return Err(error);
                        }
                        Some(Err(error)) => {
                            connections.abort_all();
                            while connections.join_next().await.is_some() {}
                            return Err(service_error(
                                ErrorCode::Internal,
                                "serve-windows-host-client",
                                format!("Windows SDK client task failed: {error}"),
                            ));
                        }
                        None => {}
                    }
                }
                accepted = self.accept(), if connections.len() < MAX_CLIENT_CONNECTIONS => {
                    let stream = accepted?;
                    let service: Arc<dyn OciRuntimeService> = self.service.clone();
                    connections.spawn(serve_transport_connection(service, stream));
                }
            }
        }
    }

    async fn accept(&mut self) -> Result<NamedPipeServer> {
        let pipe_name = self.endpoint.as_windows_named_pipe();
        self.pending.connect().await.map_err(|error| {
            service_error(
                ErrorCode::Unavailable,
                "accept-windows-host-client",
                format!("failed to accept Windows SDK client on {pipe_name}: {error}"),
            )
            .retryable(true)
        })?;

        // Publish the next protected instance before handing the connected
        // stream to its task. The connected instance keeps the pipe object
        // alive while this replacement closes the listener gap.
        let replacement = create_pipe_instance(pipe_name, false)?;
        Ok(std::mem::replace(&mut self.pending, replacement))
    }
}

fn create_pipe_instance(pipe_name: &str, first: bool) -> Result<NamedPipeServer> {
    let mut security = PrivateSecurityDescriptor::for_kernel_object(pipe_name)?;
    let mut attributes =
        security.security_attributes("bind-windows-host-service", Path::new(pipe_name))?;
    let mut options = ServerOptions::new();
    options
        .access_inbound(true)
        .access_outbound(true)
        .pipe_mode(PipeMode::Byte)
        .first_pipe_instance(first)
        .reject_remote_clients(true);

    // SAFETY: `attributes` points to a fully initialized descriptor whose ACL
    // and copied SIDs remain live until `CreateNamedPipeW` returns.
    let server = unsafe {
        options.create_with_security_attributes_raw(
            pipe_name,
            ptr::from_mut(&mut attributes).cast::<c_void>(),
        )
    }
    .map_err(|error| bind_error(pipe_name, error))?;
    security.verify_kernel_object(server.as_raw_handle() as HANDLE, pipe_name)?;
    Ok(server)
}

fn bind_error(pipe_name: &str, error: std::io::Error) -> Error {
    let collision = error.raw_os_error().is_some_and(|code| {
        u32::try_from(code).is_ok_and(|code| matches!(code, ERROR_ACCESS_DENIED | ERROR_PIPE_BUSY))
    });
    let code = if collision {
        ErrorCode::Conflict
    } else {
        ErrorCode::Internal
    };
    service_error(
        code,
        "bind-windows-host-service",
        format!("failed to bind Windows SDK pipe {pipe_name}: {error}"),
    )
}

fn service_error(code: ErrorCode, operation: &'static str, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation(operation)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use a3s_oci_sdk::{LocalIpcEndpoint, RuntimeClient, RuntimeOperation};
    use tokio::sync::oneshot;

    use super::WindowsHostService;
    use crate::HostRuntimeService;

    static NEXT_PIPE: AtomicU64 = AtomicU64::new(1);

    fn unique_endpoint() -> LocalIpcEndpoint {
        LocalIpcEndpoint::windows_named_pipe(format!(
            r"\\.\pipe\a3s-oci-host-test-{}-{}",
            std::process::id(),
            NEXT_PIPE.fetch_add(1, Ordering::Relaxed)
        ))
        .expect("valid Windows SDK endpoint")
    }

    #[test]
    fn host_service_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<WindowsHostService>();
    }

    #[tokio::test]
    async fn first_instance_prevents_windows_sdk_endpoint_squatting() {
        let endpoint = unique_endpoint();
        let _owner = WindowsHostService::bind(endpoint.clone(), HostRuntimeService::new())
            .expect("bind first Windows host service");
        let error = WindowsHostService::bind(endpoint, HostRuntimeService::new())
            .expect_err("second Windows host service must be rejected");
        assert_eq!(error.code, a3s_oci_sdk::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn protected_windows_host_service_serves_concurrent_sdk_clients_and_releases_pipe() {
        let endpoint = unique_endpoint();
        let service = WindowsHostService::bind(endpoint.clone(), HostRuntimeService::new())
            .expect("bind Windows host service");
        assert_eq!(service.endpoint(), &endpoint);
        let (shutdown_send, shutdown_receive) = oneshot::channel();
        let server = tokio::spawn(service.serve_until(async move {
            let _ = shutdown_receive.await;
        }));

        let first = RuntimeClient::connect(&endpoint)
            .await
            .expect("connect first Windows SDK client");
        let second = RuntimeClient::connect(&endpoint)
            .await
            .expect("connect second Windows SDK client while first remains live");
        let (first_info, second_info) = tokio::join!(first.features(), second.features());
        assert_eq!(
            first_info.expect("first feature response").operations,
            vec![RuntimeOperation::Features]
        );
        assert_eq!(
            second_info.expect("second feature response").operations,
            vec![RuntimeOperation::Features]
        );
        drop(first);
        drop(second);

        shutdown_send.send(()).expect("request server shutdown");
        server
            .await
            .expect("Windows host task must join")
            .expect("Windows host service must stop cleanly");

        let _rebound = WindowsHostService::bind(endpoint, HostRuntimeService::new())
            .expect("pipe name must be released after shutdown");
    }
}
