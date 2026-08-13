use std::future::Future;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_sdk::{serve_transport_connection, Error, ErrorCode, OciRuntimeService, Result};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;

pub(crate) const SERVICE_SOCKET_NAME: &str = "runtime.sock";

const MAX_CLIENT_CONNECTIONS: usize = 32;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_SOCKET_MODE: u32 = 0o600;
const STALE_SOCKET_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// One inode-pinned, same-UID Unix SDK endpoint.
///
/// The socket guard is declared before the listener so cleanup checks and
/// unlinks the published inode while the original listener still owns it.
pub(crate) struct UnixServiceEndpoint {
    socket: OwnedSocketPath,
    listener: UnixListener,
    effective_uid: u32,
}

impl UnixServiceEndpoint {
    #[cfg(any(test, target_os = "linux"))]
    pub(crate) async fn bind(path: &Path) -> Result<Self> {
        validate_absolute_normalized_path(path, "Unix SDK service socket")?;
        match tokio::fs::symlink_metadata(path).await {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(service_error(
                    ErrorCode::PermissionDenied,
                    "bind-unix-sdk-service",
                    format!(
                        "failed to inspect Unix SDK service socket {}: {error}",
                        path.display()
                    ),
                ));
            }
            Ok(_) => {
                return Err(service_error(
                    ErrorCode::Conflict,
                    "bind-unix-sdk-service",
                    format!("Unix SDK service socket already exists: {}", path.display()),
                ));
            }
        }

        Self::bind_absent(path).await
    }

    /// Bind after recovering only a verified, unreachable socket inode.
    ///
    /// The caller must already own the durable service-state lock. That lock
    /// is the race boundary proving that another legitimate service owner
    /// cannot publish this endpoint while stale-path recovery is in progress.
    pub(crate) async fn bind_recovering_stale(path: &Path) -> Result<Self> {
        validate_absolute_normalized_path(path, "Unix SDK service socket")?;
        recover_stale_socket(path).await?;
        Self::bind_absent(path).await
    }

    async fn bind_absent(path: &Path) -> Result<Self> {
        let listener = UnixListener::bind(path).map_err(|error| {
            service_error(
                ErrorCode::Unavailable,
                "bind-unix-sdk-service",
                format!(
                    "failed to bind Unix SDK service socket {}: {error}",
                    path.display()
                ),
            )
        })?;
        let initial_metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
            service_error(
                ErrorCode::PermissionDenied,
                "bind-unix-sdk-service",
                format!(
                    "failed to capture Unix SDK service socket {}: {error}",
                    path.display()
                ),
            )
        })?;
        let socket = OwnedSocketPath {
            path: path.to_path_buf(),
            device: initial_metadata.dev(),
            inode: initial_metadata.ino(),
        };
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_SOCKET_MODE))
            .await
            .map_err(|error| {
                service_error(
                    ErrorCode::PermissionDenied,
                    "bind-unix-sdk-service",
                    format!(
                        "failed to protect Unix SDK service socket {}: {error}",
                        path.display()
                    ),
                )
            })?;
        let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
            service_error(
                ErrorCode::PermissionDenied,
                "bind-unix-sdk-service",
                format!(
                    "failed to verify Unix SDK service socket {}: {error}",
                    path.display()
                ),
            )
        })?;
        // SAFETY: geteuid has no preconditions or failure result.
        let effective_uid = unsafe { libc::geteuid() };
        if !metadata.file_type().is_socket()
            || metadata.uid() != effective_uid
            || metadata.mode() & 0o777 != PRIVATE_SOCKET_MODE
            || metadata.dev() != socket.device
            || metadata.ino() != socket.inode
        {
            return Err(service_error(
                ErrorCode::PermissionDenied,
                "bind-unix-sdk-service",
                format!(
                    "Unix SDK service socket {} must be owned by UID {effective_uid} with mode 0600",
                    path.display()
                ),
            ));
        }

        Ok(Self {
            socket,
            listener,
            effective_uid,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        self.socket.path()
    }

    pub(crate) async fn serve_until<F>(
        &self,
        service: Arc<dyn OciRuntimeService>,
        shutdown: F,
    ) -> Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        serve_authenticated_connections(
            &self.listener,
            self.path(),
            service,
            self.effective_uid,
            shutdown,
        )
        .await
    }
}

async fn recover_stale_socket(path: &Path) -> Result<()> {
    let metadata = match tokio::fs::symlink_metadata(path).await {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(service_error(
                ErrorCode::PermissionDenied,
                "recover-unix-sdk-service-socket",
                format!(
                    "failed to inspect Unix SDK service socket {}: {error}",
                    path.display()
                ),
            ));
        }
        Ok(metadata) => metadata,
    };
    // SAFETY: geteuid has no preconditions or failure result.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_socket()
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o777 != PRIVATE_SOCKET_MODE
    {
        return Err(service_error(
            ErrorCode::PermissionDenied,
            "recover-unix-sdk-service-socket",
            format!(
                "refusing to replace Unix SDK service path {}; expected a same-UID mode-0600 socket",
                path.display()
            ),
        ));
    }
    let expected_device = metadata.dev();
    let expected_inode = metadata.ino();

    match tokio::time::timeout(STALE_SOCKET_PROBE_TIMEOUT, UnixStream::connect(path)).await {
        Ok(Ok(stream)) => {
            drop(stream);
            return Err(service_error(
                ErrorCode::Conflict,
                "recover-unix-sdk-service-socket",
                format!(
                    "Unix SDK service socket still has a live listener: {}",
                    path.display()
                ),
            ));
        }
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {}
        Ok(Err(error)) => {
            return Err(service_error(
                ErrorCode::Unavailable,
                "recover-unix-sdk-service-socket",
                format!(
                    "could not prove Unix SDK service socket {} is stale: {error}",
                    path.display()
                ),
            )
            .retryable(true));
        }
        Err(_) => {
            return Err(service_error(
                ErrorCode::Unavailable,
                "recover-unix-sdk-service-socket",
                format!(
                    "timed out probing existing Unix SDK service socket {}",
                    path.display()
                ),
            )
            .retryable(true));
        }
    }

    let current = match tokio::fs::symlink_metadata(path).await {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(service_error(
                ErrorCode::PermissionDenied,
                "recover-unix-sdk-service-socket",
                format!(
                    "failed to re-inspect stale Unix SDK service socket {}: {error}",
                    path.display()
                ),
            ));
        }
        Ok(metadata) => metadata,
    };
    if !current.file_type().is_socket()
        || current.uid() != effective_uid
        || current.mode() & 0o777 != PRIVATE_SOCKET_MODE
        || current.dev() != expected_device
        || current.ino() != expected_inode
    {
        return Err(service_error(
            ErrorCode::Conflict,
            "recover-unix-sdk-service-socket",
            format!(
                "Unix SDK service socket changed during stale-path recovery: {}",
                path.display()
            ),
        ));
    }
    tokio::fs::remove_file(path).await.map_err(|error| {
        service_error(
            ErrorCode::PermissionDenied,
            "recover-unix-sdk-service-socket",
            format!(
                "failed to remove verified stale Unix SDK service socket {}: {error}",
                path.display()
            ),
        )
    })
}

pub(crate) fn validate_absolute_normalized_path(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(service_error(
            ErrorCode::InvalidArgument,
            "configure-unix-sdk-service",
            format!(
                "{label} must be an absolute normalized path: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

pub(crate) async fn prepare_private_directory(path: &Path, label: &str) -> Result<()> {
    validate_absolute_normalized_path(path, label)?;
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = tokio::fs::DirBuilder::new();
            builder.mode(PRIVATE_DIRECTORY_MODE);
            builder.create(path).await.map_err(|error| {
                service_error(
                    ErrorCode::PermissionDenied,
                    "prepare-unix-sdk-service-directory",
                    format!("failed to create {label} {}: {error}", path.display()),
                )
            })?;
        }
        Err(error) => {
            return Err(service_error(
                ErrorCode::PermissionDenied,
                "prepare-unix-sdk-service-directory",
                format!("failed to inspect {label} {}: {error}", path.display()),
            ));
        }
    }
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        service_error(
            ErrorCode::PermissionDenied,
            "prepare-unix-sdk-service-directory",
            format!("failed to re-inspect {label} {}: {error}", path.display()),
        )
    })?;
    // SAFETY: geteuid has no preconditions or failure result.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
    {
        return Err(service_error(
            ErrorCode::PermissionDenied,
            "prepare-unix-sdk-service-directory",
            format!(
                "{label} {} must be a real directory owned by UID {effective_uid} with mode 0700",
                path.display()
            ),
        ));
    }
    let canonical = tokio::fs::canonicalize(path).await.map_err(|error| {
        service_error(
            ErrorCode::PermissionDenied,
            "prepare-unix-sdk-service-directory",
            format!("failed to canonicalize {label} {}: {error}", path.display()),
        )
    })?;
    if canonical != path {
        return Err(service_error(
            ErrorCode::PermissionDenied,
            "prepare-unix-sdk-service-directory",
            format!(
                "{label} resolves through an alias: {} -> {}",
                path.display(),
                canonical.display()
            ),
        ));
    }
    Ok(())
}

pub(crate) fn combine_service_and_cleanup(
    serve: Result<()>,
    cleanup: Result<()>,
    cleanup_label: &str,
) -> Result<()> {
    match (serve, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(mut primary), Err(cleanup)) => {
            primary.message = format!(
                "{}; {cleanup_label} shutdown also failed: {}",
                primary.message, cleanup.message
            );
            primary.retryable |= cleanup.retryable;
            Err(primary)
        }
    }
}

async fn serve_authenticated_connections<F>(
    listener: &UnixListener,
    socket_path: &Path,
    service: Arc<dyn OciRuntimeService>,
    effective_uid: u32,
    shutdown: F,
) -> Result<()>
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
                    // Transport and client-disconnect failures are scoped to
                    // the accepted connection and never stop the shared owner.
                    Some(Ok(Err(_))) => {}
                    Some(Err(error)) => {
                        connections.abort_all();
                        while connections.join_next().await.is_some() {}
                        return Err(service_error(
                            ErrorCode::Internal,
                            "serve-unix-sdk-client",
                            format!("Unix SDK client task failed: {error}"),
                        ));
                    }
                    None => {}
                }
            }
            accepted = listener.accept(), if connections.len() < MAX_CLIENT_CONNECTIONS => {
                let (stream, _) = accepted.map_err(|error| {
                    service_error(
                        ErrorCode::Unavailable,
                        "accept-unix-sdk-client",
                        format!(
                            "failed to accept Unix SDK client on {}: {error}",
                            socket_path.display()
                        ),
                    )
                })?;
                // Authentication failure belongs to this connection. Dropping
                // it here prevents an untrusted peer from stopping the owner.
                if verify_peer(&stream, effective_uid).is_ok() {
                    connections.spawn(serve_transport_connection(service.clone(), stream));
                }
            }
        }
    }
}

fn verify_peer(stream: &UnixStream, effective_uid: u32) -> Result<()> {
    let credentials = stream.peer_cred().map_err(|error| {
        service_error(
            ErrorCode::PermissionDenied,
            "authenticate-unix-sdk-client",
            format!("failed to inspect Unix SDK peer credentials: {error}"),
        )
    })?;
    if credentials.uid() == effective_uid {
        Ok(())
    } else {
        Err(service_error(
            ErrorCode::PermissionDenied,
            "authenticate-unix-sdk-client",
            format!(
                "Unix SDK peer UID {} does not match service UID {}",
                credentials.uid(),
                effective_uid
            ),
        ))
    }
}

struct OwnedSocketPath {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl OwnedSocketPath {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for OwnedSocketPath {
    fn drop(&mut self) {
        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn service_error(code: ErrorCode, operation: &'static str, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation(operation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct UnsupportedService;

    #[a3s_oci_sdk::async_trait]
    impl OciRuntimeService for UnsupportedService {
        async fn features(&self) -> Result<a3s_oci_sdk::RuntimeInfo> {
            Err(Error::unsupported("features-test"))
        }

        async fn create(
            &self,
            _request: a3s_oci_sdk::CreateRequest,
        ) -> Result<a3s_oci_sdk::ContainerRecord> {
            Err(Error::unsupported("create-test"))
        }

        async fn state(
            &self,
            _request: a3s_oci_sdk::StateRequest,
        ) -> Result<a3s_oci_sdk::ContainerRecord> {
            Err(Error::unsupported("state-test"))
        }

        async fn start(
            &self,
            _request: a3s_oci_sdk::StartRequest,
        ) -> Result<a3s_oci_sdk::ContainerRecord> {
            Err(Error::unsupported("start-test"))
        }

        async fn kill(
            &self,
            _request: a3s_oci_sdk::KillRequest,
        ) -> Result<a3s_oci_sdk::ContainerRecord> {
            Err(Error::unsupported("kill-test"))
        }

        async fn delete(&self, _request: a3s_oci_sdk::DeleteRequest) -> Result<()> {
            Err(Error::unsupported("delete-test"))
        }
    }

    fn canonical_temporary_root(temporary: &tempfile::TempDir) -> PathBuf {
        std::fs::canonicalize(temporary.path()).expect("canonical temporary root")
    }

    #[test]
    fn rejects_relative_and_ambiguous_paths() {
        assert!(validate_absolute_normalized_path(Path::new("relative"), "test path").is_err());
        assert!(validate_absolute_normalized_path(Path::new("/tmp/a/../b"), "test path").is_err());
    }

    #[tokio::test]
    async fn private_layout_and_socket_cleanup_are_inode_scoped() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = canonical_temporary_root(&temporary).join("service");
        prepare_private_directory(&root, "test root")
            .await
            .expect("private root");
        let socket_path = root.join(SERVICE_SOCKET_NAME);
        let endpoint = UnixServiceEndpoint::bind(&socket_path)
            .await
            .expect("private socket");
        let metadata = std::fs::symlink_metadata(&socket_path).expect("socket metadata");
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.mode() & 0o777, PRIVATE_SOCKET_MODE);

        std::fs::remove_file(&socket_path).expect("unlink original socket");
        let replacement =
            std::os::unix::net::UnixListener::bind(&socket_path).expect("bind replacement socket");
        drop(endpoint);
        assert!(socket_path.exists());
        drop(replacement);
        std::fs::remove_file(&socket_path).expect("unlink replacement socket");

        let endpoint = UnixServiceEndpoint::bind(&socket_path)
            .await
            .expect("bind another owned socket");
        drop(endpoint);
        assert!(!socket_path.exists());
    }

    #[tokio::test]
    async fn replacement_bind_recovers_only_an_unreachable_private_socket() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = canonical_temporary_root(&temporary).join("service");
        prepare_private_directory(&root, "test root")
            .await
            .expect("private root");
        let socket_path = root.join(SERVICE_SOCKET_NAME);

        let stale =
            std::os::unix::net::UnixListener::bind(&socket_path).expect("bind predecessor socket");
        std::fs::set_permissions(
            &socket_path,
            std::fs::Permissions::from_mode(PRIVATE_SOCKET_MODE),
        )
        .expect("protect predecessor socket");
        let stale_metadata =
            std::fs::symlink_metadata(&socket_path).expect("predecessor socket metadata");
        drop(stale);

        let endpoint = UnixServiceEndpoint::bind_recovering_stale(&socket_path)
            .await
            .expect("recover stale predecessor socket");
        let replacement_metadata =
            std::fs::symlink_metadata(&socket_path).expect("replacement socket metadata");
        assert_ne!(replacement_metadata.ino(), stale_metadata.ino());
        assert_eq!(replacement_metadata.mode() & 0o777, PRIVATE_SOCKET_MODE);
        drop(endpoint);
        assert!(!socket_path.exists());
    }

    #[tokio::test]
    async fn replacement_bind_refuses_a_live_listener() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = canonical_temporary_root(&temporary).join("service");
        prepare_private_directory(&root, "test root")
            .await
            .expect("private root");
        let socket_path = root.join(SERVICE_SOCKET_NAME);
        let listener = std::os::unix::net::UnixListener::bind(&socket_path)
            .expect("bind live predecessor socket");
        std::fs::set_permissions(
            &socket_path,
            std::fs::Permissions::from_mode(PRIVATE_SOCKET_MODE),
        )
        .expect("protect live predecessor socket");
        let metadata = std::fs::symlink_metadata(&socket_path).expect("live predecessor metadata");

        let error = match UnixServiceEndpoint::bind_recovering_stale(&socket_path).await {
            Ok(_) => panic!("live listener must not be replaced"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::Conflict);
        let retained = std::fs::symlink_metadata(&socket_path).expect("retained live socket");
        assert_eq!(retained.ino(), metadata.ino());
        drop(listener);
        std::fs::remove_file(&socket_path).expect("remove test socket");
    }

    #[tokio::test]
    async fn replacement_bind_refuses_unprotected_or_non_socket_paths() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = canonical_temporary_root(&temporary).join("service");
        prepare_private_directory(&root, "test root")
            .await
            .expect("private root");
        let socket_path = root.join(SERVICE_SOCKET_NAME);

        let listener = std::os::unix::net::UnixListener::bind(&socket_path)
            .expect("bind permissive predecessor socket");
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666))
            .expect("make predecessor socket permissive");
        drop(listener);
        let error = match UnixServiceEndpoint::bind_recovering_stale(&socket_path).await {
            Ok(_) => panic!("permissive socket must not be replaced"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        std::fs::remove_file(&socket_path).expect("remove permissive socket");

        std::fs::write(&socket_path, b"not a socket").expect("ordinary file");
        std::fs::set_permissions(
            &socket_path,
            std::fs::Permissions::from_mode(PRIVATE_SOCKET_MODE),
        )
        .expect("protect ordinary file");
        let error = match UnixServiceEndpoint::bind_recovering_stale(&socket_path).await {
            Ok(_) => panic!("ordinary file must not be replaced"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert_eq!(
            std::fs::read(&socket_path).expect("retained ordinary file"),
            b"not a socket"
        );
    }

    #[tokio::test]
    async fn service_negotiates_multiple_live_sdk_clients() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = canonical_temporary_root(&temporary).join("service");
        prepare_private_directory(&root, "test root")
            .await
            .expect("private root");
        let socket_path = root.join(SERVICE_SOCKET_NAME);
        let endpoint = UnixServiceEndpoint::bind(&socket_path)
            .await
            .expect("private socket");
        let sdk_endpoint =
            a3s_oci_sdk::LocalIpcEndpoint::unix_socket(&socket_path).expect("local SDK endpoint");
        let service: Arc<dyn OciRuntimeService> = Arc::new(UnsupportedService);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            endpoint
                .serve_until(service, async move {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let first = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            a3s_oci_sdk::RuntimeClient::connect(&sdk_endpoint),
        )
        .await
        .expect("first SDK client negotiation timed out")
        .expect("first SDK client");
        let second = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            a3s_oci_sdk::RuntimeClient::connect(&sdk_endpoint),
        )
        .await
        .expect("second SDK client negotiation timed out while first remained live")
        .expect("second SDK client");

        let (first_result, second_result) =
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                tokio::join!(first.features(), second.features())
            })
            .await
            .expect("concurrent SDK requests timed out");
        assert_eq!(
            first_result
                .expect_err("test service rejects features")
                .code,
            ErrorCode::Unsupported
        );
        assert_eq!(
            second_result
                .expect_err("test service rejects features")
                .code,
            ErrorCode::Unsupported
        );

        shutdown_tx.send(()).expect("request service shutdown");
        server
            .await
            .expect("service task")
            .expect("clean service shutdown");
        assert!(!socket_path.exists());
    }

    #[tokio::test]
    async fn aborted_and_rejected_clients_do_not_terminate_service() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = canonical_temporary_root(&temporary).join("service");
        prepare_private_directory(&root, "test root")
            .await
            .expect("private root");
        let socket_path = root.join(SERVICE_SOCKET_NAME);
        let endpoint = UnixServiceEndpoint::bind(&socket_path)
            .await
            .expect("private socket");
        let sdk_endpoint =
            a3s_oci_sdk::LocalIpcEndpoint::unix_socket(&socket_path).expect("local SDK endpoint");
        let service: Arc<dyn OciRuntimeService> = Arc::new(UnsupportedService);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            endpoint
                .serve_until(service, async move {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let aborted = tokio::net::UnixStream::connect(&socket_path)
            .await
            .expect("connect client that aborts before negotiation");
        drop(aborted);

        let client = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            a3s_oci_sdk::RuntimeClient::connect(&sdk_endpoint),
        )
        .await
        .expect("replacement SDK client negotiation timed out")
        .expect("replacement SDK client");
        assert_eq!(
            client
                .features()
                .await
                .expect_err("test service rejects features")
                .code,
            ErrorCode::Unsupported
        );

        let (stream, _) = UnixStream::pair().expect("Unix stream pair");
        // SAFETY: geteuid has no preconditions or failure result.
        let mismatched_uid = unsafe { libc::geteuid() }.wrapping_add(1);
        assert_eq!(
            verify_peer(&stream, mismatched_uid)
                .expect_err("mismatched UID must be rejected")
                .code,
            ErrorCode::PermissionDenied
        );

        shutdown_tx.send(()).expect("request service shutdown");
        server
            .await
            .expect("service task")
            .expect("clean service shutdown");
    }

    #[tokio::test]
    async fn private_layout_rejects_permissive_existing_directory() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = canonical_temporary_root(&temporary).join("service");
        std::fs::create_dir(&root).expect("service root");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
            .expect("permissive mode");
        let error = prepare_private_directory(&root, "test root")
            .await
            .expect_err("permissive root must fail");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
    }
}
