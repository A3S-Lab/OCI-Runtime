use std::future::Future;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use a3s_oci_sdk::{
    serve_transport_connection, ContainerId, Error, ErrorCode, OciRuntimeService, Result,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;

use crate::{HostRuntimeService, NativeControlDescriptors, NativeLinuxDriver, RuntimeDriver};

const SERVICE_SOCKET_NAME: &str = "runtime.sock";
const STATE_DIRECTORY_NAME: &str = "state";
const EXECUTOR_DIRECTORY_NAME: &str = "executor";
const MAX_CLIENT_CONNECTIONS: usize = 32;

/// Filesystem and identity contract for one native Linux runtime owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeLinuxServiceConfig {
    root: PathBuf,
    init_executable: PathBuf,
    container_id: ContainerId,
}

impl NativeLinuxServiceConfig {
    /// Bind one service to a private absolute root and one container identity.
    pub fn new(
        root: impl Into<PathBuf>,
        init_executable: impl Into<PathBuf>,
        container_id: ContainerId,
    ) -> Result<Self> {
        let root = root.into();
        validate_absolute_normalized_path(&root, "native service root")?;
        let init_executable = init_executable.into();
        validate_absolute_normalized_path(&init_executable, "native init executable")?;
        Ok(Self {
            root,
            init_executable,
            container_id,
        })
    }

    /// Private root containing the endpoint, durable state, and executor root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Unix socket consumed by [`a3s_oci_sdk::RuntimeClient::connect`].
    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.root.join(SERVICE_SOCKET_NAME)
    }

    /// Container identity allowed to consume the inherited control handles.
    #[must_use]
    pub fn container_id(&self) -> &ContainerId {
        &self.container_id
    }

    fn state_root(&self) -> PathBuf {
        self.root.join(STATE_DIRECTORY_NAME)
    }

    fn executor_parent(&self) -> PathBuf {
        self.root.join(EXECUTOR_DIRECTORY_NAME)
    }
}

/// Bound native Linux SDK service owning one exact A3S Box runtime process.
pub struct NativeLinuxService {
    config: NativeLinuxServiceConfig,
    // Drop the path guard while the listener still pins the original socket
    // inode, preventing a replacement path from matching through inode reuse.
    socket: OwnedSocketPath,
    listener: UnixListener,
    service: Arc<HostRuntimeService>,
    driver: Arc<NativeLinuxDriver>,
    effective_uid: u32,
}

impl NativeLinuxService {
    /// Prepare private state, open the native driver, and bind the SDK socket.
    ///
    /// The endpoint appears only after the driver and durable state store are
    /// ready. The inherited descriptors are attached only to the configured
    /// container ID and cannot be reused by another create request.
    pub async fn bind(
        config: NativeLinuxServiceConfig,
        descriptors: NativeControlDescriptors,
    ) -> Result<Self> {
        prepare_private_directory(&config.root, "native service root").await?;
        prepare_private_directory(&config.state_root(), "native service state root").await?;
        prepare_private_directory(&config.executor_parent(), "native service executor parent")
            .await?;

        let driver = Arc::new(
            NativeLinuxDriver::open_experimental(config.executor_parent(), &config.init_executable)
                .await?,
        );
        let runtime_driver: Arc<dyn RuntimeDriver> = driver.clone();
        let service = match HostRuntimeService::open_with_native_control_descriptors(
            config.state_root(),
            runtime_driver,
            config.container_id.clone(),
            descriptors,
        )
        .await
        {
            Ok(service) => Arc::new(service),
            Err(error) => {
                let _ = driver.shutdown().await;
                return Err(error);
            }
        };
        let (listener, socket) = match bind_private_socket(&config.socket_path()).await {
            Ok(bound) => bound,
            Err(error) => {
                let _ = driver.shutdown().await;
                return Err(error);
            }
        };

        // SAFETY: geteuid has no preconditions or failure result.
        let effective_uid = unsafe { libc::geteuid() };
        Ok(Self {
            config,
            socket,
            listener,
            service,
            driver,
            effective_uid,
        })
    }

    /// Bound SDK endpoint, available after [`Self::bind`] returns.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        self.socket.path()
    }

    /// Serve authenticated same-UID clients until the supplied shutdown future
    /// resolves, then stop all driver-owned processes and transient state.
    pub async fn serve_until<F>(self, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        let serve_result = self.serve_connections(shutdown).await;
        let cleanup_result = self.driver.shutdown().await;
        combine_service_and_cleanup(serve_result, cleanup_result)
    }

    async fn serve_connections<F>(&self, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        let socket_path = self.config.socket_path();
        serve_authenticated_connections(
            &self.listener,
            &socket_path,
            self.service.clone(),
            self.effective_uid,
            shutdown,
        )
        .await
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
                            "serve-native-service-client",
                            format!("native SDK client task failed: {error}"),
                        ));
                    }
                    None => {}
                }
            }
            accepted = listener.accept(),
                if connections.len() < MAX_CLIENT_CONNECTIONS => {
                let (stream, _) = accepted.map_err(|error| {
                    service_error(
                        ErrorCode::Unavailable,
                        "accept-native-service-client",
                        format!(
                            "failed to accept native SDK client on {}: {error}",
                            socket_path.display()
                        ),
                    )
                })?;
                verify_peer(&stream, effective_uid)?;
                connections.spawn(serve_transport_connection(service.clone(), stream));
            }
        }
    }
}

fn verify_peer(stream: &UnixStream, effective_uid: u32) -> Result<()> {
    let credentials = stream.peer_cred().map_err(|error| {
        service_error(
            ErrorCode::PermissionDenied,
            "authenticate-native-service-client",
            format!("failed to inspect native SDK peer credentials: {error}"),
        )
    })?;
    if credentials.uid() == effective_uid {
        Ok(())
    } else {
        Err(service_error(
            ErrorCode::PermissionDenied,
            "authenticate-native-service-client",
            format!(
                "native SDK peer UID {} does not match service UID {}",
                credentials.uid(),
                effective_uid
            ),
        ))
    }
}

fn validate_absolute_normalized_path(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(service_error(
            ErrorCode::InvalidArgument,
            "configure-native-service",
            format!(
                "{label} must be an absolute normalized path: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

async fn prepare_private_directory(path: &Path, label: &str) -> Result<()> {
    validate_absolute_normalized_path(path, label)?;
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = tokio::fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(path).await.map_err(|error| {
                service_error(
                    ErrorCode::PermissionDenied,
                    "prepare-native-service-directory",
                    format!("failed to create {label} {}: {error}", path.display()),
                )
            })?;
        }
        Err(error) => {
            return Err(service_error(
                ErrorCode::PermissionDenied,
                "prepare-native-service-directory",
                format!("failed to inspect {label} {}: {error}", path.display()),
            ));
        }
    }
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        service_error(
            ErrorCode::PermissionDenied,
            "prepare-native-service-directory",
            format!("failed to re-inspect {label} {}: {error}", path.display()),
        )
    })?;
    // SAFETY: geteuid has no preconditions or failure result.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(service_error(
            ErrorCode::PermissionDenied,
            "prepare-native-service-directory",
            format!(
                "{label} {} must be a real directory owned by UID {effective_uid} with mode 0700",
                path.display()
            ),
        ));
    }
    let canonical = tokio::fs::canonicalize(path).await.map_err(|error| {
        service_error(
            ErrorCode::PermissionDenied,
            "prepare-native-service-directory",
            format!("failed to canonicalize {label} {}: {error}", path.display()),
        )
    })?;
    if canonical != path {
        return Err(service_error(
            ErrorCode::PermissionDenied,
            "prepare-native-service-directory",
            format!(
                "{label} resolves through an alias: {} -> {}",
                path.display(),
                canonical.display()
            ),
        ));
    }
    Ok(())
}

async fn bind_private_socket(path: &Path) -> Result<(UnixListener, OwnedSocketPath)> {
    validate_absolute_normalized_path(path, "native service socket")?;
    match tokio::fs::symlink_metadata(path).await {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(service_error(
                ErrorCode::PermissionDenied,
                "bind-native-service",
                format!(
                    "failed to inspect native service socket {}: {error}",
                    path.display()
                ),
            ));
        }
        Ok(_) => {
            return Err(service_error(
                ErrorCode::Conflict,
                "bind-native-service",
                format!("native service socket already exists: {}", path.display()),
            ));
        }
    }
    let listener = UnixListener::bind(path).map_err(|error| {
        service_error(
            ErrorCode::Unavailable,
            "bind-native-service",
            format!(
                "failed to bind native service socket {}: {error}",
                path.display()
            ),
        )
    })?;
    let initial_metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        service_error(
            ErrorCode::PermissionDenied,
            "bind-native-service",
            format!(
                "failed to capture native service socket {}: {error}",
                path.display()
            ),
        )
    })?;
    let socket = OwnedSocketPath {
        path: path.to_path_buf(),
        device: initial_metadata.dev(),
        inode: initial_metadata.ino(),
    };
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .await
        .map_err(|error| {
            service_error(
                ErrorCode::PermissionDenied,
                "bind-native-service",
                format!(
                    "failed to protect native service socket {}: {error}",
                    path.display()
                ),
            )
        })?;
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        service_error(
            ErrorCode::PermissionDenied,
            "bind-native-service",
            format!(
                "failed to verify native service socket {}: {error}",
                path.display()
            ),
        )
    })?;
    // SAFETY: geteuid has no preconditions or failure result.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_socket()
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.dev() != socket.device
        || metadata.ino() != socket.inode
    {
        return Err(service_error(
            ErrorCode::PermissionDenied,
            "bind-native-service",
            format!(
                "native service socket {} must be owned by UID {effective_uid} with mode 0600",
                path.display()
            ),
        ));
    }
    Ok((listener, socket))
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

fn combine_service_and_cleanup(serve: Result<()>, cleanup: Result<()>) -> Result<()> {
    match (serve, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(mut primary), Err(cleanup)) => {
            primary.message = format!(
                "{}; native driver shutdown also failed: {}",
                primary.message, cleanup.message
            );
            primary.retryable |= cleanup.retryable;
            Err(primary)
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

    #[test]
    fn config_rejects_relative_and_ambiguous_paths() {
        let id = ContainerId::new("service-test").expect("container ID");
        assert!(NativeLinuxServiceConfig::new("relative", "/bin/true", id.clone()).is_err());
        assert!(NativeLinuxServiceConfig::new("/tmp/a/../b", "/bin/true", id.clone()).is_err());
        assert!(NativeLinuxServiceConfig::new("/tmp/service", "relative", id).is_err());
    }

    #[tokio::test]
    async fn private_layout_and_socket_are_exact_and_cleanup_is_inode_scoped() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("service");
        prepare_private_directory(&root, "test root")
            .await
            .expect("private root");
        let socket_path = root.join(SERVICE_SOCKET_NAME);
        let (listener, socket) = bind_private_socket(&socket_path)
            .await
            .expect("private socket");
        let metadata = std::fs::symlink_metadata(&socket_path).expect("socket metadata");
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        std::fs::remove_file(&socket_path).expect("unlink original socket");
        let replacement =
            std::os::unix::net::UnixListener::bind(&socket_path).expect("bind replacement socket");
        drop(socket);
        assert!(socket_path.exists());
        drop(listener);
        drop(replacement);
        std::fs::remove_file(&socket_path).expect("unlink replacement socket");

        let (listener, socket) = bind_private_socket(&socket_path)
            .await
            .expect("bind another owned socket");
        drop(socket);
        assert!(!socket_path.exists());
        drop(listener);
    }

    #[tokio::test]
    async fn service_negotiates_multiple_live_sdk_clients() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let socket_path = temporary.path().join(SERVICE_SOCKET_NAME);
        let (listener, socket) = bind_private_socket(&socket_path)
            .await
            .expect("private socket");
        let endpoint =
            a3s_oci_sdk::LocalIpcEndpoint::unix_socket(&socket_path).expect("local SDK endpoint");
        let service: Arc<dyn OciRuntimeService> = Arc::new(UnsupportedService);
        // SAFETY: geteuid has no preconditions or failure result.
        let effective_uid = unsafe { libc::geteuid() };
        let server_socket_path = socket_path.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            serve_authenticated_connections(
                &listener,
                &server_socket_path,
                service,
                effective_uid,
                async move {
                    let _ = shutdown_rx.await;
                },
            )
            .await
        });

        let first = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            a3s_oci_sdk::RuntimeClient::connect(&endpoint),
        )
        .await
        .expect("first SDK client negotiation timed out")
        .expect("first SDK client");
        let second = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            a3s_oci_sdk::RuntimeClient::connect(&endpoint),
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
        drop(socket);
    }

    #[tokio::test]
    async fn private_layout_rejects_permissive_existing_directory() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("service");
        std::fs::create_dir(&root).expect("service root");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
            .expect("permissive mode");
        let error = prepare_private_directory(&root, "test root")
            .await
            .expect_err("permissive root must fail");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
    }
}
