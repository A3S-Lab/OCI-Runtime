use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use a3s_oci_sdk::{ContainerId, Result};

use crate::unix_service::{
    combine_service_and_cleanup, prepare_private_directory, validate_absolute_normalized_path,
    validate_unix_socket_path, UnixServiceEndpoint, SERVICE_SOCKET_NAME,
};
use crate::{
    HostRuntimeService, NativeControlDescriptors, NativeLinuxDriver, RootlessDevicePolicyBootstrap,
    RuntimeDriver,
};

const STATE_DIRECTORY_NAME: &str = "state";
const EXECUTOR_DIRECTORY_NAME: &str = "executor";

/// Filesystem and identity contract for one native Linux runtime owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeLinuxServiceConfig {
    root: PathBuf,
    init_executable: PathBuf,
    container_id: ContainerId,
    delegated_cgroup_root: Option<PathBuf>,
}

/// Filesystem contract for one long-lived, multi-container native Linux owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeLinuxHostServiceConfig {
    root: PathBuf,
    init_executable: PathBuf,
    delegated_cgroup_root: Option<PathBuf>,
}

impl NativeLinuxHostServiceConfig {
    /// Bind one host service to a private absolute root.
    pub fn new(root: impl Into<PathBuf>, init_executable: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        validate_absolute_normalized_path(&root, "native host service root")?;
        validate_unix_socket_path(
            &root.join(SERVICE_SOCKET_NAME),
            "native Host Service endpoint",
        )?;
        let init_executable = init_executable.into();
        validate_absolute_normalized_path(&init_executable, "native init executable")?;
        Ok(Self {
            root,
            init_executable,
            delegated_cgroup_root: None,
        })
    }

    /// Supply the explicit user-owned cgroup root required by rootless
    /// device isolation.
    pub fn with_delegated_cgroup_root(mut self, root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        validate_absolute_normalized_path(&root, "native delegated cgroup root")?;
        self.delegated_cgroup_root = Some(root);
        Ok(self)
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

    fn state_root(&self) -> PathBuf {
        self.root.join(STATE_DIRECTORY_NAME)
    }

    fn executor_parent(&self) -> PathBuf {
        self.root.join(EXECUTOR_DIRECTORY_NAME)
    }
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
        validate_unix_socket_path(&root.join(SERVICE_SOCKET_NAME), "native service endpoint")?;
        let init_executable = init_executable.into();
        validate_absolute_normalized_path(&init_executable, "native init executable")?;
        Ok(Self {
            root,
            init_executable,
            container_id,
            delegated_cgroup_root: None,
        })
    }

    /// Supply the explicit user-owned cgroup root required by rootless
    /// device isolation.
    pub fn with_delegated_cgroup_root(mut self, root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        validate_absolute_normalized_path(&root, "native delegated cgroup root")?;
        self.delegated_cgroup_root = Some(root);
        Ok(self)
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
    endpoint: UnixServiceEndpoint,
    service: Arc<HostRuntimeService>,
    driver: Arc<NativeLinuxDriver>,
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
        Self::bind_inner(config, descriptors, None).await
    }

    /// Prepare one native Linux service after a privileged rootless device
    /// policy bootstrap has been completed by the CLI launcher.
    pub async fn bind_with_rootless_device_policy(
        config: NativeLinuxServiceConfig,
        descriptors: NativeControlDescriptors,
        bootstrap: Option<RootlessDevicePolicyBootstrap>,
    ) -> Result<Self> {
        Self::bind_inner(config, descriptors, bootstrap).await
    }

    async fn bind_inner(
        config: NativeLinuxServiceConfig,
        descriptors: NativeControlDescriptors,
        bootstrap: Option<RootlessDevicePolicyBootstrap>,
    ) -> Result<Self> {
        prepare_private_directory(&config.root, "native service root").await?;
        prepare_private_directory(&config.state_root(), "native service state root").await?;
        prepare_private_directory(&config.executor_parent(), "native service executor parent")
            .await?;

        let driver = Arc::new(match bootstrap {
            Some(bootstrap) => {
                NativeLinuxDriver::open_experimental_with_rootless_device_policy(
                    config.executor_parent(),
                    &config.init_executable,
                    bootstrap,
                )
                .await?
            }
            None => match config.delegated_cgroup_root.as_deref() {
                Some(root) => {
                    NativeLinuxDriver::open_experimental_with_rootless_cgroup_delegation(
                        config.executor_parent(),
                        &config.init_executable,
                        root,
                    )
                    .await?
                }
                None => {
                    NativeLinuxDriver::open_experimental(
                        config.executor_parent(),
                        &config.init_executable,
                    )
                    .await?
                }
            },
        });
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
        let endpoint = match UnixServiceEndpoint::bind(&config.socket_path()).await {
            Ok(endpoint) => endpoint,
            Err(error) => {
                let _ = driver.shutdown().await;
                return Err(error);
            }
        };

        Ok(Self {
            endpoint,
            service,
            driver,
        })
    }

    /// Bound SDK endpoint, available after [`Self::bind`] returns.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        self.endpoint.path()
    }

    /// Serve authenticated same-UID clients until the supplied shutdown future
    /// resolves, then stop all driver-owned processes and transient state.
    pub async fn serve_until<F>(self, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        let serve_result = self
            .endpoint
            .serve_until(self.service.clone(), shutdown)
            .await;
        let cleanup_result = self.driver.shutdown().await;
        combine_service_and_cleanup(serve_result, cleanup_result, "native driver")
    }
}

/// Bound native Linux SDK service owning multiple independently fenced containers.
///
/// Unlike [`NativeLinuxService`], this owner carries no process-local A3S Box
/// descriptors and therefore accepts normal SDK create requests for any valid
/// container ID. Exact driver selection and generation routing remain durable
/// in [`HostRuntimeService`].
pub struct NativeLinuxHostService {
    endpoint: UnixServiceEndpoint,
    service: Arc<HostRuntimeService>,
    driver: Arc<NativeLinuxDriver>,
}

impl NativeLinuxHostService {
    /// Open the native driver and durable host state before publishing the socket.
    pub async fn bind(config: NativeLinuxHostServiceConfig) -> Result<Self> {
        prepare_private_directory(&config.root, "native host service root").await?;
        prepare_private_directory(&config.state_root(), "native host service state root").await?;
        prepare_private_directory(
            &config.executor_parent(),
            "native host service executor parent",
        )
        .await?;

        let driver = Arc::new(match config.delegated_cgroup_root.as_deref() {
            Some(root) => {
                NativeLinuxDriver::open_experimental_with_rootless_cgroup_delegation(
                    config.executor_parent(),
                    &config.init_executable,
                    root,
                )
                .await?
            }
            None => {
                NativeLinuxDriver::open_experimental(
                    config.executor_parent(),
                    &config.init_executable,
                )
                .await?
            }
        });
        let runtime_driver: Arc<dyn RuntimeDriver> = driver.clone();
        let service = match HostRuntimeService::open(config.state_root(), runtime_driver).await {
            Ok(service) => Arc::new(service),
            Err(error) => {
                let _ = driver.shutdown().await;
                return Err(error);
            }
        };
        let endpoint = match UnixServiceEndpoint::bind(&config.socket_path()).await {
            Ok(endpoint) => endpoint,
            Err(error) => {
                let _ = driver.shutdown().await;
                return Err(error);
            }
        };

        Ok(Self {
            endpoint,
            service,
            driver,
        })
    }

    /// Bound SDK endpoint, available after [`Self::bind`] returns.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        self.endpoint.path()
    }

    /// Serve authenticated same-UID clients until shutdown, then reap the driver.
    pub async fn serve_until<F>(self, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        let serve_result = self
            .endpoint
            .serve_until(self.service.clone(), shutdown)
            .await;
        let cleanup_result = self.driver.shutdown().await;
        combine_service_and_cleanup(serve_result, cleanup_result, "native driver")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_rejects_relative_and_ambiguous_paths() {
        let id = ContainerId::new("service-test").expect("container ID");
        assert!(NativeLinuxServiceConfig::new("relative", "/bin/true", id.clone()).is_err());
        assert!(NativeLinuxServiceConfig::new("/tmp/a/../b", "/bin/true", id.clone()).is_err());
        assert!(NativeLinuxServiceConfig::new("/tmp/service", "relative", id).is_err());

        assert!(NativeLinuxHostServiceConfig::new("relative", "/bin/true").is_err());
        assert!(NativeLinuxHostServiceConfig::new("/tmp/a/../b", "/bin/true").is_err());
        assert!(NativeLinuxHostServiceConfig::new("/tmp/service", "relative").is_err());
    }

    #[test]
    fn host_config_derives_one_private_durable_layout() {
        let config = NativeLinuxHostServiceConfig::new("/tmp/a3s-oci-host", "/bin/true")
            .expect("valid native host config");

        assert_eq!(config.root(), Path::new("/tmp/a3s-oci-host"));
        assert_eq!(
            config.socket_path(),
            Path::new("/tmp/a3s-oci-host/runtime.sock")
        );
        assert_eq!(config.state_root(), Path::new("/tmp/a3s-oci-host/state"));
        assert_eq!(
            config.executor_parent(),
            Path::new("/tmp/a3s-oci-host/executor")
        );
    }
}
