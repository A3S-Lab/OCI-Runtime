use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use a3s_oci_sdk::{Error, ErrorCode, Result};

use crate::unix_service::{
    combine_service_and_cleanup, prepare_private_directory, validate_absolute_normalized_path,
    UnixServiceEndpoint, SERVICE_SOCKET_NAME,
};
use crate::{HostRuntimeService, HvfRuntimeDriver, HvfRuntimeDriverConfig, RuntimeDriver};

const STATE_DIRECTORY_NAME: &str = "state";
const DRIVER_RUNTIME_DIRECTORY_NAME: &str = "runtime";

/// Filesystem and immutable-asset contract for one Apple Silicon HVF owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosHvfHostServiceConfig {
    root: PathBuf,
    shim: PathBuf,
    system_image_manifest: PathBuf,
}

impl MacosHvfHostServiceConfig {
    /// Configure one same-UID SDK owner around the launch-ready HVF driver.
    pub fn new(
        root: impl Into<PathBuf>,
        shim: impl Into<PathBuf>,
        system_image_manifest: impl Into<PathBuf>,
    ) -> Result<Self> {
        let root = root.into();
        validate_absolute_normalized_path(&root, "macOS HVF host service root")?;
        let shim = shim.into();
        validate_absolute_normalized_path(&shim, "macOS HVF libkrun shim")?;
        let system_image_manifest = system_image_manifest.into();
        validate_absolute_normalized_path(
            &system_image_manifest,
            "macOS HVF system-image manifest",
        )?;
        if system_image_manifest.starts_with(&root) || root.starts_with(&system_image_manifest) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "immutable macOS HVF system-image manifest must be outside writable host service root {}: {}",
                    root.display(),
                    system_image_manifest.display()
                ),
            )
            .for_operation("configure-macos-hvf-host-service"));
        }
        Ok(Self {
            root,
            shim,
            system_image_manifest,
        })
    }

    /// Private owner root containing only the endpoint and writable state.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Unix socket consumed by [`a3s_oci_sdk::RuntimeClient::connect`].
    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.root.join(SERVICE_SOCKET_NAME)
    }

    /// Entitlement-signed isolated libkrun shim.
    #[must_use]
    pub fn shim(&self) -> &Path {
        &self.shim
    }

    /// Immutable manifest binding the system image and runtime provenance.
    #[must_use]
    pub fn system_image_manifest(&self) -> &Path {
        &self.system_image_manifest
    }

    fn state_root(&self) -> PathBuf {
        self.root.join(STATE_DIRECTORY_NAME)
    }

    fn driver_runtime_root(&self) -> PathBuf {
        self.root.join(DRIVER_RUNTIME_DIRECTORY_NAME)
    }

    fn driver_config(&self) -> Result<HvfRuntimeDriverConfig> {
        HvfRuntimeDriverConfig::new(
            self.shim.clone(),
            self.driver_runtime_root(),
            self.system_image_manifest.clone(),
        )
    }
}

/// Same-UID SDK service owning one dedicated HVF VM per exact generation.
pub struct MacosHvfHostService {
    endpoint: UnixServiceEndpoint,
    service: Arc<HostRuntimeService>,
    driver: Arc<HvfRuntimeDriver>,
}

impl MacosHvfHostService {
    /// Open the HVF driver and durable state before publishing `runtime.sock`.
    pub async fn bind(config: MacosHvfHostServiceConfig) -> Result<Self> {
        Self::prepare_layout(&config).await?;
        let driver = Arc::new(HvfRuntimeDriver::open(config.driver_config()?).await?);
        Self::bind_driver(config, driver).await
    }

    async fn prepare_layout(config: &MacosHvfHostServiceConfig) -> Result<()> {
        prepare_private_directory(&config.root, "macOS HVF host service root").await?;
        prepare_private_directory(&config.state_root(), "macOS HVF durable state root").await?;
        prepare_private_directory(
            &config.driver_runtime_root(),
            "macOS HVF driver runtime root",
        )
        .await
    }

    async fn bind_driver(
        config: MacosHvfHostServiceConfig,
        driver: Arc<HvfRuntimeDriver>,
    ) -> Result<Self> {
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

    /// Bound SDK endpoint, available only after driver recovery completes.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        self.endpoint.path()
    }

    /// Serve concurrent authenticated clients until shutdown, then reap each VM once.
    pub async fn serve_until<F>(self, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        let serve_result = self
            .endpoint
            .serve_until(self.service.clone(), shutdown)
            .await;
        let cleanup_result = self.driver.shutdown().await;
        combine_service_and_cleanup(serve_result, cleanup_result, "HVF driver")
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    use a3s_oci_core::DriverKind;
    use a3s_oci_sdk::{
        LocalIpcEndpoint, RuntimeClient, RUNTIME_BUNDLE_HANDOFF_EXTENSION,
        RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION,
    };

    use super::*;

    fn canonical_temporary_root(temporary: &tempfile::TempDir) -> PathBuf {
        std::fs::canonicalize(temporary.path()).expect("canonical temporary root")
    }

    fn config(temporary: &tempfile::TempDir) -> MacosHvfHostServiceConfig {
        let temporary = canonical_temporary_root(temporary);
        let assets = temporary.join("assets");
        std::fs::create_dir(&assets).expect("asset directory");
        std::fs::set_permissions(&assets, std::fs::Permissions::from_mode(0o700))
            .expect("protect asset directory");
        let shim = assets.join("shim");
        let manifest = assets.join("system-image.json");
        std::fs::write(&shim, b"test shim").expect("test shim");
        std::fs::write(&manifest, b"{}\n").expect("test manifest");
        MacosHvfHostServiceConfig::new(temporary.join("owner"), shim, manifest)
            .expect("test host service config")
    }

    #[test]
    fn config_rejects_relative_ambiguous_and_overlapping_paths() {
        assert!(
            MacosHvfHostServiceConfig::new("relative", "/tmp/shim", "/tmp/system-image.json")
                .is_err()
        );
        assert!(MacosHvfHostServiceConfig::new(
            "/tmp/a/../owner",
            "/tmp/shim",
            "/tmp/system-image.json"
        )
        .is_err());
        assert!(
            MacosHvfHostServiceConfig::new("/tmp/owner", "relative", "/tmp/system-image.json")
                .is_err()
        );
        assert!(MacosHvfHostServiceConfig::new(
            "/tmp/owner",
            "/tmp/shim",
            "/tmp/owner/system-image.json"
        )
        .is_err());
    }

    #[test]
    fn config_separates_durable_state_from_driver_runtime() {
        let config = MacosHvfHostServiceConfig::new(
            "/tmp/a3s-oci-hvf-owner",
            "/tmp/a3s-oci-hvf-shim",
            "/tmp/a3s-oci-hvf-system-image.json",
        )
        .expect("valid macOS HVF host config");

        assert_eq!(config.root(), Path::new("/tmp/a3s-oci-hvf-owner"));
        assert_eq!(
            config.socket_path(),
            Path::new("/tmp/a3s-oci-hvf-owner/runtime.sock")
        );
        assert_eq!(
            config.state_root(),
            Path::new("/tmp/a3s-oci-hvf-owner/state")
        );
        assert_eq!(
            config.driver_runtime_root(),
            Path::new("/tmp/a3s-oci-hvf-owner/runtime")
        );
        assert_ne!(config.state_root(), config.driver_runtime_root());
    }

    #[tokio::test]
    async fn public_socket_advertises_hvf_and_graceful_shutdown_reaps_once() {
        let temporary = tempfile::tempdir().expect("temporary host service fixture");
        let config = config(&temporary);
        MacosHvfHostService::prepare_layout(&config)
            .await
            .expect("private host layout");
        let fixture = crate::hvf_driver::tests::shutdown_fixture(
            config.driver_runtime_root(),
            config.system_image_manifest.clone(),
        )
        .await;
        let service = MacosHvfHostService::bind_driver(config.clone(), fixture.driver.clone())
            .await
            .expect("bind test HVF host service");
        let socket_path = service.socket_path().to_path_buf();
        let metadata = std::fs::symlink_metadata(&socket_path).expect("SDK socket metadata");
        // SAFETY: geteuid has no preconditions or failure result.
        let effective_uid = unsafe { libc::geteuid() };
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.uid(), effective_uid);
        assert_eq!(metadata.mode() & 0o777, 0o600);
        let endpoint = LocalIpcEndpoint::unix_socket(&socket_path).expect("SDK endpoint");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            service
                .serve_until(async move {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let client = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            RuntimeClient::connect(&endpoint),
        )
        .await
        .expect("SDK connection timed out")
        .expect("SDK client");
        let info = client.features().await.expect("public SDK features");
        assert_eq!(info.drivers.drivers.len(), 1);
        assert_eq!(info.drivers.drivers[0].driver, DriverKind::LibkrunHvf);
        for operation in crate::agent_driver::AGENT_DRIVER_OPERATIONS {
            assert!(
                info.operations.contains(&operation),
                "public HVF service did not advertise {operation:?}"
            );
        }
        assert!(info
            .operations
            .contains(&a3s_oci_sdk::RuntimeOperation::Features));
        assert!(info
            .operations
            .contains(&a3s_oci_sdk::RuntimeOperation::List));
        assert!(info
            .operations
            .contains(&a3s_oci_sdk::RuntimeOperation::Events));
        assert_eq!(info.operations.len(), 23);
        assert!(info.attachments.supports_extension(
            RUNTIME_BUNDLE_HANDOFF_EXTENSION,
            RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION,
        ));

        shutdown_tx.send(()).expect("request graceful shutdown");
        server
            .await
            .expect("service task")
            .expect("clean HVF host shutdown");
        assert_eq!(
            fixture
                .shutdown_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert!(!socket_path.exists());
    }
}
