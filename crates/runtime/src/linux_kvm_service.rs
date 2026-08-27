use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use a3s_oci_sdk::{async_trait, Error, ErrorCode, Result};

use crate::unix_service::{
    prepare_private_directory, validate_absolute_normalized_path, validate_unix_socket_path,
    SERVICE_SOCKET_NAME,
};
use crate::utility_vm_host_service::{UtilityVmHostDriver, UtilityVmHostService};
use crate::{KvmRuntimeDriver, KvmRuntimeDriverConfig};

const STATE_DIRECTORY_NAME: &str = "state";
const DRIVER_RUNTIME_DIRECTORY_NAME: &str = "runtime";

/// Exact paths for the qualification-only Linux KVM recovery owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxKvmRecoveryHostServiceConfig {
    root: PathBuf,
    shim: PathBuf,
    system_image_manifest: PathBuf,
}

impl LinuxKvmRecoveryHostServiceConfig {
    /// Configure a private SDK owner without promoting the public KVM driver.
    pub fn new(
        root: impl Into<PathBuf>,
        shim: impl Into<PathBuf>,
        system_image_manifest: impl Into<PathBuf>,
    ) -> Result<Self> {
        Self::new_for_qualification(
            root,
            shim,
            system_image_manifest,
            "Linux KVM recovery Host Service",
            "configure-linux-kvm-recovery-host-service",
        )
    }

    fn new_for_qualification(
        root: impl Into<PathBuf>,
        shim: impl Into<PathBuf>,
        system_image_manifest: impl Into<PathBuf>,
        service_label: &str,
        operation: &'static str,
    ) -> Result<Self> {
        let root = root.into();
        validate_absolute_normalized_path(&root, &format!("{service_label} root"))?;
        validate_unix_socket_path(
            &root.join(SERVICE_SOCKET_NAME),
            &format!("{service_label} endpoint"),
        )?;
        let shim = shim.into();
        validate_absolute_normalized_path(&shim, "Linux KVM libkrun shim")?;
        let system_image_manifest = system_image_manifest.into();
        validate_absolute_normalized_path(
            &system_image_manifest,
            "Linux KVM system-image manifest",
        )?;
        if system_image_manifest.starts_with(&root) || root.starts_with(&system_image_manifest) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "immutable Linux KVM system-image manifest must be outside writable Host \
                     Service root {}: {}",
                    root.display(),
                    system_image_manifest.display()
                ),
            )
            .for_operation(operation));
        }
        Ok(Self {
            root,
            shim,
            system_image_manifest,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.root.join(SERVICE_SOCKET_NAME)
    }

    #[must_use]
    pub fn shim(&self) -> &Path {
        &self.shim
    }

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

    fn driver_config(&self) -> Result<KvmRuntimeDriverConfig> {
        KvmRuntimeDriverConfig::new(
            self.shim.clone(),
            self.driver_runtime_root(),
            self.system_image_manifest.clone(),
        )
    }
}

/// Exact paths for the qualification-only bounded Linux KVM soak owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxKvmSoakHostServiceConfig {
    inner: LinuxKvmRecoveryHostServiceConfig,
}

impl LinuxKvmSoakHostServiceConfig {
    pub fn new(
        root: impl Into<PathBuf>,
        shim: impl Into<PathBuf>,
        system_image_manifest: impl Into<PathBuf>,
    ) -> Result<Self> {
        LinuxKvmRecoveryHostServiceConfig::new_for_qualification(
            root,
            shim,
            system_image_manifest,
            "Linux KVM soak Host Service",
            "configure-linux-kvm-soak-host-service",
        )
        .map(|inner| Self { inner })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        self.inner.root()
    }

    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.inner.socket_path()
    }

    #[must_use]
    pub fn shim(&self) -> &Path {
        self.inner.shim()
    }

    #[must_use]
    pub fn system_image_manifest(&self) -> &Path {
        self.inner.system_image_manifest()
    }
}

/// Qualification-only same-UID SDK owner for one KVM VM per generation.
pub struct LinuxKvmRecoveryHostService {
    inner: UtilityVmHostService<KvmRuntimeDriver>,
}

/// Qualification-only same-UID SDK owner for bounded KVM soak waves.
pub struct LinuxKvmSoakHostService {
    inner: UtilityVmHostService<KvmRuntimeDriver>,
}

impl LinuxKvmSoakHostService {
    pub async fn bind(config: LinuxKvmSoakHostServiceConfig) -> Result<Self> {
        LinuxKvmRecoveryHostService::prepare_layout(&config.inner).await?;
        let driver = Arc::new(
            KvmRuntimeDriver::open_soak_qualification(config.inner.driver_config()?).await?,
        );
        Self::bind_driver(config, driver).await
    }

    async fn bind_driver(
        config: LinuxKvmSoakHostServiceConfig,
        driver: Arc<KvmRuntimeDriver>,
    ) -> Result<Self> {
        let inner =
            UtilityVmHostService::bind(&config.inner.root, &config.inner.state_root(), driver)
                .await?;
        Ok(Self { inner })
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        self.inner.socket_path()
    }

    pub async fn serve_until<F>(self, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        self.inner.serve_until(shutdown).await
    }
}

impl LinuxKvmRecoveryHostService {
    /// Bind only with the narrow owner-death/restart registration override.
    pub async fn bind(config: LinuxKvmRecoveryHostServiceConfig) -> Result<Self> {
        Self::prepare_layout(&config).await?;
        let driver =
            Arc::new(KvmRuntimeDriver::open_recovery_qualification(config.driver_config()?).await?);
        Self::bind_driver(config, driver).await
    }

    async fn prepare_layout(config: &LinuxKvmRecoveryHostServiceConfig) -> Result<()> {
        prepare_private_directory(&config.root, "Linux KVM qualification Host Service root")
            .await?;
        prepare_private_directory(
            &config.state_root(),
            "Linux KVM qualification durable state root",
        )
        .await?;
        prepare_private_directory(
            &config.driver_runtime_root(),
            "Linux KVM qualification driver runtime root",
        )
        .await
    }

    async fn bind_driver(
        config: LinuxKvmRecoveryHostServiceConfig,
        driver: Arc<KvmRuntimeDriver>,
    ) -> Result<Self> {
        let inner = UtilityVmHostService::bind(&config.root, &config.state_root(), driver).await?;
        Ok(Self { inner })
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        self.inner.socket_path()
    }

    pub async fn serve_until<F>(self, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        self.inner.serve_until(shutdown).await
    }
}

#[async_trait]
impl UtilityVmHostDriver for KvmRuntimeDriver {
    async fn shutdown_host_driver(&self) -> Result<()> {
        self.shutdown().await
    }

    fn host_driver_label(&self) -> &'static str {
        "KVM qualification driver"
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    use a3s_oci_core::{
        CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, IsolationClass,
    };
    use a3s_oci_sdk::{
        async_trait, LocalIpcEndpoint, RuntimeClient, RUNTIME_BUNDLE_HANDOFF_EXTENSION,
        RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION,
    };

    use super::*;
    use crate::utility_vm_driver::{
        LaunchedUtilityVm, UtilityVmFactory, UtilityVmLaunchRequest, UtilityVmRuntimeDriver,
    };

    struct NoLaunchFactory;

    #[async_trait]
    impl UtilityVmFactory for NoLaunchFactory {
        async fn launch(&self, _request: UtilityVmLaunchRequest<'_>) -> Result<LaunchedUtilityVm> {
            Err(Error::new(
                ErrorCode::Internal,
                "KVM Host Service contract fixture must not launch",
            ))
        }
    }

    fn canonical_temporary_root(temporary: &tempfile::TempDir) -> PathBuf {
        std::fs::canonicalize(temporary.path()).expect("canonical temporary root")
    }

    fn config(temporary: &tempfile::TempDir) -> LinuxKvmRecoveryHostServiceConfig {
        let temporary = canonical_temporary_root(temporary);
        let assets = temporary.join("assets");
        std::fs::create_dir(&assets).expect("asset directory");
        std::fs::set_permissions(&assets, std::fs::Permissions::from_mode(0o700))
            .expect("protect asset directory");
        let shim = assets.join("shim");
        let manifest = assets.join("system-image.json");
        std::fs::write(&shim, b"test shim").expect("test shim");
        std::fs::write(&manifest, b"{}\n").expect("test manifest");
        LinuxKvmRecoveryHostServiceConfig::new(temporary.join("owner"), shim, manifest)
            .expect("test Host Service config")
    }

    fn driver(
        config: &LinuxKvmRecoveryHostServiceConfig,
        qualification_scope: &str,
    ) -> Arc<KvmRuntimeDriver> {
        let runtime_root = config.driver_runtime_root();
        let capability = DriverCapability {
            driver: DriverKind::LibkrunKvm,
            status: CapabilityStatus::Available,
            readiness: DriverReadiness::Experimental,
            isolation_classes: vec![IsolationClass::DedicatedVm],
            reason: None,
            evidence: BTreeMap::from([
                ("opt_in".to_string(), "qualification-only".to_string()),
                (
                    "qualification_scope".to_string(),
                    qualification_scope.to_string(),
                ),
            ]),
        };
        let inner = UtilityVmRuntimeDriver::new(
            capability,
            a3s_oci_sdk::AttachmentCapabilities::base_v1(),
            "KVM qualification fixture",
            runtime_root.clone(),
            runtime_root.join("shares"),
            config.system_image_manifest.clone(),
            "fixture-manifest-sha256".to_string(),
            runtime_root.join("recovery"),
            Arc::new(NoLaunchFactory),
        );
        Arc::new(KvmRuntimeDriver::from_test_inner(inner))
    }

    async fn assert_qualification_scope(
        service: UtilityVmHostService<KvmRuntimeDriver>,
        expected_scope: &str,
    ) {
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
        let launchable = info
            .drivers
            .drivers
            .iter()
            .filter(|capability| capability.can_launch())
            .collect::<Vec<_>>();
        assert_eq!(launchable.len(), 1);
        let capability = launchable[0];
        assert_eq!(capability.driver, DriverKind::LibkrunKvm);
        assert_eq!(capability.readiness, DriverReadiness::Experimental);
        assert_eq!(
            capability
                .evidence
                .get("qualification_scope")
                .map(String::as_str),
            Some(expected_scope)
        );
        assert!(info.attachments.supports_extension(
            RUNTIME_BUNDLE_HANDOFF_EXTENSION,
            RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION,
        ));

        shutdown_tx.send(()).expect("request graceful shutdown");
        server
            .await
            .expect("service task")
            .expect("clean KVM qualification Host Service shutdown");
        assert!(!socket_path.exists());
    }

    #[test]
    fn config_rejects_relative_ambiguous_and_overlapping_paths() {
        assert!(LinuxKvmRecoveryHostServiceConfig::new(
            "relative",
            "/tmp/shim",
            "/tmp/system-image.json"
        )
        .is_err());
        assert!(LinuxKvmRecoveryHostServiceConfig::new(
            "/tmp/a/../owner",
            "/tmp/shim",
            "/tmp/system-image.json"
        )
        .is_err());
        assert!(LinuxKvmRecoveryHostServiceConfig::new(
            "/tmp/owner",
            "relative",
            "/tmp/system-image.json"
        )
        .is_err());
        assert!(LinuxKvmRecoveryHostServiceConfig::new(
            "/tmp/owner",
            "/tmp/shim",
            "/tmp/owner/system-image.json"
        )
        .is_err());
    }

    #[test]
    fn config_separates_durable_state_from_driver_runtime() {
        let config = LinuxKvmRecoveryHostServiceConfig::new(
            "/tmp/a3s-oci-kvm-owner",
            "/tmp/a3s-oci-kvm-shim",
            "/tmp/a3s-oci-kvm-system-image.json",
        )
        .expect("valid Linux KVM recovery config");

        assert_eq!(
            config.socket_path(),
            Path::new("/tmp/a3s-oci-kvm-owner/runtime.sock")
        );
        assert_eq!(
            config.state_root(),
            Path::new("/tmp/a3s-oci-kvm-owner/state")
        );
        assert_eq!(
            config.driver_runtime_root(),
            Path::new("/tmp/a3s-oci-kvm-owner/runtime")
        );
        assert_ne!(config.state_root(), config.driver_runtime_root());
    }

    #[tokio::test]
    async fn qualification_socket_advertises_only_the_explicit_kvm_route() {
        let temporary = tempfile::tempdir().expect("temporary Host Service fixture");
        let config = config(&temporary);
        LinuxKvmRecoveryHostService::prepare_layout(&config)
            .await
            .expect("private host layout");
        let service = LinuxKvmRecoveryHostService::bind_driver(
            config.clone(),
            driver(
                &config,
                crate::kvm_driver::LINUX_KVM_RECOVERY_QUALIFICATION_SCOPE,
            ),
        )
        .await
        .expect("bind test KVM recovery Host Service");
        assert_qualification_scope(
            service.inner,
            crate::kvm_driver::LINUX_KVM_RECOVERY_QUALIFICATION_SCOPE,
        )
        .await;
    }

    #[tokio::test]
    async fn soak_socket_advertises_only_the_bounded_soak_route() {
        let temporary = tempfile::tempdir().expect("temporary Host Service fixture");
        let recovery_config = config(&temporary);
        LinuxKvmRecoveryHostService::prepare_layout(&recovery_config)
            .await
            .expect("private host layout");
        let soak_config = LinuxKvmSoakHostServiceConfig {
            inner: recovery_config.clone(),
        };
        let service = LinuxKvmSoakHostService::bind_driver(
            soak_config,
            driver(
                &recovery_config,
                crate::kvm_driver::LINUX_KVM_SOAK_QUALIFICATION_SCOPE,
            ),
        )
        .await
        .expect("bind test KVM soak Host Service");
        assert_qualification_scope(
            service.inner,
            crate::kvm_driver::LINUX_KVM_SOAK_QUALIFICATION_SCOPE,
        )
        .await;
    }
}
