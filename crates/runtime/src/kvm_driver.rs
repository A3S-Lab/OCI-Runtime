use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use a3s_oci_agent_protocol::GuestAgentService;
use a3s_oci_core::{CapabilityStatus, DriverCapability, DriverReadiness, IsolationClass};
use a3s_oci_sdk::{async_trait, Error, ErrorCode, Result};

use crate::agent_driver::AgentDriverClient;
use crate::agent_session::{UtilityVmSession, VerifiedLinuxUtilityVmConnectOptions};
use crate::utility_vm_driver::layout::{
    validate_absolute_normalized_path, PreparedUtilityVmLayout, UtilityVmBootstrap,
};
use crate::utility_vm_driver::recovery::RecoveryStore;
use crate::utility_vm_driver::{
    delegate_utility_vm_runtime_driver, LaunchedUtilityVm, UtilityVmFactory,
    UtilityVmLaunchRequest, UtilityVmOwner, UtilityVmRuntimeDriver,
};

pub(crate) const LINUX_KVM_RECOVERY_QUALIFICATION_SCOPE: &str =
    "linux-kvm-owner-death-restart-only-v1";
pub(crate) const LINUX_KVM_SOAK_QUALIFICATION_SCOPE: &str = "linux-kvm-bounded-soak-only-v1";

/// Runtime-owned host paths for the Linux KVM driver candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvmRuntimeDriverConfig {
    shim: PathBuf,
    runtime_root: PathBuf,
    system_image_manifest: PathBuf,
}

impl KvmRuntimeDriverConfig {
    /// Configure the isolated shim, private writable runtime root, and exact
    /// immutable system-image manifest used by every dedicated KVM guest.
    pub fn new(
        shim: impl Into<PathBuf>,
        runtime_root: impl Into<PathBuf>,
        system_image_manifest: impl Into<PathBuf>,
    ) -> Result<Self> {
        let config = Self {
            shim: shim.into(),
            runtime_root: runtime_root.into(),
            system_image_manifest: system_image_manifest.into(),
        };
        validate_absolute_normalized_path(&config.shim, "KVM libkrun shim")?;
        validate_absolute_normalized_path(&config.runtime_root, "KVM runtime root")?;
        validate_absolute_normalized_path(
            &config.system_image_manifest,
            "KVM system-image manifest",
        )?;
        Ok(config)
    }

    /// Isolated libkrun shim executable.
    #[must_use]
    pub fn shim(&self) -> &Path {
        &self.shim
    }

    /// Same-UID private root for bootstrap, shares, consoles, and recovery evidence.
    #[must_use]
    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }

    /// Immutable, digest-bound Linux KVM system-image manifest.
    #[must_use]
    pub fn system_image_manifest(&self) -> &Path {
        &self.system_image_manifest
    }
}

/// Launch-capable KVM driver candidate owning one utility VM per exact generation.
///
/// Direct qualification may exercise the complete twenty-operation contract.
/// The reported capability deliberately remains `probe-only`, so a normal
/// [`crate::HostRuntimeService`] cannot register it before both advertised
/// architectures pass the retained real-host recovery and soak gates.
pub struct KvmRuntimeDriver {
    inner: UtilityVmRuntimeDriver,
}

impl fmt::Debug for KvmRuntimeDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("KvmRuntimeDriver")
            .field(&self.inner)
            .finish()
    }
}

impl KvmRuntimeDriver {
    /// Open the non-registerable KVM candidate around verified private paths.
    pub async fn open_candidate(config: KvmRuntimeDriverConfig) -> Result<Self> {
        Self::open(config, KvmRegistration::ProbeOnly).await
    }

    /// Open the candidate only for the real-host recovery qualification owner.
    pub(crate) async fn open_recovery_qualification(
        config: KvmRuntimeDriverConfig,
    ) -> Result<Self> {
        Self::open(
            config,
            KvmRegistration::Qualification(KvmQualification::OwnerDeathRestart),
        )
        .await
    }

    /// Open the candidate only for the bounded real-host soak owner.
    pub(crate) async fn open_soak_qualification(config: KvmRuntimeDriverConfig) -> Result<Self> {
        Self::open(
            config,
            KvmRegistration::Qualification(KvmQualification::BoundedSoak),
        )
        .await
    }

    async fn open(config: KvmRuntimeDriverConfig, registration: KvmRegistration) -> Result<Self> {
        let capability = crate::platform::kvm_driver_capability();
        if capability.status != CapabilityStatus::Available {
            return Err(Error::new(
                ErrorCode::Unavailable,
                capability
                    .reason
                    .clone()
                    .unwrap_or_else(|| "Linux KVM is unavailable".to_string()),
            )
            .for_operation("open-kvm-driver-candidate"));
        }
        let prepared = PreparedUtilityVmLayout::open(
            config.shim,
            config.runtime_root,
            config.system_image_manifest,
            UtilityVmBootstrap::PrivateEmptyRoot,
        )
        .await?;
        let bootstrap_root = prepared.bootstrap_root.clone();

        let capability = candidate_capability(
            capability,
            &prepared.system_image_manifest_sha256,
            registration,
        );

        let recovery = RecoveryStore::new(prepared.recovery_directory.clone());
        let factory: Arc<dyn UtilityVmFactory> = Arc::new(LiveKvmVmFactory {
            shim: prepared.shim,
            bootstrap_root,
            system_image_manifest: prepared.system_image_manifest.clone(),
            system_image_manifest_sha256: prepared.system_image_manifest_sha256.clone(),
            console_directory: prepared.console_directory,
            recovery,
        });
        Ok(Self {
            inner: UtilityVmRuntimeDriver::new(
                capability,
                a3s_oci_sdk::AttachmentCapabilities::base_v1(),
                "KVM",
                prepared.runtime_root,
                prepared.runtime_share_root,
                prepared.system_image_manifest,
                prepared.system_image_manifest_sha256,
                prepared.recovery_directory,
                factory,
            ),
        })
    }

    /// Close every live guest connection and reap each driver-owned VM once.
    pub async fn shutdown(&self) -> Result<()> {
        self.inner.shutdown().await
    }

    /// Number of exact generations still owning a live KVM utility VM.
    pub async fn active_session_count(&self) -> usize {
        self.inner.active_session_count().await
    }

    #[cfg(test)]
    pub(crate) fn from_test_inner(inner: UtilityVmRuntimeDriver) -> Self {
        Self { inner }
    }
}

fn candidate_capability(
    mut capability: DriverCapability,
    system_image_manifest_sha256: &str,
    registration: KvmRegistration,
) -> DriverCapability {
    capability.readiness = registration.readiness();
    capability.isolation_classes = vec![IsolationClass::DedicatedVm];
    capability.evidence.extend([
        (
            "execution_path".to_string(),
            "one-kvm-utility-vm-per-generation".to_string(),
        ),
        (
            "system_image_manifest_sha256".to_string(),
            system_image_manifest_sha256.to_string(),
        ),
        (
            "immutable_system_root".to_string(),
            "manifest-bound-read-only-virtio-blk".to_string(),
        ),
        (
            "runtime_share".to_string(),
            "same-uid-private-per-generation-virtiofs".to_string(),
        ),
        (
            "bundle_handoff".to_string(),
            "required-atomic-move-v1".to_string(),
        ),
        (
            "owner_death".to_string(),
            "pidfd-exact-owner-process-group-cleanup".to_string(),
        ),
        ("native_linux_fallback".to_string(), "disabled".to_string()),
        ("opt_in".to_string(), "qualification-only".to_string()),
    ]);
    if let Some(scope) = registration.qualification_scope() {
        capability
            .evidence
            .insert("qualification_scope".to_string(), scope.to_string());
    }
    capability
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KvmRegistration {
    ProbeOnly,
    Qualification(KvmQualification),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KvmQualification {
    OwnerDeathRestart,
    BoundedSoak,
}

impl KvmQualification {
    const fn scope(self) -> &'static str {
        match self {
            Self::OwnerDeathRestart => LINUX_KVM_RECOVERY_QUALIFICATION_SCOPE,
            Self::BoundedSoak => LINUX_KVM_SOAK_QUALIFICATION_SCOPE,
        }
    }
}

impl KvmRegistration {
    const fn readiness(self) -> DriverReadiness {
        match self {
            Self::ProbeOnly => DriverReadiness::ProbeOnly,
            Self::Qualification(_) => DriverReadiness::Experimental,
        }
    }

    const fn qualification_scope(self) -> Option<&'static str> {
        match self {
            Self::ProbeOnly => None,
            Self::Qualification(qualification) => Some(qualification.scope()),
        }
    }
}

delegate_utility_vm_runtime_driver!(KvmRuntimeDriver, inner);

struct LiveKvmVmFactory {
    shim: PathBuf,
    bootstrap_root: PathBuf,
    system_image_manifest: PathBuf,
    system_image_manifest_sha256: String,
    console_directory: PathBuf,
    recovery: RecoveryStore,
}

#[async_trait]
impl UtilityVmFactory for LiveKvmVmFactory {
    async fn launch(&self, request: UtilityVmLaunchRequest<'_>) -> Result<LaunchedUtilityVm> {
        let vm_attachment_manifest_sha256 =
            crate::utility_vm_driver::kvm_network::prepare(&request).await?;
        let UtilityVmLaunchRequest {
            target,
            runtime_share,
            attachment_contract,
            ..
        } = request;
        let generation = target.generation.ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "KVM driver launch requires an exact generation for container {}",
                    target.id
                ),
            )
            .for_operation("launch-kvm-utility-vm")
        })?;
        let console = self
            .console_directory
            .join(format!("{}-{}.log", target.id, generation.0));
        let recovery_report = self
            .recovery
            .path(target, attachment_contract.guest_session())?;
        let session = Arc::new(
            UtilityVmSession::connect_with_verified_runtime_share_and_vm_attachments(
                &self.shim,
                VerifiedLinuxUtilityVmConnectOptions {
                    rootfs: &self.bootstrap_root,
                    system_image_manifest: &self.system_image_manifest,
                    expected_system_image_manifest_sha256: &self.system_image_manifest_sha256,
                    runtime_share,
                    console: &console,
                    recovery_report: Some(&recovery_report),
                    vm_attachment_manifest_sha256: vm_attachment_manifest_sha256.as_deref(),
                },
            )
            .await
            .map_err(kvm_launch_error)?,
        );
        let service: Arc<dyn GuestAgentService> = Arc::new(session.client());
        Ok(LaunchedUtilityVm {
            client: AgentDriverClient::new(service, "KVM guest agent", "kvm"),
            owner: Arc::new(LiveKvmVmOwner { session }),
        })
    }
}

struct LiveKvmVmOwner {
    session: Arc<UtilityVmSession>,
}

#[async_trait]
impl UtilityVmOwner for LiveKvmVmOwner {
    async fn shutdown(&self) -> Result<()> {
        let report = self.session.shutdown().await;
        if report.session_is_success() {
            Ok(())
        } else {
            Err(kvm_report_error("shutdown-kvm-utility-vm", report))
        }
    }
}

fn kvm_launch_error(report: crate::AgentVmSmokeReport) -> Error {
    let retryable = !report.protocol_negotiated;
    kvm_report_error("launch-kvm-utility-vm", report).retryable(retryable)
}

fn kvm_report_error(operation: &'static str, report: crate::AgentVmSmokeReport) -> Error {
    let reason = report
        .reason
        .unwrap_or_else(|| "authenticated KVM utility VM did not satisfy its contract".to_string());
    Error::new(ErrorCode::Unavailable, reason).for_operation(operation)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    use a3s_oci_core::{DriverKind, DriverReadiness};

    use super::*;
    use crate::{HostRuntimeService, RuntimeDriver};

    struct NoLaunchFactory;

    #[async_trait]
    impl UtilityVmFactory for NoLaunchFactory {
        async fn launch(&self, _request: UtilityVmLaunchRequest<'_>) -> Result<LaunchedUtilityVm> {
            Err(Error::new(
                ErrorCode::Internal,
                "contract-only KVM driver must never launch",
            ))
        }
    }

    fn test_driver(root: &Path) -> KvmRuntimeDriver {
        let capability = candidate_capability(
            DriverCapability {
                driver: DriverKind::LibkrunKvm,
                status: CapabilityStatus::Available,
                readiness: DriverReadiness::Experimental,
                isolation_classes: vec![IsolationClass::SharedHostKernel],
                reason: None,
                evidence: BTreeMap::new(),
            },
            "test-manifest-sha256",
            KvmRegistration::ProbeOnly,
        );
        let runtime_root = root.join("runtime");
        let inner = UtilityVmRuntimeDriver::new(
            capability,
            a3s_oci_sdk::AttachmentCapabilities::base_v1(),
            "KVM",
            runtime_root.clone(),
            runtime_root.join("shares"),
            root.join("system-image.json"),
            "test-manifest-sha256".to_string(),
            runtime_root.join("recovery"),
            Arc::new(NoLaunchFactory),
        );
        KvmRuntimeDriver::from_test_inner(inner)
    }

    fn write_test_file(path: &Path) {
        std::fs::write(path, b"test\n").expect("write test file");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("protect test file");
    }

    #[test]
    fn candidate_advertises_only_the_qualified_contract() {
        let temporary = tempfile::tempdir().expect("temporary KVM driver root");
        let driver = test_driver(temporary.path());
        let capability = driver.capability();

        assert_eq!(capability.driver, DriverKind::LibkrunKvm);
        assert_eq!(capability.status, CapabilityStatus::Available);
        assert_eq!(capability.readiness, DriverReadiness::ProbeOnly);
        assert_eq!(capability.isolation_classes, [IsolationClass::DedicatedVm]);
        assert!(!capability.can_launch());
        assert_eq!(
            capability
                .evidence
                .get("native_linux_fallback")
                .map(String::as_str),
            Some("disabled")
        );
        assert_eq!(
            capability
                .evidence
                .get("system_image_manifest_sha256")
                .map(String::as_str),
            Some("test-manifest-sha256")
        );
        assert_eq!(
            driver.operations(),
            &crate::agent_driver::AGENT_DRIVER_OPERATIONS
        );
        assert_eq!(driver.operations().len(), 20);
        assert_eq!(driver.hooks(), &crate::agent_driver::AGENT_DRIVER_HOOKS);
        assert_eq!(driver.hooks().len(), 6);
    }

    #[tokio::test]
    async fn probe_only_candidate_cannot_open_a_host_runtime_service() {
        let temporary = tempfile::tempdir().expect("temporary KVM service root");
        let state_root = temporary.path().join("state");
        let driver: Arc<dyn RuntimeDriver> = Arc::new(test_driver(temporary.path()));

        let error = HostRuntimeService::open(&state_root, driver)
            .await
            .expect_err("probe-only KVM candidate must not register");

        assert_eq!(error.code, ErrorCode::Unsupported);
        assert!(!state_root.exists());
    }

    #[test]
    fn recovery_qualification_is_explicit_and_does_not_promote_the_candidate() {
        let capability = candidate_capability(
            DriverCapability {
                driver: DriverKind::LibkrunKvm,
                status: CapabilityStatus::Available,
                readiness: DriverReadiness::Supported,
                isolation_classes: vec![IsolationClass::SharedHostKernel],
                reason: None,
                evidence: BTreeMap::new(),
            },
            "test-manifest-sha256",
            KvmRegistration::Qualification(KvmQualification::OwnerDeathRestart),
        );

        assert_eq!(capability.readiness, DriverReadiness::Experimental);
        assert!(capability.can_launch());
        assert_eq!(
            capability
                .evidence
                .get("qualification_scope")
                .map(String::as_str),
            Some(LINUX_KVM_RECOVERY_QUALIFICATION_SCOPE)
        );
        assert_eq!(
            capability.evidence.get("opt_in").map(String::as_str),
            Some("qualification-only")
        );

        let soak = candidate_capability(
            DriverCapability {
                driver: DriverKind::LibkrunKvm,
                status: CapabilityStatus::Available,
                readiness: DriverReadiness::Supported,
                isolation_classes: vec![IsolationClass::SharedHostKernel],
                reason: None,
                evidence: BTreeMap::new(),
            },
            "test-manifest-sha256",
            KvmRegistration::Qualification(KvmQualification::BoundedSoak),
        );
        assert_eq!(soak.readiness, DriverReadiness::Experimental);
        assert_eq!(
            soak.evidence.get("qualification_scope").map(String::as_str),
            Some(LINUX_KVM_SOAK_QUALIFICATION_SCOPE)
        );
    }

    #[tokio::test]
    async fn layout_keeps_an_empty_private_bootstrap_separate_from_runtime_shares() {
        let temporary = tempfile::tempdir().expect("temporary KVM layout root");
        let root = std::fs::canonicalize(temporary.path()).expect("canonical test root");
        let shim = root.join("shim");
        let manifest = root.join("system-image.json");
        let runtime_root = root.join("runtime");
        write_test_file(&shim);
        write_test_file(&manifest);

        let prepared = PreparedUtilityVmLayout::open(
            shim.clone(),
            runtime_root.clone(),
            manifest.clone(),
            UtilityVmBootstrap::PrivateEmptyRoot,
        )
        .await
        .expect("prepare KVM layout");

        assert_eq!(prepared.bootstrap_root, runtime_root.join("bootstrap"));
        assert_ne!(prepared.bootstrap_root, prepared.runtime_share_root);
        assert_eq!(
            std::fs::metadata(&prepared.bootstrap_root)
                .expect("bootstrap metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(std::fs::read_dir(&prepared.bootstrap_root)
            .expect("enumerate bootstrap")
            .next()
            .is_none());

        write_test_file(&prepared.bootstrap_root.join("stale"));
        let error = PreparedUtilityVmLayout::open(
            shim,
            runtime_root,
            manifest,
            UtilityVmBootstrap::PrivateEmptyRoot,
        )
        .await
        .expect_err("a stale bootstrap root must fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(error.message.contains("must remain empty"));
    }

    #[tokio::test]
    async fn layout_rejects_a_manifest_inside_the_writable_runtime_root() {
        let temporary = tempfile::tempdir().expect("temporary KVM overlap root");
        let root = std::fs::canonicalize(temporary.path()).expect("canonical test root");
        let shim = root.join("shim");
        let runtime_root = root.join("runtime");
        std::fs::create_dir(&runtime_root).expect("create runtime root");
        std::fs::set_permissions(&runtime_root, std::fs::Permissions::from_mode(0o700))
            .expect("protect runtime root");
        let manifest = runtime_root.join("system-image.json");
        write_test_file(&shim);
        write_test_file(&manifest);

        let error = PreparedUtilityVmLayout::open(
            shim,
            runtime_root,
            manifest,
            UtilityVmBootstrap::PrivateEmptyRoot,
        )
        .await
        .expect_err("writable manifest overlap must fail closed");

        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(error
            .message
            .contains("must be outside writable runtime root"));
    }

    #[test]
    fn config_rejects_relative_or_ambiguous_paths() {
        assert!(KvmRuntimeDriverConfig::new(
            "relative-shim",
            "/tmp/a3s-oci-kvm",
            "/tmp/system-image.json"
        )
        .is_err());
        assert!(KvmRuntimeDriverConfig::new(
            "/tmp/shim",
            "/tmp/a3s-oci-kvm/../runtime",
            "/tmp/system-image.json"
        )
        .is_err());
        assert!(KvmRuntimeDriverConfig::new(
            "/tmp/shim",
            "/tmp/a3s-oci-kvm",
            "relative-system-image.json"
        )
        .is_err());
    }
}
