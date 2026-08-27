use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use a3s_oci_agent_protocol::GuestAgentService;
use a3s_oci_core::{CapabilityStatus, DriverReadiness, IsolationClass};
use a3s_oci_sdk::{async_trait, Error, ErrorCode, Result};

use crate::agent_driver::AgentDriverClient;
use crate::agent_session::UtilityVmSession;
use crate::utility_vm_driver::layout::{
    validate_absolute_normalized_path, PreparedUtilityVmLayout, UtilityVmBootstrap,
};
use crate::utility_vm_driver::recovery::RecoveryStore;
use crate::utility_vm_driver::{
    delegate_utility_vm_runtime_driver, LaunchedUtilityVm, UtilityVmFactory,
    UtilityVmLaunchRequest, UtilityVmOwner, UtilityVmRuntimeDriver,
};

/// Runtime-owned host paths for the Apple Silicon HVF driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HvfRuntimeDriverConfig {
    shim: PathBuf,
    runtime_root: PathBuf,
    system_image_manifest: PathBuf,
}

impl HvfRuntimeDriverConfig {
    /// Configure the signed shim, private writable runtime root, and immutable
    /// system-image manifest used by every dedicated utility VM.
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
        validate_absolute_normalized_path(&config.shim, "HVF libkrun shim")?;
        validate_absolute_normalized_path(&config.runtime_root, "HVF runtime root")?;
        validate_absolute_normalized_path(
            &config.system_image_manifest,
            "HVF system-image manifest",
        )?;
        Ok(config)
    }

    /// Signed isolated libkrun shim executable.
    #[must_use]
    pub fn shim(&self) -> &Path {
        &self.shim
    }

    /// Same-UID private root for shares, consoles, and recovery evidence.
    #[must_use]
    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }

    /// Immutable, digest-bound macOS utility-VM system-image manifest.
    #[must_use]
    pub fn system_image_manifest(&self) -> &Path {
        &self.system_image_manifest
    }
}

/// Launch-ready Apple Silicon driver owning one authenticated HVF VM per generation.
pub struct HvfRuntimeDriver {
    inner: UtilityVmRuntimeDriver,
}

impl fmt::Debug for HvfRuntimeDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("HvfRuntimeDriver")
            .field(&self.inner)
            .finish()
    }
}

impl HvfRuntimeDriver {
    /// Verify the host, immutable image, shim, and private runtime layout before
    /// making a launch-ready experimental driver available to a host service.
    pub async fn open(config: HvfRuntimeDriverConfig) -> Result<Self> {
        let mut capability = crate::platform::hvf_driver_capability();
        if capability.status != CapabilityStatus::Available {
            return Err(Error::new(
                ErrorCode::Unavailable,
                capability.reason.clone().unwrap_or_else(|| {
                    "Apple Silicon Hypervisor.framework is unavailable".to_string()
                }),
            )
            .for_operation("open-hvf-runtime-driver"));
        }
        let prepared = PreparedUtilityVmLayout::open(
            config.shim,
            config.runtime_root,
            config.system_image_manifest,
            UtilityVmBootstrap::RuntimeShare,
        )
        .await?;
        capability.readiness = DriverReadiness::Experimental;
        capability.isolation_classes = vec![IsolationClass::DedicatedVm];
        capability.evidence.extend([
            (
                "execution_path".to_string(),
                "one-hvf-utility-vm-per-generation".to_string(),
            ),
            (
                "system_image_manifest_sha256".to_string(),
                prepared.system_image_manifest_sha256.clone(),
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
                "kqueue-exact-owner-process-group-cleanup".to_string(),
            ),
        ]);

        let recovery = RecoveryStore::new(prepared.recovery_directory.clone());
        let factory: Arc<dyn UtilityVmFactory> = Arc::new(LiveHvfVmFactory {
            shim: prepared.shim,
            system_image_manifest: prepared.system_image_manifest.clone(),
            system_image_manifest_sha256: prepared.system_image_manifest_sha256.clone(),
            console_directory: prepared.console_directory,
            recovery,
        });
        Ok(Self {
            inner: UtilityVmRuntimeDriver::new(
                capability,
                a3s_oci_sdk::AttachmentCapabilities::base_v1(),
                "HVF",
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

    /// Number of exact generations still owning a live utility VM.
    pub async fn active_session_count(&self) -> usize {
        self.inner.active_session_count().await
    }

    #[cfg(test)]
    pub(crate) fn from_test_inner(inner: UtilityVmRuntimeDriver) -> Self {
        Self { inner }
    }
}

delegate_utility_vm_runtime_driver!(HvfRuntimeDriver, inner);

struct LiveHvfVmFactory {
    shim: PathBuf,
    system_image_manifest: PathBuf,
    system_image_manifest_sha256: String,
    console_directory: PathBuf,
    recovery: RecoveryStore,
}

#[async_trait]
impl UtilityVmFactory for LiveHvfVmFactory {
    async fn launch(&self, request: UtilityVmLaunchRequest<'_>) -> Result<LaunchedUtilityVm> {
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
                    "HVF driver launch requires an exact generation for container {}",
                    target.id
                ),
            )
            .for_operation("launch-hvf-utility-vm")
        })?;
        let console = self
            .console_directory
            .join(format!("{}-{}.log", target.id, generation.0));
        let recovery_report = self
            .recovery
            .path(target, attachment_contract.guest_session())?;
        let session = Arc::new(
            UtilityVmSession::connect_with_runtime_share(
                &self.shim,
                &self.system_image_manifest,
                &self.system_image_manifest_sha256,
                runtime_share,
                &console,
                Some(&recovery_report),
            )
            .await
            .map_err(hvf_launch_error)?,
        );
        let service: Arc<dyn GuestAgentService> = Arc::new(session.client());
        Ok(LaunchedUtilityVm {
            client: AgentDriverClient::new(service, "HVF guest agent", "hvf"),
            owner: Arc::new(LiveHvfVmOwner { session }),
        })
    }
}

struct LiveHvfVmOwner {
    session: Arc<UtilityVmSession>,
}

#[async_trait]
impl UtilityVmOwner for LiveHvfVmOwner {
    async fn shutdown(&self) -> Result<()> {
        let report = self.session.shutdown().await;
        if report.session_is_success() {
            Ok(())
        } else {
            Err(hvf_report_error("shutdown-hvf-utility-vm", report))
        }
    }
}

fn hvf_launch_error(report: crate::AgentVmSmokeReport) -> Error {
    let retryable = !report.protocol_negotiated;
    hvf_report_error("launch-hvf-utility-vm", report).retryable(retryable)
}

fn hvf_report_error(operation: &'static str, report: crate::AgentVmSmokeReport) -> Error {
    let reason = report
        .reason
        .unwrap_or_else(|| "authenticated HVF utility VM did not satisfy its contract".to_string());
    Error::new(ErrorCode::Unavailable, reason).for_operation(operation)
}
