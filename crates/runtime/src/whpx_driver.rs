use std::collections::BTreeMap;
use std::fmt;
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::Duration;

use a3s_oci_agent_protocol::{
    AgentRecoveryReport, GuestAgentService, GuestPath, AGENT_RECOVERY_REPORT_MAX_BYTES,
    AGENT_RECOVERY_REPORT_PENDING_SUFFIX, AGENT_RUNTIME_SHARE_GUEST_ROOT,
};
use a3s_oci_core::{CapabilityStatus, DriverCapability, DriverReadiness, IsolationClass};
use a3s_oci_sdk::{
    async_trait, runtime_bundle_handoff_directory, runtime_bundle_handoff_root,
    AttachmentCapabilities, ContainerId, ContainerRecord, ContainerStats, ContainerTarget, Error,
    ErrorCode, ExitStatus, FileRequest, FileResponse, FilesystemRequest, FilesystemResponse,
    OciBundle, OperationId, OutputChunk, ProcessRecord, Result, RuntimeOperation,
    RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY, RUNTIME_BUNDLE_HANDOFF_EXTENSION,
    RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::{sleep, Instant};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

use crate::agent_driver::{AgentDriverClient, AGENT_DRIVER_HOOKS, AGENT_DRIVER_OPERATIONS};
use crate::agent_session::UtilityVmSession;
use crate::driver::{
    DriverCloseStdinRequest, DriverContainerOperationRequest, DriverCreateRequest,
    DriverDeleteRequest, DriverExecRequest, DriverKillRequest, DriverProcess,
    DriverReadOutputRequest, DriverResizeRequest, DriverSignalProcessRequest, DriverStartRequest,
    DriverState, DriverUpdateRequest, DriverWaitProcessRequest, DriverWaitRequest,
    DriverWriteStdinRequest, OciHookPhase, RuntimeDriver,
};

const CONSOLE_DIRECTORY: &str = "console";
const RECOVERY_DIRECTORY: &str = "recovery";
const RUNTIME_SHARE_DIRECTORY: &str = "shares";
const BUNDLE_HANDOFF_MARKER: &str = ".a3s-oci-bundle-handoff.json";
const BUNDLE_HANDOFF_MARKER_PENDING: &str = ".a3s-oci-bundle-handoff.pending";
const BUNDLE_HANDOFF_MARKER_SCHEMA: &str = "a3s.oci.bundle-handoff.v1";
const MAX_BUNDLE_HANDOFF_MARKER_BYTES: usize = 4 * 1024;
const RECOVERY_HANDOFF_POLL_INTERVAL: Duration = Duration::from_millis(25);
const RECOVERY_HANDOFF_TIMEOUT: Duration = Duration::from_secs(16);

/// Protected host paths used by the one-VM-per-container WHPX driver candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhpxRuntimeDriverConfig {
    shim: PathBuf,
    runtime_root: PathBuf,
    vm_rootfs: PathBuf,
    system_image_manifest: PathBuf,
    runtime_share_root: PathBuf,
}

impl WhpxRuntimeDriverConfig {
    /// Describe the isolated shim, protected runtime root, empty bootstrap, and
    /// immutable system-image manifest.
    ///
    /// The bootstrap must be a strict, empty descendant of `runtime_root`; the
    /// manifest and its assets must remain outside that mutable tree. Opening
    /// the candidate verifies those paths, binds the manifest digest into the
    /// driver capability, creates the share parent, and applies the private
    /// Windows DACL before any VM can launch.
    #[must_use]
    pub fn new(
        shim: impl Into<PathBuf>,
        runtime_root: impl Into<PathBuf>,
        vm_rootfs: impl Into<PathBuf>,
        system_image_manifest: impl Into<PathBuf>,
    ) -> Self {
        let runtime_root = runtime_root.into();
        Self {
            shim: shim.into(),
            runtime_share_root: runtime_root.join(RUNTIME_SHARE_DIRECTORY),
            runtime_root,
            vm_rootfs: vm_rootfs.into(),
            system_image_manifest: system_image_manifest.into(),
        }
    }

    /// Isolated libkrun shim executable.
    #[must_use]
    pub fn shim(&self) -> &Path {
        &self.shim
    }

    /// Protected root that owns every mutable WHPX runtime artifact.
    #[must_use]
    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }

    /// Empty bootstrap root used while each dedicated utility VM starts.
    #[must_use]
    pub fn vm_rootfs(&self) -> &Path {
        &self.vm_rootfs
    }

    /// Manifest for the pinned, read-only x86_64 system disk.
    #[must_use]
    pub fn system_image_manifest(&self) -> &Path {
        &self.system_image_manifest
    }

    /// Protected parent of every exact-generation writable guest share.
    #[must_use]
    pub fn runtime_share_root(&self) -> &Path {
        &self.runtime_share_root
    }
}

/// Candidate WHPX driver that owns one authenticated utility VM per container.
///
/// The complete live twenty-operation contract is implemented and
/// qualification tests may invoke it directly. Its capability deliberately
/// remains `probe-only`, so
/// [`crate::HostRuntimeService`] rejects production registration until the
/// fresh-host recovery and native-handle reclamation gates are complete.
pub struct WhpxRuntimeDriver {
    capability: DriverCapability,
    runtime_root: PathBuf,
    vm_rootfs: PathBuf,
    system_image_manifest: PathBuf,
    system_image_manifest_sha256: String,
    runtime_share_root: PathBuf,
    recovery_directory: PathBuf,
    factory: Arc<dyn UtilityVmFactory>,
    sessions: Mutex<BTreeMap<ContainerId, WhpxAttachment>>,
    create_gates: Mutex<BTreeMap<ContainerId, Weak<Mutex<()>>>>,
}

impl fmt::Debug for WhpxRuntimeDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WhpxRuntimeDriver")
            .field("capability", &self.capability)
            .field("runtime_root", &self.runtime_root)
            .field("vm_rootfs", &self.vm_rootfs)
            .field("system_image_manifest", &self.system_image_manifest)
            .field(
                "system_image_manifest_sha256",
                &self.system_image_manifest_sha256,
            )
            .field("runtime_share_root", &self.runtime_share_root)
            .finish_non_exhaustive()
    }
}

impl WhpxRuntimeDriver {
    /// Open the non-registerable WHPX driver candidate around protected paths.
    pub async fn open_candidate(config: WhpxRuntimeDriverConfig) -> Result<Self> {
        let mut capability = crate::platform::whpx_driver_capability();
        if capability.status != CapabilityStatus::Available {
            return Err(Error::new(
                ErrorCode::Unavailable,
                capability
                    .reason
                    .clone()
                    .unwrap_or_else(|| "Windows Hypervisor Platform is unavailable".to_string()),
            )
            .for_operation("open-whpx-driver-candidate"));
        }
        let prepared = PreparedWhpxLayout::open(config).await?;
        capability.readiness = DriverReadiness::ProbeOnly;
        capability.isolation_classes = vec![IsolationClass::DedicatedVm];
        capability.evidence.insert(
            "execution_path".to_string(),
            "one-utility-vm-per-container".to_string(),
        );
        capability
            .evidence
            .insert("runtime_root_protected".to_string(), "true".to_string());
        capability.evidence.insert(
            "runtime_share".to_string(),
            "protected-per-generation-virtiofs".to_string(),
        );
        capability.evidence.insert(
            "immutable_system_root".to_string(),
            "manifest-bound-read-only-virtio-blk".to_string(),
        );
        capability.evidence.insert(
            "system_image_manifest_sha256".to_string(),
            prepared.system_image_manifest_sha256.clone(),
        );
        capability.evidence.insert(
            "owner_death_recovery".to_string(),
            "stopped-with-authenticated-exit".to_string(),
        );
        capability.evidence.insert(
            "restart_exit_evidence".to_string(),
            "implemented-unqualified".to_string(),
        );
        capability
            .evidence
            .insert("opt_in".to_string(), "qualification-only".to_string());

        let factory = Arc::new(LiveUtilityVmFactory {
            shim: prepared.shim,
            vm_rootfs: prepared.vm_rootfs.clone(),
            system_image_manifest: prepared.system_image_manifest.clone(),
            system_image_manifest_sha256: prepared.system_image_manifest_sha256.clone(),
            console_directory: prepared.console_directory,
            recovery_directory: prepared.recovery_directory.clone(),
        });
        Ok(Self {
            capability,
            runtime_root: prepared.runtime_root,
            vm_rootfs: prepared.vm_rootfs,
            system_image_manifest: prepared.system_image_manifest,
            system_image_manifest_sha256: prepared.system_image_manifest_sha256,
            runtime_share_root: prepared.runtime_share_root,
            recovery_directory: prepared.recovery_directory,
            factory,
            sessions: Mutex::new(BTreeMap::new()),
            create_gates: Mutex::new(BTreeMap::new()),
        })
    }

    /// Open one launch-ready instance exclusively for the multi-process
    /// host-service recovery qualification gate.
    ///
    /// The public candidate remains `probe-only`. Keeping this constructor
    /// crate-private prevents normal SDK or product paths from bypassing the
    /// remaining promotion gates while still exercising the exact durable
    /// [`crate::HostRuntimeService`] recovery path on real hardware.
    pub(crate) async fn open_service_qualification(
        config: WhpxRuntimeDriverConfig,
    ) -> Result<Self> {
        Self::open_qualification(config, "host-service-owner-death-only").await
    }

    /// Open one launch-ready instance exclusively for the A3S Box product
    /// lifecycle qualification gate.
    ///
    /// This remains crate-private and leaves [`Self::open_candidate`] in its
    /// public probe-only state. The separately scoped evidence prevents a Box
    /// qualification service from being mistaken for production promotion or
    /// for the owner-death recovery gate.
    pub(crate) async fn open_box_qualification(config: WhpxRuntimeDriverConfig) -> Result<Self> {
        Self::open_qualification(config, "box-product-lifecycle-only").await
    }

    async fn open_qualification(
        config: WhpxRuntimeDriverConfig,
        scope: &'static str,
    ) -> Result<Self> {
        let mut driver = Self::open_candidate(config).await?;
        driver.capability.readiness = DriverReadiness::Experimental;
        driver
            .capability
            .evidence
            .insert("qualification_override".to_string(), scope.to_string());
        Ok(driver)
    }

    /// Close every attached guest transport, reap each owned VM once, and
    /// retain stopped tombstones for durable host reconciliation.
    pub async fn shutdown(&self) -> Result<()> {
        let sessions = {
            let sessions = self.sessions.lock().await;
            sessions
                .values()
                .filter_map(|attachment| match attachment {
                    WhpxAttachment::Live(session) => Some(Arc::clone(session)),
                    WhpxAttachment::RecoveredStopped { .. } => None,
                })
                .collect::<Vec<_>>()
        };
        let mut shutdowns = JoinSet::new();
        for session in sessions {
            shutdowns.spawn(async move {
                let result = session.owner.shutdown().await;
                (session, result)
            });
        }
        let mut failures = Vec::new();
        while let Some(completed) = shutdowns.join_next().await {
            match completed {
                Ok((session, Ok(()))) => self.replace_with_stopped(&session).await,
                Ok((_session, Err(error))) => failures.push(error.to_string()),
                Err(error) => failures.push(format!("utility VM shutdown task failed: {error}")),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::Internal,
                format!(
                    "failed to shut down {} WHPX utility VM session(s): {}",
                    failures.len(),
                    failures.join("; ")
                ),
            )
            .for_operation("shutdown-whpx-driver"))
        }
    }

    /// Number of container generations with an attached utility VM.
    pub async fn active_session_count(&self) -> usize {
        self.sessions
            .lock()
            .await
            .values()
            .filter(|attachment| matches!(attachment, WhpxAttachment::Live(_)))
            .count()
    }

    async fn attachment_for(
        &self,
        target: &ContainerTarget,
        operation: &'static str,
    ) -> Result<WhpxAttachment> {
        require_exact_generation(target, operation)?;
        let sessions = self.sessions.lock().await;
        let attachment = sessions.get(&target.id).cloned().ok_or_else(|| {
            Error::new(
                ErrorCode::Unavailable,
                format!(
                    "container {} has neither an attached WHPX utility VM nor a recovered stop record",
                    target.id
                ),
            )
            .for_operation(operation)
        })?;
        if attachment.target() != target {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!(
                    "container {} is attached at generation {:?}, not {:?}",
                    target.id,
                    attachment.target().generation,
                    target.generation
                ),
            )
            .for_operation(operation));
        }
        Ok(attachment)
    }

    async fn session_for(
        &self,
        target: &ContainerTarget,
        operation: &'static str,
    ) -> Result<Arc<WhpxContainer>> {
        match self.attachment_for(target, operation).await? {
            WhpxAttachment::Live(session) => Ok(session),
            WhpxAttachment::RecoveredStopped { .. } => {
                Err(recovered_stopped_error(target, operation))
            }
        }
    }

    async fn remove_live_session(&self, expected: &Arc<WhpxContainer>) {
        let mut sessions = self.sessions.lock().await;
        let remove = matches!(
            sessions.get(&expected.target.id),
            Some(WhpxAttachment::Live(current)) if Arc::ptr_eq(current, expected)
        );
        if remove {
            sessions.remove(&expected.target.id);
        }
    }

    async fn replace_with_stopped(&self, expected: &Arc<WhpxContainer>) {
        let mut sessions = self.sessions.lock().await;
        let replace = matches!(
            sessions.get(&expected.target.id),
            Some(WhpxAttachment::Live(current)) if Arc::ptr_eq(current, expected)
        );
        if replace {
            sessions.insert(
                expected.target.id.clone(),
                WhpxAttachment::RecoveredStopped {
                    target: expected.target.clone(),
                    init_exit_status: None,
                },
            );
        }
    }

    async fn remove_stopped(&self, expected: &ContainerTarget) {
        let mut sessions = self.sessions.lock().await;
        let remove = matches!(
            sessions.get(&expected.id),
            Some(WhpxAttachment::RecoveredStopped { target, .. }) if target == expected
        );
        if remove {
            sessions.remove(&expected.id);
        }
    }

    async fn load_recovery_exit(
        &self,
        target: &ContainerTarget,
        expected_config_digest: &str,
    ) -> Result<Option<ExitStatus>> {
        let path = self.recovery_report_path(target)?;
        let Some(metadata) = self.wait_for_recovery_report(&path).await? else {
            return Ok(None);
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.len() > AGENT_RECOVERY_REPORT_MAX_BYTES as u64
        {
            return Err(recovery_artifact_error(format!(
                "WHPX recovery report must be a plain file of at most {} bytes: {}",
                AGENT_RECOVERY_REPORT_MAX_BYTES,
                path.display()
            )));
        }
        let file = tokio::fs::File::open(&path).await.map_err(|error| {
            recovery_artifact_error(format!(
                "failed to open WHPX recovery report {}: {error}",
                path.display()
            ))
        })?;
        let mut encoded = Vec::with_capacity(metadata.len() as usize);
        file.take((AGENT_RECOVERY_REPORT_MAX_BYTES + 1) as u64)
            .read_to_end(&mut encoded)
            .await
            .map_err(|error| {
                recovery_artifact_error(format!(
                    "failed to read WHPX recovery report {}: {error}",
                    path.display()
                ))
            })?;
        if encoded.len() > AGENT_RECOVERY_REPORT_MAX_BYTES {
            return Err(recovery_artifact_error(format!(
                "WHPX recovery report grew beyond {} bytes: {}",
                AGENT_RECOVERY_REPORT_MAX_BYTES,
                path.display()
            )));
        }
        let report = AgentRecoveryReport::from_json(&encoded).map_err(|error| {
            recovery_artifact_error(format!(
                "WHPX recovery report {} is invalid: {error}",
                path.display()
            ))
        })?;
        if report.records().is_empty() {
            return Ok(None);
        }
        let record = report
            .records()
            .iter()
            .find(|record| &record.target == target)
            .ok_or_else(|| {
                recovery_artifact_error(format!(
                    "WHPX recovery report {} does not contain container {} generation {:?}",
                    path.display(),
                    target.id,
                    target.generation
                ))
            })?;
        if record.config_digest != expected_config_digest {
            return Err(recovery_artifact_error(format!(
                "WHPX recovery report config digest mismatch for container {} generation {:?}: durable {}, report {}",
                target.id,
                target.generation,
                expected_config_digest,
                record.config_digest
            )));
        }
        Ok(Some(record.init_exit_status.clone()))
    }

    async fn remove_recovery_report(&self, target: &ContainerTarget) -> Result<()> {
        let path = self.recovery_report_path(target)?;
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                {
                    return Err(recovery_artifact_error(format!(
                        "refusing to delete a non-plain WHPX recovery report: {}",
                        path.display()
                    )));
                }
                tokio::fs::remove_file(&path).await.map_err(|error| {
                    recovery_artifact_error(format!(
                        "failed to delete WHPX recovery report {}: {error}",
                        path.display()
                    ))
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(recovery_artifact_error(format!(
                    "failed to inspect WHPX recovery report {} before delete: {error}",
                    path.display()
                )))
            }
        }
        self.remove_recovery_pending(&path).await
    }

    async fn wait_for_recovery_report(&self, path: &Path) -> Result<Option<std::fs::Metadata>> {
        self.wait_for_recovery_report_until(path, Instant::now() + RECOVERY_HANDOFF_TIMEOUT)
            .await
    }

    async fn wait_for_recovery_report_until(
        &self,
        path: &Path,
        deadline: Instant,
    ) -> Result<Option<std::fs::Metadata>> {
        let pending = recovery_pending_path(path);
        loop {
            match tokio::fs::symlink_metadata(path).await {
                Ok(metadata) => return Ok(Some(metadata)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(recovery_artifact_error(format!(
                        "failed to inspect WHPX recovery report {}: {error}",
                        path.display()
                    )))
                }
            }
            match tokio::fs::symlink_metadata(&pending).await {
                Ok(metadata) => {
                    if !metadata.is_file()
                        || metadata.file_type().is_symlink()
                        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                        || metadata.len() != 0
                    {
                        return Err(recovery_artifact_error(format!(
                            "WHPX recovery pending marker must be a plain empty file: {}",
                            pending.display()
                        )));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return match tokio::fs::symlink_metadata(path).await {
                        Ok(metadata) => Ok(Some(metadata)),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                        Err(error) => Err(recovery_artifact_error(format!(
                            "failed to recheck WHPX recovery report {}: {error}",
                            path.display()
                        ))),
                    };
                }
                Err(error) => {
                    return Err(recovery_artifact_error(format!(
                        "failed to inspect WHPX recovery pending marker {}: {error}",
                        pending.display()
                    )))
                }
            }
            if Instant::now() >= deadline {
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    format!(
                        "timed out waiting for WHPX recovery handoff marker {}",
                        pending.display()
                    ),
                )
                .for_operation("whpx-recover")
                .retryable(true));
            }
            sleep(RECOVERY_HANDOFF_POLL_INTERVAL).await;
        }
    }

    async fn remove_recovery_pending(&self, report: &Path) -> Result<()> {
        let pending = recovery_pending_path(report);
        match tokio::fs::symlink_metadata(&pending).await {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                    || metadata.len() != 0
                {
                    return Err(recovery_artifact_error(format!(
                        "refusing to delete a non-plain WHPX recovery pending marker: {}",
                        pending.display()
                    )));
                }
                tokio::fs::remove_file(&pending).await.map_err(|error| {
                    recovery_artifact_error(format!(
                        "failed to delete WHPX recovery pending marker {}: {error}",
                        pending.display()
                    ))
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(recovery_artifact_error(format!(
                "failed to inspect WHPX recovery pending marker {} before delete: {error}",
                pending.display()
            ))),
        }
    }

    fn recovery_report_path(&self, target: &ContainerTarget) -> Result<PathBuf> {
        let generation = require_exact_generation(target, "whpx-recovery-report-path")?;
        Ok(self
            .recovery_directory
            .join(format!("{}-{}.json", target.id, generation.0)))
    }

    async fn cleanup_terminal_create_error(
        &self,
        session: &Arc<WhpxContainer>,
        mut error: Error,
    ) -> Error {
        match session.owner.shutdown().await {
            Ok(()) => self.remove_live_session(session).await,
            Err(cleanup) => {
                error.message = format!(
                    "{}; failed to reap the dedicated utility VM: {}",
                    error.message, cleanup
                );
            }
        }
        if let Err(cleanup) = self.cleanup_runtime_bundle_handoff(&session.target).await {
            error.message = format!(
                "{}; failed to remove the runtime-owned bundle handoff: {}",
                error.message, cleanup
            );
        }
        error
    }

    async fn create_gate_for(&self, id: &ContainerId) -> Arc<Mutex<()>> {
        let mut gates = self.create_gates.lock().await;
        gates.retain(|_, gate| gate.strong_count() > 0);
        if let Some(gate) = gates.get(id).and_then(Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(Mutex::new(()));
        gates.insert(id.clone(), Arc::downgrade(&gate));
        gate
    }

    async fn prepare_runtime_bundle_handoff(
        &self,
        request: &DriverCreateRequest,
    ) -> Result<OciBundle> {
        let create_gate = self.create_gate_for(&request.target.id).await;
        let _create_guard = create_gate.lock().await;
        let runtime_share =
            ensure_exact_runtime_share_path(&self.runtime_share_root, &request.target).await?;
        let destination = runtime_share.join(RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY);
        let source = runtime_bundle_handoff_directory(
            &self.runtime_root,
            &request.target.id,
            &request.context.operation_id,
        )?;

        if path_metadata(&destination).await?.is_some() {
            if path_metadata(&source).await?.is_some() {
                return Err(bundle_handoff_error(
                    ErrorCode::Conflict,
                    format!(
                        "both the operation handoff and exact-generation bundle exist: {} and {}",
                        source.display(),
                        destination.display()
                    ),
                ));
            }
            let bundle = load_exact_handoff_bundle(&destination, &request.bundle).await?;
            ensure_bundle_handoff_marker(&runtime_share, &request.target, bundle.config_digest())
                .await?;
            cleanup_empty_handoff_parents(&source, &self.runtime_root)
                .await
                .map_err(|error| error.retryable(true))?;
            return Ok(bundle);
        }

        let source = canonical_plain_directory(&source, "WHPX operation bundle handoff").await?;
        validate_handoff_ancestry(
            &self.runtime_root,
            &source,
            &request.target.id,
            &request.context.operation_id,
        )
        .await?;
        let source_bundle = load_exact_handoff_bundle(&source, &request.bundle).await?;
        ensure_bundle_handoff_marker(
            &runtime_share,
            &request.target,
            source_bundle.config_digest(),
        )
        .await?;

        tokio::fs::rename(&source, &destination)
            .await
            .map_err(|error| {
                bundle_handoff_error(
                    ErrorCode::Unavailable,
                    format!(
                        "failed to atomically move WHPX bundle handoff {} into {}: {error}",
                        source.display(),
                        destination.display()
                    ),
                )
                .retryable(true)
            })?;
        let bundle = load_exact_handoff_bundle(&destination, &source_bundle).await?;
        cleanup_empty_handoff_parents(&source, &self.runtime_root)
            .await
            .map_err(|error| error.retryable(true))?;
        Ok(bundle)
    }

    async fn cleanup_runtime_bundle_handoff(&self, target: &ContainerTarget) -> Result<()> {
        let Some(runtime_share) = existing_exact_runtime_share_path(
            &self.runtime_share_root,
            target,
            "cleanup-whpx-bundle-handoff",
        )
        .await?
        else {
            return Ok(());
        };
        let marker = runtime_share.join(BUNDLE_HANDOFF_MARKER);
        let Some(metadata) = path_metadata(&marker).await? else {
            return Ok(());
        };
        ensure_plain_file_metadata(&metadata, &marker, "WHPX bundle-handoff marker")?;
        let retained = read_bundle_handoff_marker(&marker).await?;
        if retained.target != *target {
            return Err(bundle_handoff_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "bundle-handoff marker targets {:?}, not {:?}",
                    retained.target, target
                ),
            ));
        }

        let configured_bundle = runtime_share.join(RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY);
        if path_metadata(&configured_bundle).await?.is_some() {
            let bundle =
                canonical_plain_directory(&configured_bundle, "runtime-owned WHPX bundle").await?;
            if bundle.parent() != Some(runtime_share.as_path()) {
                return Err(bundle_handoff_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "runtime-owned WHPX bundle escaped exact share {}: {}",
                        runtime_share.display(),
                        bundle.display()
                    ),
                ));
            }
            let loaded = OciBundle::load(&bundle).await?;
            if loaded.config_digest() != retained.config_digest {
                return Err(bundle_handoff_error(
                    ErrorCode::FailedPrecondition,
                    "runtime-owned WHPX bundle no longer matches its handoff marker",
                ));
            }
            tokio::fs::remove_dir_all(&bundle).await.map_err(|error| {
                bundle_handoff_error(
                    ErrorCode::Internal,
                    format!(
                        "failed to remove runtime-owned WHPX bundle {}: {error}",
                        bundle.display()
                    ),
                )
            })?;
        }
        tokio::fs::remove_file(&marker).await.map_err(|error| {
            bundle_handoff_error(
                ErrorCode::Internal,
                format!(
                    "failed to remove WHPX bundle-handoff marker {}: {error}",
                    marker.display()
                ),
            )
        })?;
        remove_plain_file_if_present(&runtime_share.join(BUNDLE_HANDOFF_MARKER_PENDING)).await?;
        remove_directory_if_empty(&runtime_share.join("run")).await?;
        remove_directory_if_empty(&runtime_share).await?;
        if let Some(container_directory) = runtime_share.parent() {
            remove_directory_if_empty(container_directory).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl RuntimeDriver for WhpxRuntimeDriver {
    fn capability(&self) -> DriverCapability {
        self.capability.clone()
    }

    fn operations(&self) -> &[RuntimeOperation] {
        &AGENT_DRIVER_OPERATIONS
    }

    fn hooks(&self) -> &[OciHookPhase] {
        &AGENT_DRIVER_HOOKS
    }

    fn attachment_capabilities(&self) -> AttachmentCapabilities {
        AttachmentCapabilities::base_v1()
            .with_extension(
                RUNTIME_BUNDLE_HANDOFF_EXTENSION,
                vec![RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION],
            )
            .expect("the fixed WHPX bundle-handoff extension is valid")
    }

    async fn acknowledge_operation(&self, operation_id: &OperationId) -> Result<()> {
        let clients = self
            .sessions
            .lock()
            .await
            .values()
            .filter_map(|attachment| match attachment {
                WhpxAttachment::Live(session) => Some(session.client.clone()),
                WhpxAttachment::RecoveredStopped { .. } => None,
            })
            .collect::<Vec<_>>();
        for client in clients {
            client.acknowledge_operation(operation_id).await?;
        }
        Ok(())
    }

    async fn prepare_create_bundle(&self, request: &DriverCreateRequest) -> Result<OciBundle> {
        if request.attachment_contract.uses_runtime_bundle_handoff() {
            self.prepare_runtime_bundle_handoff(request).await
        } else {
            Ok(request.bundle.clone())
        }
    }

    async fn recover(&self, record: &ContainerRecord) -> Result<crate::DriverRecovery> {
        let target =
            ContainerTarget::exact(ContainerId::new(record.state.id())?, record.generation);
        let can_commit_stopped =
            *record.state.status() != a3s_oci_sdk::oci_spec::runtime::ContainerState::Creating;
        let attachment = self.sessions.lock().await.get(&target.id).cloned();
        let attachment = match attachment {
            Some(attachment) => attachment,
            None => {
                let init_exit_status = if can_commit_stopped {
                    self.load_recovery_exit(&target, &record.config_digest)
                        .await?
                } else {
                    None
                };
                let recovered = WhpxAttachment::RecoveredStopped {
                    target: target.clone(),
                    init_exit_status,
                };
                let mut sessions = self.sessions.lock().await;
                sessions
                    .entry(target.id.clone())
                    .or_insert_with(|| recovered.clone())
                    .clone()
            }
        };
        if attachment.target() != &target {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!(
                    "container {} is attached at generation {:?}, not durable generation {:?}",
                    target.id,
                    attachment.target().generation,
                    target.generation
                ),
            )
            .for_operation("whpx-recover"));
        }
        match attachment {
            WhpxAttachment::Live(session) => {
                let observed = session
                    .client
                    .state_with_digest(target, Some(&record.config_digest))
                    .await?;
                Ok(if can_commit_stopped {
                    crate::DriverRecovery::observed(observed)
                } else {
                    crate::DriverRecovery::none()
                })
            }
            WhpxAttachment::RecoveredStopped {
                init_exit_status, ..
            } => recovery_result(can_commit_stopped, init_exit_status),
        }
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        if request.isolation.class() != IsolationClass::DedicatedVm {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "the WHPX driver candidate provides only one-VM-per-container isolation",
            )
            .for_operation("whpx-create"));
        }
        require_exact_generation(&request.target, "whpx-create")?;
        let runtime_share =
            exact_runtime_share_path(&self.runtime_share_root, &request.target).await?;
        let guest_directory = guest_bundle_path(&runtime_share, request.bundle.directory()).await?;
        let target = request.target.clone();

        let create_gate = self.create_gate_for(&target.id).await;
        let _create_guard = create_gate.lock().await;
        let session = match self.session_for_existing_create(&target).await? {
            Some(session) => session,
            None => {
                let launched = match self.factory.launch(&target, &runtime_share).await {
                    Ok(launched) => launched,
                    Err(error) if error.retryable => return Err(error),
                    Err(mut error) => {
                        if let Err(cleanup) = self.cleanup_runtime_bundle_handoff(&target).await {
                            error.message = format!(
                                "{}; failed to remove the runtime-owned bundle handoff: {}",
                                error.message, cleanup
                            );
                        }
                        return Err(error);
                    }
                };
                let session = Arc::new(WhpxContainer {
                    target: target.clone(),
                    client: launched.client,
                    owner: launched.owner,
                });
                self.sessions.lock().await.insert(
                    target.id.clone(),
                    WhpxAttachment::Live(Arc::clone(&session)),
                );
                session
            }
        };

        match session.client.create(request, guest_directory).await {
            Ok(state) => Ok(state),
            Err(error) if error.retryable => Err(error),
            Err(error) => Err(self.cleanup_terminal_create_error(&session, error).await),
        }
    }

    async fn state(&self, target: ContainerTarget) -> Result<DriverState> {
        match self.attachment_for(&target, "whpx-state").await? {
            WhpxAttachment::Live(session) => session.client.state(target).await,
            WhpxAttachment::RecoveredStopped { .. } => Ok(DriverState::stopped()),
        }
    }

    async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        self.session_for(&request.target, "whpx-start")
            .await?
            .client
            .start(request)
            .await
    }

    async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        match self.attachment_for(&request.target, "whpx-kill").await? {
            WhpxAttachment::Live(session) => session.client.kill(request).await,
            WhpxAttachment::RecoveredStopped { .. } => Ok(DriverState::stopped()),
        }
    }

    async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        match self.attachment_for(&request.target, "whpx-delete").await? {
            WhpxAttachment::Live(session) => {
                session.client.delete(request).await?;
                session.owner.shutdown().await?;
                self.replace_with_stopped(&session).await;
                self.remove_recovery_report(&session.target).await?;
                self.cleanup_runtime_bundle_handoff(&session.target).await?;
                self.remove_stopped(&session.target).await;
                Ok(())
            }
            WhpxAttachment::RecoveredStopped { target, .. } => {
                self.remove_recovery_report(&target).await?;
                self.cleanup_runtime_bundle_handoff(&target).await?;
                self.remove_stopped(&target).await;
                Ok(())
            }
        }
    }

    async fn wait(&self, request: DriverWaitRequest) -> Result<ExitStatus> {
        match self.attachment_for(&request.target, "whpx-wait").await? {
            WhpxAttachment::Live(session) => session.client.wait(request).await,
            WhpxAttachment::RecoveredStopped {
                init_exit_status: Some(status),
                ..
            } => Ok(status),
            WhpxAttachment::RecoveredStopped {
                init_exit_status: None,
                ..
            } => Err(recovered_exit_evidence_error(&request.target, "whpx-wait")),
        }
    }

    async fn exec(&self, request: DriverExecRequest) -> Result<DriverProcess> {
        self.session_for(&request.target.container, "whpx-exec")
            .await?
            .client
            .exec(request)
            .await
    }

    async fn signal_process(&self, request: DriverSignalProcessRequest) -> Result<()> {
        self.session_for(&request.target.container, "whpx-signal-process")
            .await?
            .client
            .signal_process(request)
            .await
    }

    async fn wait_process(&self, request: DriverWaitProcessRequest) -> Result<ExitStatus> {
        self.session_for(&request.target.container, "whpx-wait-process")
            .await?
            .client
            .wait_process(request)
            .await
    }

    async fn pause(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.session_for(&request.target, "whpx-pause")
            .await?
            .client
            .pause(request)
            .await
    }

    async fn resume(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.session_for(&request.target, "whpx-resume")
            .await?
            .client
            .resume(request)
            .await
    }

    async fn processes(&self, target: ContainerTarget) -> Result<Vec<ProcessRecord>> {
        match self.attachment_for(&target, "whpx-processes").await? {
            WhpxAttachment::Live(session) => session.client.processes(target).await,
            WhpxAttachment::RecoveredStopped { .. } => Ok(Vec::new()),
        }
    }

    async fn update(&self, request: DriverUpdateRequest) -> Result<DriverState> {
        self.session_for(&request.target, "whpx-update")
            .await?
            .client
            .update(request)
            .await
    }

    async fn stats(&self, target: ContainerTarget) -> Result<ContainerStats> {
        self.session_for(&target, "whpx-stats")
            .await?
            .client
            .stats(target)
            .await
    }

    async fn read_output(&self, request: DriverReadOutputRequest) -> Result<Vec<OutputChunk>> {
        self.session_for(&request.target.container, "whpx-read-output")
            .await?
            .client
            .read_output(request)
            .await
    }

    async fn write_stdin(&self, request: DriverWriteStdinRequest) -> Result<()> {
        self.session_for(&request.target.container, "whpx-write-stdin")
            .await?
            .client
            .write_stdin(request)
            .await
    }

    async fn close_stdin(&self, request: DriverCloseStdinRequest) -> Result<()> {
        self.session_for(&request.target.container, "whpx-close-stdin")
            .await?
            .client
            .close_stdin(request)
            .await
    }

    async fn resize(&self, request: DriverResizeRequest) -> Result<()> {
        self.session_for(&request.target.container, "whpx-resize")
            .await?
            .client
            .resize(request)
            .await
    }

    async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        self.session_for(&request.target, "whpx-file")
            .await?
            .client
            .file(request)
            .await
    }

    async fn filesystem(&self, request: FilesystemRequest) -> Result<FilesystemResponse> {
        self.session_for(&request.target, "whpx-filesystem")
            .await?
            .client
            .filesystem(request)
            .await
    }
}

impl WhpxRuntimeDriver {
    async fn session_for_existing_create(
        &self,
        target: &ContainerTarget,
    ) -> Result<Option<Arc<WhpxContainer>>> {
        let sessions = self.sessions.lock().await;
        let Some(attachment) = sessions.get(&target.id) else {
            return Ok(None);
        };
        if attachment.target() != target {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!(
                    "container {} already owns a WHPX attachment at generation {:?}",
                    target.id,
                    attachment.target().generation
                ),
            )
            .for_operation("whpx-create"));
        }
        match attachment {
            WhpxAttachment::Live(session) => Ok(Some(Arc::clone(session))),
            WhpxAttachment::RecoveredStopped { .. } => {
                Err(recovered_stopped_error(target, "whpx-create"))
            }
        }
    }
}

#[derive(Clone)]
enum WhpxAttachment {
    Live(Arc<WhpxContainer>),
    RecoveredStopped {
        target: ContainerTarget,
        init_exit_status: Option<ExitStatus>,
    },
}

impl WhpxAttachment {
    fn target(&self) -> &ContainerTarget {
        match self {
            Self::Live(session) => &session.target,
            Self::RecoveredStopped { target, .. } => target,
        }
    }
}

struct WhpxContainer {
    target: ContainerTarget,
    client: AgentDriverClient,
    owner: Arc<dyn UtilityVmOwner>,
}

struct LaunchedUtilityVm {
    client: AgentDriverClient,
    owner: Arc<dyn UtilityVmOwner>,
}

#[async_trait]
trait UtilityVmFactory: Send + Sync {
    async fn launch(
        &self,
        target: &ContainerTarget,
        runtime_share: &Path,
    ) -> Result<LaunchedUtilityVm>;
}

#[async_trait]
trait UtilityVmOwner: Send + Sync {
    async fn shutdown(&self) -> Result<()>;
}

struct LiveUtilityVmFactory {
    shim: PathBuf,
    vm_rootfs: PathBuf,
    system_image_manifest: PathBuf,
    system_image_manifest_sha256: String,
    console_directory: PathBuf,
    recovery_directory: PathBuf,
}

#[async_trait]
impl UtilityVmFactory for LiveUtilityVmFactory {
    async fn launch(
        &self,
        target: &ContainerTarget,
        runtime_share: &Path,
    ) -> Result<LaunchedUtilityVm> {
        let generation = require_exact_generation(target, "launch-whpx-utility-vm")?;
        let console = self
            .console_directory
            .join(format!("{}-{}.log", target.id, generation.0));
        let recovery_report = self
            .recovery_directory
            .join(format!("{}-{}.json", target.id, generation.0));
        let session = Arc::new(
            UtilityVmSession::connect_with_recovery(
                &self.shim,
                &self.vm_rootfs,
                &self.system_image_manifest,
                &self.system_image_manifest_sha256,
                runtime_share,
                &console,
                &recovery_report,
            )
            .await
            .map_err(vm_launch_error)?,
        );
        let service: Arc<dyn GuestAgentService> = Arc::new(session.client());
        Ok(LaunchedUtilityVm {
            client: AgentDriverClient::new(service, "WHPX guest agent", "whpx"),
            owner: Arc::new(LiveUtilityVmOwner { session }),
        })
    }
}

struct LiveUtilityVmOwner {
    session: Arc<UtilityVmSession>,
}

#[async_trait]
impl UtilityVmOwner for LiveUtilityVmOwner {
    async fn shutdown(&self) -> Result<()> {
        let report = self.session.shutdown().await;
        if report.is_success() {
            Ok(())
        } else {
            Err(vm_report_error("shutdown-whpx-utility-vm", report))
        }
    }
}

#[derive(Debug)]
struct PreparedWhpxLayout {
    shim: PathBuf,
    runtime_root: PathBuf,
    vm_rootfs: PathBuf,
    system_image_manifest: PathBuf,
    system_image_manifest_sha256: String,
    runtime_share_root: PathBuf,
    console_directory: PathBuf,
    recovery_directory: PathBuf,
}

impl PreparedWhpxLayout {
    async fn open(config: WhpxRuntimeDriverConfig) -> Result<Self> {
        let shim = canonical_plain_file(&config.shim, "WHPX shim").await?;
        let runtime_root =
            canonical_plain_directory(&config.runtime_root, "WHPX runtime root").await?;
        let vm_rootfs = canonical_plain_directory(&config.vm_rootfs, "WHPX bootstrap root").await?;
        if vm_rootfs == runtime_root || !vm_rootfs.starts_with(&runtime_root) {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "WHPX bootstrap root must be a strict descendant of protected runtime root {}: {}",
                    runtime_root.display(),
                    vm_rootfs.display()
                ),
            )
            .for_operation("open-whpx-driver-candidate"));
        }
        let mut bootstrap_entries = tokio::fs::read_dir(&vm_rootfs).await.map_err(|error| {
            path_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to inspect WHPX bootstrap root {}: {error}",
                    vm_rootfs.display()
                ),
            )
        })?;
        if bootstrap_entries
            .next_entry()
            .await
            .map_err(|error| {
                path_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "failed to enumerate WHPX bootstrap root {}: {error}",
                        vm_rootfs.display()
                    ),
                )
            })?
            .is_some()
        {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "WHPX bootstrap root must be empty because the manifest-bound ext4 disk owns the guest system root: {}",
                    vm_rootfs.display()
                ),
            )
            .for_operation("open-whpx-driver-candidate"));
        }

        let system_image_manifest =
            canonical_plain_file(&config.system_image_manifest, "WHPX system-image manifest")
                .await?;
        let system_image_directory = system_image_manifest.parent().ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "WHPX system-image manifest has no parent directory: {}",
                    system_image_manifest.display()
                ),
            )
            .for_operation("open-whpx-driver-candidate")
        })?;
        if system_image_manifest.starts_with(&runtime_root)
            || runtime_root.starts_with(system_image_directory)
        {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "WHPX immutable system-image assets and mutable runtime root must be disjoint: {} and {}",
                    system_image_directory.display(),
                    runtime_root.display()
                ),
            )
            .for_operation("open-whpx-driver-candidate"));
        }
        let system_image_manifest_sha256 =
            crate::agent_session::sha256_path(&system_image_manifest)
                .await
                .map_err(|reason| path_error(ErrorCode::FailedPrecondition, reason))?;

        protect_path(runtime_root.clone()).await?;
        protect_path(vm_rootfs.clone()).await?;
        let configured_runtime_share_root = config.runtime_share_root;
        ensure_private_directory(configured_runtime_share_root.clone(), "runtime-share").await?;
        let runtime_share_root =
            canonical_plain_directory(&configured_runtime_share_root, "WHPX runtime-share root")
                .await?;
        if runtime_share_root == vm_rootfs
            || runtime_share_root.starts_with(&vm_rootfs)
            || vm_rootfs.starts_with(&runtime_share_root)
        {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "WHPX bootstrap root and writable runtime-share root must be disjoint: {} and {}",
                    vm_rootfs.display(),
                    runtime_share_root.display()
                ),
            )
            .for_operation("open-whpx-driver-candidate"));
        }
        let console_directory = runtime_root.join(CONSOLE_DIRECTORY);
        ensure_private_directory(console_directory.clone(), "console").await?;
        let recovery_directory = runtime_root.join(RECOVERY_DIRECTORY);
        ensure_private_directory(recovery_directory.clone(), "recovery").await?;
        let handoff_directory = runtime_bundle_handoff_root(&runtime_root)?;
        ensure_private_directory(handoff_directory, "bundle-handoff").await?;
        Ok(Self {
            shim,
            runtime_root,
            vm_rootfs,
            system_image_manifest,
            system_image_manifest_sha256,
            runtime_share_root,
            console_directory,
            recovery_directory,
        })
    }
}

async fn canonical_plain_file(path: &Path, label: &str) -> Result<PathBuf> {
    canonical_plain_path(path, label, true).await
}

async fn canonical_plain_directory(path: &Path, label: &str) -> Result<PathBuf> {
    canonical_plain_path(path, label, false).await
}

async fn canonical_plain_path(path: &Path, label: &str, file: bool) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{label} must be absolute: {}", path.display()),
        )
        .for_operation("open-whpx-driver-candidate"));
    }
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        path_error(
            ErrorCode::FailedPrecondition,
            format!("failed to inspect {label} {}: {error}", path.display()),
        )
    })?;
    let expected_kind = if file {
        metadata.is_file()
    } else {
        metadata.is_dir()
    };
    if !expected_kind
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(path_error(
            ErrorCode::FailedPrecondition,
            format!(
                "{label} is not a plain {}: {}",
                if file { "file" } else { "directory" },
                path.display()
            ),
        ));
    }
    tokio::fs::canonicalize(path).await.map_err(|error| {
        path_error(
            ErrorCode::FailedPrecondition,
            format!("failed to resolve {label} {}: {error}", path.display()),
        )
    })
}

async fn protect_path(path: PathBuf) -> Result<()> {
    tokio::task::spawn_blocking(move || crate::windows_security::protect_path(&path))
        .await
        .map_err(|error| {
            path_error(
                ErrorCode::Internal,
                format!("WHPX path-protection task failed: {error}"),
            )
        })?
}

async fn ensure_private_directory(path: PathBuf, label: &'static str) -> Result<()> {
    match tokio::fs::symlink_metadata(&path).await {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 =>
        {
            protect_path(path).await
        }
        Ok(_) => Err(path_error(
            ErrorCode::FailedPrecondition,
            format!(
                "WHPX {label} path is not a plain directory: {}",
                path.display()
            ),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            tokio::task::spawn_blocking(move || {
                crate::windows_security::create_private_directory(&path)
            })
            .await
            .map_err(|error| {
                path_error(
                    ErrorCode::Internal,
                    format!("WHPX {label}-directory task failed: {error}"),
                )
            })?
        }
        Err(error) => Err(path_error(
            ErrorCode::Internal,
            format!(
                "failed to inspect WHPX {label} directory {}: {error}",
                path.display()
            ),
        )),
    }
}

async fn exact_runtime_share_path(
    runtime_share_root: &Path,
    target: &ContainerTarget,
) -> Result<PathBuf> {
    existing_exact_runtime_share_path(
        runtime_share_root,
        target,
        "resolve-whpx-runtime-share",
    )
    .await?
    .ok_or_else(|| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "WHPX exact-generation runtime share does not exist for container {} generation {:?}",
                target.id, target.generation
            ),
        )
        .for_operation("resolve-whpx-runtime-share")
    })
}

async fn ensure_exact_runtime_share_path(
    runtime_share_root: &Path,
    target: &ContainerTarget,
) -> Result<PathBuf> {
    let generation = require_exact_generation(target, "prepare-whpx-runtime-share")?;
    ensure_private_directory(
        runtime_share_root.join(target.id.as_str()),
        "container-share",
    )
    .await?;
    ensure_private_directory(
        runtime_share_root
            .join(target.id.as_str())
            .join(generation.0.to_string()),
        "generation-share",
    )
    .await?;
    let runtime_share = exact_runtime_share_path(runtime_share_root, target).await?;
    ensure_private_directory(runtime_share.join("run"), "runtime-state").await?;
    Ok(runtime_share)
}

async fn existing_exact_runtime_share_path(
    runtime_share_root: &Path,
    target: &ContainerTarget,
    operation: &'static str,
) -> Result<Option<PathBuf>> {
    let generation = require_exact_generation(target, operation)?;
    let configured_id_directory = runtime_share_root.join(target.id.as_str());
    if path_metadata(&configured_id_directory).await?.is_none() {
        return Ok(None);
    }
    let id_directory =
        canonical_plain_directory(&configured_id_directory, "WHPX container share directory")
            .await?;
    if id_directory.parent() != Some(runtime_share_root) {
        return Err(Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "WHPX container share escaped protected root {}: {}",
                runtime_share_root.display(),
                id_directory.display()
            ),
        )
        .for_operation("resolve-whpx-runtime-share"));
    }
    let configured_runtime_share = id_directory.join(generation.0.to_string());
    if path_metadata(&configured_runtime_share).await?.is_none() {
        return Ok(None);
    }
    let runtime_share = canonical_plain_directory(
        &configured_runtime_share,
        "WHPX exact-generation runtime share",
    )
    .await?;
    if runtime_share.parent() != Some(id_directory.as_path()) {
        return Err(Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "WHPX generation share escaped container directory {}: {}",
                id_directory.display(),
                runtime_share.display()
            ),
        )
        .for_operation("resolve-whpx-runtime-share"));
    }
    protect_path(id_directory).await?;
    protect_path(runtime_share.clone()).await?;
    Ok(Some(runtime_share))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BundleHandoffMarker {
    schema_version: String,
    target: ContainerTarget,
    config_digest: String,
}

async fn validate_handoff_ancestry(
    runtime_root: &Path,
    source: &Path,
    container_id: &ContainerId,
    operation_id: &a3s_oci_sdk::OperationId,
) -> Result<()> {
    let expected = runtime_bundle_handoff_directory(runtime_root, container_id, operation_id)?;
    let expected = canonical_plain_directory(&expected, "WHPX operation bundle handoff").await?;
    if source != expected {
        return Err(bundle_handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "WHPX bundle handoff must use the exact operation path {}: {}",
                expected.display(),
                source.display()
            ),
        ));
    }

    let operation_directory = source.parent().ok_or_else(|| {
        bundle_handoff_error(
            ErrorCode::FailedPrecondition,
            "WHPX bundle handoff has no operation directory",
        )
    })?;
    let container_directory = operation_directory.parent().ok_or_else(|| {
        bundle_handoff_error(
            ErrorCode::FailedPrecondition,
            "WHPX bundle handoff has no container directory",
        )
    })?;
    let handoff_root = container_directory.parent().ok_or_else(|| {
        bundle_handoff_error(
            ErrorCode::FailedPrecondition,
            "WHPX bundle handoff has no protected root",
        )
    })?;
    let expected_root = canonical_plain_directory(
        &runtime_bundle_handoff_root(runtime_root)?,
        "WHPX bundle-handoff root",
    )
    .await?;
    if handoff_root != expected_root {
        return Err(bundle_handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "WHPX bundle handoff escaped protected root {}: {}",
                expected_root.display(),
                source.display()
            ),
        ));
    }
    for path in [container_directory, operation_directory, source] {
        let path = canonical_plain_directory(path, "WHPX bundle-handoff ancestor").await?;
        protect_path(path).await?;
    }
    Ok(())
}

async fn load_exact_handoff_bundle(path: &Path, expected: &OciBundle) -> Result<OciBundle> {
    let directory = canonical_plain_directory(path, "WHPX portable OCI bundle").await?;
    let config =
        canonical_plain_file(&directory.join("config.json"), "WHPX OCI configuration").await?;
    if config.parent() != Some(directory.as_path()) {
        return Err(bundle_handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "WHPX OCI configuration escaped bundle {}: {}",
                directory.display(),
                config.display()
            ),
        ));
    }
    let bundle = OciBundle::load(&directory).await?;
    if bundle.config_bytes() != expected.config_bytes()
        || bundle.config_digest() != expected.config_digest()
    {
        return Err(bundle_handoff_error(
            ErrorCode::Conflict,
            format!(
                "WHPX bundle handoff configuration differs from durable digest {}",
                expected.config_digest()
            ),
        ));
    }
    validate_portable_handoff_bundle(&bundle).await?;
    Ok(bundle)
}

async fn validate_portable_handoff_bundle(bundle: &OciBundle) -> Result<()> {
    let root = bundle.spec().root().as_ref().ok_or_else(|| {
        bundle_handoff_error(
            ErrorCode::InvalidArgument,
            "WHPX bundle handoff requires an OCI root filesystem",
        )
    })?;
    let root_path = root.path();
    if root_path.is_absolute()
        || root_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(bundle_handoff_error(
            ErrorCode::InvalidArgument,
            format!(
                "WHPX bundle handoff requires a normalized relative root.path: {}",
                root_path.display()
            ),
        ));
    }
    let rootfs = canonical_plain_directory(
        &bundle.directory().join(root_path),
        "WHPX portable bundle rootfs",
    )
    .await?;
    if rootfs == bundle.directory() || !rootfs.starts_with(bundle.directory()) {
        return Err(bundle_handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "WHPX portable rootfs escapes bundle {}: {}",
                bundle.directory().display(),
                rootfs.display()
            ),
        ));
    }

    for (index, mount) in bundle
        .spec()
        .mounts()
        .as_deref()
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        let is_bind = mount
            .options()
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|option| matches!(option.as_str(), "bind" | "rbind"));
        if !is_bind {
            continue;
        }
        let source = mount.source().as_ref().ok_or_else(|| {
            bundle_handoff_error(
                ErrorCode::InvalidArgument,
                format!("WHPX portable bind mount {index} has no source"),
            )
        })?;
        if source.is_absolute()
            || source
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(bundle_handoff_error(
                ErrorCode::InvalidArgument,
                format!(
                    "WHPX portable bind mount {index} requires a normalized relative source: {}",
                    source.display()
                ),
            ));
        }
    }
    Ok(())
}

async fn ensure_bundle_handoff_marker(
    runtime_share: &Path,
    target: &ContainerTarget,
    config_digest: &str,
) -> Result<()> {
    let marker = runtime_share.join(BUNDLE_HANDOFF_MARKER);
    let expected = BundleHandoffMarker {
        schema_version: BUNDLE_HANDOFF_MARKER_SCHEMA.to_string(),
        target: target.clone(),
        config_digest: config_digest.to_string(),
    };
    if path_metadata(&marker).await?.is_some() {
        let retained = read_bundle_handoff_marker(&marker).await?;
        if retained != expected {
            return Err(bundle_handoff_error(
                ErrorCode::Conflict,
                "existing WHPX bundle-handoff marker differs from this create",
            ));
        }
        remove_plain_file_if_present(&runtime_share.join(BUNDLE_HANDOFF_MARKER_PENDING)).await?;
        return Ok(());
    }

    let pending = runtime_share.join(BUNDLE_HANDOFF_MARKER_PENDING);
    remove_plain_file_if_present(&pending).await?;
    let encoded = serde_json::to_vec(&expected).map_err(|error| {
        bundle_handoff_error(
            ErrorCode::Internal,
            format!("failed to encode WHPX bundle-handoff marker: {error}"),
        )
    })?;
    if encoded.len() > MAX_BUNDLE_HANDOFF_MARKER_BYTES {
        return Err(bundle_handoff_error(
            ErrorCode::Internal,
            "WHPX bundle-handoff marker exceeds its fixed bound",
        ));
    }
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)
        .await
        .map_err(|error| {
            bundle_handoff_error(
                ErrorCode::Internal,
                format!(
                    "failed to create WHPX bundle-handoff marker {}: {error}",
                    pending.display()
                ),
            )
        })?;
    file.write_all(&encoded).await.map_err(|error| {
        bundle_handoff_error(
            ErrorCode::Internal,
            format!(
                "failed to write WHPX bundle-handoff marker {}: {error}",
                pending.display()
            ),
        )
    })?;
    file.flush().await.map_err(|error| {
        bundle_handoff_error(
            ErrorCode::Internal,
            format!(
                "failed to flush WHPX bundle-handoff marker {}: {error}",
                pending.display()
            ),
        )
    })?;
    file.sync_all().await.map_err(|error| {
        bundle_handoff_error(
            ErrorCode::Internal,
            format!(
                "failed to sync WHPX bundle-handoff marker {}: {error}",
                pending.display()
            ),
        )
    })?;
    drop(file);
    protect_path(pending.clone()).await?;
    tokio::fs::rename(&pending, &marker)
        .await
        .map_err(|error| {
            bundle_handoff_error(
                ErrorCode::Internal,
                format!(
                    "failed to commit WHPX bundle-handoff marker {}: {error}",
                    marker.display()
                ),
            )
        })?;
    protect_path(marker).await
}

async fn read_bundle_handoff_marker(path: &Path) -> Result<BundleHandoffMarker> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        bundle_handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect WHPX bundle-handoff marker {}: {error}",
                path.display()
            ),
        )
    })?;
    ensure_plain_file_metadata(&metadata, path, "WHPX bundle-handoff marker")?;
    if metadata.len() > MAX_BUNDLE_HANDOFF_MARKER_BYTES as u64 {
        return Err(bundle_handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "WHPX bundle-handoff marker exceeds {} bytes: {}",
                MAX_BUNDLE_HANDOFF_MARKER_BYTES,
                path.display()
            ),
        ));
    }
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    tokio::fs::File::open(path)
        .await
        .map_err(|error| {
            bundle_handoff_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to open WHPX bundle-handoff marker {}: {error}",
                    path.display()
                ),
            )
        })?
        .take((MAX_BUNDLE_HANDOFF_MARKER_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .await
        .map_err(|error| {
            bundle_handoff_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to read WHPX bundle-handoff marker {}: {error}",
                    path.display()
                ),
            )
        })?;
    let marker: BundleHandoffMarker = serde_json::from_slice(&encoded).map_err(|error| {
        bundle_handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "invalid WHPX bundle-handoff marker {}: {error}",
                path.display()
            ),
        )
    })?;
    if marker.schema_version != BUNDLE_HANDOFF_MARKER_SCHEMA
        || marker.target.generation.is_none()
        || marker.config_digest.len() != 71
        || !marker.config_digest.starts_with("sha256:")
    {
        return Err(bundle_handoff_error(
            ErrorCode::FailedPrecondition,
            format!("invalid WHPX bundle-handoff evidence: {}", path.display()),
        ));
    }
    Ok(marker)
}

fn ensure_plain_file_metadata(
    metadata: &std::fs::Metadata,
    path: &Path,
    label: &str,
) -> Result<()> {
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(bundle_handoff_error(
            ErrorCode::FailedPrecondition,
            format!("{label} is not a plain file: {}", path.display()),
        ));
    }
    Ok(())
}

async fn path_metadata(path: &Path) -> Result<Option<std::fs::Metadata>> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(bundle_handoff_error(
            ErrorCode::Internal,
            format!("failed to inspect {}: {error}", path.display()),
        )),
    }
}

async fn remove_plain_file_if_present(path: &Path) -> Result<()> {
    let Some(metadata) = path_metadata(path).await? else {
        return Ok(());
    };
    ensure_plain_file_metadata(&metadata, path, "WHPX bundle-handoff temporary file")?;
    tokio::fs::remove_file(path).await.map_err(|error| {
        bundle_handoff_error(
            ErrorCode::Internal,
            format!("failed to remove {}: {error}", path.display()),
        )
    })
}

async fn cleanup_empty_handoff_parents(source: &Path, runtime_root: &Path) -> Result<()> {
    let expected_root = canonical_plain_directory(
        &runtime_bundle_handoff_root(runtime_root)?,
        "WHPX bundle-handoff root",
    )
    .await?;
    let operation_directory = source.parent().ok_or_else(|| {
        bundle_handoff_error(
            ErrorCode::FailedPrecondition,
            "WHPX bundle handoff has no operation parent",
        )
    })?;
    let container_directory = operation_directory.parent().ok_or_else(|| {
        bundle_handoff_error(
            ErrorCode::FailedPrecondition,
            "WHPX bundle handoff has no container parent",
        )
    })?;
    if container_directory.parent() != Some(expected_root.as_path()) {
        return Err(bundle_handoff_error(
            ErrorCode::FailedPrecondition,
            "refusing to clean bundle-handoff parents outside the protected root",
        ));
    }
    remove_directory_if_empty(operation_directory).await?;
    remove_directory_if_empty(container_directory).await
}

async fn remove_directory_if_empty(path: &Path) -> Result<()> {
    let Some(metadata) = path_metadata(path).await? else {
        return Ok(());
    };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(bundle_handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "refusing to remove a non-plain directory: {}",
                path.display()
            ),
        ));
    }
    let mut entries = tokio::fs::read_dir(path).await.map_err(|error| {
        bundle_handoff_error(
            ErrorCode::Internal,
            format!("failed to inspect directory {}: {error}", path.display()),
        )
    })?;
    if entries
        .next_entry()
        .await
        .map_err(|error| {
            bundle_handoff_error(
                ErrorCode::Internal,
                format!("failed to enumerate directory {}: {error}", path.display()),
            )
        })?
        .is_none()
    {
        tokio::fs::remove_dir(path).await.map_err(|error| {
            bundle_handoff_error(
                ErrorCode::Internal,
                format!(
                    "failed to remove empty directory {}: {error}",
                    path.display()
                ),
            )
        })?;
    }
    Ok(())
}

fn bundle_handoff_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("prepare-whpx-bundle-handoff")
}

async fn guest_bundle_path(runtime_share: &Path, bundle: &Path) -> Result<GuestPath> {
    let bundle = canonical_plain_directory(bundle, "WHPX OCI bundle").await?;
    let relative = bundle.strip_prefix(runtime_share).map_err(|error| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "WHPX OCI bundle must be contained by exact runtime share {}: {} ({error})",
                runtime_share.display(),
                bundle.display()
            ),
        )
        .for_operation("whpx-create")
    })?;
    let mut components = Vec::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "WHPX OCI bundle has a non-normal component: {}",
                    bundle.display()
                ),
            )
            .for_operation("whpx-create"));
        };
        let component = component.to_str().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("WHPX OCI bundle path is not Unicode: {}", bundle.display()),
            )
            .for_operation("whpx-create")
        })?;
        if component.contains(['/', '\\', '\0']) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "WHPX OCI bundle has an invalid guest component: {}",
                    bundle.display()
                ),
            )
            .for_operation("whpx-create"));
        }
        components.push(component);
    }
    if components.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "WHPX OCI bundle cannot be the runtime-share root itself",
        )
        .for_operation("whpx-create"));
    }
    GuestPath::new(format!(
        "{AGENT_RUNTIME_SHARE_GUEST_ROOT}/{}",
        components.join("/")
    ))
}

fn require_exact_generation(
    target: &ContainerTarget,
    operation: &'static str,
) -> Result<a3s_oci_sdk::Generation> {
    target.generation.ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "WHPX driver operation requires an exact generation for container {}",
                target.id
            ),
        )
        .for_operation(operation)
    })
}

fn recovery_result(
    can_commit_stopped: bool,
    init_exit_status: Option<ExitStatus>,
) -> Result<crate::DriverRecovery> {
    if !can_commit_stopped {
        return Ok(crate::DriverRecovery::none());
    }
    match init_exit_status {
        Some(status) => crate::DriverRecovery::stopped_with_exit(status),
        None => Ok(crate::DriverRecovery::observed(DriverState::stopped())),
    }
}

fn recovery_artifact_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message).for_operation("whpx-recover")
}

fn recovery_pending_path(report: &Path) -> PathBuf {
    let mut path = report.as_os_str().to_os_string();
    path.push(AGENT_RECOVERY_REPORT_PENDING_SUFFIX);
    PathBuf::from(path)
}

fn recovered_stopped_error(target: &ContainerTarget, operation: &'static str) -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        format!(
            "container {} generation {:?} was recovered as stopped after its WHPX owner exited; no live utility VM remains, so this generation must be deleted before another live operation",
            target.id, target.generation
        ),
    )
    .for_operation(operation)
}

fn recovered_exit_evidence_error(target: &ContainerTarget, operation: &'static str) -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        format!(
            "container {} generation {:?} was stopped by WHPX owner-death cleanup, but its exact init exit status was not retained",
            target.id, target.generation
        ),
    )
    .for_operation(operation)
}

fn vm_launch_error(report: crate::AgentVmSmokeReport) -> Error {
    let retryable = !report.protocol_negotiated;
    vm_report_error("launch-whpx-utility-vm", report).retryable(retryable)
}

fn vm_report_error(operation: &'static str, report: crate::AgentVmSmokeReport) -> Error {
    let reason = report.reason.unwrap_or_else(|| {
        "authenticated WHPX utility VM did not satisfy its contract".to_string()
    });
    Error::new(ErrorCode::Unavailable, reason).for_operation(operation)
}

fn path_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("open-whpx-driver-candidate")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::Duration;

    use a3s_oci_agent_protocol::{
        AgentCapabilities, AgentCreateRequest, AgentDeleteRequest, AgentKillRequest,
        AgentRecoveryRecord, AgentRecoveryReport, AgentStartRequest, AgentState, AgentStateRequest,
        GuestAgentService,
    };
    use a3s_oci_core::{
        CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, IsolationClass,
    };
    use a3s_oci_sdk::oci_spec::runtime::{ContainerState, StateBuilder};
    use a3s_oci_sdk::{
        async_trait, runtime_bundle_handoff_directory, ContainerId, ContainerRecord,
        ContainerTarget, CreateAttachments, DeleteMode, Error, ErrorCode, ExitStatus, Generation,
        IsolationRequest, OciBundle, OperationContext, OperationId, ProcessIo, Result, Signal,
        RUNTIME_BUNDLE_HANDOFF_EXTENSION, RUNTIME_BUNDLE_HANDOFF_MOVE_V1,
    };
    use tokio::sync::Mutex;

    use super::{
        recovery_pending_path, AgentDriverClient, DriverCreateRequest, DriverDeleteRequest,
        DriverKillRequest, DriverWaitRequest, LaunchedUtilityVm, PreparedWhpxLayout, RuntimeDriver,
        UtilityVmFactory, UtilityVmOwner, WhpxRuntimeDriver, WhpxRuntimeDriverConfig,
    };
    use crate::DriverCreateAttachments;

    const TEST_CONFIG: &str = concat!(
        "{\n",
        "  \"ociVersion\": \"1.3.0\",\n",
        "  \"process\": {\n",
        "    \"terminal\": false,\n",
        "    \"user\": {\"uid\": 0, \"gid\": 0},\n",
        "    \"args\": [\"/bin/true\"],\n",
        "    \"cwd\": \"/\"\n",
        "  },\n",
        "  \"root\": {\"path\": \"rootfs\", \"readonly\": true}\n",
        "}\n",
    );

    #[derive(Default)]
    struct FakeGuest {
        create_calls: AtomicUsize,
        delete_calls: AtomicUsize,
        state_calls: AtomicUsize,
        last_guest_directory: StdMutex<Option<String>>,
        next_create_failure: StdMutex<Option<Error>>,
        state: StdMutex<Option<AgentState>>,
    }

    impl FakeGuest {
        fn fail_next_create(&self, error: Error) {
            *self
                .next_create_failure
                .lock()
                .expect("create failure lock") = Some(error);
        }
    }

    #[async_trait]
    impl GuestAgentService for FakeGuest {
        fn capabilities(&self) -> AgentCapabilities {
            AgentCapabilities::linux_executor("test", "x86_64").expect("capabilities")
        }

        async fn create(&self, request: AgentCreateRequest) -> Result<AgentState> {
            self.create_calls.fetch_add(1, Ordering::Relaxed);
            *self
                .last_guest_directory
                .lock()
                .expect("guest directory lock") =
                Some(request.bundle.guest_directory().as_str().to_string());
            if let Some(error) = self
                .next_create_failure
                .lock()
                .expect("create failure lock")
                .take()
            {
                return Err(error);
            }
            let state = AgentState::new(
                request.target,
                ContainerState::Created,
                Some(101),
                request.bundle.config_digest(),
            )?;
            *self.state.lock().expect("state lock") = Some(state.clone());
            Ok(state)
        }

        async fn state(&self, request: AgentStateRequest) -> Result<AgentState> {
            self.state_calls.fetch_add(1, Ordering::Relaxed);
            self.state
                .lock()
                .expect("state lock")
                .clone()
                .filter(|state| state.target() == &request.target)
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "missing fake guest state"))
        }

        async fn start(&self, request: AgentStartRequest) -> Result<AgentState> {
            let state = AgentState::new(
                request.target,
                ContainerState::Running,
                Some(101),
                request.expected_config_digest,
            )?;
            *self.state.lock().expect("state lock") = Some(state.clone());
            Ok(state)
        }

        async fn kill(&self, request: AgentKillRequest) -> Result<AgentState> {
            let digest = self
                .state
                .lock()
                .expect("state lock")
                .as_ref()
                .map(|state| state.config_digest().to_string())
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "missing fake guest state"))?;
            let state = AgentState::new(request.target, ContainerState::Stopped, None, digest)?;
            *self.state.lock().expect("state lock") = Some(state.clone());
            Ok(state)
        }

        async fn delete(&self, _request: AgentDeleteRequest) -> Result<()> {
            self.delete_calls.fetch_add(1, Ordering::Relaxed);
            *self.state.lock().expect("state lock") = None;
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeOwner {
        shutdown_calls: AtomicUsize,
        active_shutdowns: AtomicUsize,
        max_active_shutdowns: AtomicUsize,
        shutdown_barrier: StdMutex<Option<Arc<tokio::sync::Barrier>>>,
    }

    impl FakeOwner {
        fn synchronize_two_shutdowns(&self) {
            *self.shutdown_barrier.lock().expect("shutdown barrier lock") =
                Some(Arc::new(tokio::sync::Barrier::new(2)));
        }
    }

    #[async_trait]
    impl UtilityVmOwner for FakeOwner {
        async fn shutdown(&self) -> Result<()> {
            self.shutdown_calls.fetch_add(1, Ordering::Relaxed);
            let active = self.active_shutdowns.fetch_add(1, Ordering::Relaxed) + 1;
            self.max_active_shutdowns
                .fetch_max(active, Ordering::Relaxed);
            let barrier = self
                .shutdown_barrier
                .lock()
                .expect("shutdown barrier lock")
                .clone();
            match barrier {
                Some(barrier) => {
                    barrier.wait().await;
                }
                None => tokio::task::yield_now().await,
            }
            self.active_shutdowns.fetch_sub(1, Ordering::Relaxed);
            Ok(())
        }
    }

    struct FakeFactory {
        launches: AtomicUsize,
        active_launches: AtomicUsize,
        max_active_launches: AtomicUsize,
        launch_shares: StdMutex<Vec<PathBuf>>,
        launch_barrier: StdMutex<Option<Arc<tokio::sync::Barrier>>>,
        guest: Arc<FakeGuest>,
        owner: Arc<FakeOwner>,
    }

    impl FakeFactory {
        fn synchronize_two_launches(&self) {
            *self.launch_barrier.lock().expect("launch barrier lock") =
                Some(Arc::new(tokio::sync::Barrier::new(2)));
        }
    }

    #[async_trait]
    impl UtilityVmFactory for FakeFactory {
        async fn launch(
            &self,
            _target: &ContainerTarget,
            runtime_share: &std::path::Path,
        ) -> Result<LaunchedUtilityVm> {
            self.launches.fetch_add(1, Ordering::Relaxed);
            self.launch_shares
                .lock()
                .expect("launch-share lock")
                .push(runtime_share.to_path_buf());
            let active = self.active_launches.fetch_add(1, Ordering::Relaxed) + 1;
            self.max_active_launches
                .fetch_max(active, Ordering::Relaxed);
            let barrier = self
                .launch_barrier
                .lock()
                .expect("launch barrier lock")
                .clone();
            match barrier {
                Some(barrier) => {
                    barrier.wait().await;
                }
                None => tokio::task::yield_now().await,
            }
            self.active_launches.fetch_sub(1, Ordering::Relaxed);
            let service: Arc<dyn GuestAgentService> = self.guest.clone();
            let owner: Arc<dyn UtilityVmOwner> = self.owner.clone();
            Ok(LaunchedUtilityVm {
                client: AgentDriverClient::new(service, "fake WHPX guest", "fake-whpx"),
                owner,
            })
        }
    }

    struct Fixture {
        _temporary: tempfile::TempDir,
        bundle: OciBundle,
        guest: Arc<FakeGuest>,
        owner: Arc<FakeOwner>,
        factory: Arc<FakeFactory>,
        runtime_root: PathBuf,
        runtime_share_root: PathBuf,
        recovery_directory: PathBuf,
        driver: WhpxRuntimeDriver,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().expect("temporary WHPX fixture");
            let vm_rootfs = temporary.path().join("vm-root");
            let system_image_manifest = temporary.path().join("system-image.json");
            let runtime_share_root = temporary.path().join("shares");
            let recovery_directory = temporary.path().join("recovery");
            let bundle_directory = runtime_share_root.join("whpx-test/1/workloads/test");
            std::fs::create_dir(&vm_rootfs).expect("VM root directory");
            std::fs::write(&system_image_manifest, b"manifest")
                .expect("system-image manifest fixture");
            std::fs::create_dir_all(&bundle_directory).expect("bundle directory");
            std::fs::create_dir(&recovery_directory).expect("recovery directory");
            let vm_rootfs = std::fs::canonicalize(vm_rootfs).expect("canonical WHPX fixture root");
            let runtime_root = std::fs::canonicalize(temporary.path())
                .expect("canonical WHPX runtime fixture root");
            let runtime_share_root = std::fs::canonicalize(runtime_share_root)
                .expect("canonical runtime-share fixture root");
            let bundle_directory = runtime_share_root.join("whpx-test/1/workloads/test");
            let bundle = OciBundle::from_json(bundle_directory, TEST_CONFIG).expect("OCI bundle");
            let guest = Arc::new(FakeGuest::default());
            let owner = Arc::new(FakeOwner::default());
            let factory = Arc::new(FakeFactory {
                launches: AtomicUsize::new(0),
                active_launches: AtomicUsize::new(0),
                max_active_launches: AtomicUsize::new(0),
                launch_shares: StdMutex::new(Vec::new()),
                launch_barrier: StdMutex::new(None),
                guest: guest.clone(),
                owner: owner.clone(),
            });
            let factory_dyn: Arc<dyn UtilityVmFactory> = factory.clone();
            let driver = WhpxRuntimeDriver {
                capability: candidate_capability(),
                runtime_root: runtime_root.clone(),
                vm_rootfs: vm_rootfs.clone(),
                system_image_manifest,
                system_image_manifest_sha256: "fixture-manifest-sha256".to_string(),
                runtime_share_root: runtime_share_root.clone(),
                recovery_directory: recovery_directory.clone(),
                factory: factory_dyn,
                sessions: Mutex::new(BTreeMap::new()),
                create_gates: Mutex::new(BTreeMap::new()),
            };
            Self {
                _temporary: temporary,
                bundle,
                guest,
                owner,
                factory,
                runtime_root,
                runtime_share_root,
                recovery_directory,
                driver,
            }
        }

        fn create_request(&self, generation: u64, operation: &str) -> DriverCreateRequest {
            let bundle = self.bundle_for("whpx-test", generation);
            DriverCreateRequest {
                context: context(operation),
                target: target(generation),
                attachment_contract: CreateAttachments::from_bundle(&bundle, ProcessIo::default())
                    .expect("attachment contract"),
                bundle,
                isolation: IsolationRequest::DedicatedVm,
                io: ProcessIo::default(),
                attachments: DriverCreateAttachments::None,
            }
        }

        fn bundle_for(&self, id: &str, generation: u64) -> OciBundle {
            let directory = self
                .runtime_share_root
                .join(id)
                .join(generation.to_string())
                .join("workloads/test");
            std::fs::create_dir_all(&directory).expect("exact runtime-share bundle directory");
            OciBundle::from_json(directory, TEST_CONFIG).expect("OCI bundle")
        }

        fn handoff_request(
            &self,
            id: &str,
            generation: u64,
            operation: &str,
        ) -> DriverCreateRequest {
            let target = ContainerTarget::exact(
                ContainerId::new(id).expect("handoff container ID"),
                Generation(generation),
            );
            let context = context(operation);
            let directory = runtime_bundle_handoff_directory(
                &self.runtime_root,
                &target.id,
                &context.operation_id,
            )
            .expect("handoff directory");
            std::fs::create_dir_all(directory.join("rootfs")).expect("portable handoff rootfs");
            let mut config: serde_json::Value =
                serde_json::from_str(TEST_CONFIG).expect("test OCI config");
            config["annotations"] = serde_json::json!({
                RUNTIME_BUNDLE_HANDOFF_EXTENSION: RUNTIME_BUNDLE_HANDOFF_MOVE_V1
            });
            let config = serde_json::to_string_pretty(&config).expect("handoff config");
            std::fs::write(directory.join("config.json"), config.as_bytes())
                .expect("handoff config file");
            let bundle = OciBundle::from_json(directory, config).expect("handoff bundle");
            let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
                .expect("base handoff attachments")
                .with_runtime_bundle_handoff(&bundle)
                .expect("bundle handoff attachment");
            DriverCreateRequest {
                context,
                target,
                bundle,
                isolation: IsolationRequest::DedicatedVm,
                io: ProcessIo::default(),
                attachment_contract: attachments,
                attachments: DriverCreateAttachments::None,
            }
        }

        fn record(&self, generation: u64, status: ContainerState) -> ContainerRecord {
            let target = target(generation);
            let mut builder = StateBuilder::default()
                .version(self.bundle.spec().version())
                .id(target.id.as_str())
                .status(status)
                .bundle(self.bundle.directory().to_path_buf());
            if matches!(status, ContainerState::Created | ContainerState::Running) {
                builder = builder.pid(101);
            }
            ContainerRecord {
                state: builder.build().expect("recovery OCI state"),
                generation: Generation(generation),
                driver: DriverKind::LibkrunWhpx,
                isolation: IsolationClass::DedicatedVm,
                config_digest: self.bundle.config_digest().to_string(),
                attachments_digest: Some(
                    CreateAttachments::from_bundle(&self.bundle, ProcessIo::default())
                        .expect("attachment contract")
                        .digest()
                        .expect("attachment digest"),
                ),
            }
        }

        fn write_recovery(
            &self,
            generation: u64,
            config_digest: &str,
            status: ExitStatus,
        ) -> PathBuf {
            let target = target(generation);
            let report = AgentRecoveryReport::new(vec![AgentRecoveryRecord::new(
                target.clone(),
                config_digest,
                status,
            )
            .expect("recovery record")])
            .expect("recovery report")
            .to_json()
            .expect("normalized recovery report");
            let path = self
                .recovery_directory
                .join(format!("{}-{generation}.json", target.id));
            std::fs::write(&path, report).expect("write recovery report");
            path
        }
    }

    fn candidate_capability() -> DriverCapability {
        DriverCapability {
            driver: DriverKind::LibkrunWhpx,
            status: CapabilityStatus::Available,
            readiness: DriverReadiness::ProbeOnly,
            isolation_classes: vec![IsolationClass::DedicatedVm],
            reason: None,
            evidence: BTreeMap::new(),
        }
    }

    fn target(generation: u64) -> ContainerTarget {
        ContainerTarget::exact(
            ContainerId::new("whpx-test").expect("container ID"),
            Generation(generation),
        )
    }

    fn context(operation: &str) -> OperationContext {
        OperationContext::new(OperationId::new(operation).expect("operation ID"))
    }

    fn delete_request(generation: u64) -> DriverDeleteRequest {
        DriverDeleteRequest {
            context: context("delete"),
            target: target(generation),
            mode: DeleteMode::Force,
        }
    }

    #[tokio::test]
    async fn prepared_layout_creates_a_disjoint_protected_share_parent() {
        let temporary = tempfile::tempdir().expect("temporary WHPX layout");
        let shim = temporary.path().join("a3s-oci-krun-shim.exe");
        let runtime_root = temporary.path().join("runtime");
        let system_root = runtime_root.join("system");
        let asset_root = temporary.path().join("assets");
        let system_image_manifest = asset_root.join("system-image.json");
        std::fs::create_dir_all(&system_root).expect("bootstrap root");
        std::fs::create_dir_all(&asset_root).expect("asset root");
        std::fs::write(&shim, b"shim").expect("shim fixture");
        std::fs::write(&system_image_manifest, b"manifest").expect("manifest fixture");
        let config = WhpxRuntimeDriverConfig::new(
            &shim,
            &runtime_root,
            &system_root,
            &system_image_manifest,
        );
        assert_eq!(config.runtime_share_root(), runtime_root.join("shares"));
        assert_eq!(config.system_image_manifest(), system_image_manifest);

        let prepared = PreparedWhpxLayout::open(config)
            .await
            .expect("protected WHPX layout");
        assert!(prepared.runtime_share_root.is_dir());
        assert!(!prepared.runtime_share_root.starts_with(&prepared.vm_rootfs));
        assert!(!prepared.vm_rootfs.starts_with(&prepared.runtime_share_root));
        assert_eq!(prepared.system_image_manifest_sha256.len(), 64);
        assert!(prepared
            .system_image_manifest_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    }

    #[tokio::test]
    async fn prepared_layout_rejects_a_nonempty_bootstrap_root() {
        let temporary = tempfile::tempdir().expect("temporary WHPX layout");
        let shim = temporary.path().join("a3s-oci-krun-shim.exe");
        let runtime_root = temporary.path().join("runtime");
        let system_root = runtime_root.join("system");
        let asset_root = temporary.path().join("assets");
        let system_image_manifest = asset_root.join("system-image.json");
        std::fs::create_dir_all(&system_root).expect("bootstrap root");
        std::fs::create_dir_all(&asset_root).expect("asset root");
        std::fs::write(&shim, b"shim").expect("shim fixture");
        std::fs::write(system_root.join("unexpected"), b"mutable root").expect("root fixture");
        std::fs::write(&system_image_manifest, b"manifest").expect("manifest fixture");

        let error = PreparedWhpxLayout::open(WhpxRuntimeDriverConfig::new(
            &shim,
            &runtime_root,
            &system_root,
            &system_image_manifest,
        ))
        .await
        .expect_err("nonempty bootstrap root must fail");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
    }

    #[tokio::test]
    async fn prepared_layout_rejects_system_assets_below_the_mutable_runtime_root() {
        let temporary = tempfile::tempdir().expect("temporary WHPX layout");
        let shim = temporary.path().join("a3s-oci-krun-shim.exe");
        let runtime_root = temporary.path().join("runtime");
        let bootstrap_root = runtime_root.join("bootstrap");
        let system_image_manifest = runtime_root.join("assets/system-image.json");
        std::fs::create_dir_all(&bootstrap_root).expect("bootstrap root");
        std::fs::create_dir_all(
            system_image_manifest
                .parent()
                .expect("manifest parent fixture"),
        )
        .expect("asset root");
        std::fs::write(&shim, b"shim").expect("shim fixture");
        std::fs::write(&system_image_manifest, b"manifest").expect("manifest fixture");

        let error = PreparedWhpxLayout::open(WhpxRuntimeDriverConfig::new(
            &shim,
            &runtime_root,
            &bootstrap_root,
            &system_image_manifest,
        ))
        .await
        .expect_err("mutable runtime roots must not contain immutable system assets");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
    }

    #[tokio::test]
    async fn concurrent_create_reuses_one_vm_and_delete_reaps_it_once() {
        let fixture = Fixture::new();
        let request = fixture.create_request(1, "create");
        let (first, replay) = tokio::join!(
            fixture.driver.create(request.clone()),
            fixture.driver.create(request)
        );
        let first = first.expect("first create");
        let replay = replay.expect("concurrent replayed create");

        assert_eq!(first, replay);
        assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
        assert_eq!(
            fixture.factory.max_active_launches.load(Ordering::Relaxed),
            1
        );
        assert_eq!(fixture.guest.create_calls.load(Ordering::Relaxed), 2);
        assert_eq!(
            fixture
                .guest
                .last_guest_directory
                .lock()
                .expect("guest directory lock")
                .as_deref(),
            Some("/run/a3s-oci-runtime/workloads/test")
        );
        assert_eq!(fixture.driver.active_session_count().await, 1);

        fixture
            .driver
            .delete(delete_request(1))
            .await
            .expect("delete");
        assert_eq!(fixture.guest.delete_calls.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.driver.active_session_count().await, 0);
        fixture
            .driver
            .shutdown()
            .await
            .expect("idempotent shutdown");
        assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn different_container_ids_launch_in_parallel() {
        let fixture = Fixture::new();
        fixture.factory.synchronize_two_launches();
        let first = fixture.create_request(1, "parallel-create-a");
        let mut second = fixture.create_request(1, "parallel-create-b");
        second.target = ContainerTarget::exact(
            ContainerId::new("whpx-test-b").expect("second container ID"),
            Generation(1),
        );
        second.bundle = fixture.bundle_for("whpx-test-b", 1);

        let (first, second) =
            tokio::join!(fixture.driver.create(first), fixture.driver.create(second));
        first.expect("first parallel create");
        second.expect("second parallel create");
        assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 2);
        assert_eq!(
            fixture.factory.max_active_launches.load(Ordering::Relaxed),
            2
        );
        {
            let launch_shares = fixture
                .factory
                .launch_shares
                .lock()
                .expect("launch-share lock");
            assert_eq!(launch_shares.len(), 2);
            assert_ne!(launch_shares[0], launch_shares[1]);
            assert!(launch_shares
                .iter()
                .any(|path| path.ends_with("whpx-test\\1")));
            assert!(launch_shares
                .iter()
                .any(|path| path.ends_with("whpx-test-b\\1")));
        }
        assert_eq!(fixture.driver.active_session_count().await, 2);
        fixture.owner.synchronize_two_shutdowns();
        fixture.driver.shutdown().await.expect("parallel shutdown");
        assert_eq!(
            fixture.owner.max_active_shutdowns.load(Ordering::Relaxed),
            2
        );
    }

    #[tokio::test]
    async fn retryable_create_reuses_the_attached_vm() {
        let fixture = Fixture::new();
        fixture.guest.fail_next_create(
            Error::new(ErrorCode::Unavailable, "transient guest failure").retryable(true),
        );
        let request = fixture.create_request(1, "retryable-create");
        let error = fixture
            .driver
            .create(request.clone())
            .await
            .expect_err("first create must fail retryably");
        assert!(error.retryable);
        assert_eq!(fixture.driver.active_session_count().await, 1);
        assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 0);

        fixture
            .driver
            .create(request)
            .await
            .expect("retried create");
        assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
        fixture.driver.shutdown().await.expect("shutdown");
        assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn terminal_create_failure_reaps_and_releases_the_generation() {
        let fixture = Fixture::new();
        fixture.guest.fail_next_create(Error::new(
            ErrorCode::FailedPrecondition,
            "terminal guest failure",
        ));
        fixture
            .driver
            .create(fixture.create_request(1, "terminal-create"))
            .await
            .expect_err("terminal create must fail");

        assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.driver.active_session_count().await, 0);
    }

    #[tokio::test]
    async fn runtime_bundle_handoff_uses_allocated_generation_and_cleans_on_delete() {
        let fixture = Fixture::new();
        let mut request = fixture.handoff_request("product-box", 37, "product-create");
        let source = request.bundle.directory().to_path_buf();

        let staged = fixture
            .driver
            .prepare_create_bundle(&request)
            .await
            .expect("prepare runtime-owned bundle");
        let expected = fixture.runtime_share_root.join("product-box/37/bundle");
        assert_eq!(staged.directory(), expected);
        assert!(!source.exists());
        assert!(expected.join("rootfs").is_dir());
        assert!(expected
            .parent()
            .expect("generation share")
            .join(super::BUNDLE_HANDOFF_MARKER)
            .is_file());

        let replayed = fixture
            .driver
            .prepare_create_bundle(&request)
            .await
            .expect("replay runtime-owned bundle preparation");
        assert_eq!(replayed, staged);

        request.bundle = staged;
        fixture
            .driver
            .create(request.clone())
            .await
            .expect("create from runtime-owned bundle");
        fixture
            .driver
            .delete(DriverDeleteRequest {
                context: context("product-delete"),
                target: request.target,
                mode: DeleteMode::Force,
            })
            .await
            .expect("delete runtime-owned bundle generation");
        assert!(!expected.exists());
    }

    #[tokio::test]
    async fn runtime_bundle_handoff_cleans_committed_intent_before_move() {
        let fixture = Fixture::new();
        let request = fixture.handoff_request("product-box", 38, "product-create-pending");
        let source = request.bundle.directory().to_path_buf();
        let runtime_share =
            super::ensure_exact_runtime_share_path(&fixture.runtime_share_root, &request.target)
                .await
                .expect("exact runtime share");
        super::ensure_bundle_handoff_marker(
            &runtime_share,
            &request.target,
            request.bundle.config_digest(),
        )
        .await
        .expect("committed handoff intent");

        fixture
            .driver
            .cleanup_runtime_bundle_handoff(&request.target)
            .await
            .expect("clean handoff before move");

        assert!(source.exists());
        assert!(!runtime_share.exists());
    }

    #[tokio::test]
    async fn runtime_bundle_handoff_rejects_non_operation_source_before_launch() {
        let fixture = Fixture::new();
        let mut request = fixture.handoff_request("product-box", 9, "product-create-wrong");
        let outside = fixture.runtime_root.join("outside-bundle");
        std::fs::rename(request.bundle.directory(), &outside).expect("move bundle outside handoff");
        request.bundle = OciBundle::from_json(outside, request.bundle.config_json().to_string())
            .expect("outside handoff bundle");

        let error = fixture
            .driver
            .prepare_create_bundle(&request)
            .await
            .expect_err("non-operation handoff source must fail");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn stale_generation_and_external_bundle_fail_before_another_launch() {
        let fixture = Fixture::new();
        fixture
            .driver
            .create(fixture.create_request(1, "create-one"))
            .await
            .expect("first generation");
        let stale = fixture
            .driver
            .create(fixture.create_request(2, "create-two"))
            .await
            .expect_err("second generation must not replace a live VM");
        assert_eq!(stale.code, ErrorCode::Conflict);
        assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);

        let external = fixture._temporary.path().join("outside/workload");
        std::fs::create_dir_all(&external).expect("external bundle directory");
        let bundle = OciBundle::from_json(external, TEST_CONFIG).expect("external bundle");
        let mut request = fixture.create_request(3, "external-bundle");
        request.target = ContainerTarget::exact(
            ContainerId::new("external-test").expect("container ID"),
            Generation(1),
        );
        request.bundle = bundle;
        let error = fixture
            .driver
            .create(request)
            .await
            .expect_err("external bundle must fail");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
        fixture.driver.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn cross_generation_bundle_is_rejected_before_vm_launch() {
        let fixture = Fixture::new();
        let mut request = fixture.create_request(2, "cross-generation-bundle");
        request.bundle = fixture.bundle_for("whpx-test", 1);

        let error = fixture
            .driver
            .create(request)
            .await
            .expect_err("generation-two VM must not see generation-one share");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn owner_death_recovery_exposes_a_stopped_cleanup_tombstone() {
        let fixture = Fixture::new();
        let record = fixture.record(1, ContainerState::Running);
        let recovered = fixture
            .driver
            .recover(&record)
            .await
            .expect("recover missing live session");
        let (observation, init_exit_status) = recovered.into_parts();
        assert_eq!(observation, Some(super::DriverState::stopped()));
        assert_eq!(init_exit_status, None);
        assert_eq!(fixture.driver.active_session_count().await, 0);

        let target = target(1);
        assert_eq!(
            fixture
                .driver
                .state(target.clone())
                .await
                .expect("state recovered tombstone"),
            super::DriverState::stopped()
        );
        assert_eq!(
            fixture
                .driver
                .kill(DriverKillRequest {
                    context: context("recovered-kill"),
                    target: target.clone(),
                    signal: Signal::new(9).expect("signal"),
                    all: true,
                })
                .await
                .expect("kill recovered tombstone"),
            super::DriverState::stopped()
        );
        assert!(fixture
            .driver
            .processes(target.clone())
            .await
            .expect("processes recovered tombstone")
            .is_empty());

        let wait_error = fixture
            .driver
            .wait(DriverWaitRequest {
                target: target.clone(),
                timeout_ms: None,
            })
            .await
            .expect_err("recovery must not invent an exit status");
        assert_eq!(wait_error.code, ErrorCode::FailedPrecondition);
        assert!(!wait_error.retryable);
        assert!(wait_error.message.contains("exact init exit status"));

        fixture
            .driver
            .delete(delete_request(1))
            .await
            .expect("delete recovered tombstone");
        assert_eq!(fixture.guest.delete_calls.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 0);
        let missing = fixture
            .driver
            .state(target)
            .await
            .expect_err("deleted tombstone must be absent");
        assert_eq!(missing.code, ErrorCode::Unavailable);
    }

    #[tokio::test]
    async fn owner_death_recovery_replays_and_deletes_exact_init_exit() {
        let fixture = Fixture::new();
        let expected = ExitStatus::exited(37).expect("exit status");
        let report_path =
            fixture.write_recovery(1, fixture.bundle.config_digest(), expected.clone());
        let recovered = fixture
            .driver
            .recover(&fixture.record(1, ContainerState::Running))
            .await
            .expect("recover exact exit evidence");
        assert_eq!(
            recovered.into_parts(),
            (Some(super::DriverState::stopped()), Some(expected.clone()))
        );
        assert!(
            report_path.is_file(),
            "recovery faults must remain replayable"
        );
        assert_eq!(
            fixture
                .driver
                .wait(DriverWaitRequest {
                    target: target(1),
                    timeout_ms: Some(0),
                })
                .await
                .expect("wait recovered exit"),
            expected
        );
        fixture
            .driver
            .delete(delete_request(1))
            .await
            .expect("delete recovered evidence");
        assert!(!report_path.exists());
    }

    #[tokio::test]
    async fn recovery_waits_for_an_in_progress_shim_handoff() {
        let fixture = Fixture::new();
        let expected = ExitStatus::exited(41).expect("exit status");
        let report_path =
            fixture.write_recovery(1, fixture.bundle.config_digest(), expected.clone());
        let encoded = std::fs::read(&report_path).expect("read staged report");
        std::fs::remove_file(&report_path).expect("remove staged report");
        let pending = recovery_pending_path(&report_path);
        std::fs::write(&pending, b"").expect("pending marker");

        let writer_report = report_path.clone();
        let writer_pending = pending.clone();
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            tokio::fs::write(&writer_report, encoded)
                .await
                .expect("commit delayed report");
            tokio::fs::remove_file(&writer_pending)
                .await
                .expect("remove delayed pending marker");
        });
        let recovered = fixture
            .driver
            .recover(&fixture.record(1, ContainerState::Running))
            .await
            .expect("wait for recovery handoff");
        writer.await.expect("recovery writer task");
        assert_eq!(
            recovered.into_parts(),
            (Some(super::DriverState::stopped()), Some(expected))
        );
    }

    #[tokio::test]
    async fn recovery_handoff_timeout_is_retryable() {
        let fixture = Fixture::new();
        let report = fixture.recovery_directory.join("whpx-test-1.json");
        let pending = recovery_pending_path(&report);
        std::fs::write(&pending, b"").expect("pending marker");
        let error = fixture
            .driver
            .wait_for_recovery_report_until(&report, tokio::time::Instant::now())
            .await
            .expect_err("stuck handoff must fail service startup");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(error.retryable);
        assert!(
            pending.is_file(),
            "stuck marker must not be removed blindly"
        );
    }

    #[tokio::test]
    async fn recovery_rejects_a_mismatched_durable_config_digest() {
        let fixture = Fixture::new();
        fixture.write_recovery(
            1,
            &format!("sha256:{}", "c".repeat(64)),
            ExitStatus::exited(0).expect("exit status"),
        );
        let error = fixture
            .driver
            .recover(&fixture.record(1, ContainerState::Running))
            .await
            .expect_err("mismatched recovery digest must fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(error.message.contains("config digest mismatch"));
    }

    #[tokio::test]
    async fn recovery_queries_an_existing_live_generation() {
        let fixture = Fixture::new();
        fixture
            .driver
            .create(fixture.create_request(1, "live-recovery-create"))
            .await
            .expect("create live generation");
        let recovered = fixture
            .driver
            .recover(&fixture.record(1, ContainerState::Created))
            .await
            .expect("recover live generation");
        let (recovered, init_exit_status) = recovered.into_parts();
        let recovered = recovered.expect("live recovery observation");
        assert_eq!(init_exit_status, None);
        assert_eq!(recovered.status(), ContainerState::Created);
        assert_eq!(recovered.pid(), Some(101));
        assert_eq!(fixture.guest.state_calls.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.driver.active_session_count().await, 1);
        fixture
            .driver
            .shutdown()
            .await
            .expect("shutdown live recovery");
    }

    #[tokio::test]
    async fn interrupted_create_cannot_replace_a_recovered_generation() {
        let fixture = Fixture::new();
        let observation = fixture
            .driver
            .recover(&fixture.record(1, ContainerState::Creating))
            .await
            .expect("recover interrupted create");
        assert_eq!(
            observation,
            crate::DriverRecovery::none(),
            "creating cannot transition to stopped"
        );
        let error = fixture
            .driver
            .create(fixture.create_request(1, "recovered-create-retry"))
            .await
            .expect_err("recovered generation must not be recreated");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(!error.retryable);
        assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 0);
        fixture
            .driver
            .delete(delete_request(1))
            .await
            .expect("delete interrupted create tombstone");
    }

    #[tokio::test]
    async fn graceful_shutdown_reaps_live_vms_into_stopped_tombstones() {
        let fixture = Fixture::new();
        fixture
            .driver
            .create(fixture.create_request(1, "shutdown-create"))
            .await
            .expect("create before shutdown");
        fixture.driver.shutdown().await.expect("first shutdown");
        assert_eq!(fixture.driver.active_session_count().await, 0);
        assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            fixture
                .driver
                .state(target(1))
                .await
                .expect("state after shutdown"),
            super::DriverState::stopped()
        );
        fixture
            .driver
            .shutdown()
            .await
            .expect("idempotent shutdown");
        assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn candidate_remains_probe_only() {
        let fixture = Fixture::new();
        let capability = fixture.driver.capability();
        assert_eq!(capability.readiness, DriverReadiness::ProbeOnly);
        assert!(!capability.can_launch());
        assert!(fixture.driver.attachment_capabilities().supports_extension(
            RUNTIME_BUNDLE_HANDOFF_EXTENSION,
            a3s_oci_sdk::RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION,
        ));
    }
}
