use std::path::Path;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{ContainerTarget, ExitStatus};
use serde::{Deserialize, Serialize};

/// Versioned evidence emitted by the direct WHPX driver qualification path.
pub const WHPX_DRIVER_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.whpx-driver-smoke.v1";

/// Machine-readable evidence for one exact-generation WHPX driver lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhpxDriverSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the qualification was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of this qualification path.
    pub status: CapabilityStatus,
    /// Exact container generation used by the driver.
    pub target: ContainerTarget,
    /// Whether the host loaded and validated the OCI bundle.
    pub bundle_loaded: bool,
    /// Whether the bundle was below `shares/<container>/<generation>`.
    pub exact_runtime_share_layout: bool,
    /// Whether the qualification-only WHPX driver opened successfully.
    pub candidate_opened: bool,
    /// Whether the candidate remained deliberately non-registerable.
    pub readiness_remained_probe_only: bool,
    /// Whether the candidate advertised the protected per-generation share contract.
    pub runtime_share_capability_verified: bool,
    /// Whether create returned the exact OCI `created` barrier.
    pub create_returned_created: bool,
    /// Whether retrying create replayed the exact result without a second VM.
    pub create_replayed: bool,
    /// Guest init-wrapper PID returned by create.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_pid: Option<i32>,
    /// Whether the workload marker remained absent before start.
    pub marker_absent_after_create: bool,
    /// Whether start released the prepared init wrapper.
    pub start_released: bool,
    /// Whether retrying start replayed the exact running state.
    pub start_replayed: bool,
    /// Whether the driver observed the configured workload running.
    pub running_observed: bool,
    /// Whether a bounded wait refused to return while init was still running.
    pub wait_timeout_enforced: bool,
    /// Whether the exact signal request reached the guest executor.
    pub kill_delivered: bool,
    /// Whether retrying kill replayed the exact result.
    pub kill_replayed: bool,
    /// Exact terminal result returned for init.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_exit_status: Option<ExitStatus>,
    /// Whether repeated wait returned the exact same terminal result.
    pub wait_replayed: bool,
    /// Whether the driver observed the workload stopped.
    pub stopped_observed: bool,
    /// Whether the workload wrote the exact expected marker through its bundle rootfs.
    pub marker_verified: bool,
    /// Whether stopped-only delete completed guest and VM cleanup.
    pub delete_succeeded: bool,
    /// Whether successful VM shutdown verified shim v4 runtime-share evidence.
    pub runtime_share_configured: bool,
    /// Whether the driver removed the exact in-memory attachment after delete.
    pub driver_attachment_removed: bool,
    /// Whether the candidate retained no active VM session.
    pub session_reaped: bool,
    /// Whether the expected per-generation console is a regular file.
    pub console_created: bool,
    /// Whether one-time token and guest recovery directories were absent afterward.
    pub runtime_share_transients_clean: bool,
    /// Whether normalized recovery and pending artifacts were absent afterward.
    pub recovery_artifacts_clean: bool,
    /// Whether the known workload marker was removed by the qualification harness.
    pub marker_removed: bool,
    /// Whether final candidate shutdown completed successfully.
    pub candidate_shutdown_succeeded: bool,
    /// Diagnostic reason when qualification did not succeed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl WhpxDriverSmokeReport {
    fn initial(platform: HostPlatform, target: ContainerTarget) -> Self {
        Self {
            schema_version: WHPX_DRIVER_SMOKE_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            target,
            bundle_loaded: false,
            exact_runtime_share_layout: false,
            candidate_opened: false,
            readiness_remained_probe_only: false,
            runtime_share_capability_verified: false,
            create_returned_created: false,
            create_replayed: false,
            created_pid: None,
            marker_absent_after_create: false,
            start_released: false,
            start_replayed: false,
            running_observed: false,
            wait_timeout_enforced: false,
            kill_delivered: false,
            kill_replayed: false,
            wait_exit_status: None,
            wait_replayed: false,
            stopped_observed: false,
            marker_verified: false,
            delete_succeeded: false,
            runtime_share_configured: false,
            driver_attachment_removed: false,
            session_reaped: false,
            console_created: false,
            runtime_share_transients_clean: false,
            recovery_artifacts_clean: false,
            marker_removed: false,
            candidate_shutdown_succeeded: false,
            reason: None,
        }
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    fn unsupported(platform: HostPlatform, target: ContainerTarget) -> Self {
        let mut report = Self::initial(platform, target);
        report.status = CapabilityStatus::Unsupported;
        report.reason =
            Some("the direct WHPX driver smoke is implemented only for Windows x86_64".to_string());
        report
    }

    fn contract_complete(&self) -> bool {
        let expected_exit = ExitStatus::exited(0).ok();
        self.bundle_loaded
            && self.exact_runtime_share_layout
            && self.candidate_opened
            && self.readiness_remained_probe_only
            && self.runtime_share_capability_verified
            && self.create_returned_created
            && self.create_replayed
            && self.created_pid.is_some_and(|pid| pid > 0)
            && self.marker_absent_after_create
            && self.start_released
            && self.start_replayed
            && self.running_observed
            && self.wait_timeout_enforced
            && self.kill_delivered
            && self.kill_replayed
            && self.wait_exit_status == expected_exit
            && self.wait_replayed
            && self.stopped_observed
            && self.marker_verified
            && self.delete_succeeded
            && self.runtime_share_configured
            && self.driver_attachment_removed
            && self.session_reaped
            && self.console_created
            && self.runtime_share_transients_clean
            && self.recovery_artifacts_clean
            && self.marker_removed
            && self.candidate_shutdown_succeeded
            && self.reason.is_none()
    }

    /// Whether every required lifecycle and cleanup invariant passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status == CapabilityStatus::Available && self.contract_complete()
    }
}

/// Exercise one exact lifecycle through the qualification-only WHPX driver.
///
/// Unlike the diagnostic utility-VM commands, this path requires the bundle
/// below `runtime_root/shares/<container>/<generation>` and therefore proves
/// that the formal driver launches with its protected per-generation share.
#[must_use]
pub async fn whpx_driver_smoke(
    shim: &Path,
    runtime_root: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle: &Path,
    target: ContainerTarget,
) -> WhpxDriverSmokeReport {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        windows::run(
            shim,
            runtime_root,
            vm_rootfs,
            system_image_manifest,
            bundle,
            target,
        )
        .await
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        let _ = (shim, runtime_root, vm_rootfs, system_image_manifest, bundle);
        WhpxDriverSmokeReport::unsupported(HostPlatform::current(), target)
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod windows {
    use std::collections::BTreeSet;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use a3s_oci_agent_protocol::{
        AGENT_RECOVERY_REPORT_DIRECTORY_PREFIX, AGENT_RECOVERY_REPORT_PENDING_SUFFIX,
        AGENT_SESSION_TOKEN_DIRECTORY_PREFIX,
    };
    use a3s_oci_core::{CapabilityStatus, DriverReadiness, HostPlatform};
    use a3s_oci_sdk::oci_spec::runtime::ContainerState;
    use a3s_oci_sdk::{
        ContainerTarget, CreateAttachments, DeleteMode, ErrorCode, ExitStatus, IsolationRequest,
        OciBundle, OperationContext, OperationId, ProcessIo, Signal,
    };
    use tokio::io::AsyncReadExt;
    use tokio::time::{sleep, Instant};

    use super::WhpxDriverSmokeReport;
    use crate::{
        DriverCreateAttachments, DriverCreateRequest, DriverDeleteRequest, DriverKillRequest,
        DriverStartRequest, DriverWaitRequest, RuntimeDriver, WhpxRuntimeDriver,
        WhpxRuntimeDriverConfig,
    };

    const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(15);
    const POLL_INTERVAL: Duration = Duration::from_millis(25);
    const RUNNING_WAIT_TIMEOUT_MS: u64 = 100;
    const LINUX_SIGTERM: i32 = 15;
    const LINUX_SIGKILL: i32 = 9;
    const MARKER_NAME: &str = ".a3s-oci-create-start-smoke";
    const MARKER_CONTENTS: &[u8] = b"a3s-oci-create-start-user-time-v1\n";
    const MAX_MARKER_BYTES: u64 = 1_024;

    pub(super) async fn run(
        shim: &Path,
        runtime_root: &Path,
        vm_rootfs: &Path,
        system_image_manifest: &Path,
        bundle_directory: &Path,
        target: ContainerTarget,
    ) -> WhpxDriverSmokeReport {
        let mut report = WhpxDriverSmokeReport::initial(HostPlatform::Windows, target.clone());
        let Some(generation) = target.generation else {
            return failed(report, "WHPX driver smoke requires an exact generation");
        };
        let bundle = match OciBundle::load(bundle_directory).await {
            Ok(bundle) => {
                report.bundle_loaded = true;
                bundle
            }
            Err(error) => {
                return failed(
                    report,
                    format!("failed to load WHPX driver smoke bundle: {error}"),
                )
            }
        };
        let marker = match fixed_marker(&bundle).await {
            Ok(marker) => marker,
            Err(reason) => return failed(report, reason),
        };
        match path_exists(&marker).await {
            Ok(false) => {}
            Ok(true) => {
                return failed(
                    report,
                    format!(
                        "refusing to overwrite an existing WHPX driver smoke marker: {}",
                        marker.display()
                    ),
                )
            }
            Err(reason) => return failed(report, reason),
        }

        let runtime_root = match canonical_directory(runtime_root, "WHPX runtime root").await {
            Ok(path) => path,
            Err(reason) => return failed(report, reason),
        };
        let runtime_share = match canonical_directory(
            &runtime_root
                .join("shares")
                .join(target.id.as_str())
                .join(generation.0.to_string()),
            "exact WHPX runtime share",
        )
        .await
        {
            Ok(path) => path,
            Err(reason) => return failed(report, reason),
        };
        let bundle_directory = match canonical_directory(bundle.directory(), "OCI bundle").await {
            Ok(path) => path,
            Err(reason) => return failed(report, reason),
        };
        report.exact_runtime_share_layout =
            bundle_directory != runtime_share && bundle_directory.starts_with(&runtime_share);
        if !report.exact_runtime_share_layout {
            return failed(
                report,
                format!(
                    "WHPX driver smoke bundle must be a strict descendant of {}: {}",
                    runtime_share.display(),
                    bundle_directory.display()
                ),
            );
        }
        match runtime_transients(&runtime_share).await {
            Ok(entries) if entries.is_empty() => {}
            Ok(entries) => {
                return failed(
                    report,
                    format!(
                        "WHPX runtime share already contains transient handoff entries: {entries:?}"
                    ),
                )
            }
            Err(reason) => return failed(report, reason),
        }

        let driver = match WhpxRuntimeDriver::open_candidate(WhpxRuntimeDriverConfig::new(
            shim,
            &runtime_root,
            vm_rootfs,
            system_image_manifest,
        ))
        .await
        {
            Ok(driver) => {
                report.candidate_opened = true;
                driver
            }
            Err(error) => {
                return failed(
                    report,
                    format!("failed to open WHPX driver candidate: {error}"),
                )
            }
        };
        let capability = driver.capability();
        report.readiness_remained_probe_only = capability.status == CapabilityStatus::Available
            && capability.readiness == DriverReadiness::ProbeOnly;
        report.runtime_share_capability_verified = capability
            .evidence
            .get("runtime_share")
            .is_some_and(|value| value == "protected-per-generation-virtiofs");

        let exercise =
            if report.readiness_remained_probe_only && report.runtime_share_capability_verified {
                exercise(&driver, &bundle, &target, &marker, &mut report).await
            } else {
                Err("WHPX candidate did not retain its exact qualification capability".to_string())
            };
        if let Err(reason) = &exercise {
            append_reason(&mut report, reason.clone());
            best_effort_cleanup(&driver, &target).await;
        }

        match driver.shutdown().await {
            Ok(()) => report.candidate_shutdown_succeeded = true,
            Err(error) => append_reason(
                &mut report,
                format!("failed to shut down WHPX driver candidate: {error}"),
            ),
        }
        report.session_reaped = driver.active_session_count().await == 0;
        if !report.session_reaped {
            append_reason(
                &mut report,
                "WHPX driver retained an active utility-VM session",
            );
        }

        let console = runtime_root
            .join("console")
            .join(format!("{}-{}.log", target.id, generation.0));
        report.console_created = plain_file(&console).await.unwrap_or(false);
        if !report.console_created {
            append_reason(
                &mut report,
                format!(
                    "WHPX driver console is missing or not plain: {}",
                    console.display()
                ),
            );
        }
        match runtime_transients(&runtime_share).await {
            Ok(entries) => {
                report.runtime_share_transients_clean = entries.is_empty();
                if !entries.is_empty() {
                    append_reason(
                        &mut report,
                        format!("WHPX runtime share retained transient entries: {entries:?}"),
                    );
                }
            }
            Err(reason) => append_reason(&mut report, reason),
        }
        match recovery_artifacts_absent(&runtime_root, &target).await {
            Ok(absent) => {
                report.recovery_artifacts_clean = absent;
                if !absent {
                    append_reason(&mut report, "WHPX recovery artifacts remained after delete");
                }
            }
            Err(reason) => append_reason(&mut report, reason),
        }
        match remove_marker(&marker).await {
            Ok(()) => report.marker_removed = true,
            Err(reason) => append_reason(&mut report, reason),
        }

        if exercise.is_ok() && report.contract_complete() {
            report.status = CapabilityStatus::Available;
            report.reason = None;
        }
        report
    }

    async fn exercise(
        driver: &WhpxRuntimeDriver,
        bundle: &OciBundle,
        target: &ContainerTarget,
        marker: &Path,
        report: &mut WhpxDriverSmokeReport,
    ) -> Result<(), String> {
        let io = ProcessIo::default();
        let create = DriverCreateRequest {
            context: operation("whpx-driver-smoke-create")?,
            target: target.clone(),
            bundle: bundle.clone(),
            isolation: IsolationRequest::DedicatedVm,
            io: io.clone(),
            attachment_contract: CreateAttachments::from_bundle(bundle, io)
                .map_err(|error| format!("WHPX attachment contract failed: {error}"))?,
            attachments: DriverCreateAttachments::None,
        };
        let created = driver
            .create(create.clone())
            .await
            .map_err(|error| format!("WHPX driver create failed: {error}"))?;
        report.create_returned_created = created.status() == ContainerState::Created;
        report.created_pid = created.pid();
        if !report.create_returned_created {
            return Err("WHPX driver create did not preserve the created barrier".to_string());
        }
        let observed = driver
            .state(target.clone())
            .await
            .map_err(|error| format!("WHPX driver state after create failed: {error}"))?;
        if observed != created {
            return Err("WHPX driver state after create differed from create".to_string());
        }
        report.create_replayed = driver
            .create(create)
            .await
            .map_err(|error| format!("WHPX driver create replay failed: {error}"))?
            == created;
        if !report.create_replayed {
            return Err("WHPX driver did not replay the exact create result".to_string());
        }
        report.marker_absent_after_create = !path_exists(marker).await?;
        if !report.marker_absent_after_create {
            return Err("WHPX workload ran before the start request".to_string());
        }

        let start = DriverStartRequest {
            context: operation("whpx-driver-smoke-start")?,
            target: target.clone(),
            bundle: bundle.clone(),
        };
        let started = driver
            .start(start.clone())
            .await
            .map_err(|error| format!("WHPX driver start failed: {error}"))?;
        report.start_released = started.status() == ContainerState::Running;
        if !report.start_released {
            return Err("WHPX driver start did not return running".to_string());
        }
        report.start_replayed = driver
            .start(start)
            .await
            .map_err(|error| format!("WHPX driver start replay failed: {error}"))?
            == started;
        if !report.start_replayed {
            return Err("WHPX driver did not replay the exact start result".to_string());
        }
        wait_for_running_and_marker(driver, target, marker).await?;
        report.running_observed = true;

        report.wait_timeout_enforced = match driver
            .wait(DriverWaitRequest {
                target: target.clone(),
                timeout_ms: Some(RUNNING_WAIT_TIMEOUT_MS),
            })
            .await
        {
            Err(error) if error.code == ErrorCode::DeadlineExceeded => true,
            Err(error) => {
                return Err(format!(
                    "WHPX running wait returned the wrong error: {error}"
                ))
            }
            Ok(status) => {
                return Err(format!(
                    "WHPX running wait returned prematurely with {status:?}"
                ))
            }
        };

        let kill = DriverKillRequest {
            context: operation("whpx-driver-smoke-kill")?,
            target: target.clone(),
            signal: Signal::new(LINUX_SIGTERM)
                .map_err(|error| format!("invalid WHPX smoke signal: {error}"))?,
            all: false,
        };
        let killed = driver
            .kill(kill.clone())
            .await
            .map_err(|error| format!("WHPX driver kill failed: {error}"))?;
        report.kill_delivered = matches!(
            killed.status(),
            ContainerState::Running | ContainerState::Stopped
        );
        if !report.kill_delivered {
            return Err("WHPX driver kill returned an invalid state".to_string());
        }
        report.kill_replayed = driver
            .kill(kill)
            .await
            .map_err(|error| format!("WHPX driver kill replay failed: {error}"))?
            == killed;
        if !report.kill_replayed {
            return Err("WHPX driver did not replay the exact kill result".to_string());
        }

        let wait = DriverWaitRequest {
            target: target.clone(),
            timeout_ms: Some(
                u64::try_from(LIFECYCLE_TIMEOUT.as_millis())
                    .map_err(|_| "WHPX lifecycle timeout does not fit u64".to_string())?,
            ),
        };
        let waited = driver
            .wait(wait.clone())
            .await
            .map_err(|error| format!("WHPX driver wait failed: {error}"))?;
        let expected = ExitStatus::exited(0)
            .map_err(|error| format!("failed to construct expected exit status: {error}"))?;
        report.wait_exit_status = Some(waited.clone());
        if waited != expected {
            return Err(format!(
                "WHPX driver wait returned {waited:?}, expected {expected:?}"
            ));
        }
        report.wait_replayed = driver
            .wait(wait)
            .await
            .map_err(|error| format!("WHPX driver repeated wait failed: {error}"))?
            == waited;
        if !report.wait_replayed {
            return Err("WHPX driver repeated wait changed the exit result".to_string());
        }
        wait_for_stopped(driver, target).await?;
        report.stopped_observed = true;
        report.marker_verified = read_marker(marker).await? == MARKER_CONTENTS;
        if !report.marker_verified {
            return Err("WHPX workload marker did not contain exact evidence".to_string());
        }

        driver
            .delete(DriverDeleteRequest {
                context: operation("whpx-driver-smoke-delete")?,
                target: target.clone(),
                mode: DeleteMode::StoppedOnly,
            })
            .await
            .map_err(|error| format!("WHPX driver delete failed: {error}"))?;
        report.delete_succeeded = true;
        // A successful live delete includes UtilityVmSession shutdown, whose
        // The driver-owned contract rejects missing shim v4 runtime-share evidence.
        report.runtime_share_configured = true;
        report.driver_attachment_removed = matches!(
            driver.state(target.clone()).await,
            Err(error) if error.code == ErrorCode::Unavailable
        );
        if !report.driver_attachment_removed {
            return Err("WHPX driver retained the deleted attachment".to_string());
        }
        Ok(())
    }

    async fn best_effort_cleanup(driver: &WhpxRuntimeDriver, target: &ContainerTarget) {
        if let Ok(state) = driver.state(target.clone()).await {
            if state.status() == ContainerState::Running {
                if let (Ok(context), Ok(signal)) = (
                    operation("whpx-driver-smoke-cleanup-kill"),
                    Signal::new(LINUX_SIGKILL),
                ) {
                    let _ = driver
                        .kill(DriverKillRequest {
                            context,
                            target: target.clone(),
                            signal,
                            all: true,
                        })
                        .await;
                }
            }
            if let Ok(context) = operation("whpx-driver-smoke-cleanup-delete") {
                let _ = driver
                    .delete(DriverDeleteRequest {
                        context,
                        target: target.clone(),
                        mode: DeleteMode::Force,
                    })
                    .await;
            }
        }
    }

    async fn wait_for_running_and_marker(
        driver: &WhpxRuntimeDriver,
        target: &ContainerTarget,
        marker: &Path,
    ) -> Result<(), String> {
        let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
        loop {
            let state = driver
                .state(target.clone())
                .await
                .map_err(|error| format!("failed to observe running WHPX state: {error}"))?;
            if state.status() == ContainerState::Running && path_exists(marker).await? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for the WHPX workload marker".to_string());
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    async fn wait_for_stopped(
        driver: &WhpxRuntimeDriver,
        target: &ContainerTarget,
    ) -> Result<(), String> {
        let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
        loop {
            let state = driver
                .state(target.clone())
                .await
                .map_err(|error| format!("failed to observe stopped WHPX state: {error}"))?;
            if state.status() == ContainerState::Stopped {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for stopped WHPX state".to_string());
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    async fn fixed_marker(bundle: &OciBundle) -> Result<PathBuf, String> {
        let root = bundle
            .spec()
            .root()
            .as_ref()
            .ok_or_else(|| "WHPX driver smoke bundle has no root filesystem".to_string())?;
        if root.path() != Path::new("rootfs") || root.readonly().unwrap_or(false) {
            return Err(
                "WHPX driver smoke requires writable normalized relative root.path `rootfs`"
                    .to_string(),
            );
        }
        let rootfs =
            canonical_directory(&bundle.directory().join(root.path()), "container rootfs").await?;
        if rootfs == bundle.directory() || !rootfs.starts_with(bundle.directory()) {
            return Err(format!(
                "WHPX driver smoke rootfs escapes bundle {}: {}",
                bundle.directory().display(),
                rootfs.display()
            ));
        }
        Ok(rootfs.join(MARKER_NAME))
    }

    async fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
        let canonical = tokio::fs::canonicalize(path)
            .await
            .map_err(|error| format!("failed to resolve {label} {}: {error}", path.display()))?;
        let metadata = tokio::fs::metadata(&canonical).await.map_err(|error| {
            format!("failed to inspect {label} {}: {error}", canonical.display())
        })?;
        if !metadata.is_dir() {
            return Err(format!(
                "{label} is not a directory: {}",
                canonical.display()
            ));
        }
        Ok(canonical)
    }

    async fn runtime_transients(runtime_share: &Path) -> Result<BTreeSet<String>, String> {
        let mut entries = tokio::fs::read_dir(runtime_share).await.map_err(|error| {
            format!(
                "failed to inspect WHPX runtime share {}: {error}",
                runtime_share.display()
            )
        })?;
        let mut transient = BTreeSet::new();
        while let Some(entry) = entries.next_entry().await.map_err(|error| {
            format!(
                "failed to enumerate WHPX runtime share {}: {error}",
                runtime_share.display()
            )
        })? {
            let name = entry.file_name().into_string().map_err(|_| {
                format!(
                    "WHPX runtime share contains a non-Unicode entry: {}",
                    runtime_share.display()
                )
            })?;
            if name.starts_with(AGENT_SESSION_TOKEN_DIRECTORY_PREFIX)
                || name.starts_with(AGENT_RECOVERY_REPORT_DIRECTORY_PREFIX)
            {
                transient.insert(name);
            }
        }
        Ok(transient)
    }

    async fn recovery_artifacts_absent(
        runtime_root: &Path,
        target: &ContainerTarget,
    ) -> Result<bool, String> {
        let generation = target
            .generation
            .ok_or_else(|| "WHPX recovery path requires an exact generation".to_string())?;
        let report = runtime_root
            .join("recovery")
            .join(format!("{}-{}.json", target.id, generation.0));
        let mut pending = OsString::from(report.as_os_str());
        pending.push(AGENT_RECOVERY_REPORT_PENDING_SUFFIX);
        Ok(!path_exists(&report).await? && !path_exists(Path::new(&pending)).await?)
    }

    async fn read_marker(path: &Path) -> Result<Vec<u8>, String> {
        let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
            format!(
                "failed to inspect WHPX smoke marker {}: {error}",
                path.display()
            )
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!(
                "WHPX smoke marker is not a plain file: {}",
                path.display()
            ));
        }
        let file = tokio::fs::File::open(path).await.map_err(|error| {
            format!(
                "failed to open WHPX smoke marker {}: {error}",
                path.display()
            )
        })?;
        let mut contents = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_MARKER_BYTES + 1)
            .read_to_end(&mut contents)
            .await
            .map_err(|error| {
                format!(
                    "failed to read WHPX smoke marker {}: {error}",
                    path.display()
                )
            })?;
        if contents.len() as u64 > MAX_MARKER_BYTES {
            return Err("WHPX smoke marker exceeded its bounded size".to_string());
        }
        Ok(contents)
    }

    async fn remove_marker(path: &Path) -> Result<(), String> {
        match tokio::fs::symlink_metadata(path).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                tokio::fs::remove_file(path).await.map_err(|error| {
                    format!(
                        "failed to remove WHPX smoke marker {}: {error}",
                        path.display()
                    )
                })
            }
            Ok(_) => Err(format!(
                "refusing to remove a non-plain WHPX smoke marker: {}",
                path.display()
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "failed to inspect WHPX smoke marker before removal {}: {error}",
                path.display()
            )),
        }
    }

    async fn plain_file(path: &Path) -> Result<bool, String> {
        match tokio::fs::symlink_metadata(path).await {
            Ok(metadata) => Ok(metadata.is_file() && !metadata.file_type().is_symlink()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!("failed to inspect {}: {error}", path.display())),
        }
    }

    async fn path_exists(path: &Path) -> Result<bool, String> {
        match tokio::fs::symlink_metadata(path).await {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!("failed to inspect {}: {error}", path.display())),
        }
    }

    fn operation(id: &str) -> Result<OperationContext, String> {
        OperationId::new(id)
            .map(OperationContext::new)
            .map_err(|error| format!("failed to construct WHPX smoke operation: {error}"))
    }

    fn append_reason(report: &mut WhpxDriverSmokeReport, reason: impl Into<String>) {
        let reason = reason.into();
        report.reason = Some(match report.reason.take() {
            Some(existing) if existing != reason => format!("{existing}; {reason}"),
            Some(existing) => existing,
            None => reason,
        });
    }

    fn failed(
        mut report: WhpxDriverSmokeReport,
        reason: impl Into<String>,
    ) -> WhpxDriverSmokeReport {
        report.reason = Some(reason.into());
        report
    }

    #[cfg(test)]
    mod tests {
        use a3s_oci_agent_protocol::{
            AGENT_RECOVERY_REPORT_DIRECTORY_PREFIX, AGENT_SESSION_TOKEN_DIRECTORY_PREFIX,
        };

        use super::runtime_transients;

        #[tokio::test]
        async fn runtime_transient_inventory_is_exactly_prefix_scoped() {
            let temporary = tempfile::tempdir().expect("temporary runtime share");
            std::fs::create_dir(temporary.path().join("workloads")).expect("workload directory");
            std::fs::create_dir(
                temporary
                    .path()
                    .join(format!("{AGENT_SESSION_TOKEN_DIRECTORY_PREFIX}token")),
            )
            .expect("token directory");
            std::fs::create_dir(
                temporary
                    .path()
                    .join(format!("{AGENT_RECOVERY_REPORT_DIRECTORY_PREFIX}report")),
            )
            .expect("recovery directory");

            let entries = runtime_transients(temporary.path())
                .await
                .expect("transient inventory");
            assert_eq!(entries.len(), 2);
            assert!(entries.iter().all(|name| !name.starts_with("workloads")));
        }
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_core::{CapabilityStatus, HostPlatform};
    use a3s_oci_sdk::{ContainerId, ContainerTarget, Generation};

    use super::WhpxDriverSmokeReport;

    #[test]
    fn report_is_fail_closed_until_every_invariant_is_present() {
        let report = WhpxDriverSmokeReport::initial(
            HostPlatform::current(),
            ContainerTarget::exact(
                ContainerId::new("whpx-report-test").expect("container ID"),
                Generation(1),
            ),
        );
        assert_eq!(report.status, CapabilityStatus::Unavailable);
        assert!(!report.is_success());
    }
}
