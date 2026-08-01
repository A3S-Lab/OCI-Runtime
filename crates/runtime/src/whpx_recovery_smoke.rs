use std::path::Path;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{ContainerId, ContainerTarget, ExitStatus, Result};
use serde::{Deserialize, Serialize};

/// Versioned readiness handoff written by the process that owns the live VM.
pub const WHPX_RECOVERY_OWNER_READY_SCHEMA_VERSION: &str = "a3s.oci.whpx-recovery-owner-ready.v1";
/// Versioned evidence emitted after owner death and host-service recovery.
pub const WHPX_RECOVERY_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.whpx-recovery-smoke.v1";

/// Machine-readable point at which the qualification parent may kill the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhpxRecoveryOwnerReady {
    pub schema_version: String,
    pub status: CapabilityStatus,
    pub target: ContainerTarget,
    pub config_digest: String,
    pub owner_pid: u32,
    pub created_pid: i32,
    pub running_observed: bool,
    pub marker_observed: bool,
    pub qualification_override_scoped: bool,
}

/// Real-host evidence for WHPX owner-death and host-service restart recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhpxRecoverySmokeReport {
    pub schema_version: String,
    pub platform: HostPlatform,
    pub status: CapabilityStatus,
    pub target: ContainerTarget,
    pub bundle_loaded: bool,
    pub default_candidate_remained_probe_only: bool,
    pub qualification_override_scoped: bool,
    pub before_recover_fault_injected: bool,
    pub handoff_retained_after_before_fault: bool,
    pub after_recover_fault_injected: bool,
    pub report_retained_after_after_fault: bool,
    pub host_service_reopened: bool,
    pub stopped_observed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovered_exit_status: Option<ExitStatus>,
    pub wait_replayed: bool,
    pub driver_kill_replayed: bool,
    pub marker_verified_after_owner_death: bool,
    pub delete_succeeded: bool,
    pub durable_record_removed: bool,
    pub driver_attachment_removed: bool,
    pub session_reaped: bool,
    pub console_created: bool,
    pub runtime_share_transients_clean: bool,
    pub recovery_artifacts_clean: bool,
    pub marker_removed: bool,
    pub candidate_shutdown_succeeded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl WhpxRecoverySmokeReport {
    fn initial(platform: HostPlatform, target: ContainerTarget) -> Self {
        Self {
            schema_version: WHPX_RECOVERY_SMOKE_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            target,
            bundle_loaded: false,
            default_candidate_remained_probe_only: false,
            qualification_override_scoped: false,
            before_recover_fault_injected: false,
            handoff_retained_after_before_fault: false,
            after_recover_fault_injected: false,
            report_retained_after_after_fault: false,
            host_service_reopened: false,
            stopped_observed: false,
            recovered_exit_status: None,
            wait_replayed: false,
            driver_kill_replayed: false,
            marker_verified_after_owner_death: false,
            delete_succeeded: false,
            durable_record_removed: false,
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
        report.reason = Some(
            "the WHPX host-service recovery smoke is implemented only for Windows x86_64"
                .to_string(),
        );
        report
    }

    fn contract_complete(&self) -> bool {
        self.bundle_loaded
            && self.default_candidate_remained_probe_only
            && self.qualification_override_scoped
            && self.before_recover_fault_injected
            && self.handoff_retained_after_before_fault
            && self.after_recover_fault_injected
            && self.report_retained_after_after_fault
            && self.host_service_reopened
            && self.stopped_observed
            && self.recovered_exit_status.is_some()
            && self.wait_replayed
            && self.driver_kill_replayed
            && self.marker_verified_after_owner_death
            && self.delete_succeeded
            && self.durable_record_removed
            && self.driver_attachment_removed
            && self.session_reaped
            && self.console_created
            && self.runtime_share_transients_clean
            && self.recovery_artifacts_clean
            && self.marker_removed
            && self.candidate_shutdown_succeeded
            && self.reason.is_none()
    }

    /// Whether every owner-death, fault-recovery, replay, and cleanup gate passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status == CapabilityStatus::Available && self.contract_complete()
    }
}

/// Start a durable WHPX host service, run one workload, publish readiness, and
/// remain alive until the qualification parent forcibly terminates this process.
pub async fn whpx_recovery_owner(
    shim: &Path,
    runtime_root: &Path,
    vm_rootfs: &Path,
    state_root: &Path,
    bundle: &Path,
    container_id: ContainerId,
    ready_file: &Path,
) -> Result<()> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        windows::owner(
            shim,
            runtime_root,
            vm_rootfs,
            state_root,
            bundle,
            container_id,
            ready_file,
        )
        .await
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        let _ = (
            shim,
            runtime_root,
            vm_rootfs,
            state_root,
            bundle,
            container_id,
            ready_file,
        );
        Err(a3s_oci_sdk::Error::unsupported("whpx-recovery-owner"))
    }
}

/// Reopen durable state after the owner was killed, inject both sides of the
/// recovery boundary, and finish exact wait/delete cleanup.
#[must_use]
pub async fn whpx_recovery_resume(
    shim: &Path,
    runtime_root: &Path,
    vm_rootfs: &Path,
    state_root: &Path,
    bundle: &Path,
    target: ContainerTarget,
) -> WhpxRecoverySmokeReport {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        windows::resume(shim, runtime_root, vm_rootfs, state_root, bundle, target).await
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        let _ = (shim, runtime_root, vm_rootfs, state_root, bundle);
        WhpxRecoverySmokeReport::unsupported(HostPlatform::current(), target)
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod windows {
    use std::collections::BTreeSet;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use a3s_oci_agent_protocol::{
        AGENT_RECOVERY_REPORT_DIRECTORY_PREFIX, AGENT_RECOVERY_REPORT_PENDING_SUFFIX,
        AGENT_SESSION_TOKEN_DIRECTORY_PREFIX,
    };
    use a3s_oci_core::{CapabilityStatus, DriverReadiness, HostPlatform};
    use a3s_oci_sdk::oci_spec::runtime::ContainerState;
    use a3s_oci_sdk::{
        ContainerId, ContainerTarget, CreateAttachments, CreateRequest, DeleteMode, DeleteRequest,
        Error, ErrorCode, ListRequest, OciBundle, OciRuntimeService, OperationContext, OperationId,
        ProcessIo, Result, Signal, StartRequest, StateRequest, WaitRequest,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{sleep, Instant};

    use super::{WhpxRecoveryOwnerReady, WhpxRecoverySmokeReport};
    use crate::fault::{DriverBoundaryStage, DriverOperation, FaultInjector, FaultPoint};
    use crate::{
        DriverKillRequest, HostRuntimeService, RuntimeDriver, WhpxRuntimeDriver,
        WhpxRuntimeDriverConfig, WHPX_RECOVERY_OWNER_READY_SCHEMA_VERSION,
    };

    const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(20);
    const OWNER_MAX_LIFETIME: Duration = Duration::from_secs(300);
    const POLL_INTERVAL: Duration = Duration::from_millis(25);
    const LINUX_SIGKILL: i32 = 9;
    const MARKER_NAME: &str = ".a3s-oci-create-start-smoke";
    const MARKER_CONTENTS: &[u8] = b"a3s-oci-create-start-user-time-v1\n";
    const MAX_MARKER_BYTES: u64 = 1_024;

    pub(super) async fn owner(
        shim: &Path,
        runtime_root: &Path,
        vm_rootfs: &Path,
        state_root: &Path,
        bundle_directory: &Path,
        container_id: ContainerId,
        ready_file: &Path,
    ) -> Result<()> {
        let bundle = OciBundle::load(bundle_directory).await?;
        let marker = fixed_marker(&bundle).await.map_err(owner_error)?;
        if path_exists(&marker).await.map_err(owner_error)? {
            return Err(owner_error(format!(
                "refusing to overwrite an existing recovery-smoke marker: {}",
                marker.display()
            )));
        }

        let config = WhpxRuntimeDriverConfig::new(shim, runtime_root, vm_rootfs);
        let driver = Arc::new(WhpxRuntimeDriver::open_service_qualification(config).await?);
        let capability = driver.capability();
        let qualification_override_scoped = capability.readiness == DriverReadiness::Experimental
            && capability
                .evidence
                .get("qualification_override")
                .is_some_and(|value| value == "host-service-owner-death-only");
        if !qualification_override_scoped {
            return Err(owner_error(
                "WHPX recovery owner did not receive the scoped qualification capability",
            ));
        }
        let runtime_driver: Arc<dyn RuntimeDriver> = driver.clone();
        let service = HostRuntimeService::open(state_root, runtime_driver).await?;
        let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())?;
        let created = service
            .create(CreateRequest {
                context: operation("whpx-recovery-owner-create")?,
                id: container_id.clone(),
                bundle,
                isolation: a3s_oci_sdk::IsolationRequest::DedicatedVm,
                attachments,
            })
            .await?;
        if *created.state.status() != ContainerState::Created {
            return Err(owner_error(
                "WHPX recovery owner create did not preserve the created barrier",
            ));
        }
        let created_pid = created.state.pid().ok_or_else(|| {
            owner_error("WHPX recovery owner create returned no configured init PID")
        })?;
        let target = ContainerTarget::exact(container_id, created.generation);
        let started = service
            .start(StartRequest {
                context: operation("whpx-recovery-owner-start")?,
                target: target.clone(),
            })
            .await?;
        if *started.state.status() != ContainerState::Running {
            return Err(owner_error(
                "WHPX recovery owner start did not return running state",
            ));
        }
        wait_for_running_and_marker(&service, &target, &marker).await?;

        write_ready(
            ready_file,
            &WhpxRecoveryOwnerReady {
                schema_version: WHPX_RECOVERY_OWNER_READY_SCHEMA_VERSION.to_string(),
                status: CapabilityStatus::Available,
                target: target.clone(),
                config_digest: created.config_digest,
                owner_pid: std::process::id(),
                created_pid,
                running_observed: true,
                marker_observed: true,
                qualification_override_scoped,
            },
        )
        .await?;

        sleep(OWNER_MAX_LIFETIME).await;
        let _ = service
            .kill(a3s_oci_sdk::KillRequest {
                context: operation("whpx-recovery-owner-timeout-kill")?,
                target: target.clone(),
                signal: Signal::new(LINUX_SIGKILL)?,
                all: true,
            })
            .await;
        let _ = service
            .delete(DeleteRequest {
                context: operation("whpx-recovery-owner-timeout-delete")?,
                target,
                mode: DeleteMode::Force,
            })
            .await;
        let _ = driver.shutdown().await;
        Err(Error::new(
            ErrorCode::DeadlineExceeded,
            "the WHPX recovery owner was not externally terminated within five minutes",
        )
        .for_operation("whpx-recovery-owner"))
    }

    pub(super) async fn resume(
        shim: &Path,
        runtime_root: &Path,
        vm_rootfs: &Path,
        state_root: &Path,
        bundle_directory: &Path,
        target: ContainerTarget,
    ) -> WhpxRecoverySmokeReport {
        let mut report = WhpxRecoverySmokeReport::initial(HostPlatform::Windows, target.clone());
        let bundle = match OciBundle::load(bundle_directory).await {
            Ok(bundle) => {
                report.bundle_loaded = true;
                bundle
            }
            Err(error) => {
                return failed(report, format!("failed to load recovery bundle: {error}"))
            }
        };
        let marker = match fixed_marker(&bundle).await {
            Ok(marker) => marker,
            Err(reason) => return failed(report, reason),
        };
        if target.generation.is_none() {
            return failed(report, "WHPX recovery smoke requires an exact generation");
        }
        let config = WhpxRuntimeDriverConfig::new(shim, runtime_root, vm_rootfs);

        let default_candidate = match WhpxRuntimeDriver::open_candidate(config.clone()).await {
            Ok(driver) => driver,
            Err(error) => {
                return failed(
                    report,
                    format!("failed to reopen default WHPX candidate: {error}"),
                )
            }
        };
        report.default_candidate_remained_probe_only =
            default_candidate.capability().readiness == DriverReadiness::ProbeOnly;
        drop(default_candidate);
        if !report.default_candidate_remained_probe_only {
            return failed(
                report,
                "default WHPX candidate no longer reports probe-only",
            );
        }

        report.before_recover_fault_injected =
            match inject_recovery_fault(state_root, &config, DriverBoundaryStage::BeforeCall).await
            {
                Ok(injected) => injected,
                Err(reason) => return failed(report, reason),
            };
        if !report.before_recover_fault_injected {
            return failed(report, "before-recover fault was not reached exactly once");
        }
        report.handoff_retained_after_before_fault =
            match recovery_handoff_present(runtime_root, &target).await {
                Ok(present) => present,
                Err(reason) => return failed(report, reason),
            };
        if !report.handoff_retained_after_before_fault {
            return failed(
                report,
                "owner-death handoff disappeared after the before-recover fault",
            );
        }

        report.after_recover_fault_injected = match inject_recovery_fault(
            state_root,
            &config,
            DriverBoundaryStage::AfterCall,
        )
        .await
        {
            Ok(injected) => injected,
            Err(reason) => return failed(report, reason),
        };
        if !report.after_recover_fault_injected {
            return failed(report, "after-recover fault was not reached exactly once");
        }
        report.report_retained_after_after_fault =
            match recovery_report_is_plain(runtime_root, &target).await {
                Ok(present) => present,
                Err(reason) => return failed(report, reason),
            };
        if !report.report_retained_after_after_fault {
            return failed(
                report,
                "authenticated recovery report disappeared after the after-recover fault",
            );
        }

        let driver = match WhpxRuntimeDriver::open_service_qualification(config).await {
            Ok(driver) => Arc::new(driver),
            Err(error) => {
                return failed(
                    report,
                    format!("failed to open recovery qualification driver: {error}"),
                )
            }
        };
        let capability = driver.capability();
        report.qualification_override_scoped = capability.readiness
            == DriverReadiness::Experimental
            && capability
                .evidence
                .get("qualification_override")
                .is_some_and(|value| value == "host-service-owner-death-only");
        if !report.qualification_override_scoped {
            return failed(
                report,
                "reopened WHPX driver did not retain the scoped qualification capability",
            );
        }
        let runtime_driver: Arc<dyn RuntimeDriver> = driver.clone();
        let service = match HostRuntimeService::open(state_root, runtime_driver).await {
            Ok(service) => {
                report.host_service_reopened = true;
                service
            }
            Err(error) => {
                return failed(
                    report,
                    format!("failed to reopen WHPX host service: {error}"),
                )
            }
        };

        let exercise =
            exercise_recovered_service(&service, &driver, &target, &marker, &mut report).await;
        if let Err(reason) = &exercise {
            append_reason(&mut report, reason.clone());
        }
        match driver.shutdown().await {
            Ok(()) => report.candidate_shutdown_succeeded = true,
            Err(error) => append_reason(
                &mut report,
                format!("failed to shut down recovered WHPX candidate: {error}"),
            ),
        }
        report.session_reaped = driver.active_session_count().await == 0;
        if !report.session_reaped {
            append_reason(
                &mut report,
                "recovered WHPX candidate retained an active utility-VM session",
            );
        }

        let generation = target.generation.expect("exact generation checked above");
        let console = runtime_root
            .join("console")
            .join(format!("{}-{}.log", target.id, generation.0));
        report.console_created = plain_file(&console).await.unwrap_or(false);
        match runtime_transients(
            &runtime_root
                .join("shares")
                .join(target.id.as_str())
                .join(generation.0.to_string()),
        )
        .await
        {
            Ok(entries) => report.runtime_share_transients_clean = entries.is_empty(),
            Err(reason) => append_reason(&mut report, reason),
        }
        match recovery_artifacts_absent(runtime_root, &target).await {
            Ok(absent) => report.recovery_artifacts_clean = absent,
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

    async fn exercise_recovered_service(
        service: &HostRuntimeService,
        driver: &Arc<WhpxRuntimeDriver>,
        target: &ContainerTarget,
        marker: &Path,
        report: &mut WhpxRecoverySmokeReport,
    ) -> std::result::Result<(), String> {
        let state = service
            .state(StateRequest {
                target: target.clone(),
            })
            .await
            .map_err(|error| format!("recovered state failed: {error}"))?;
        report.stopped_observed = *state.state.status() == ContainerState::Stopped;
        if !report.stopped_observed {
            return Err(format!(
                "recovered host service returned {:?}, expected stopped",
                state.state.status()
            ));
        }
        report.marker_verified_after_owner_death = read_marker(marker).await? == MARKER_CONTENTS;
        if !report.marker_verified_after_owner_death {
            return Err("workload marker changed across owner death".to_string());
        }

        let wait = WaitRequest {
            target: target.clone(),
            timeout_ms: Some(0),
        };
        let exit = service
            .wait(wait.clone())
            .await
            .map_err(|error| format!("recovered wait failed: {error}"))?;
        exit.validate()
            .map_err(|error| format!("recovered exit status is invalid: {error}"))?;
        report.recovered_exit_status = Some(exit.clone());
        report.wait_replayed = service
            .wait(wait)
            .await
            .map_err(|error| format!("repeated recovered wait failed: {error}"))?
            == exit;
        if !report.wait_replayed {
            return Err("repeated recovered wait changed the exact exit result".to_string());
        }

        let kill = DriverKillRequest {
            context: operation("whpx-recovery-resume-kill").map_err(|error| error.to_string())?,
            target: target.clone(),
            signal: Signal::new(LINUX_SIGKILL).map_err(|error| error.to_string())?,
            all: true,
        };
        let killed = driver
            .kill(kill.clone())
            .await
            .map_err(|error| format!("recovered driver tombstone kill failed: {error}"))?;
        let replayed = driver
            .kill(kill)
            .await
            .map_err(|error| format!("repeated recovered driver tombstone kill failed: {error}"))?;
        report.driver_kill_replayed =
            killed == replayed && killed.status() == ContainerState::Stopped;
        if !report.driver_kill_replayed {
            return Err("recovered driver kill did not replay the stopped tombstone".to_string());
        }

        service
            .delete(DeleteRequest {
                context: operation("whpx-recovery-resume-delete")
                    .map_err(|error| error.to_string())?,
                target: target.clone(),
                mode: DeleteMode::StoppedOnly,
            })
            .await
            .map_err(|error| format!("recovered delete failed: {error}"))?;
        report.delete_succeeded = true;
        report.durable_record_removed = service
            .list(ListRequest::default())
            .await
            .map_err(|error| format!("post-delete durable list failed: {error}"))?
            .is_empty()
            && matches!(
                service
                    .state(StateRequest {
                        target: target.clone(),
                    })
                    .await,
                Err(error) if error.code == ErrorCode::NotFound
            );
        report.driver_attachment_removed = matches!(
            driver.state(target.clone()).await,
            Err(error) if error.code == ErrorCode::Unavailable
        );
        if !report.durable_record_removed || !report.driver_attachment_removed {
            return Err("recovered delete retained durable or driver state".to_string());
        }
        Ok(())
    }

    async fn inject_recovery_fault(
        state_root: &Path,
        config: &WhpxRuntimeDriverConfig,
        stage: DriverBoundaryStage,
    ) -> std::result::Result<bool, String> {
        let driver = Arc::new(
            WhpxRuntimeDriver::open_service_qualification(config.clone())
                .await
                .map_err(|error| format!("failed to open fault qualification driver: {error}"))?,
        );
        let injector = Arc::new(RecoveryFaultInjector::new(stage));
        let faults: Arc<dyn FaultInjector> = injector.clone();
        let runtime_driver: Arc<dyn RuntimeDriver> = driver.clone();
        let opened =
            HostRuntimeService::open_with_fault_injector(state_root, runtime_driver, faults).await;
        let injected = matches!(
            opened,
            Err(ref error)
                if error.code == ErrorCode::Unavailable
                    && error.retryable
                    && error.operation.as_deref()
                        == Some("whpx-recovery-qualification-fault")
        ) && injector.fired();
        if opened.is_ok() {
            return Err(format!(
                "host service unexpectedly opened with {stage:?} recovery fault"
            ));
        }
        driver
            .shutdown()
            .await
            .map_err(|error| format!("failed to close fault qualification driver: {error}"))?;
        Ok(injected)
    }

    #[derive(Debug)]
    struct RecoveryFaultInjector {
        stage: DriverBoundaryStage,
        fired: AtomicBool,
    }

    impl RecoveryFaultInjector {
        fn new(stage: DriverBoundaryStage) -> Self {
            Self {
                stage,
                fired: AtomicBool::new(false),
            }
        }

        fn fired(&self) -> bool {
            self.fired.load(Ordering::SeqCst)
        }
    }

    impl FaultInjector for RecoveryFaultInjector {
        fn check(&self, point: FaultPoint) -> Result<()> {
            let target = FaultPoint::DriverBoundary {
                operation: DriverOperation::Recover,
                stage: self.stage,
            };
            if point == target && !self.fired.swap(true, Ordering::SeqCst) {
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    format!("injected real-host recovery fault at {point}"),
                )
                .for_operation("whpx-recovery-qualification-fault")
                .retryable(true));
            }
            Ok(())
        }
    }

    async fn wait_for_running_and_marker(
        service: &HostRuntimeService,
        target: &ContainerTarget,
        marker: &Path,
    ) -> Result<()> {
        let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
        loop {
            let state = service
                .state(StateRequest {
                    target: target.clone(),
                })
                .await?;
            if *state.state.status() == ContainerState::Running
                && path_exists(marker).await.map_err(owner_error)?
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::new(
                    ErrorCode::DeadlineExceeded,
                    "timed out waiting for the recovery owner workload marker",
                )
                .for_operation("whpx-recovery-owner"));
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    async fn write_ready(path: &Path, ready: &WhpxRecoveryOwnerReady) -> Result<()> {
        if !path.is_absolute() {
            return Err(owner_error(format!(
                "owner readiness path must be absolute: {}",
                path.display()
            )));
        }
        let mut encoded = serde_json::to_vec_pretty(ready).map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("failed to encode owner readiness: {error}"),
            )
            .for_operation("whpx-recovery-owner")
        })?;
        encoded.push(b'\n');
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .await
            .map_err(|error| {
                owner_error(format!(
                    "failed to create owner readiness {}: {error}",
                    path.display()
                ))
            })?;
        file.write_all(&encoded).await.map_err(|error| {
            owner_error(format!(
                "failed to write owner readiness {}: {error}",
                path.display()
            ))
        })?;
        file.flush().await.map_err(|error| {
            owner_error(format!(
                "failed to flush owner readiness {}: {error}",
                path.display()
            ))
        })?;
        file.sync_all().await.map_err(|error| {
            owner_error(format!(
                "failed to sync owner readiness {}: {error}",
                path.display()
            ))
        })
    }

    async fn fixed_marker(bundle: &OciBundle) -> std::result::Result<PathBuf, String> {
        let root = bundle
            .spec()
            .root()
            .as_ref()
            .ok_or_else(|| "WHPX recovery bundle has no root filesystem".to_string())?;
        if root.path() != Path::new("rootfs") || root.readonly().unwrap_or(false) {
            return Err(
                "WHPX recovery smoke requires writable normalized relative root.path `rootfs`"
                    .to_string(),
            );
        }
        let rootfs = tokio::fs::canonicalize(bundle.directory().join(root.path()))
            .await
            .map_err(|error| format!("failed to resolve recovery bundle rootfs: {error}"))?;
        if rootfs == bundle.directory() || !rootfs.starts_with(bundle.directory()) {
            return Err("WHPX recovery bundle rootfs escapes its bundle".to_string());
        }
        Ok(rootfs.join(MARKER_NAME))
    }

    async fn recovery_handoff_present(
        runtime_root: &Path,
        target: &ContainerTarget,
    ) -> std::result::Result<bool, String> {
        let (report, pending) = recovery_paths(runtime_root, target)?;
        Ok(plain_file(&report).await? || plain_file(&pending).await?)
    }

    async fn recovery_report_is_plain(
        runtime_root: &Path,
        target: &ContainerTarget,
    ) -> std::result::Result<bool, String> {
        let (report, _) = recovery_paths(runtime_root, target)?;
        plain_file(&report).await
    }

    async fn recovery_artifacts_absent(
        runtime_root: &Path,
        target: &ContainerTarget,
    ) -> std::result::Result<bool, String> {
        let (report, pending) = recovery_paths(runtime_root, target)?;
        Ok(!path_exists(&report).await? && !path_exists(&pending).await?)
    }

    fn recovery_paths(
        runtime_root: &Path,
        target: &ContainerTarget,
    ) -> std::result::Result<(PathBuf, PathBuf), String> {
        let generation = target
            .generation
            .ok_or_else(|| "WHPX recovery path requires an exact generation".to_string())?;
        let report = runtime_root
            .join("recovery")
            .join(format!("{}-{}.json", target.id, generation.0));
        let mut pending = OsString::from(report.as_os_str());
        pending.push(AGENT_RECOVERY_REPORT_PENDING_SUFFIX);
        Ok((report, PathBuf::from(pending)))
    }

    async fn runtime_transients(
        runtime_share: &Path,
    ) -> std::result::Result<BTreeSet<String>, String> {
        let mut entries = tokio::fs::read_dir(runtime_share).await.map_err(|error| {
            format!(
                "failed to inspect WHPX recovery runtime share {}: {error}",
                runtime_share.display()
            )
        })?;
        let mut transient = BTreeSet::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| format!("failed to enumerate runtime share: {error}"))?
        {
            let name = entry.file_name().into_string().map_err(|_| {
                format!(
                    "WHPX recovery runtime share contains a non-Unicode entry: {}",
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

    async fn read_marker(path: &Path) -> std::result::Result<Vec<u8>, String> {
        let metadata = tokio::fs::symlink_metadata(path)
            .await
            .map_err(|error| format!("failed to inspect recovery marker: {error}"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!(
                "WHPX recovery marker is not a plain file: {}",
                path.display()
            ));
        }
        let file = tokio::fs::File::open(path)
            .await
            .map_err(|error| format!("failed to open recovery marker: {error}"))?;
        let mut contents = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_MARKER_BYTES + 1)
            .read_to_end(&mut contents)
            .await
            .map_err(|error| format!("failed to read recovery marker: {error}"))?;
        if contents.len() as u64 > MAX_MARKER_BYTES {
            return Err("WHPX recovery marker exceeded its bounded size".to_string());
        }
        Ok(contents)
    }

    async fn remove_marker(path: &Path) -> std::result::Result<(), String> {
        match tokio::fs::symlink_metadata(path).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                tokio::fs::remove_file(path)
                    .await
                    .map_err(|error| format!("failed to remove recovery marker: {error}"))
            }
            Ok(_) => Err(format!(
                "refusing to remove a non-plain recovery marker: {}",
                path.display()
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("failed to inspect recovery marker: {error}")),
        }
    }

    async fn plain_file(path: &Path) -> std::result::Result<bool, String> {
        match tokio::fs::symlink_metadata(path).await {
            Ok(metadata) => Ok(metadata.is_file() && !metadata.file_type().is_symlink()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!("failed to inspect {}: {error}", path.display())),
        }
    }

    async fn path_exists(path: &Path) -> std::result::Result<bool, String> {
        match tokio::fs::symlink_metadata(path).await {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!("failed to inspect {}: {error}", path.display())),
        }
    }

    fn operation(id: &str) -> Result<OperationContext> {
        OperationId::new(id).map(OperationContext::new)
    }

    fn owner_error(message: impl Into<String>) -> Error {
        Error::new(ErrorCode::FailedPrecondition, message).for_operation("whpx-recovery-owner")
    }

    fn append_reason(report: &mut WhpxRecoverySmokeReport, reason: impl Into<String>) {
        let reason = reason.into();
        report.reason = Some(match report.reason.take() {
            Some(existing) if existing != reason => format!("{existing}; {reason}"),
            Some(existing) => existing,
            None => reason,
        });
    }

    fn failed(
        mut report: WhpxRecoverySmokeReport,
        reason: impl Into<String>,
    ) -> WhpxRecoverySmokeReport {
        report.reason = Some(reason.into());
        report
    }

    #[cfg(test)]
    mod tests {
        use super::{DriverBoundaryStage, FaultInjector, RecoveryFaultInjector};
        use crate::fault::{DriverOperation, FaultPoint};

        #[test]
        fn qualification_fault_fires_once_only_at_the_selected_recover_boundary() {
            let injector = RecoveryFaultInjector::new(DriverBoundaryStage::AfterCall);
            let other = FaultPoint::DriverBoundary {
                operation: DriverOperation::State,
                stage: DriverBoundaryStage::AfterCall,
            };
            let target = FaultPoint::DriverBoundary {
                operation: DriverOperation::Recover,
                stage: DriverBoundaryStage::AfterCall,
            };

            assert!(injector.check(other).is_ok());
            assert!(injector.check(target).is_err());
            assert!(injector.check(target).is_ok());
            assert!(injector.fired());
        }
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_core::{CapabilityStatus, HostPlatform};
    use a3s_oci_sdk::{ContainerId, ContainerTarget, Generation};

    use super::WhpxRecoverySmokeReport;

    #[test]
    fn recovery_report_is_fail_closed_until_every_gate_passes() {
        let report = WhpxRecoverySmokeReport::initial(
            HostPlatform::current(),
            ContainerTarget::exact(
                ContainerId::new("whpx-recovery-report-test").expect("container ID"),
                Generation(1),
            ),
        );
        assert_eq!(report.status, CapabilityStatus::Unavailable);
        assert!(!report.is_success());
    }
}
