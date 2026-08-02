use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerId, ContainerTarget, CreateAttachments, CreateRequest, DeleteMode, DeleteRequest,
    Error, ErrorCode, IsolationRequest, KillRequest, OciBundle, OciRuntimeService,
    OperationContext, OperationId, ProcessIo, ProcessesRequest, Result, Signal, StartRequest,
    StateRequest, WaitRequest,
};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::{DriverKillRequest, HostRuntimeService, NativeLinuxDriver, RuntimeDriver};

/// Versioned readiness handoff written by the live Native Linux owner.
pub const NATIVE_LINUX_RECOVERY_OWNER_READY_SCHEMA_VERSION: &str =
    "a3s.oci.native-linux-recovery-owner-ready.v1";
/// Versioned evidence emitted after real owner death and driver reopen.
pub const NATIVE_LINUX_RECOVERY_SMOKE_SCHEMA_VERSION: &str =
    "a3s.oci.native-linux-recovery-smoke.v1";

const OWNER_MAX_LIFETIME: Duration = Duration::from_secs(300);
const LINUX_SIGKILL: i32 = 9;

/// Machine-readable point at which a qualification parent may kill the owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeLinuxRecoveryOwnerReady {
    pub schema_version: String,
    pub status: CapabilityStatus,
    pub platform: HostPlatform,
    pub target: ContainerTarget,
    pub config_digest: String,
    pub owner_pid: u32,
    pub init_pid: i32,
    pub running_observed: bool,
}

/// Real-host evidence for safe Native Linux owner-death reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeLinuxRecoverySmokeReport {
    pub schema_version: String,
    pub status: CapabilityStatus,
    pub platform: HostPlatform,
    pub target: ContainerTarget,
    pub replacement_owner_pid: u32,
    pub bundle_loaded: bool,
    pub host_service_reopened: bool,
    pub stopped_observed: bool,
    pub process_inventory_empty: bool,
    pub kill_idempotent: bool,
    pub exact_wait_evidence_refused: bool,
    pub stopped_delete_succeeded: bool,
    pub durable_record_removed: bool,
    pub current_driver_shutdown: bool,
    pub executor_transients_clean: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl NativeLinuxRecoverySmokeReport {
    fn initial(target: ContainerTarget) -> Self {
        Self {
            schema_version: NATIVE_LINUX_RECOVERY_SMOKE_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Unavailable,
            platform: HostPlatform::Linux,
            target,
            replacement_owner_pid: std::process::id(),
            bundle_loaded: false,
            host_service_reopened: false,
            stopped_observed: false,
            process_inventory_empty: false,
            kill_idempotent: false,
            exact_wait_evidence_refused: false,
            stopped_delete_succeeded: false,
            durable_record_removed: false,
            current_driver_shutdown: false,
            executor_transients_clean: false,
            reason: None,
        }
    }

    fn contract_complete(&self) -> bool {
        self.bundle_loaded
            && self.host_service_reopened
            && self.stopped_observed
            && self.process_inventory_empty
            && self.kill_idempotent
            && self.exact_wait_evidence_refused
            && self.stopped_delete_succeeded
            && self.durable_record_removed
            && self.current_driver_shutdown
            && self.executor_transients_clean
            && self.reason.is_none()
    }

    /// Whether safe termination, tombstone behavior, and cleanup all passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status == CapabilityStatus::Available && self.contract_complete()
    }
}

/// Create and start one real Native Linux workload, publish readiness, and
/// remain alive until the qualification parent sends an uncatchable signal.
pub async fn native_linux_recovery_owner(
    agent: &Path,
    root: &Path,
    bundle_directory: &Path,
    container_id: ContainerId,
    ready_file: &Path,
) -> Result<()> {
    prepare_layout(root).await?;
    let bundle = OciBundle::load(bundle_directory).await?;
    let driver =
        Arc::new(NativeLinuxDriver::open_experimental(root.join("executor"), agent).await?);
    let runtime_driver: Arc<dyn RuntimeDriver> = driver.clone();
    let service = HostRuntimeService::open(root.join("state"), runtime_driver).await?;
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())?;
    let created = service
        .create(CreateRequest {
            context: operation("native-recovery-owner-create")?,
            id: container_id.clone(),
            bundle,
            isolation: IsolationRequest::SharedHostKernel,
            attachments,
        })
        .await?;
    if *created.state.status() != ContainerState::Created {
        return Err(owner_error(
            "native recovery owner create did not retain the OCI created barrier",
        ));
    }
    let init_pid = created.state.pid().ok_or_else(|| {
        owner_error("native recovery owner create returned no configured init PID")
    })?;
    let target = ContainerTarget::exact(container_id, created.generation);
    let started = service
        .start(StartRequest {
            context: operation("native-recovery-owner-start")?,
            target: target.clone(),
        })
        .await?;
    if *started.state.status() != ContainerState::Running || *started.state.pid() != Some(init_pid)
    {
        return Err(owner_error(
            "native recovery owner start did not retain the exact running init",
        ));
    }
    write_ready(
        ready_file,
        &NativeLinuxRecoveryOwnerReady {
            schema_version: NATIVE_LINUX_RECOVERY_OWNER_READY_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Available,
            platform: HostPlatform::Linux,
            target: target.clone(),
            config_digest: created.config_digest,
            owner_pid: std::process::id(),
            init_pid,
            running_observed: true,
        },
    )?;

    sleep(OWNER_MAX_LIFETIME).await;
    let _ = service
        .kill(KillRequest {
            context: operation("native-recovery-owner-timeout-kill")?,
            target: target.clone(),
            signal: Signal::new(LINUX_SIGKILL)?,
            all: true,
        })
        .await;
    let _ = service
        .delete(DeleteRequest {
            context: operation("native-recovery-owner-timeout-delete")?,
            target,
            mode: DeleteMode::Force,
        })
        .await;
    let _ = driver.shutdown().await;
    Err(Error::new(
        ErrorCode::DeadlineExceeded,
        "the native recovery owner was not externally terminated within five minutes",
    )
    .for_operation("native-linux-recovery-owner"))
}

/// Reopen a real Native Linux driver after owner death and finish stopped-only
/// reconciliation, explicit missing-exit reporting, and exact cleanup.
#[must_use]
pub async fn native_linux_recovery_resume(
    agent: &Path,
    root: &Path,
    bundle_directory: &Path,
    target: ContainerTarget,
) -> NativeLinuxRecoverySmokeReport {
    let mut report = NativeLinuxRecoverySmokeReport::initial(target.clone());
    let bundle = match OciBundle::load(bundle_directory).await {
        Ok(bundle) => bundle,
        Err(error) => return failed(report, format!("failed to reload recovery bundle: {error}")),
    };
    report.bundle_loaded = true;
    if let Err(error) = prepare_layout(root).await {
        return failed(report, format!("failed to reopen recovery layout: {error}"));
    }
    let driver = match NativeLinuxDriver::open_experimental(root.join("executor"), agent).await {
        Ok(driver) => Arc::new(driver),
        Err(error) => return failed(report, format!("failed to reopen native driver: {error}")),
    };
    let runtime_driver: Arc<dyn RuntimeDriver> = driver.clone();
    let service = match HostRuntimeService::open(root.join("state"), runtime_driver).await {
        Ok(service) => service,
        Err(error) => {
            let _ = driver.shutdown().await;
            return failed(
                report,
                format!("failed to recover durable host service: {error}"),
            );
        }
    };
    report.host_service_reopened = true;

    match service
        .state(StateRequest {
            target: target.clone(),
        })
        .await
    {
        Ok(record) => {
            report.stopped_observed = *record.state.status() == ContainerState::Stopped
                && record.state.pid().is_none()
                && record.config_digest == bundle.config_digest();
        }
        Err(error) => append_reason(&mut report, format!("recovered state failed: {error}")),
    }
    match service
        .processes(ProcessesRequest {
            target: target.clone(),
        })
        .await
    {
        Ok(processes) => report.process_inventory_empty = processes.is_empty(),
        Err(error) => append_reason(
            &mut report,
            format!("recovered process inventory failed: {error}"),
        ),
    }
    let kill = DriverKillRequest {
        context: match operation("native-recovery-resume-kill") {
            Ok(context) => context,
            Err(error) => return failed(report, error.to_string()),
        },
        target: target.clone(),
        signal: match Signal::new(LINUX_SIGKILL) {
            Ok(signal) => signal,
            Err(error) => return failed(report, error.to_string()),
        },
        all: true,
    };
    match driver.kill(kill.clone()).await {
        Ok(first) => match driver.kill(kill).await {
            Ok(replayed) => {
                report.kill_idempotent = first == replayed
                    && first.status() == ContainerState::Stopped
                    && first.pid().is_none();
            }
            Err(error) => append_reason(
                &mut report,
                format!("repeated recovered driver tombstone kill failed: {error}"),
            ),
        },
        Err(error) => append_reason(
            &mut report,
            format!("recovered driver tombstone kill failed: {error}"),
        ),
    }
    match service
        .wait(WaitRequest {
            target: target.clone(),
            timeout_ms: Some(0),
        })
        .await
    {
        Err(error) => {
            report.exact_wait_evidence_refused = error.code == ErrorCode::FailedPrecondition
                && error.message.contains("no authenticated parent remained");
            if !report.exact_wait_evidence_refused {
                append_reason(
                    &mut report,
                    format!("recovered wait returned the wrong error: {error}"),
                );
            }
        }
        Ok(status) => append_reason(
            &mut report,
            format!("recovered wait invented terminal evidence: {status:?}"),
        ),
    }
    match service
        .delete(DeleteRequest {
            context: match operation("native-recovery-resume-delete") {
                Ok(context) => context,
                Err(error) => return failed(report, error.to_string()),
            },
            target: target.clone(),
            mode: DeleteMode::StoppedOnly,
        })
        .await
    {
        Ok(()) => report.stopped_delete_succeeded = true,
        Err(error) => append_reason(&mut report, format!("recovered delete failed: {error}")),
    }
    match service
        .state(StateRequest {
            target: target.clone(),
        })
        .await
    {
        Err(error) if error.code == ErrorCode::NotFound => report.durable_record_removed = true,
        Err(error) => append_reason(
            &mut report,
            format!("post-delete state returned the wrong error: {error}"),
        ),
        Ok(record) => append_reason(
            &mut report,
            format!("post-delete durable record still exists: {record:?}"),
        ),
    }
    match driver.shutdown().await {
        Ok(()) => report.current_driver_shutdown = true,
        Err(error) => append_reason(&mut report, format!("replacement shutdown failed: {error}")),
    }
    report.executor_transients_clean = match directory_is_empty(&root.join("executor")) {
        Ok(clean) => clean,
        Err(error) => {
            append_reason(&mut report, error);
            false
        }
    };
    if report.reason.is_none()
        && report.bundle_loaded
        && report.host_service_reopened
        && report.stopped_observed
        && report.process_inventory_empty
        && report.kill_idempotent
        && report.exact_wait_evidence_refused
        && report.stopped_delete_succeeded
        && report.durable_record_removed
        && report.current_driver_shutdown
        && report.executor_transients_clean
    {
        report.status = CapabilityStatus::Available;
    }
    report
}

async fn prepare_layout(root: &Path) -> Result<()> {
    prepare_private_directory(root, "native recovery root").await?;
    prepare_private_directory(&root.join("state"), "native recovery state").await?;
    prepare_private_directory(&root.join("executor"), "native recovery executor").await
}

async fn prepare_private_directory(path: &Path, label: &str) -> Result<()> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = tokio::fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(path).await.map_err(|error| {
                owner_error(format!(
                    "failed to create {label} {}: {error}",
                    path.display()
                ))
            })?;
        }
        Err(error) => {
            return Err(owner_error(format!(
                "failed to inspect {label} {}: {error}",
                path.display()
            )));
        }
    }
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        owner_error(format!(
            "failed to verify {label} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(owner_error(format!(
            "{label} must be a real mode-0700 directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn write_ready(path: &Path, ready: &NativeLinuxRecoveryOwnerReady) -> Result<()> {
    if path.exists() {
        return Err(owner_error(format!(
            "refusing to overwrite native recovery readiness: {}",
            path.display()
        )));
    }
    let mut encoded = serde_json::to_vec_pretty(ready).map_err(|error| {
        owner_error(format!(
            "failed to encode native recovery readiness: {error}"
        ))
    })?;
    encoded.push(b'\n');
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|error| {
        owner_error(format!(
            "failed to create native recovery readiness {}: {error}",
            path.display()
        ))
    })?;
    file.write_all(&encoded).map_err(|error| {
        owner_error(format!(
            "failed to write native recovery readiness {}: {error}",
            path.display()
        ))
    })?;
    file.sync_all().map_err(|error| {
        owner_error(format!(
            "failed to sync native recovery readiness {}: {error}",
            path.display()
        ))
    })?;
    File::open(
        path.parent()
            .ok_or_else(|| owner_error("ready path has no parent"))?,
    )
    .and_then(|directory| directory.sync_all())
    .map_err(|error| owner_error(format!("failed to sync readiness directory: {error}")))
}

fn directory_is_empty(path: &Path) -> std::result::Result<bool, String> {
    let mut entries = std::fs::read_dir(path).map_err(|error| {
        format!(
            "failed to inspect executor cleanup {}: {error}",
            path.display()
        )
    })?;
    Ok(entries.next().is_none())
}

fn operation(id: &str) -> Result<OperationContext> {
    OperationId::new(id).map(OperationContext::new)
}

fn owner_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message).for_operation("native-linux-recovery-owner")
}

fn append_reason(report: &mut NativeLinuxRecoverySmokeReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

fn failed(
    mut report: NativeLinuxRecoverySmokeReport,
    reason: impl Into<String>,
) -> NativeLinuxRecoverySmokeReport {
    report.reason = Some(reason.into());
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_requires_every_safe_recovery_gate() {
        let target = ContainerTarget::exact(
            ContainerId::new("native-recovery-report").expect("container ID"),
            a3s_oci_sdk::Generation(1),
        );
        let mut report = NativeLinuxRecoverySmokeReport::initial(target);
        assert!(!report.is_success());
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.host_service_reopened = true;
        report.stopped_observed = true;
        report.process_inventory_empty = true;
        report.kill_idempotent = true;
        report.exact_wait_evidence_refused = true;
        report.stopped_delete_succeeded = true;
        report.durable_record_removed = true;
        report.current_driver_shutdown = true;
        report.executor_transients_clean = true;
        assert!(report.is_success());
        report.exact_wait_evidence_refused = false;
        assert!(!report.is_success());
    }
}
