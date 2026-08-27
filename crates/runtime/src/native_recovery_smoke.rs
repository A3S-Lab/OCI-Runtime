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

use crate::{
    native_hook_recovery_smoke::capture_native_process_identity, DriverKillRequest,
    HostRuntimeService, NativeLinuxDriver, RootlessDevicePolicyBootstrap, RuntimeDriver,
};

/// Versioned readiness handoff written by the live Native Linux owner.
pub const NATIVE_LINUX_RECOVERY_OWNER_READY_SCHEMA_VERSION: &str =
    "a3s.oci.native-linux-recovery-owner-ready.v3";
/// Versioned evidence emitted after real owner death and driver reopen.
pub const NATIVE_LINUX_RECOVERY_SMOKE_SCHEMA_VERSION: &str =
    "a3s.oci.native-linux-recovery-smoke.v2";

const OWNER_MAX_LIFETIME: Duration = Duration::from_secs(300);
const LINUX_SIGKILL: i32 = 9;

/// Exact lifecycle boundary published by a Native recovery owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeLinuxRecoveryPoint {
    Running,
    StartContainerHook,
}

/// Machine-readable point at which a qualification parent may kill the owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeLinuxRecoveryOwnerReady {
    pub schema_version: String,
    pub status: CapabilityStatus,
    pub platform: HostPlatform,
    pub target: ContainerTarget,
    pub config_digest: String,
    pub recovery_point: NativeLinuxRecoveryPoint,
    pub owner_pid: u32,
    pub owner_start_time_ticks: u64,
    pub init_pid: i32,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub cgroup_delegation_requested: bool,
    pub cgroup_delegation_verified: bool,
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
    pub replacement_effective_uid: u32,
    pub replacement_effective_gid: u32,
    pub cgroup_delegation_requested: bool,
    pub cgroup_delegation_verified: bool,
    pub bundle_loaded: bool,
    pub host_service_reopened: bool,
    pub recorded_workload_terminated: bool,
    pub stopped_observed: bool,
    pub process_inventory_empty: bool,
    pub kill_idempotent: bool,
    pub exact_wait_evidence_refused: bool,
    pub stopped_delete_succeeded: bool,
    pub durable_record_removed: bool,
    pub current_driver_shutdown: bool,
    pub executor_transients_clean: bool,
    pub cgroup_delegation_clean: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl NativeLinuxRecoverySmokeReport {
    pub(crate) fn initial(target: ContainerTarget, cgroup_delegation_requested: bool) -> Self {
        // SAFETY: these credential queries have no pointer arguments or failure
        // return values.
        let (effective_uid, effective_gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        Self {
            schema_version: NATIVE_LINUX_RECOVERY_SMOKE_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Unavailable,
            platform: HostPlatform::Linux,
            target,
            replacement_owner_pid: std::process::id(),
            replacement_effective_uid: effective_uid,
            replacement_effective_gid: effective_gid,
            cgroup_delegation_requested,
            cgroup_delegation_verified: false,
            bundle_loaded: false,
            host_service_reopened: false,
            recorded_workload_terminated: false,
            stopped_observed: false,
            process_inventory_empty: false,
            kill_idempotent: false,
            exact_wait_evidence_refused: false,
            stopped_delete_succeeded: false,
            durable_record_removed: false,
            current_driver_shutdown: false,
            executor_transients_clean: false,
            cgroup_delegation_clean: false,
            reason: None,
        }
    }

    fn contract_complete(&self) -> bool {
        self.bundle_loaded
            && self.host_service_reopened
            && self.recorded_workload_terminated
            && self.stopped_observed
            && self.process_inventory_empty
            && self.kill_idempotent
            && self.exact_wait_evidence_refused
            && self.stopped_delete_succeeded
            && self.durable_record_removed
            && self.current_driver_shutdown
            && self.executor_transients_clean
            && self.cgroup_delegation_clean
            && self.cgroup_delegation_requested == self.cgroup_delegation_verified
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
    native_linux_recovery_owner_with_cgroup_delegation(
        agent,
        root,
        bundle_directory,
        container_id,
        ready_file,
        None,
    )
    .await
}

/// Run the owner-death qualification owner with an optional explicit
/// rootless cgroup-v2 delegation.
pub async fn native_linux_recovery_owner_with_cgroup_delegation(
    agent: &Path,
    root: &Path,
    bundle_directory: &Path,
    container_id: ContainerId,
    ready_file: &Path,
    delegated_cgroup_root: Option<&Path>,
) -> Result<()> {
    native_linux_recovery_owner_with_driver(
        agent,
        root,
        bundle_directory,
        container_id,
        ready_file,
        RecoveryDriverAccess::from_delegation(delegated_cgroup_root),
        NativeLinuxRecoveryPoint::Running,
    )
    .await
}

/// Run the rootless owner-death qualification with the synchronous bounded
/// helper required to prepare the OCI default device nodes.
pub async fn native_linux_recovery_owner_with_device_bootstrap(
    agent: &Path,
    root: &Path,
    bundle_directory: &Path,
    container_id: ContainerId,
    ready_file: &Path,
    bootstrap: RootlessDevicePolicyBootstrap,
) -> Result<()> {
    native_linux_recovery_owner_with_driver(
        agent,
        root,
        bundle_directory,
        container_id,
        ready_file,
        RecoveryDriverAccess::DeviceBootstrap(bootstrap),
        NativeLinuxRecoveryPoint::Running,
    )
    .await
}

/// Create one durable Native generation, publish its exact owner identity, and
/// enter a configured `startContainer` Hook until the qualification parent
/// terminates this owner.
pub async fn native_linux_hook_owner_death_owner(
    agent: &Path,
    root: &Path,
    bundle_directory: &Path,
    container_id: ContainerId,
    ready_file: &Path,
) -> Result<()> {
    native_linux_recovery_owner_with_driver(
        agent,
        root,
        bundle_directory,
        container_id,
        ready_file,
        RecoveryDriverAccess::Host,
        NativeLinuxRecoveryPoint::StartContainerHook,
    )
    .await
}

async fn native_linux_recovery_owner_with_driver(
    agent: &Path,
    root: &Path,
    bundle_directory: &Path,
    container_id: ContainerId,
    ready_file: &Path,
    access: RecoveryDriverAccess<'_>,
    recovery_point: NativeLinuxRecoveryPoint,
) -> Result<()> {
    let cgroup_delegation_requested = access.delegation_root().is_some();
    prepare_layout(root).await?;
    let bundle = OciBundle::load(bundle_directory).await?;
    let driver = open_driver(root, agent, access).await?;
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
    let owner_pid = std::process::id();
    let owner_start_time_ticks = capture_native_process_identity(owner_pid)
        .map_err(owner_error)?
        .start_time_ticks;
    let mut ready = NativeLinuxRecoveryOwnerReady {
        schema_version: NATIVE_LINUX_RECOVERY_OWNER_READY_SCHEMA_VERSION.to_string(),
        status: CapabilityStatus::Available,
        platform: HostPlatform::Linux,
        target: target.clone(),
        config_digest: created.config_digest,
        recovery_point,
        owner_pid,
        owner_start_time_ticks,
        init_pid,
        // SAFETY: these credential queries have no pointer arguments or failure
        // return values.
        effective_uid: unsafe { libc::geteuid() },
        // SAFETY: see the effective UID query above.
        effective_gid: unsafe { libc::getegid() },
        cgroup_delegation_requested,
        cgroup_delegation_verified: cgroup_delegation_requested,
        running_observed: false,
    };
    if recovery_point == NativeLinuxRecoveryPoint::StartContainerHook {
        write_ready(ready_file, &ready)?;
    }
    let started = service
        .start(StartRequest {
            context: operation("native-recovery-owner-start")?,
            target: target.clone(),
        })
        .await;
    if recovery_point == NativeLinuxRecoveryPoint::StartContainerHook {
        cleanup_uninterrupted_hook_owner(&service, &driver, &target).await;
        return Err(owner_error(match started {
            Ok(_) => "startContainer Hook completed before qualification owner death".to_string(),
            Err(error) => {
                format!("startContainer Hook stopped retaining the qualification owner: {error}")
            }
        }));
    }
    let started = started?;
    if *started.state.status() != ContainerState::Running || *started.state.pid() != Some(init_pid)
    {
        return Err(owner_error(
            "native recovery owner start did not retain the exact running init",
        ));
    }
    ready.running_observed = true;
    write_ready(ready_file, &ready)?;

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

async fn cleanup_uninterrupted_hook_owner(
    service: &HostRuntimeService,
    driver: &NativeLinuxDriver,
    target: &ContainerTarget,
) {
    if let Ok(context) = operation("native-hook-owner-uninterrupted-kill") {
        if let Ok(signal) = Signal::new(LINUX_SIGKILL) {
            let _ = service
                .kill(KillRequest {
                    context,
                    target: target.clone(),
                    signal,
                    all: true,
                })
                .await;
        }
    }
    if let Ok(context) = operation("native-hook-owner-uninterrupted-delete") {
        let _ = service
            .delete(DeleteRequest {
                context,
                target: target.clone(),
                mode: DeleteMode::Force,
            })
            .await;
    }
    let _ = driver.shutdown().await;
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
    native_linux_recovery_resume_with_cgroup_delegation(agent, root, bundle_directory, target, None)
        .await
}

/// Reopen an owner-death generation with an optional explicit rootless
/// cgroup-v2 delegation and retain exact cleanup evidence.
#[must_use]
pub async fn native_linux_recovery_resume_with_cgroup_delegation(
    agent: &Path,
    root: &Path,
    bundle_directory: &Path,
    target: ContainerTarget,
    delegated_cgroup_root: Option<&Path>,
) -> NativeLinuxRecoverySmokeReport {
    native_linux_recovery_resume_with_driver(
        agent,
        root,
        bundle_directory,
        target,
        RecoveryDriverAccess::from_delegation(delegated_cgroup_root),
    )
    .await
}

/// Reopen a killed rootless owner with a fresh synchronous bounded helper.
///
/// The helper is recreated before Tokio starts by the caller and is consumed
/// here so recovery and cleanup use the same verified delegation authority as
/// a normal rootless launch.
#[must_use]
pub async fn native_linux_recovery_resume_with_device_bootstrap(
    agent: &Path,
    root: &Path,
    bundle_directory: &Path,
    target: ContainerTarget,
    bootstrap: RootlessDevicePolicyBootstrap,
) -> NativeLinuxRecoverySmokeReport {
    native_linux_recovery_resume_with_driver(
        agent,
        root,
        bundle_directory,
        target,
        RecoveryDriverAccess::DeviceBootstrap(bootstrap),
    )
    .await
}

async fn native_linux_recovery_resume_with_driver(
    agent: &Path,
    root: &Path,
    bundle_directory: &Path,
    target: ContainerTarget,
    access: RecoveryDriverAccess<'_>,
) -> NativeLinuxRecoverySmokeReport {
    let delegated_cgroup_root = access.delegation_root().map(Path::to_path_buf);
    let mut report =
        NativeLinuxRecoverySmokeReport::initial(target.clone(), delegated_cgroup_root.is_some());
    let bundle = match OciBundle::load(bundle_directory).await {
        Ok(bundle) => bundle,
        Err(error) => return failed(report, format!("failed to reload recovery bundle: {error}")),
    };
    report.bundle_loaded = true;
    if let Err(error) = prepare_layout(root).await {
        return failed(report, format!("failed to reopen recovery layout: {error}"));
    }
    let driver = match open_driver(root, agent, access).await {
        Ok(driver) => {
            report.cgroup_delegation_verified = delegated_cgroup_root.is_some();
            driver
        }
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
    // HostRuntimeService::open cannot return until NativeLinuxDriver::recover
    // has authenticated the stale owner record and observed the exact recorded
    // launcher and init identities as terminated.
    report.recorded_workload_terminated = true;

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
    report.cgroup_delegation_clean = match delegated_cgroup_root.as_deref() {
        Some(root) => match delegated_cgroup_has_no_runtime_children(root) {
            Ok(clean) => clean,
            Err(error) => {
                append_reason(&mut report, error);
                false
            }
        },
        None => true,
    };
    if report.reason.is_none()
        && report.bundle_loaded
        && report.host_service_reopened
        && report.recorded_workload_terminated
        && report.stopped_observed
        && report.process_inventory_empty
        && report.kill_idempotent
        && report.exact_wait_evidence_refused
        && report.stopped_delete_succeeded
        && report.durable_record_removed
        && report.current_driver_shutdown
        && report.executor_transients_clean
        && report.cgroup_delegation_clean
        && report.cgroup_delegation_requested == report.cgroup_delegation_verified
    {
        report.status = CapabilityStatus::Available;
    }
    report
}

enum RecoveryDriverAccess<'a> {
    Host,
    Delegation(&'a Path),
    DeviceBootstrap(RootlessDevicePolicyBootstrap),
}

impl<'a> RecoveryDriverAccess<'a> {
    fn from_delegation(delegated_cgroup_root: Option<&'a Path>) -> Self {
        delegated_cgroup_root.map_or(Self::Host, Self::Delegation)
    }

    fn delegation_root(&self) -> Option<&Path> {
        match self {
            Self::Host => None,
            Self::Delegation(root) => Some(root),
            Self::DeviceBootstrap(bootstrap) => Some(bootstrap.delegated_cgroup_root()),
        }
    }
}

async fn open_driver(
    root: &Path,
    agent: &Path,
    access: RecoveryDriverAccess<'_>,
) -> Result<Arc<NativeLinuxDriver>> {
    let driver = match access {
        RecoveryDriverAccess::Host => {
            NativeLinuxDriver::open_experimental(root.join("executor"), agent).await?
        }
        RecoveryDriverAccess::Delegation(delegation) => {
            NativeLinuxDriver::open_experimental_with_rootless_cgroup_delegation(
                root.join("executor"),
                agent,
                delegation,
            )
            .await?
        }
        RecoveryDriverAccess::DeviceBootstrap(bootstrap) => {
            NativeLinuxDriver::open_experimental_with_rootless_device_policy(
                root.join("executor"),
                agent,
                bootstrap,
            )
            .await?
        }
    };
    Ok(Arc::new(driver))
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

fn delegated_cgroup_has_no_runtime_children(root: &Path) -> std::result::Result<bool, String> {
    let entries = std::fs::read_dir(root).map_err(|error| {
        format!(
            "failed to inspect recovered cgroup delegation {}: {error}",
            root.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "failed to enumerate recovered cgroup delegation {}: {error}",
                root.display()
            )
        })?;
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "failed to inspect recovered cgroup delegation entry {}: {error}",
                entry.path().display()
            )
        })?;
        if file_type.is_dir()
            && entry
                .file_name()
                .to_str()
                .is_none_or(|name| name.starts_with("a3s-oci-"))
        {
            return Ok(false);
        }
    }
    Ok(true)
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
        let mut report = NativeLinuxRecoverySmokeReport::initial(target, false);
        assert!(!report.is_success());
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.host_service_reopened = true;
        report.recorded_workload_terminated = true;
        report.stopped_observed = true;
        report.process_inventory_empty = true;
        report.kill_idempotent = true;
        report.exact_wait_evidence_refused = true;
        report.stopped_delete_succeeded = true;
        report.durable_record_removed = true;
        report.current_driver_shutdown = true;
        report.executor_transients_clean = true;
        report.cgroup_delegation_clean = true;
        assert!(report.is_success());
        report.exact_wait_evidence_refused = false;
        assert!(!report.is_success());
    }

    #[test]
    fn delegated_report_requires_verified_and_clean_delegation() {
        let target = ContainerTarget::exact(
            ContainerId::new("native-rootless-recovery-report").expect("container ID"),
            a3s_oci_sdk::Generation(1),
        );
        let mut report = NativeLinuxRecoverySmokeReport::initial(target, true);
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.host_service_reopened = true;
        report.recorded_workload_terminated = true;
        report.stopped_observed = true;
        report.process_inventory_empty = true;
        report.kill_idempotent = true;
        report.exact_wait_evidence_refused = true;
        report.stopped_delete_succeeded = true;
        report.durable_record_removed = true;
        report.current_driver_shutdown = true;
        report.executor_transients_clean = true;
        assert!(!report.is_success());
        report.cgroup_delegation_verified = true;
        assert!(!report.is_success());
        report.cgroup_delegation_clean = true;
        assert!(report.is_success());
    }
}
