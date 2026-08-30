use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultStage,
    AgentTransportOperationStage, AgentTransportQualificationRequest, AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{CapabilityStatus, DriverKind, HostPlatform, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, CreateRequest, DeleteMode, DeleteRequest, Error, ErrorCode, IsolationRequest,
    ListRequest, OciBundle, OciRuntimeService, OperationContext, OperationId,
};
use tokio::time::timeout;

use super::layout::{ensure_private_directory, PreparedUtilityVmLayout, UtilityVmBootstrap};
use crate::agent_session::UtilityVmSessionQualification;
use crate::driver::RuntimeDriver;
use crate::linux_kvm_recovery_smoke::bundle;
use crate::oci_smoke::utility_vm::transport_fault_cleanup::{
    read_guest_qualification_evidence, HostTransportFault,
};
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::{AgentVmSmokeReport, HostRuntimeService, OciVmReopenReplacementReport};

mod delete;
mod driver;
mod kill;
mod start;
mod state;
mod workload_marker;

pub use delete::{linux_kvm_delete_reopen_replacement, LinuxKvmDeleteReopenConfig};
use driver::QualificationKvmOperationDriver;
pub use kill::{linux_kvm_kill_reopen_replacement, LinuxKvmKillReopenConfig};
pub use start::{linux_kvm_start_reopen_replacement, LinuxKvmStartReopenConfig};
pub use state::{linux_kvm_state_reopen_replacement, LinuxKvmStateReopenConfig};

const QUALIFICATION_TIMEOUT: Duration = Duration::from_secs(25);
const QUALIFICATION_FAULT_OPERATION: &str = "oci-vm-transport-qualification-fault";
const GUEST_RUNTIME_PREFIX: &str = "a3s-oci-agent-";
const MARKER_NAME: &str = ".a3s-oci-create-start-smoke";

/// Exact inputs for one real Linux KVM Create interruption and owner reopen.
#[derive(Debug, Clone)]
pub struct LinuxKvmCreateReopenConfig {
    pub shim: PathBuf,
    pub runtime_root: PathBuf,
    pub system_image_manifest: PathBuf,
    pub bundle: PathBuf,
    pub stage: AgentTransportOperationStage,
}

/// Resume one transport-interrupted Create through a distinct real KVM owner.
///
/// This qualification uses the production immutable-image validation, private
/// bootstrap root, exact-generation runtime share, atomic bundle handoff, and
/// authenticated Guest Agent transport. It remains an explicit qualification
/// path and does not promote the probe-only KVM candidate.
pub async fn linux_kvm_create_reopen_replacement(
    config: LinuxKvmCreateReopenConfig,
) -> OciVmReopenReplacementReport {
    let mut report = OciVmReopenReplacementReport::initial(HostPlatform::current(), config.stage);
    if HostPlatform::current() != HostPlatform::Linux {
        return failed(
            report,
            "Linux KVM Create reopen qualification requires Linux",
        );
    }

    let prepared = match PreparedUtilityVmLayout::open(
        config.shim,
        config.runtime_root,
        config.system_image_manifest,
        UtilityVmBootstrap::PrivateEmptyRoot,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(error) => return failed(report, format!("failed to prepare KVM layout: {error}")),
    };
    let nonce = match unique_nonce() {
        Ok(nonce) => nonce,
        Err(reason) => return failed(report, reason),
    };
    let container_id = match a3s_oci_sdk::ContainerId::new(format!("kvm-reopen-{nonce}")) {
        Ok(id) => id,
        Err(error) => return failed(report, format!("failed to construct container ID: {error}")),
    };
    let create_operation_id = match operation_id(&format!("kvm-reopen-{nonce}-create")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let delete_operation_id = match operation_id(&format!("kvm-reopen-{nonce}-delete")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let source_bundle = match OciBundle::load(&config.bundle).await {
        Ok(bundle) => bundle,
        Err(error) => {
            return failed(
                report,
                format!("failed to load source KVM qualification bundle: {error}"),
            );
        }
    };
    let marker = match bundle_marker(&source_bundle) {
        Ok(marker) => marker,
        Err(reason) => return failed(report, reason),
    };
    if marker.exists() {
        return failed(
            report,
            format!(
                "refusing to use a KVM qualification bundle with an existing marker: {}",
                marker.display()
            ),
        );
    }
    let staged = match bundle::stage(
        &config.bundle,
        &prepared.runtime_root,
        &container_id,
        &create_operation_id,
    )
    .await
    {
        Ok(staged) => staged,
        Err(reason) => return failed(report, reason),
    };
    report.bundle_loaded = true;
    report.qualification_operation_id = Some(create_operation_id.clone());
    report.container_id = Some(container_id.clone());
    let request = CreateRequest {
        context: OperationContext::new(create_operation_id.clone()),
        id: container_id,
        bundle: staged.bundle,
        isolation: IsolationRequest::DedicatedVm,
        attachments: staged.attachments,
    };
    let state_root = prepared.runtime_root.join("operation-reopen-state");
    if let Err(error) =
        ensure_private_directory(state_root.clone(), "KVM operation-stage durable state root").await
    {
        return failed(report, format!("failed to prepare durable state: {error}"));
    }
    let first_console = prepared
        .console_directory
        .join("operation-reopen-first.log");
    let replacement_console = prepared
        .console_directory
        .join("operation-reopen-replacement.log");

    let result = exercise(
        &prepared,
        &state_root,
        &first_console,
        &replacement_console,
        &request,
        &delete_operation_id,
        config.stage,
        &mut report,
    )
    .await;
    if let Err(reason) = result {
        append_reason(&mut report, reason);
    }

    report.marker_absent_after_cleanup = !marker.exists();
    match bundle::runtime_inventory(&prepared.runtime_root) {
        Ok(inventory)
            if inventory.bundle_handoffs_clean
                && inventory.runtime_shares_clean
                && inventory.recovery_reports_clean
                && inventory.console_files == 2 => {}
        Ok(inventory) => append_reason(
            &mut report,
            format!(
                "KVM Create reopen left transient runtime state: bundle_handoffs_clean={}, runtime_shares_clean={}, recovery_reports_clean={}, console_files={}",
                inventory.bundle_handoffs_clean,
                inventory.runtime_shares_clean,
                inventory.recovery_reports_clean,
                inventory.console_files
            ),
        ),
        Err(reason) => append_reason(&mut report, reason),
    }
    match directory_is_empty(&prepared.bootstrap_root).await {
        Ok(true) => {}
        Ok(false) => append_reason(
            &mut report,
            format!(
                "KVM Create reopen modified the private bootstrap root {}",
                prepared.bootstrap_root.display()
            ),
        ),
        Err(reason) => append_reason(&mut report, reason),
    }
    match tokio::fs::remove_dir_all(&state_root).await {
        Ok(()) => report.state_root_removed = !state_root.exists(),
        Err(error) => append_reason(
            &mut report,
            format!(
                "failed to remove KVM qualification state root {}: {error}",
                state_root.display()
            ),
        ),
    }
    if report.evidence_succeeded() {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    }
    report
}

#[allow(clippy::too_many_arguments)]
async fn exercise(
    prepared: &PreparedUtilityVmLayout,
    state_root: &Path,
    first_console: &Path,
    replacement_console: &Path,
    request: &CreateRequest,
    delete_operation_id: &OperationId,
    stage: AgentTransportOperationStage,
    report: &mut OciVmReopenReplacementReport,
) -> std::result::Result<(), String> {
    let faults = Arc::new(HostTransportFault::new(AgentTransportFaultStage::from(
        stage,
    )));
    let guest_qualification = if stage.is_guest() {
        Some(
            AgentTransportQualificationRequest::new(
                request.context.operation_id.clone(),
                AgentOperation::Create,
                stage,
            )
            .map_err(|error| format!("failed to construct Guest qualification: {error}"))?,
        )
    } else {
        None
    };
    let session_qualification = match guest_qualification.as_ref() {
        Some(qualification) => UtilityVmSessionQualification::Guest(qualification.clone()),
        None => UtilityVmSessionQualification::Host(
            Arc::clone(&faults) as Arc<dyn AgentTransportFaultInjector>
        ),
    };

    let first_driver = Arc::new(QualificationKvmOperationDriver::new(
        prepared,
        first_console.to_path_buf(),
        request.clone(),
        Some(session_qualification),
    ));
    let first_service = HostRuntimeService::open(
        state_root,
        Arc::clone(&first_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    .map_err(|error| format!("failed to open first KVM Host service: {error}"))?;

    let first_error = match timeout(QUALIFICATION_TIMEOUT, first_service.create(request.clone()))
        .await
    {
        Ok(Err(error)) => error,
        Ok(Ok(record)) => {
            drop(first_service);
            report.first_vm = first_driver.shutdown().await;
            return Err(format!(
                "first KVM Create unexpectedly returned success before owner replacement: {record:?}"
            ));
        }
        Err(_) => {
            drop(first_service);
            report.first_vm = first_driver.shutdown().await;
            return Err("first KVM Create timed out".to_string());
        }
    };
    if let Err(reason) = record_first_interruption(report, first_error, stage) {
        drop(first_service);
        report.first_vm = first_driver.shutdown().await;
        return Err(reason);
    }
    if stage.is_host() {
        report.negotiated_protocol = faults.protocol_version();
        report.injected_point = faults.injected_point();
        report.fault_crossings = faults.crossing_count();
    }

    let durable = match first_service.list(ListRequest::default()).await {
        Ok(durable) => durable,
        Err(error) => {
            drop(first_service);
            report.first_vm = first_driver.shutdown().await;
            return Err(format!("failed to inspect interrupted KVM Create: {error}"));
        }
    };
    if durable.len() != 1 {
        drop(first_service);
        report.first_vm = first_driver.shutdown().await;
        return Err(format!(
            "interrupted KVM Create retained {} records instead of one",
            durable.len()
        ));
    }
    let durable = match durable.into_iter().next() {
        Some(durable) => durable,
        None => {
            drop(first_service);
            report.first_vm = first_driver.shutdown().await;
            return Err("interrupted KVM Create retained no durable record".to_string());
        }
    };
    let response_delivered = stage == AgentTransportOperationStage::GuestAfterResponseWrite;
    let exact_record = durable.driver == DriverKind::LibkrunKvm
        && durable.isolation == IsolationClass::DedicatedVm
        && durable.state.id() == request.id.as_str();
    report.generation_before_reopen = Some(durable.generation);
    report.durable_creating_retained =
        exact_record && *durable.state.status() == ContainerState::Creating;
    report.durable_created_retained =
        exact_record && *durable.state.status() == ContainerState::Created;
    if report.durable_created_retained {
        report.first_created_pid = *durable.state.pid();
    }
    if (response_delivered && !report.durable_created_retained)
        || (!response_delivered && !report.durable_creating_retained)
    {
        drop(first_service);
        report.first_vm = first_driver.shutdown().await;
        return Err(format!(
            "interrupted KVM Create retained unexpected durable state {}",
            durable.state.status()
        ));
    }
    let first_identity = match first_driver.create_identity() {
        Ok(identity) => identity,
        Err(reason) => {
            drop(first_service);
            report.first_vm = first_driver.shutdown().await;
            return Err(reason);
        }
    };
    let durable_target = ContainerTarget::exact(request.id.clone(), durable.generation);
    let mount_root = match first_driver.mount_root(&durable_target).await {
        Ok(mount_root) => mount_root,
        Err(reason) => {
            drop(first_service);
            report.first_vm = first_driver.shutdown().await;
            return Err(reason);
        }
    };
    drop(first_service);
    report.first_vm = first_driver.shutdown().await;
    report.first_guest_runtime_clean = runtime_entries_clean(&mount_root).await?;
    if !report.first_vm.is_success() {
        return Err(report
            .first_vm
            .reason
            .clone()
            .unwrap_or_else(|| "first KVM VM cleanup evidence failed".to_string()));
    }
    if let Some(qualification) = guest_qualification.as_ref() {
        let evidence = read_guest_qualification_evidence(first_console, qualification).await?;
        report.negotiated_protocol = Some(evidence.protocol_version());
        report.injected_point = Some(evidence.injected_point());
        report.fault_crossings = evidence.fault_crossings();
        report.guest_evidence_operation_id = Some(evidence.operation_id().clone());
        report.guest_evidence_verified = evidence.matches_request(qualification)
            && evidence.protocol_version() == AGENT_PROTOCOL_VERSION_MAX
            && evidence.fault_crossings() == 1;
    }
    if report.fault_crossings != 1 || !report.first_guest_runtime_clean {
        return Err("first KVM owner did not retain exact fault and cleanup evidence".to_string());
    }
    drop(first_driver);

    let replacement_driver = Arc::new(QualificationKvmOperationDriver::new(
        prepared,
        replacement_console.to_path_buf(),
        request.clone(),
        None,
    ));
    let replacement_service = match HostRuntimeService::open(
        state_root,
        Arc::clone(&replacement_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    {
        Ok(service) => service,
        Err(error) => {
            report.replacement_vm = replacement_driver.shutdown().await;
            if let Err(cleanup) = replacement_driver.cleanup(&durable_target).await {
                return Err(format!(
                    "failed to reopen KVM Host service: {error}; {cleanup}"
                ));
            }
            return Err(format!("failed to reopen KVM Host service: {error}"));
        }
    };
    report.host_service_reopened = true;
    report.replacement_recovery_calls = replacement_driver.recovery_calls();
    report.replacement_rehydrated_created_record = replacement_driver.rehydrated_created_record();

    let completed = match timeout(
        QUALIFICATION_TIMEOUT,
        replacement_service.create(request.clone()),
    )
    .await
    {
        Ok(Ok(completed)) => completed,
        Ok(Err(error)) => {
            drop(replacement_service);
            return replacement_failure(
                &replacement_driver,
                &durable_target,
                report,
                format!("replacement KVM Create failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            drop(replacement_service);
            return replacement_failure(
                &replacement_driver,
                &durable_target,
                report,
                "replacement KVM Create timed out".to_string(),
            )
            .await;
        }
    };
    report.generation_after_reopen = Some(completed.generation);
    report.replacement_created_pid = *completed.state.pid();
    report.create_completed_after_reopen = *completed.state.status() == ContainerState::Created;
    let replacement_identity = match replacement_driver.create_identity() {
        Ok(identity) => identity,
        Err(reason) => {
            drop(replacement_service);
            return replacement_failure(&replacement_driver, &durable_target, report, reason).await;
        }
    };
    report.same_generation_reused =
        report.generation_before_reopen == report.generation_after_reopen;
    report.same_operation_id_reused = first_identity == replacement_identity
        && replacement_identity.0 == request.context.operation_id;

    let target = ContainerTarget::exact(request.id.clone(), completed.generation);
    if let Err(error) = replacement_service
        .delete(DeleteRequest {
            context: OperationContext::new(delete_operation_id.clone()),
            target: target.clone(),
            mode: DeleteMode::Force,
        })
        .await
    {
        drop(replacement_service);
        return replacement_failure(
            &replacement_driver,
            &target,
            report,
            format!("replacement KVM force delete failed: {error}"),
        )
        .await;
    }
    report.force_delete_completed = true;
    report.durable_records_empty = match replacement_service.list(ListRequest::default()).await {
        Ok(records) => records.is_empty(),
        Err(error) => {
            drop(replacement_service);
            return replacement_failure(
                &replacement_driver,
                &target,
                report,
                format!("failed to list after KVM delete: {error}"),
            )
            .await;
        }
    };
    drop(replacement_service);
    report.replacement_vm = replacement_driver.shutdown().await;
    replacement_driver.cleanup(&target).await?;
    report.replacement_guest_runtime_clean = !mount_root.exists();
    report.owners_distinct =
        owner_identities_are_distinct(&report.first_vm, &report.replacement_vm);
    if !report.replacement_vm.is_success()
        || !report.replacement_guest_runtime_clean
        || !report.owners_distinct
        || !report.durable_records_empty
    {
        return Err("replacement KVM owner did not restore every cleanup invariant".to_string());
    }
    Ok(())
}

async fn replacement_failure(
    driver: &QualificationKvmOperationDriver,
    target: &ContainerTarget,
    report: &mut OciVmReopenReplacementReport,
    reason: String,
) -> std::result::Result<(), String> {
    report.replacement_vm = driver.shutdown().await;
    match driver.cleanup(target).await {
        Ok(()) => Err(reason),
        Err(cleanup) => Err(format!("{reason}; {cleanup}")),
    }
}

async fn runtime_entries_clean(runtime_share: &Path) -> std::result::Result<bool, String> {
    let runtime = runtime_share.join("run");
    let mut entries = tokio::fs::read_dir(&runtime)
        .await
        .map_err(|error| format!("failed to inspect {}: {error}", runtime.display()))?;
    let mut matching = BTreeSet::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| format!("failed to enumerate {}: {error}", runtime.display()))?
    {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "KVM runtime share contains a non-Unicode entry".to_string())?;
        if name.starts_with(GUEST_RUNTIME_PREFIX) {
            matching.insert(name);
        }
    }
    Ok(matching.is_empty())
}

async fn directory_is_empty(path: &Path) -> std::result::Result<bool, String> {
    let mut entries = tokio::fs::read_dir(path)
        .await
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    entries
        .next_entry()
        .await
        .map(|entry| entry.is_none())
        .map_err(|error| format!("failed to enumerate {}: {error}", path.display()))
}

fn bundle_marker(bundle: &OciBundle) -> std::result::Result<PathBuf, String> {
    let root = bundle
        .spec()
        .root()
        .as_ref()
        .ok_or_else(|| "KVM qualification bundle has no root filesystem".to_string())?;
    Ok(bundle.directory().join(root.path()).join(MARKER_NAME))
}

fn owner_identities_are_distinct(
    first: &AgentVmSmokeReport,
    replacement: &AgentVmSmokeReport,
) -> bool {
    first
        .endpoint_name
        .as_deref()
        .zip(replacement.endpoint_name.as_deref())
        .is_some_and(|(first, replacement)| !first.is_empty() && first != replacement)
        && first
            .shim_process_id
            .zip(replacement.shim_process_id)
            .is_some_and(|(first, replacement)| first != 0 && first != replacement)
        && first
            .bridge_process_id
            .zip(replacement.bridge_process_id)
            .is_some_and(|(first, replacement)| first != 0 && first != replacement)
}

fn record_first_interruption(
    report: &mut OciVmReopenReplacementReport,
    error: Error,
    stage: AgentTransportOperationStage,
) -> std::result::Result<(), String> {
    report.first_create_error_code = Some(error.code);
    report.first_create_error_operation = error.operation.clone();
    report.first_create_error_retryable = error.retryable;
    let expected_operation = if stage.is_guest() {
        error
            .operation
            .as_deref()
            .is_some_and(is_retryable_disconnect_operation)
    } else {
        error.operation.as_deref() == Some(QUALIFICATION_FAULT_OPERATION)
    };
    if error.code == ErrorCode::Unavailable && error.retryable && expected_operation {
        Ok(())
    } else {
        Err(format!(
            "first KVM owner returned an unexpected transport error at {}: {error}",
            stage.as_str()
        ))
    }
}

fn operation_id(value: &str) -> std::result::Result<OperationId, String> {
    OperationId::new(value)
        .map_err(|error| format!("failed to construct qualification operation ID: {error}"))
}

fn unique_nonce() -> std::result::Result<String, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?
        .as_nanos();
    Ok(format!("{}-{nanos}", std::process::id()))
}

fn append_reason(report: &mut OciVmReopenReplacementReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

fn failed(
    mut report: OciVmReopenReplacementReport,
    reason: impl Into<String>,
) -> OciVmReopenReplacementReport {
    append_reason(&mut report, reason);
    report
}
