use std::path::PathBuf;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{CreateRequest, IsolationRequest, OciBundle, OperationContext};

use super::{bundle_marker, directory_is_empty, operation_id, unique_nonce};
use crate::linux_kvm_recovery_smoke::bundle;
use crate::utility_vm_driver::layout::{
    ensure_private_directory, PreparedUtilityVmLayout, UtilityVmBootstrap,
};
use crate::OciVmOperationReopenReplacementReport;

mod flow;

use flow::exercise;

/// Exact inputs for one real Linux KVM Delete interruption and owner reopen.
#[derive(Debug, Clone)]
pub struct LinuxKvmDeleteReopenConfig {
    pub shim: PathBuf,
    pub runtime_root: PathBuf,
    pub system_image_manifest: PathBuf,
    pub bundle: PathBuf,
    pub stage: AgentTransportOperationStage,
}

/// Rebuild or replay one stopped-only Delete in a distinct KVM owner.
///
/// Create, Start, setup Kill, Delete, marker verification, and cleanup all use
/// the production immutable-image, exact-generation share, handoff, and
/// authenticated Guest Agent path. This remains qualification-only and does
/// not register the probe-only KVM candidate for workload selection.
pub async fn linux_kvm_delete_reopen_replacement(
    config: LinuxKvmDeleteReopenConfig,
) -> OciVmOperationReopenReplacementReport {
    let mut report = OciVmOperationReopenReplacementReport::initial_delete(
        HostPlatform::current(),
        config.stage,
    );
    if HostPlatform::current() != HostPlatform::Linux {
        return failed(
            report,
            "Linux KVM Delete reopen qualification requires Linux",
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
    let container_id = match a3s_oci_sdk::ContainerId::new(format!("kvm-delete-reopen-{nonce}")) {
        Ok(id) => id,
        Err(error) => return failed(report, format!("failed to construct container ID: {error}")),
    };
    let create_operation_id = match operation_id(&format!("kvm-delete-reopen-{nonce}-create")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let start_operation_id = match operation_id(&format!("kvm-delete-reopen-{nonce}-start")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let kill_operation_id = match operation_id(&format!("kvm-delete-reopen-{nonce}-kill")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let delete_operation_id = match operation_id(&format!("kvm-delete-reopen-{nonce}-delete")) {
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
    let source_marker = match bundle_marker(&source_bundle) {
        Ok(marker) => marker,
        Err(reason) => return failed(report, reason),
    };
    if source_marker.exists() {
        return failed(
            report,
            format!(
                "refusing to use a KVM Delete qualification bundle with an existing marker: {}",
                source_marker.display()
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
    report.qualification_operation_id = Some(delete_operation_id.clone());
    report.setup_create_operation_id = Some(create_operation_id.clone());
    report.setup_start_operation_id = Some(start_operation_id.clone());
    report.setup_kill_operation_id = Some(kill_operation_id.clone());
    report.container_id = Some(container_id.clone());
    let create = CreateRequest {
        context: OperationContext::new(create_operation_id),
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
    let first_console = prepared.console_directory.join("delete-reopen-first.log");
    let replacement_console = prepared
        .console_directory
        .join("delete-reopen-replacement.log");

    if let Err(reason) = exercise(
        &prepared,
        &state_root,
        &first_console,
        &replacement_console,
        &create,
        &start_operation_id,
        &kill_operation_id,
        &delete_operation_id,
        config.stage,
        &mut report,
    )
    .await
    {
        append_reason(&mut report, reason);
    }

    report.marker_absent_after_cleanup =
        report.marker_absent_after_cleanup && !source_marker.exists();
    match bundle::runtime_inventory(&prepared.runtime_root) {
        Ok(inventory)
            if inventory.bundle_handoffs_clean
                && inventory.runtime_shares_clean
                && inventory.recovery_reports_clean
                && inventory.console_files == 2 => {}
        Ok(inventory) => append_reason(
            &mut report,
            format!(
                "KVM Delete reopen left transient runtime state: bundle_handoffs_clean={}, runtime_shares_clean={}, recovery_reports_clean={}, console_files={}",
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
                "KVM Delete reopen modified the private bootstrap root {}",
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

fn append_reason(report: &mut OciVmOperationReopenReplacementReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

fn failed(
    mut report: OciVmOperationReopenReplacementReport,
    reason: impl Into<String>,
) -> OciVmOperationReopenReplacementReport {
    append_reason(&mut report, reason);
    report
}
