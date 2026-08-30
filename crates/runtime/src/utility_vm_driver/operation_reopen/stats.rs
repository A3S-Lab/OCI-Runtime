use std::path::PathBuf;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::oci_spec::runtime::LinuxResources;
use a3s_oci_sdk::{
    ContainerTarget, CreateRequest, IsolationRequest, OciBundle, OperationContext, OperationId,
};

use super::exec::nonce_bound_bundle;
use super::{bundle_marker, directory_is_empty, operation_id, unique_nonce};
use crate::linux_kvm_recovery_smoke::bundle;
use crate::oci_smoke::utility_vm::lifecycle::resource_profile;
use crate::utility_vm_driver::layout::{
    ensure_private_directory, PreparedUtilityVmLayout, UtilityVmBootstrap,
};
use crate::OciVmOperationReopenReplacementReport;

mod flow;

/// Exact inputs for one real Linux KVM Stats interruption and owner reopen.
#[derive(Debug, Clone)]
pub struct LinuxKvmStatsReopenConfig {
    pub shim: PathBuf,
    pub runtime_root: PathBuf,
    pub system_image_manifest: PathBuf,
    pub bundle: PathBuf,
    pub stage: AgentTransportOperationStage,
}

struct Qualification {
    create: CreateRequest,
    start_operation_id: OperationId,
    update_operation_id: OperationId,
    stats_operation_id: OperationId,
    delete_operation_id: OperationId,
    stats_target: ContainerTarget,
    resources: LinuxResources,
    init_marker_contents: Vec<u8>,
    stage: AgentTransportOperationStage,
}

/// Query rebuilt updated state through a distinct real KVM owner.
///
/// Create, Start, the committed setup Update, fresh Stats validation,
/// stale-generation fencing, marker verification, and cleanup all use the
/// production immutable-image, exact-generation handoff, and authenticated
/// Guest Agent path. This remains qualification-only and does not register the
/// probe-only KVM candidate.
pub async fn linux_kvm_stats_reopen_replacement(
    config: LinuxKvmStatsReopenConfig,
) -> OciVmOperationReopenReplacementReport {
    let mut report =
        OciVmOperationReopenReplacementReport::initial_stats(HostPlatform::current(), config.stage);
    if HostPlatform::current() != HostPlatform::Linux {
        return failed(
            report,
            "Linux KVM Stats reopen qualification requires Linux",
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
    let container_id = match a3s_oci_sdk::ContainerId::new(format!("kvm-stats-reopen-{nonce}")) {
        Ok(id) => id,
        Err(error) => return failed(report, format!("failed to construct container ID: {error}")),
    };
    let create_operation_id = match operation_id(&format!("kvm-stats-reopen-{nonce}-create")) {
        Ok(id) => id,
        Err(reason) => return failed(report, reason),
    };
    let start_operation_id = match operation_id(&format!("kvm-stats-reopen-{nonce}-start")) {
        Ok(id) => id,
        Err(reason) => return failed(report, reason),
    };
    let update_operation_id = match operation_id(&format!("kvm-stats-reopen-{nonce}-update")) {
        Ok(id) => id,
        Err(reason) => return failed(report, reason),
    };
    let stats_operation_id = match operation_id(&format!("kvm-stats-reopen-{nonce}-query")) {
        Ok(id) => id,
        Err(reason) => return failed(report, reason),
    };
    let delete_operation_id = match operation_id(&format!("kvm-stats-reopen-{nonce}-delete")) {
        Ok(id) => id,
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
                "refusing to use a KVM Stats qualification bundle with an existing marker: {}",
                source_marker.display()
            ),
        );
    }
    let bound_bundle = match nonce_bound_bundle(source_bundle, &nonce) {
        Ok(bundle) => bundle,
        Err(reason) => return failed(report, reason),
    };
    let staged = match bundle::stage_with_config(
        &config.bundle,
        &prepared.runtime_root,
        &container_id,
        &create_operation_id,
        bound_bundle.config_json(),
    )
    .await
    {
        Ok(staged) => staged,
        Err(reason) => return failed(report, reason),
    };
    let resources = match resource_profile(HostPlatform::Linux) {
        Ok(resources) => resources,
        Err(reason) => return failed(report, reason),
    };
    report.bundle_loaded = true;
    report.qualification_operation_id = Some(stats_operation_id.clone());
    report.setup_create_operation_id = Some(create_operation_id.clone());
    report.setup_start_operation_id = Some(start_operation_id.clone());
    report.setup_update_operation_id = Some(update_operation_id.clone());
    report.container_id = Some(container_id.clone());
    report.update_resources = Some(resources.clone());
    let qualification = Qualification {
        create: CreateRequest {
            context: OperationContext::new(create_operation_id),
            id: container_id.clone(),
            bundle: staged.bundle,
            isolation: IsolationRequest::DedicatedVm,
            attachments: staged.attachments,
        },
        start_operation_id,
        update_operation_id,
        stats_operation_id,
        delete_operation_id,
        stats_target: ContainerTarget::current(container_id),
        resources,
        init_marker_contents: format!("a3s-oci-exec-init-{nonce}\n").into_bytes(),
        stage: config.stage,
    };
    let state_root = prepared.runtime_root.join("operation-reopen-state");
    if let Err(error) =
        ensure_private_directory(state_root.clone(), "KVM operation-stage durable state root").await
    {
        return failed(report, format!("failed to prepare durable state: {error}"));
    }
    let first_console = prepared.console_directory.join("stats-reopen-first.log");
    let replacement_console = prepared
        .console_directory
        .join("stats-reopen-replacement.log");

    if let Err(reason) = flow::exercise(
        &prepared,
        &state_root,
        &first_console,
        &replacement_console,
        &qualification,
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
                "KVM Stats reopen left transient runtime state: bundle_handoffs_clean={}, runtime_shares_clean={}, recovery_reports_clean={}, console_files={}",
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
                "KVM Stats reopen modified the private bootstrap root {}",
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
