use std::path::PathBuf;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{
    ContainerTarget, CreateRequest, FilesystemOp, FilesystemRequest, IsolationRequest, OciBundle,
    OperationContext,
};

use super::exec::nonce_bound_bundle;
use super::mutation::{self, Mutation, Qualification};
use super::mutation_support::session_filesystem_bundle;
use super::{bundle_marker, directory_is_empty, operation_id, unique_nonce};
use crate::linux_kvm_recovery_smoke::bundle;
use crate::utility_vm_driver::layout::{
    ensure_private_directory, PreparedUtilityVmLayout, UtilityVmBootstrap,
};
use crate::OciVmOperationReopenReplacementReport;

/// Exact inputs for one real Linux KVM Filesystem interruption and owner reopen.
#[derive(Debug, Clone)]
pub struct LinuxKvmFilesystemReopenConfig {
    pub shim: PathBuf,
    pub runtime_root: PathBuf,
    pub system_image_manifest: PathBuf,
    pub bundle: PathBuf,
    pub stage: AgentTransportOperationStage,
}

/// Rebuild or replay one directory creation in a distinct real KVM owner.
pub async fn linux_kvm_filesystem_reopen_replacement(
    config: LinuxKvmFilesystemReopenConfig,
) -> OciVmOperationReopenReplacementReport {
    let mut report = OciVmOperationReopenReplacementReport::initial_filesystem(
        HostPlatform::current(),
        config.stage,
    );
    if HostPlatform::current() != HostPlatform::Linux {
        return failed(
            report,
            "Linux KVM Filesystem reopen qualification requires Linux",
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
    let container_id = match a3s_oci_sdk::ContainerId::new(format!("kvm-filesystem-reopen-{nonce}"))
    {
        Ok(id) => id,
        Err(error) => {
            return failed(report, format!("failed to construct container ID: {error}"));
        }
    };
    let create_operation_id = match operation_id(&format!("kvm-filesystem-reopen-{nonce}-create")) {
        Ok(id) => id,
        Err(reason) => return failed(report, reason),
    };
    let start_operation_id = match operation_id(&format!("kvm-filesystem-reopen-{nonce}-start")) {
        Ok(id) => id,
        Err(reason) => return failed(report, reason),
    };
    let filesystem_operation_id =
        match operation_id(&format!("kvm-filesystem-reopen-{nonce}-mkdir")) {
            Ok(id) => id,
            Err(reason) => return failed(report, reason),
        };
    let cleanup_operation_id = match operation_id(&format!("kvm-filesystem-reopen-{nonce}-cleanup"))
    {
        Ok(id) => id,
        Err(reason) => return failed(report, reason),
    };
    let delete_operation_id = match operation_id(&format!("kvm-filesystem-reopen-{nonce}-delete")) {
        Ok(id) => id,
        Err(reason) => return failed(report, reason),
    };
    let stale_guest_operation_id =
        match operation_id(&format!("kvm-filesystem-reopen-{nonce}-stale-guest")) {
            Ok(id) => id,
            Err(reason) => return failed(report, reason),
        };
    let stale_host_operation_id =
        match operation_id(&format!("kvm-filesystem-reopen-{nonce}-stale-host")) {
            Ok(id) => id,
            Err(reason) => return failed(report, reason),
        };

    let source_bundle = match OciBundle::load(&config.bundle).await {
        Ok(bundle) => bundle,
        Err(error) => {
            return failed(
                report,
                format!("failed to load source KVM Filesystem qualification bundle: {error}"),
            )
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
                "refusing to use a KVM Filesystem qualification bundle with an existing marker: {}",
                source_marker.display()
            ),
        );
    }
    let bound_bundle = match nonce_bound_bundle(source_bundle, &nonce)
        .and_then(|bundle| session_filesystem_bundle(bundle, "Filesystem"))
    {
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

    let path = format!("/tmp/.a3s-oci-filesystem-reopen-{nonce}");
    let current_target = ContainerTarget::current(container_id.clone());
    let filesystem = FilesystemRequest {
        target: current_target.clone(),
        op: FilesystemOp::MakeDir,
        path: path.clone(),
        destination: None,
        depth: 0,
        user: None,
        context: Some(OperationContext::new(filesystem_operation_id.clone())),
    };
    let stat = FilesystemRequest {
        target: current_target.clone(),
        op: FilesystemOp::Stat,
        path: path.clone(),
        destination: None,
        depth: 0,
        user: None,
        context: None,
    };
    let cleanup = FilesystemRequest {
        target: current_target,
        op: FilesystemOp::Remove,
        path: path.clone(),
        destination: None,
        depth: 0,
        user: None,
        context: Some(OperationContext::new(cleanup_operation_id)),
    };
    report.bundle_loaded = true;
    report.qualification_operation_id = Some(filesystem_operation_id);
    report.setup_create_operation_id = Some(create_operation_id.clone());
    report.setup_start_operation_id = Some(start_operation_id.clone());
    report.container_id = Some(container_id.clone());
    report.filesystem_op = Some(FilesystemOp::MakeDir);
    report.filesystem_path = Some(path);
    report.filesystem_destination = None;
    report.filesystem_depth = Some(0);
    report.filesystem_user = None;

    let create = CreateRequest {
        context: OperationContext::new(create_operation_id),
        id: container_id,
        bundle: staged.bundle,
        isolation: IsolationRequest::DedicatedVm,
        attachments: staged.attachments,
    };
    let qualification = Qualification {
        create,
        start_operation_id,
        delete_operation_id,
        stale_guest_operation_id,
        stale_host_operation_id,
        mutation: Mutation::Filesystem {
            request: filesystem,
            stat,
            cleanup,
        },
        init_marker_contents: format!("a3s-oci-exec-init-{nonce}\n").into_bytes(),
        stage: config.stage,
    };
    let state_root = prepared.runtime_root.join("operation-reopen-state");
    if let Err(error) =
        ensure_private_directory(state_root.clone(), "KVM operation-stage durable state root").await
    {
        return failed(report, format!("failed to prepare durable state: {error}"));
    }
    let first_console = prepared
        .console_directory
        .join("filesystem-reopen-first.log");
    let replacement_console = prepared
        .console_directory
        .join("filesystem-reopen-replacement.log");
    if let Err(reason) = mutation::exercise(
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
    finalize_report(&prepared, &state_root, &mut report).await;
    if report.evidence_succeeded() {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    }
    report
}

async fn finalize_report(
    prepared: &PreparedUtilityVmLayout,
    state_root: &std::path::Path,
    report: &mut OciVmOperationReopenReplacementReport,
) {
    match bundle::runtime_inventory(&prepared.runtime_root) {
        Ok(inventory)
            if inventory.bundle_handoffs_clean
                && inventory.runtime_shares_clean
                && inventory.recovery_reports_clean
                && inventory.console_files == 2 => {}
        Ok(inventory) => append_reason(
            report,
            format!(
                "KVM Filesystem reopen left transient runtime state: bundle_handoffs_clean={}, runtime_shares_clean={}, recovery_reports_clean={}, console_files={}",
                inventory.bundle_handoffs_clean,
                inventory.runtime_shares_clean,
                inventory.recovery_reports_clean,
                inventory.console_files
            ),
        ),
        Err(reason) => append_reason(report, reason),
    }
    match directory_is_empty(&prepared.bootstrap_root).await {
        Ok(true) => {}
        Ok(false) => append_reason(
            report,
            format!(
                "KVM Filesystem reopen modified the private bootstrap root {}",
                prepared.bootstrap_root.display()
            ),
        ),
        Err(reason) => append_reason(report, reason),
    }
    match tokio::fs::remove_dir_all(state_root).await {
        Ok(()) => report.state_root_removed = !state_root.exists(),
        Err(error) => append_reason(
            report,
            format!(
                "failed to remove KVM qualification state root {}: {error}",
                state_root.display()
            ),
        ),
    }
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
