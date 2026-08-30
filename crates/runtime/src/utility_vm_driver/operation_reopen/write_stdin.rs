use std::path::PathBuf;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{
    CreateRequest, IsolationRequest, OciBundle, OperationContext, ProcessId, ProcessIo,
};

use super::exec::{nonce_bound_bundle, EXEC_MARKER_NAME};
use super::{bundle_marker, directory_is_empty, operation_id, unique_nonce};
use crate::linux_kvm_recovery_smoke::bundle;
use crate::utility_vm_driver::layout::{
    ensure_private_directory, PreparedUtilityVmLayout, UtilityVmBootstrap,
};
use crate::OciVmOperationReopenReplacementReport;

mod flow;

use flow::support::{stdin_exec_process, WRITE_MARKER_NAME};

/// Exact inputs for one real Linux KVM pipe-backed WriteStdin interruption and owner reopen.
#[derive(Debug, Clone)]
pub struct LinuxKvmWriteStdinReopenConfig {
    pub shim: PathBuf,
    pub runtime_root: PathBuf,
    pub system_image_manifest: PathBuf,
    pub bundle: PathBuf,
    pub stage: AgentTransportOperationStage,
}

pub(super) struct Qualification {
    create: CreateRequest,
    start_operation_id: a3s_oci_sdk::OperationId,
    exec_operation_id: a3s_oci_sdk::OperationId,
    write_operation_id: a3s_oci_sdk::OperationId,
    delete_operation_id: a3s_oci_sdk::OperationId,
    stale_guest_operation_id: a3s_oci_sdk::OperationId,
    stale_host_operation_id: a3s_oci_sdk::OperationId,
    process_id: ProcessId,
    process: a3s_oci_sdk::oci_spec::runtime::Process,
    io: ProcessIo,
    write_data: Vec<u8>,
    init_marker_contents: Vec<u8>,
    exec_marker_contents: Vec<u8>,
    write_marker_contents: Vec<u8>,
    stage: AgentTransportOperationStage,
}

/// Rebuild or replay one pipe-backed WriteStdin in a distinct real KVM owner.
///
/// Create, Start, Exec, WriteStdin, process-record rebinding, stale-generation
/// fencing, marker verification, and cleanup all use the production immutable-image,
/// exact-generation handoff, and authenticated Guest Agent path. This remains
/// qualification-only and does not register the probe-only KVM candidate.
pub async fn linux_kvm_write_stdin_reopen_replacement(
    config: LinuxKvmWriteStdinReopenConfig,
) -> OciVmOperationReopenReplacementReport {
    let mut report = OciVmOperationReopenReplacementReport::initial_write_stdin(
        HostPlatform::current(),
        config.stage,
    );
    if HostPlatform::current() != HostPlatform::Linux {
        return failed(
            report,
            "Linux KVM WriteStdin reopen qualification requires Linux",
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
    let container_id =
        match a3s_oci_sdk::ContainerId::new(format!("kvm-write-stdin-reopen-{nonce}")) {
            Ok(id) => id,
            Err(error) => {
                return failed(report, format!("failed to construct container ID: {error}"));
            }
        };
    let create_operation_id = match operation_id(&format!("kvm-write-stdin-reopen-{nonce}-create"))
    {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let start_operation_id = match operation_id(&format!("kvm-write-stdin-reopen-{nonce}-start")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let exec_operation_id = match operation_id(&format!("kvm-write-stdin-reopen-{nonce}-exec")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let write_operation_id = match operation_id(&format!("kvm-write-stdin-reopen-{nonce}-write")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let delete_operation_id = match operation_id(&format!("kvm-write-stdin-reopen-{nonce}-delete"))
    {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let stale_guest_operation_id =
        match operation_id(&format!("kvm-write-stdin-reopen-{nonce}-stale-guest")) {
            Ok(operation_id) => operation_id,
            Err(reason) => return failed(report, reason),
        };
    let stale_host_operation_id =
        match operation_id(&format!("kvm-write-stdin-reopen-{nonce}-stale-host")) {
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
    let source_init_marker = match bundle_marker(&source_bundle) {
        Ok(marker) => marker,
        Err(reason) => return failed(report, reason),
    };
    let source_rootfs = match source_init_marker.parent() {
        Some(rootfs) => rootfs,
        None => return failed(report, "KVM WriteStdin init marker has no rootfs parent"),
    };
    let source_exec_marker = source_rootfs.join(EXEC_MARKER_NAME);
    let source_write_marker = source_rootfs.join(WRITE_MARKER_NAME);
    for (label, marker) in [
        ("init", &source_init_marker),
        ("Exec", &source_exec_marker),
        ("WriteStdin", &source_write_marker),
    ] {
        if marker.exists() {
            return failed(
                report,
                format!(
                    "refusing to use a KVM WriteStdin qualification bundle with an existing {label} marker: {}",
                    marker.display()
                ),
            );
        }
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
    let (process_id, process, io) = match stdin_exec_process(&nonce) {
        Ok(process) => process,
        Err(reason) => return failed(report, reason),
    };
    let write_data = format!("a3s-oci-write-stdin-{nonce}\n").into_bytes();
    report.bundle_loaded = true;
    report.qualification_operation_id = Some(write_operation_id.clone());
    report.setup_create_operation_id = Some(create_operation_id.clone());
    report.setup_start_operation_id = Some(start_operation_id.clone());
    report.setup_exec_operation_id = Some(exec_operation_id.clone());
    report.container_id = Some(container_id.clone());
    report.exec_process_id = Some(process_id.clone());
    report.exec_terminal = Some(false);
    report.write_stdin_data = Some(write_data.clone());
    let qualification = Qualification {
        create: CreateRequest {
            context: OperationContext::new(create_operation_id),
            id: container_id,
            bundle: staged.bundle,
            isolation: IsolationRequest::DedicatedVm,
            attachments: staged.attachments,
        },
        start_operation_id,
        exec_operation_id,
        write_operation_id,
        delete_operation_id,
        stale_guest_operation_id,
        stale_host_operation_id,
        process_id,
        process,
        io,
        write_data: write_data.clone(),
        init_marker_contents: format!("a3s-oci-exec-init-{nonce}\n").into_bytes(),
        exec_marker_contents: format!("a3s-oci-exec-process-{nonce}\n").into_bytes(),
        write_marker_contents: write_data,
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
        .join("write-stdin-reopen-first.log");
    let replacement_console = prepared
        .console_directory
        .join("write-stdin-reopen-replacement.log");

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
        report.marker_absent_after_cleanup && !source_init_marker.exists();
    report.exec_marker_absent_after_cleanup =
        report.exec_marker_absent_after_cleanup && !source_exec_marker.exists();
    report.write_marker_absent_after_cleanup =
        report.write_marker_absent_after_cleanup && !source_write_marker.exists();
    match bundle::runtime_inventory(&prepared.runtime_root) {
        Ok(inventory)
            if inventory.bundle_handoffs_clean
                && inventory.runtime_shares_clean
                && inventory.recovery_reports_clean
                && inventory.console_files == 2 => {}
        Ok(inventory) => append_reason(
            &mut report,
            format!(
                "KVM WriteStdin reopen left transient runtime state: bundle_handoffs_clean={}, runtime_shares_clean={}, recovery_reports_clean={}, console_files={}",
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
                "KVM WriteStdin reopen modified the private bootstrap root {}",
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
