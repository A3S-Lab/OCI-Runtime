use std::path::Path;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportOperationStage, AgentTransportQualificationRequest,
};
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{
    ContainerTarget, CreateAttachments, CreateRequest, FilesystemOp, FilesystemRequest, IoMode,
    IsolationRequest, OciBundle, OperationContext, ProcessIo, StartRequest,
};

use super::super::super::{
    canonical_directory, fixed_rootfs, path_exists, runtime_entries, target, unique_nonce,
    MARKER_NAME,
};
use super::super::delete_support::{append_reason, failed, remove_marker_if_present};
use super::super::exec::support::{nonce_bound_bundle, operation_id};
use super::{exercise, Qualification};
use crate::OciVmOperationReopenReplacementReport;

pub(in crate::oci_smoke::utility_vm) async fn run(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: AgentTransportOperationStage,
) -> OciVmOperationReopenReplacementReport {
    let mut report =
        OciVmOperationReopenReplacementReport::initial_filesystem(HostPlatform::current(), stage);
    let vm_rootfs = match canonical_directory(vm_rootfs, "VM rootfs").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let bundle_directory = match canonical_directory(bundle_directory, "OCI bundle").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let console_directory =
        match canonical_directory(console_directory, "qualification console directory").await {
            Ok(path) => path,
            Err(reason) => return failed(report, reason),
        };
    if bundle_directory == vm_rootfs || !bundle_directory.starts_with(&vm_rootfs) {
        return failed(
            report,
            format!(
                "OCI bundle must be a strict descendant of VM rootfs {}: {}",
                vm_rootfs.display(),
                bundle_directory.display()
            ),
        );
    }

    let bundle = match OciBundle::load(&bundle_directory).await {
        Ok(bundle) => bundle,
        Err(error) => return failed(report, format!("failed to load OCI bundle: {error}")),
    };
    let nonce = match unique_nonce() {
        Ok(nonce) => nonce,
        Err(reason) => return failed(report, reason),
    };
    let bundle = match nonce_bound_bundle(bundle, &nonce)
        .and_then(super::super::file::support::session_filesystem_bundle)
    {
        Ok(bundle) => {
            report.bundle_loaded = true;
            bundle
        }
        Err(reason) => return failed(report, reason),
    };
    let rootfs = match fixed_rootfs(&bundle).await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let init_marker = rootfs.join(MARKER_NAME);
    match path_exists(&init_marker).await {
        Ok(false) => {}
        Ok(true) => {
            return failed(
                report,
                format!(
                    "refusing to overwrite an existing Filesystem init marker: {}",
                    init_marker.display()
                ),
            );
        }
        Err(reason) => return failed(report, reason),
    }
    let baseline_runtime_entries = match runtime_entries(&vm_rootfs).await {
        Ok(entries) => entries,
        Err(reason) => return failed(report, reason),
    };
    let exact_target = match target(&format!("filesystem-reopen-{nonce}")) {
        Ok(target) => target,
        Err(reason) => return failed(report, reason),
    };
    let create_operation_id = match operation_id(&format!("filesystem-reopen-{nonce}-create")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let start_operation_id = match operation_id(&format!("filesystem-reopen-{nonce}-start")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let filesystem_operation_id = match operation_id(&format!("filesystem-reopen-{nonce}-mkdir")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let cleanup_operation_id = match operation_id(&format!("filesystem-reopen-{nonce}-cleanup")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let delete_operation_id = match operation_id(&format!("filesystem-reopen-{nonce}-delete")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let stale_guest_operation_id =
        match operation_id(&format!("filesystem-reopen-{nonce}-stale-guest")) {
            Ok(operation_id) => operation_id,
            Err(reason) => return failed(report, reason),
        };
    let stale_host_operation_id =
        match operation_id(&format!("filesystem-reopen-{nonce}-stale-host")) {
            Ok(operation_id) => operation_id,
            Err(reason) => return failed(report, reason),
        };

    let attachments = match CreateAttachments::from_bundle(
        &bundle,
        ProcessIo {
            stdin: IoMode::Null,
            stdout: IoMode::Null,
            stderr: IoMode::Null,
            terminal_size: None,
        },
    ) {
        Ok(attachments) => attachments,
        Err(error) => {
            return failed(
                report,
                format!("failed to construct Filesystem Create attachments: {error}"),
            );
        }
    };
    let create = CreateRequest {
        context: OperationContext::new(create_operation_id.clone()),
        id: exact_target.id.clone(),
        bundle,
        isolation: IsolationRequest::DedicatedVm,
        attachments,
    };
    let start = StartRequest {
        context: OperationContext::new(start_operation_id.clone()),
        target: exact_target.clone(),
    };
    let path = format!("/tmp/.a3s-oci-filesystem-reopen-{nonce}");
    let current_target = ContainerTarget::current(exact_target.id.clone());
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
    let cleanup_filesystem = FilesystemRequest {
        target: current_target,
        op: FilesystemOp::Remove,
        path: path.clone(),
        destination: None,
        depth: 0,
        user: None,
        context: Some(OperationContext::new(cleanup_operation_id)),
    };
    let guest_qualification = if stage.is_guest() {
        match AgentTransportQualificationRequest::new(
            filesystem_operation_id.clone(),
            AgentOperation::Filesystem,
            stage,
        ) {
            Ok(request) => Some(request),
            Err(error) => {
                return failed(
                    report,
                    format!("failed to construct Guest Filesystem qualification: {error}"),
                );
            }
        }
    } else {
        None
    };
    report.qualification_operation_id = Some(filesystem_operation_id);
    report.setup_create_operation_id = Some(create_operation_id);
    report.setup_start_operation_id = Some(start_operation_id);
    report.container_id = Some(exact_target.id.clone());
    report.filesystem_op = Some(FilesystemOp::MakeDir);
    report.filesystem_path = Some(path);
    report.filesystem_destination = None;
    report.filesystem_depth = Some(0);
    report.filesystem_user = None;

    let state_root = console_directory.join(format!("a3s-oci-filesystem-reopen-{nonce}-state"));
    if let Err(reason) = super::super::create_qualification_state_root(&state_root).await {
        return failed(report, reason);
    }
    let qualification = Qualification {
        shim: shim.to_path_buf(),
        vm_rootfs,
        system_image_manifest: system_image_manifest.to_path_buf(),
        state_root: state_root.clone(),
        first_console: console_directory
            .join(format!("a3s-oci-filesystem-reopen-{nonce}-first.log")),
        replacement_console: console_directory
            .join(format!("a3s-oci-filesystem-reopen-{nonce}-replacement.log")),
        init_marker,
        init_marker_contents: format!("a3s-oci-exec-init-{nonce}\n").into_bytes(),
        create,
        start,
        filesystem,
        stat,
        cleanup_filesystem,
        delete_operation_id,
        stale_guest_operation_id,
        stale_host_operation_id,
        baseline_runtime_entries,
        stage,
        guest_qualification,
    };

    let exercise = exercise(&qualification, &mut report).await;

    match remove_marker_if_present(&qualification.init_marker).await {
        Ok(()) if path_exists(&qualification.init_marker).await == Ok(false) => {
            report.marker_absent_after_cleanup = true;
        }
        Ok(()) => append_reason(&mut report, "Filesystem init marker remained after cleanup"),
        Err(reason) => append_reason(&mut report, reason),
    }
    match tokio::fs::remove_dir_all(&state_root).await {
        Ok(()) => match path_exists(&state_root).await {
            Ok(false) => report.state_root_removed = true,
            Ok(true) => append_reason(
                &mut report,
                format!(
                    "qualification state root remained after removal: {}",
                    state_root.display()
                ),
            ),
            Err(reason) => append_reason(&mut report, reason),
        },
        Err(error) => append_reason(
            &mut report,
            format!(
                "failed to remove qualification state root {}: {error}",
                state_root.display()
            ),
        ),
    }
    if let Err(reason) = exercise {
        append_reason(&mut report, reason);
    }
    if report.evidence_succeeded() {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    }
    report
}
