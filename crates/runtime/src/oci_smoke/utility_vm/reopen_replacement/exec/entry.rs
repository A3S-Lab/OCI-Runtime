use std::path::Path;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportOperationStage, AgentTransportQualificationRequest,
};
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{
    CreateAttachments, CreateRequest, ExecRequest, IoMode, IsolationRequest, OciBundle,
    OperationContext, ProcessIo, StartRequest,
};

use super::super::super::{
    canonical_directory, fixed_rootfs, path_exists, runtime_entries, target, unique_nonce,
    MARKER_NAME,
};
use super::super::delete_support::{append_reason, failed, remove_marker_if_present};
use super::support::{nonce_bound_bundle, operation_id};
use super::{exec_process, exercise, Qualification, EXEC_MARKER_NAME};
use crate::OciVmOperationReopenReplacementReport;

pub(in crate::oci_smoke::utility_vm) async fn run(
    shim: &Path,
    vm_rootfs: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: AgentTransportOperationStage,
) -> OciVmOperationReopenReplacementReport {
    let mut report =
        OciVmOperationReopenReplacementReport::initial_exec(HostPlatform::current(), stage);
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
    let bundle = match nonce_bound_bundle(bundle, &nonce) {
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
    let exec_marker = rootfs.join(EXEC_MARKER_NAME);
    for (label, marker) in [("init", &init_marker), ("Exec", &exec_marker)] {
        match path_exists(marker).await {
            Ok(false) => {}
            Ok(true) => {
                return failed(
                    report,
                    format!(
                        "refusing to overwrite an existing {label} reopen qualification marker: {}",
                        marker.display()
                    ),
                );
            }
            Err(reason) => return failed(report, reason),
        }
    }
    let baseline_runtime_entries = match runtime_entries(&vm_rootfs).await {
        Ok(entries) => entries,
        Err(reason) => return failed(report, reason),
    };
    let exact_target = match target(&format!("exec-reopen-{nonce}")) {
        Ok(target) => target,
        Err(reason) => return failed(report, reason),
    };
    let create_operation_id = match operation_id(&format!("exec-reopen-{nonce}-create")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let start_operation_id = match operation_id(&format!("exec-reopen-{nonce}-start")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let exec_operation_id = match operation_id(&format!("exec-reopen-{nonce}-exec")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let delete_operation_id = match operation_id(&format!("exec-reopen-{nonce}-delete")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let stale_guest_operation_id = match operation_id(&format!("exec-reopen-{nonce}-stale-guest")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let stale_host_operation_id = match operation_id(&format!("exec-reopen-{nonce}-stale-host")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let (process_id, process, process_io) = match exec_process(&nonce) {
        Ok(process) => process,
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
                format!("failed to construct Exec reopen Create attachments: {error}"),
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
    let exec = ExecRequest {
        context: OperationContext::new(exec_operation_id.clone()),
        container: exact_target.clone(),
        process_id: process_id.clone(),
        process,
        io: process_io,
    };
    let guest_qualification = if stage.is_guest() {
        match AgentTransportQualificationRequest::new(
            exec_operation_id.clone(),
            AgentOperation::Exec,
            stage,
        ) {
            Ok(request) => Some(request),
            Err(error) => {
                return failed(
                    report,
                    format!("failed to construct Guest Exec qualification: {error}"),
                );
            }
        }
    } else {
        None
    };
    report.qualification_operation_id = Some(exec_operation_id);
    report.setup_create_operation_id = Some(create_operation_id);
    report.setup_start_operation_id = Some(start_operation_id);
    report.container_id = Some(exact_target.id.clone());
    report.exec_process_id = Some(process_id);

    let state_root = console_directory.join(format!("a3s-oci-exec-reopen-{nonce}-state"));
    if let Err(reason) = super::super::create_qualification_state_root(&state_root).await {
        return failed(report, reason);
    }
    let qualification = Qualification {
        shim: shim.to_path_buf(),
        vm_rootfs,
        state_root: state_root.clone(),
        first_console: console_directory.join(format!("a3s-oci-exec-reopen-{nonce}-first.log")),
        replacement_console: console_directory
            .join(format!("a3s-oci-exec-reopen-{nonce}-replacement.log")),
        init_marker,
        exec_marker,
        init_marker_contents: format!("a3s-oci-exec-init-{nonce}\n").into_bytes(),
        exec_marker_contents: format!("a3s-oci-exec-process-{nonce}\n").into_bytes(),
        create,
        start,
        exec,
        delete_operation_id,
        stale_guest_operation_id,
        stale_host_operation_id,
        baseline_runtime_entries,
        stage,
        guest_qualification,
    };

    let exercise = exercise(&qualification, &mut report).await;

    match remove_marker_if_present(&qualification.init_marker).await {
        Ok(()) => match path_exists(&qualification.init_marker).await {
            Ok(false) => report.marker_absent_after_cleanup = true,
            Ok(true) => append_reason(
                &mut report,
                format!(
                    "Exec init marker remained: {}",
                    qualification.init_marker.display()
                ),
            ),
            Err(reason) => append_reason(&mut report, reason),
        },
        Err(reason) => append_reason(&mut report, reason),
    }
    match remove_marker_if_present(&qualification.exec_marker).await {
        Ok(()) => match path_exists(&qualification.exec_marker).await {
            Ok(false) => report.exec_marker_absent_after_cleanup = true,
            Ok(true) => append_reason(
                &mut report,
                format!(
                    "Exec process marker remained: {}",
                    qualification.exec_marker.display()
                ),
            ),
            Err(reason) => append_reason(&mut report, reason),
        },
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
