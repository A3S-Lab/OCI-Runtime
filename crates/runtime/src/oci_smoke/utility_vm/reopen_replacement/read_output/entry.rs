use std::path::Path;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportOperationStage, AgentTransportQualificationRequest,
};
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{
    ContainerTarget, CreateAttachments, CreateRequest, ExecRequest, IoMode, IsolationRequest,
    OciBundle, OperationContext, ProcessIo, ProcessTarget, ReadOutputRequest, StartRequest,
};

use super::super::super::{
    canonical_directory, fixed_rootfs, path_exists, runtime_entries, target, unique_nonce,
    MARKER_NAME,
};
use super::super::delete_support::{append_reason, failed, remove_marker_if_present};
use super::super::exec::support::{nonce_bound_bundle, operation_id};
use super::support::{expected_chunks, read_output_exec};
use super::{exercise, Qualification, READ_OUTPUT_MARKER_NAME};
use crate::OciVmOperationReopenReplacementReport;

const READ_OUTPUT_WAIT_TIMEOUT_MS: u64 = 5_000;

pub(in crate::oci_smoke::utility_vm) async fn run(
    shim: &Path,
    vm_rootfs: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: AgentTransportOperationStage,
) -> OciVmOperationReopenReplacementReport {
    let mut report =
        OciVmOperationReopenReplacementReport::initial_read_output(HostPlatform::current(), stage);
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
    let exec_marker = rootfs.join(READ_OUTPUT_MARKER_NAME);
    for (label, marker) in [("init", &init_marker), ("Exec", &exec_marker)] {
        match path_exists(marker).await {
            Ok(false) => {}
            Ok(true) => {
                return failed(
                    report,
                    format!(
                        "refusing to overwrite an existing ReadOutput {label} marker: {}",
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
    let exact_target = match target(&format!("read-output-reopen-{nonce}")) {
        Ok(target) => target,
        Err(reason) => return failed(report, reason),
    };
    let qualification_operation_id =
        match operation_id(&format!("read-output-reopen-{nonce}-query")) {
            Ok(operation_id) => operation_id,
            Err(reason) => return failed(report, reason),
        };
    let create_operation_id = match operation_id(&format!("read-output-reopen-{nonce}-create")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let start_operation_id = match operation_id(&format!("read-output-reopen-{nonce}-start")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let exec_operation_id = match operation_id(&format!("read-output-reopen-{nonce}-exec")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let delete_operation_id = match operation_id(&format!("read-output-reopen-{nonce}-delete")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let (process_id, process, process_io, output) = match read_output_exec(&nonce) {
        Ok(process) => process,
        Err(reason) => return failed(report, reason),
    };
    let expected_output = match expected_chunks(output) {
        Ok(output) => output,
        Err(reason) => return failed(report, reason),
    };
    let max_bytes = match u32::try_from(expected_output[0].data.len()) {
        Ok(max_bytes) => max_bytes,
        Err(_) => return failed(report, "ReadOutput payload length does not fit u32"),
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
                format!("failed to construct ReadOutput Create attachments: {error}"),
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
    let read_output = ReadOutputRequest {
        process: ProcessTarget {
            container: ContainerTarget::current(exact_target.id.clone()),
            process_id: process_id.clone(),
        },
        after_sequence: 0,
        max_bytes,
        wait_timeout_ms: Some(READ_OUTPUT_WAIT_TIMEOUT_MS),
    };
    let guest_qualification = if stage.is_guest() {
        match AgentTransportQualificationRequest::new(
            qualification_operation_id.clone(),
            AgentOperation::ReadOutput,
            stage,
        ) {
            Ok(request) => Some(request),
            Err(error) => {
                return failed(
                    report,
                    format!("failed to construct Guest ReadOutput qualification: {error}"),
                );
            }
        }
    } else {
        None
    };
    report.qualification_operation_id = Some(qualification_operation_id);
    report.setup_create_operation_id = Some(create_operation_id);
    report.setup_start_operation_id = Some(start_operation_id);
    report.setup_exec_operation_id = Some(exec_operation_id);
    report.container_id = Some(exact_target.id.clone());
    report.exec_process_id = Some(process_id);
    report.exec_terminal = Some(false);
    report.read_output_after_sequence = Some(read_output.after_sequence);
    report.read_output_max_bytes = Some(read_output.max_bytes);
    report.read_output_wait_timeout_ms = read_output.wait_timeout_ms;
    report.expected_output_chunks = Some(expected_output.clone());

    let state_root = console_directory.join(format!("a3s-oci-read-output-reopen-{nonce}-state"));
    if let Err(reason) = super::super::create_qualification_state_root(&state_root).await {
        return failed(report, reason);
    }
    let qualification = Qualification {
        shim: shim.to_path_buf(),
        vm_rootfs,
        state_root: state_root.clone(),
        first_console: console_directory
            .join(format!("a3s-oci-read-output-reopen-{nonce}-first.log")),
        replacement_console: console_directory.join(format!(
            "a3s-oci-read-output-reopen-{nonce}-replacement.log"
        )),
        init_marker,
        exec_marker,
        init_marker_contents: format!("a3s-oci-exec-init-{nonce}\n").into_bytes(),
        exec_marker_contents: format!("a3s-oci-read-output-ready-{nonce}\n").into_bytes(),
        create,
        start,
        exec,
        read_output,
        expected_output,
        delete_operation_id,
        baseline_runtime_entries,
        stage,
        guest_qualification,
    };

    let exercise = exercise(&qualification, &mut report).await;

    match remove_marker_if_present(&qualification.init_marker).await {
        Ok(()) if path_exists(&qualification.init_marker).await == Ok(false) => {
            report.marker_absent_after_cleanup = true;
        }
        Ok(()) => append_reason(&mut report, "ReadOutput init marker remained after cleanup"),
        Err(reason) => append_reason(&mut report, reason),
    }
    match remove_marker_if_present(&qualification.exec_marker).await {
        Ok(()) if path_exists(&qualification.exec_marker).await == Ok(false) => {
            report.exec_marker_absent_after_cleanup = true;
        }
        Ok(()) => append_reason(&mut report, "ReadOutput Exec marker remained after cleanup"),
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
