use super::*;

pub(in crate::oci_smoke::utility_vm) async fn run(
    shim: &Path,
    vm_rootfs: &Path,
    bundle_directory: &Path,
    console_directory: &Path,
    stage: AgentTransportOperationStage,
) -> OciVmOperationReopenReplacementReport {
    let mut report =
        OciVmOperationReopenReplacementReport::initial_wait(HostPlatform::current(), stage);
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
        Ok(bundle) => {
            report.bundle_loaded = true;
            bundle
        }
        Err(error) => return failed(report, format!("failed to load OCI bundle: {error}")),
    };
    let rootfs = match fixed_rootfs(&bundle).await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let marker = rootfs.join(MARKER_NAME);
    match path_exists(&marker).await {
        Ok(false) => {}
        Ok(true) => {
            return failed(
                report,
                format!(
                    "refusing to overwrite an existing Wait reopen qualification marker: {}",
                    marker.display()
                ),
            );
        }
        Err(reason) => return failed(report, reason),
    }
    let baseline_runtime_entries = match runtime_entries(&vm_rootfs).await {
        Ok(entries) => entries,
        Err(reason) => return failed(report, reason),
    };
    let nonce = match unique_nonce() {
        Ok(nonce) => nonce,
        Err(reason) => return failed(report, reason),
    };
    let exact_target = match target(&format!("wait-reopen-{nonce}")) {
        Ok(target) => target,
        Err(reason) => return failed(report, reason),
    };
    let create_operation_id = match operation_id(&format!("wait-reopen-{nonce}-create")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let start_operation_id = match operation_id(&format!("wait-reopen-{nonce}-start")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let kill_operation_id = match operation_id(&format!("wait-reopen-{nonce}-kill")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let qualification_operation_id =
        match operation_id(&format!("wait-reopen-{nonce}-qualification")) {
            Ok(operation_id) => operation_id,
            Err(reason) => return failed(report, reason),
        };
    let delete_operation_id = match operation_id(&format!("wait-reopen-{nonce}-delete")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let process_io = ProcessIo {
        stdin: IoMode::Null,
        stdout: IoMode::Null,
        stderr: IoMode::Null,
        terminal_size: None,
    };
    let attachments = match CreateAttachments::from_bundle(&bundle, process_io) {
        Ok(attachments) => attachments,
        Err(error) => {
            return failed(
                report,
                format!("failed to construct Wait reopen Create attachments: {error}"),
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
    let guest_qualification = if stage.is_guest() {
        match AgentTransportQualificationRequest::new(
            qualification_operation_id.clone(),
            AgentOperation::Wait,
            stage,
        ) {
            Ok(request) => Some(request),
            Err(error) => {
                return failed(
                    report,
                    format!("failed to construct Guest Wait qualification: {error}"),
                );
            }
        }
    } else {
        None
    };
    report.qualification_operation_id = Some(qualification_operation_id);
    report.setup_create_operation_id = Some(create_operation_id);
    report.setup_start_operation_id = Some(start_operation_id.clone());
    report.setup_kill_operation_id = Some(kill_operation_id.clone());
    report.container_id = Some(exact_target.id.clone());

    let state_root = console_directory.join(format!("a3s-oci-wait-reopen-{nonce}-state"));
    if let Err(reason) = create_qualification_state_root(&state_root).await {
        return failed(report, reason);
    }
    let first_console = console_directory.join(format!("a3s-oci-wait-reopen-{nonce}-first.log"));
    let replacement_console =
        console_directory.join(format!("a3s-oci-wait-reopen-{nonce}-replacement.log"));

    let exercise = exercise(
        shim,
        &vm_rootfs,
        &state_root,
        &first_console,
        &replacement_console,
        &marker,
        &create,
        &start_operation_id,
        &kill_operation_id,
        &delete_operation_id,
        &baseline_runtime_entries,
        stage,
        guest_qualification.as_ref(),
        &mut report,
    )
    .await;

    match remove_marker_if_present(&marker).await {
        Ok(()) => match path_exists(&marker).await {
            Ok(false) => report.marker_absent_after_cleanup = true,
            Ok(true) => append_reason(
                &mut report,
                format!("Wait qualification marker remained: {}", marker.display()),
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
