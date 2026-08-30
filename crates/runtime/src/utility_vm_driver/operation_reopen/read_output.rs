use std::path::PathBuf;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{
    ContainerTarget, CreateRequest, IoMode, IsolationRequest, OciBundle, OperationContext,
    OutputChunk, OutputStream, ProcessId, ProcessIo, ProcessTarget, ReadOutputRequest,
};

use super::exec::nonce_bound_bundle;
use super::{bundle_marker, directory_is_empty, operation_id, unique_nonce};
use crate::linux_kvm_recovery_smoke::bundle;
use crate::utility_vm_driver::layout::{
    ensure_private_directory, PreparedUtilityVmLayout, UtilityVmBootstrap,
};
use crate::OciVmOperationReopenReplacementReport;

mod flow;

const READ_OUTPUT_MARKER_NAME: &str = ".a3s-oci-read-output-reopen-smoke";
const READ_OUTPUT_WAIT_TIMEOUT_MS: u64 = 5_000;

/// Exact inputs for one real Linux KVM ReadOutput interruption and owner reopen.
#[derive(Debug, Clone)]
pub struct LinuxKvmReadOutputReopenConfig {
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
    read_output_operation_id: a3s_oci_sdk::OperationId,
    delete_operation_id: a3s_oci_sdk::OperationId,
    process_id: ProcessId,
    process: Process,
    io: ProcessIo,
    read_output: ReadOutputRequest,
    expected_output: Vec<OutputChunk>,
    init_marker_contents: Vec<u8>,
    exec_marker_contents: Vec<u8>,
    stage: AgentTransportOperationStage,
}

/// Rebuild one captured-output Exec and query it through a distinct KVM owner.
///
/// Create, Start, Exec, ReadOutput, output validation, stale-generation
/// fencing, process-record rebinding, marker verification, and cleanup use the
/// production
/// immutable-image, exact-generation handoff, and authenticated Guest Agent
/// path. This remains qualification-only and does not register the probe-only
/// KVM candidate.
pub async fn linux_kvm_read_output_reopen_replacement(
    config: LinuxKvmReadOutputReopenConfig,
) -> OciVmOperationReopenReplacementReport {
    let mut report = OciVmOperationReopenReplacementReport::initial_read_output(
        HostPlatform::current(),
        config.stage,
    );
    if HostPlatform::current() != HostPlatform::Linux {
        return failed(
            report,
            "Linux KVM ReadOutput reopen qualification requires Linux",
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
        match a3s_oci_sdk::ContainerId::new(format!("kvm-read-output-reopen-{nonce}")) {
            Ok(id) => id,
            Err(error) => {
                return failed(report, format!("failed to construct container ID: {error}"))
            }
        };
    let create_operation_id = match operation_id(&format!("kvm-read-output-reopen-{nonce}-create"))
    {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let start_operation_id = match operation_id(&format!("kvm-read-output-reopen-{nonce}-start")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let exec_operation_id = match operation_id(&format!("kvm-read-output-reopen-{nonce}-exec")) {
        Ok(operation_id) => operation_id,
        Err(reason) => return failed(report, reason),
    };
    let read_output_operation_id =
        match operation_id(&format!("kvm-read-output-reopen-{nonce}-query")) {
            Ok(operation_id) => operation_id,
            Err(reason) => return failed(report, reason),
        };
    let delete_operation_id = match operation_id(&format!("kvm-read-output-reopen-{nonce}-delete"))
    {
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
    let source_exec_marker = match source_init_marker.parent() {
        Some(rootfs) => rootfs.join(READ_OUTPUT_MARKER_NAME),
        None => return failed(report, "KVM ReadOutput init marker has no rootfs parent"),
    };
    for (label, marker) in [("init", &source_init_marker), ("Exec", &source_exec_marker)] {
        if marker.exists() {
            return failed(
                report,
                format!(
                    "refusing to use a KVM ReadOutput qualification bundle with an existing {label} marker: {}",
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
    let (process_id, process, io, output) = match read_output_exec(&nonce) {
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
    let read_output = ReadOutputRequest {
        process: ProcessTarget {
            container: ContainerTarget::current(container_id.clone()),
            process_id: process_id.clone(),
        },
        after_sequence: 0,
        max_bytes,
        wait_timeout_ms: Some(READ_OUTPUT_WAIT_TIMEOUT_MS),
    };
    report.bundle_loaded = true;
    report.qualification_operation_id = Some(read_output_operation_id.clone());
    report.setup_create_operation_id = Some(create_operation_id.clone());
    report.setup_start_operation_id = Some(start_operation_id.clone());
    report.setup_exec_operation_id = Some(exec_operation_id.clone());
    report.container_id = Some(container_id.clone());
    report.exec_process_id = Some(process_id.clone());
    report.exec_terminal = Some(false);
    report.read_output_after_sequence = Some(read_output.after_sequence);
    report.read_output_max_bytes = Some(read_output.max_bytes);
    report.read_output_wait_timeout_ms = read_output.wait_timeout_ms;
    report.expected_output_chunks = Some(expected_output.clone());
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
        read_output_operation_id,
        delete_operation_id,
        process_id,
        process,
        io,
        read_output,
        expected_output,
        init_marker_contents: format!("a3s-oci-exec-init-{nonce}\n").into_bytes(),
        exec_marker_contents: format!("a3s-oci-read-output-ready-{nonce}\n").into_bytes(),
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
        .join("read-output-reopen-first.log");
    let replacement_console = prepared
        .console_directory
        .join("read-output-reopen-replacement.log");

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
    match bundle::runtime_inventory(&prepared.runtime_root) {
        Ok(inventory)
            if inventory.bundle_handoffs_clean
                && inventory.runtime_shares_clean
                && inventory.recovery_reports_clean
                && inventory.console_files == 2 => {}
        Ok(inventory) => append_reason(
            &mut report,
            format!(
                "KVM ReadOutput reopen left transient runtime state: bundle_handoffs_clean={}, runtime_shares_clean={}, recovery_reports_clean={}, console_files={}",
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
                "KVM ReadOutput reopen modified the private bootstrap root {}",
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

fn read_output_exec(nonce: &str) -> Result<(ProcessId, Process, ProcessIo, Vec<u8>), String> {
    let process_id = ProcessId::new(format!("reader-{nonce}"))
        .map_err(|error| format!("failed to construct ReadOutput process ID: {error}"))?;
    let output = format!("a3s-oci-read-output-{nonce}\n").into_bytes();
    let command = format!(
        "set -eu; printf 'a3s-oci-read-output-{nonce}\\n'; printf 'a3s-oci-read-output-ready-{nonce}\\n' > /{READ_OUTPUT_MARKER_NAME}; while :; do /bin/busybox sleep 1; done"
    );
    let process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", command],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .map_err(|error| format!("failed to construct ReadOutput Exec process: {error}"))?;
    let io = ProcessIo {
        stdin: IoMode::Null,
        stdout: IoMode::Capture,
        stderr: IoMode::Capture,
        terminal_size: None,
    };
    Ok((process_id, process, io, output))
}

fn expected_chunks(output: Vec<u8>) -> Result<Vec<OutputChunk>, String> {
    let sequence = u64::try_from(output.len())
        .map_err(|_| "ReadOutput payload length does not fit u64".to_string())?;
    Ok(vec![OutputChunk {
        sequence,
        stream: OutputStream::Stdout,
        data: output,
        eof: false,
    }])
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
