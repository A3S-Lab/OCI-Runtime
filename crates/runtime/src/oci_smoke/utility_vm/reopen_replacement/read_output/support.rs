use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{
    Error, ErrorCode, IoMode, OutputChunk, OutputStream, ProcessId, ProcessIo, TerminalSize,
};

use super::super::{QualificationHvfDriver, FAULT_OPERATION};
use super::READ_OUTPUT_MARKER_NAME;
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::OciVmOperationReopenReplacementReport;

pub(super) fn read_output_exec(
    nonce: &str,
) -> std::result::Result<(ProcessId, Process, ProcessIo, Vec<u8>), String> {
    let process_id = ProcessId::new(format!("reader-{nonce}"))
        .map_err(|error| format!("failed to construct ReadOutput process ID: {error}"))?;
    let output = format!("a3s-oci-read-output-{nonce}\n").into_bytes();
    let command = format!(
        "set -eu; printf 'a3s-oci-read-output-{nonce}\\n'; printf 'a3s-oci-read-output-ready-{nonce}\\n' > /{READ_OUTPUT_MARKER_NAME}; while :; do /bin/busybox sleep 1; done"
    );
    let process: Process = serde_json::from_value(serde_json::json!({
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
        terminal_size: None::<TerminalSize>,
    };
    Ok((process_id, process, io, output))
}

pub(super) fn expected_chunks(output: Vec<u8>) -> std::result::Result<Vec<OutputChunk>, String> {
    let sequence = u64::try_from(output.len())
        .map_err(|_| "ReadOutput payload length does not fit u64".to_string())?;
    Ok(vec![OutputChunk {
        sequence,
        stream: OutputStream::Stdout,
        data: output,
        eof: false,
    }])
}

pub(super) fn record_recovery_evidence(
    report: &mut OciVmOperationReopenReplacementReport,
    driver: &QualificationHvfDriver,
) {
    super::super::exec::support::record_recovery_evidence(report, driver);
}

pub(super) fn record_interruption(
    report: &mut OciVmOperationReopenReplacementReport,
    error: Error,
    stage: AgentTransportOperationStage,
) -> std::result::Result<(), String> {
    report.first_operation_error_code = Some(error.code);
    report.first_operation_error_operation = error.operation.clone();
    report.first_operation_error_retryable = error.retryable;
    let expected_operation = if stage.is_guest() {
        error
            .operation
            .as_deref()
            .is_some_and(is_retryable_disconnect_operation)
    } else {
        error.operation.as_deref() == Some(FAULT_OPERATION)
    };
    if error.code == ErrorCode::Unavailable && error.retryable && expected_operation {
        Ok(())
    } else {
        Err(format!(
            "first owner returned an unexpected ReadOutput transport error at {}: {error}",
            stage.as_str()
        ))
    }
}
