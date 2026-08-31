use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{
    ContainerTarget, DeleteRequest, Error, ErrorCode, ExecRequest, IoMode, OperationId, ProcessId,
    ProcessIo, ProcessTarget, ResizeRequest, StartRequest, TerminalSize,
};

use super::super::super::exec::{dispatch_may_have_reached, EXEC_MARKER_NAME};
pub(super) use super::super::super::workload_marker::{path_absent, reset_marker, runtime_marker};
use super::super::super::QUALIFICATION_FAULT_OPERATION;
use crate::marker::{exact_marker_state, ExactMarkerState};
pub(super) use crate::operation_journal_evidence::EmptyOperationJournalStatus as ResizeJournalStatus;
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::{DriverExecRequest, DriverResizeRequest, OciVmOperationReopenReplacementReport};

pub(in crate::utility_vm_driver::operation_reopen::resize) const RESIZE_MARKER_NAME: &str =
    ".a3s-oci-resize-reopen-smoke";

pub(super) type CreateIdentity = (OperationId, ContainerTarget);

pub(super) struct FirstOwnerOutcome {
    pub(super) target: ContainerTarget,
    pub(super) mount_root: PathBuf,
    pub(super) init_marker: PathBuf,
    pub(super) exec_marker: PathBuf,
    pub(super) resize_marker: PathBuf,
    pub(super) create_identity: CreateIdentity,
    pub(super) start_identity: CreateIdentity,
    pub(super) exec_identity: DriverExecRequest,
    pub(super) resize_identity: DriverResizeRequest,
    pub(super) start: StartRequest,
    pub(super) exec: ExecRequest,
    pub(super) resize: ResizeRequest,
    pub(super) delete: DeleteRequest,
    pub(super) response_delivered: bool,
}

pub(in crate::utility_vm_driver::operation_reopen::resize) fn terminal_exec_process(
    nonce: &str,
) -> Result<(ProcessId, Process, ProcessIo), String> {
    if nonce.is_empty()
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("KVM Resize qualification nonce contains unsafe shell characters".into());
    }
    let process_id = ProcessId::new(format!("resize-worker-{nonce}"))
        .map_err(|error| format!("failed to construct terminal Exec process ID: {error}"))?;
    let command = format!(
        r#"set -eu; trap 'size=$(/bin/busybox stty size); printf "a3s-oci-resize-{nonce}:%s\n" "$size" > /{RESIZE_MARKER_NAME}' WINCH; printf 'a3s-oci-exec-process-{nonce}\n' > /{EXEC_MARKER_NAME}; while :; do /bin/busybox sleep 1; done"#,
    );
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": true,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", command],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .map_err(|error| format!("failed to construct terminal Exec process: {error}"))?;
    let io = ProcessIo {
        stdin: IoMode::Terminal,
        stdout: IoMode::Terminal,
        stderr: IoMode::Terminal,
        terminal_size: Some(TerminalSize {
            width: 80,
            height: 24,
        }),
    };
    Ok((process_id, process, io))
}

pub(super) fn process_marker(
    init_marker: &Path,
    name: &str,
    label: &str,
) -> Result<PathBuf, String> {
    init_marker
        .parent()
        .map(|rootfs| rootfs.join(name))
        .ok_or_else(|| format!("KVM Resize {label} marker has no rootfs parent"))
}

pub(super) async fn verify_first_resize_marker(
    marker: &Path,
    expected: &[u8],
    stage: AgentTransportOperationStage,
) -> Result<(), String> {
    let marker_exists = !path_absent(marker).await?;
    if !dispatch_may_have_reached(stage) && marker_exists {
        return Err(format!(
            "{} produced a KVM Resize marker before Guest dispatch",
            stage.as_str()
        ));
    }
    if !marker_exists {
        return Ok(());
    }
    let contents = tokio::fs::read(marker).await.map_err(|error| {
        format!(
            "failed to read first-owner KVM Resize marker {}: {error}",
            marker.display()
        )
    })?;
    match exact_marker_state(&contents, expected) {
        ExactMarkerState::Complete | ExactMarkerState::InProgress => Ok(()),
        ExactMarkerState::Mismatch => {
            Err("first-owner KVM Resize produced unexpected marker contents".to_string())
        }
    }
}

pub(super) async fn resize_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    target: &ProcessTarget,
) -> Result<ResizeJournalStatus, String> {
    crate::operation_journal_evidence::process_empty_operation_journal_status(
        state_root,
        operation_id,
        "resize",
        target,
    )
    .await
}

pub(super) async fn durable_exec_process(
    state_root: &Path,
    target: &ProcessTarget,
) -> Result<a3s_oci_sdk::ProcessRecord, String> {
    crate::operation_journal_evidence::durable_process(state_root, target).await
}

pub(super) fn record_interruption(
    report: &mut OciVmOperationReopenReplacementReport,
    error: Error,
    stage: AgentTransportOperationStage,
) -> Result<(), String> {
    report.first_operation_error_code = Some(error.code);
    report.first_operation_error_operation = error.operation.clone();
    report.first_operation_error_retryable = error.retryable;
    let expected_operation = if stage.is_guest() {
        error
            .operation
            .as_deref()
            .is_some_and(is_retryable_disconnect_operation)
    } else {
        error.operation.as_deref() == Some(QUALIFICATION_FAULT_OPERATION)
    };
    if error.code == ErrorCode::Unavailable && error.retryable && expected_operation {
        Ok(())
    } else {
        Err(format!(
            "first KVM owner returned an unexpected Resize transport error at {}: {error}",
            stage.as_str()
        ))
    }
}

pub(super) fn append_failure(failure: &mut Option<String>, reason: impl Into<String>) {
    let reason = reason.into();
    *failure = Some(match failure.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

#[cfg(test)]
mod tests {
    use super::{terminal_exec_process, RESIZE_MARKER_NAME};
    use crate::utility_vm_driver::operation_reopen::exec::EXEC_MARKER_NAME;

    #[test]
    fn terminal_exec_is_nonce_bound_and_resizable() {
        let (process_id, process, io) =
            terminal_exec_process("resize-123").expect("terminal Exec payload");
        assert_eq!(process_id.as_str(), "resize-worker-resize-123");
        let process = serde_json::to_value(process).expect("process JSON");
        assert_eq!(
            process.get("terminal"),
            Some(&serde_json::Value::Bool(true))
        );
        assert!(process
            .pointer("/args/2")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|command| {
                command.contains("stty size")
                    && command.contains("trap")
                    && command.contains(RESIZE_MARKER_NAME)
                    && command.contains(EXEC_MARKER_NAME)
            }));
        assert_eq!(io.stdin, a3s_oci_sdk::IoMode::Terminal);
        assert_eq!(io.stdout, a3s_oci_sdk::IoMode::Terminal);
        assert_eq!(io.stderr, a3s_oci_sdk::IoMode::Terminal);
        assert_eq!(
            io.terminal_size,
            Some(a3s_oci_sdk::TerminalSize {
                width: 80,
                height: 24,
            })
        );
        assert!(terminal_exec_process("unsafe nonce").is_err());
    }
}
