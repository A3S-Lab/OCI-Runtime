use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{
    ContainerTarget, DeleteRequest, Error, ErrorCode, ExecRequest, IoMode, OperationId, ProcessId,
    ProcessIo, ProcessTarget, StartRequest, WriteStdinRequest,
};

use super::super::super::exec::{dispatch_may_have_reached, EXEC_MARKER_NAME};
pub(super) use super::super::super::workload_marker::{path_absent, reset_marker, runtime_marker};
use super::super::super::QUALIFICATION_FAULT_OPERATION;
use crate::marker::{exact_marker_state, ExactMarkerState};
pub(super) use crate::operation_journal_evidence::EmptyOperationJournalStatus as WriteStdinJournalStatus;
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::{DriverExecRequest, DriverWriteStdinRequest, OciVmOperationReopenReplacementReport};

pub(in crate::utility_vm_driver::operation_reopen::write_stdin) const WRITE_MARKER_NAME: &str =
    ".a3s-oci-write-stdin-reopen-smoke";

pub(super) type CreateIdentity = (OperationId, ContainerTarget);

pub(super) struct FirstOwnerOutcome {
    pub(super) target: ContainerTarget,
    pub(super) mount_root: PathBuf,
    pub(super) init_marker: PathBuf,
    pub(super) exec_marker: PathBuf,
    pub(super) write_marker: PathBuf,
    pub(super) create_identity: CreateIdentity,
    pub(super) start_identity: CreateIdentity,
    pub(super) exec_identity: DriverExecRequest,
    pub(super) write_stdin_identity: DriverWriteStdinRequest,
    pub(super) start: StartRequest,
    pub(super) exec: ExecRequest,
    pub(super) write_stdin: WriteStdinRequest,
    pub(super) delete: DeleteRequest,
    pub(super) response_delivered: bool,
}

pub(in crate::utility_vm_driver::operation_reopen::write_stdin) fn stdin_exec_process(
    nonce: &str,
) -> Result<(ProcessId, Process, ProcessIo), String> {
    if nonce.is_empty()
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("KVM WriteStdin qualification nonce contains unsafe shell characters".into());
    }
    let process_id = ProcessId::new(format!("stdin-worker-{nonce}"))
        .map_err(|error| format!("failed to construct stdin Exec process ID: {error}"))?;
    let command = format!(
        "set -eu; printf 'a3s-oci-exec-process-{nonce}\\n' > /{EXEC_MARKER_NAME}; IFS= read -r input; printf '%s\\n' \"$input\" > /{WRITE_MARKER_NAME}; while :; do /bin/busybox sleep 1; done"
    );
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", command],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .map_err(|error| format!("failed to construct stdin Exec process: {error}"))?;
    let io = ProcessIo {
        stdin: IoMode::Pipe,
        stdout: IoMode::Null,
        stderr: IoMode::Null,
        terminal_size: None,
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
        .ok_or_else(|| format!("KVM WriteStdin {label} marker has no rootfs parent"))
}

pub(super) async fn verify_first_write_marker(
    marker: &Path,
    expected: &[u8],
    stage: AgentTransportOperationStage,
) -> Result<(), String> {
    let marker_exists = !path_absent(marker).await?;
    if !dispatch_may_have_reached(stage) && marker_exists {
        return Err(format!(
            "{} produced a KVM WriteStdin marker before Guest dispatch",
            stage.as_str()
        ));
    }
    if !marker_exists {
        return Ok(());
    }
    let contents = tokio::fs::read(marker).await.map_err(|error| {
        format!(
            "failed to read first-owner KVM WriteStdin marker {}: {error}",
            marker.display()
        )
    })?;
    match exact_marker_state(&contents, expected) {
        ExactMarkerState::Complete | ExactMarkerState::InProgress => Ok(()),
        ExactMarkerState::Mismatch => {
            Err("first-owner KVM WriteStdin produced unexpected marker contents".to_string())
        }
    }
}

pub(super) async fn write_stdin_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    target: &ProcessTarget,
) -> Result<WriteStdinJournalStatus, String> {
    crate::operation_journal_evidence::process_empty_operation_journal_status(
        state_root,
        operation_id,
        "write-stdin",
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
            "first KVM owner returned an unexpected WriteStdin transport error at {}: {error}",
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
    use super::{stdin_exec_process, WRITE_MARKER_NAME};
    use crate::utility_vm_driver::operation_reopen::exec::EXEC_MARKER_NAME;

    #[test]
    fn stdin_exec_is_nonce_bound_pipe_backed_workload() {
        let (process_id, process, io) =
            stdin_exec_process("write-123").expect("stdin Exec payload");
        assert_eq!(process_id.as_str(), "stdin-worker-write-123");
        let process = serde_json::to_value(process).expect("process JSON");
        assert_eq!(
            process.get("terminal"),
            Some(&serde_json::Value::Bool(false))
        );
        assert!(process
            .pointer("/args/2")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|command| {
                command.contains("IFS= read -r input")
                    && command.contains(WRITE_MARKER_NAME)
                    && command.contains(EXEC_MARKER_NAME)
                    && command.contains("while :")
            }));
        assert_eq!(io.stdin, a3s_oci_sdk::IoMode::Pipe);
        assert_eq!(io.stdout, a3s_oci_sdk::IoMode::Null);
        assert_eq!(io.stderr, a3s_oci_sdk::IoMode::Null);
        assert_eq!(io.terminal_size, None);
        assert!(stdin_exec_process("unsafe nonce").is_err());
    }
}
