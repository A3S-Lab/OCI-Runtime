use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{
    ContainerTarget, DeleteRequest, Error, ErrorCode, ExecRequest, ExitStatus, OperationId,
    ProcessId, ProcessIo, ProcessRecord, ProcessTarget, SignalProcessRequest, StartRequest,
    TerminalSize, WaitProcessRequest,
};

pub(super) use super::super::super::exec::{
    exact_process_target, stale_target, wait_for_exact_marker, EXEC_MARKER_NAME,
};
pub(super) use super::super::super::workload_marker::{path_absent, reset_marker, runtime_marker};
use super::super::super::QUALIFICATION_FAULT_OPERATION;
pub(super) use crate::operation_journal_evidence::EmptyOperationJournalStatus as SignalProcessJournalStatus;
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::{DriverExecRequest, DriverSignalProcessRequest, OciVmOperationReopenReplacementReport};

pub(super) type CreateIdentity = (OperationId, ContainerTarget);
pub(super) type WaitProcessIdentity = (ProcessTarget, Option<u64>);

pub(super) struct FirstOwnerOutcome {
    pub(super) target: ContainerTarget,
    pub(super) mount_root: PathBuf,
    pub(super) init_marker: PathBuf,
    pub(super) exec_marker: PathBuf,
    pub(super) create_identity: CreateIdentity,
    pub(super) start_identity: CreateIdentity,
    pub(super) exec_record: ProcessRecord,
    pub(super) exec_identity: DriverExecRequest,
    pub(super) signal_process_identity: DriverSignalProcessRequest,
    pub(super) wait_process_identity: WaitProcessIdentity,
    pub(super) start: StartRequest,
    pub(super) exec: ExecRequest,
    pub(super) signal_process: SignalProcessRequest,
    pub(super) wait_process: WaitProcessRequest,
    pub(super) delete: DeleteRequest,
    pub(super) response_delivered: bool,
}

pub(in crate::utility_vm_driver::operation_reopen::wait_process) fn waitable_exec_process(
    nonce: &str,
) -> Result<(ProcessId, Process, ProcessIo), String> {
    if nonce.is_empty()
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("KVM WaitProcess qualification nonce contains unsafe shell characters".into());
    }
    let process_id = ProcessId::new(format!("wait-worker-{nonce}"))
        .map_err(|error| format!("failed to construct waitable Exec process ID: {error}"))?;
    let command = format!(
        "set -eu; printf 'a3s-oci-wait-process-{nonce}\\n' > /{EXEC_MARKER_NAME}; exec /bin/busybox sleep 3600"
    );
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": true,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", command],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .map_err(|error| format!("failed to construct waitable terminal Exec process: {error}"))?;
    let io = ProcessIo {
        stdin: a3s_oci_sdk::IoMode::Terminal,
        stdout: a3s_oci_sdk::IoMode::Terminal,
        stderr: a3s_oci_sdk::IoMode::Terminal,
        terminal_size: Some(TerminalSize {
            width: 80,
            height: 24,
        }),
    };
    Ok((process_id, process, io))
}

pub(super) fn exec_marker(init_marker: &Path) -> Result<PathBuf, String> {
    init_marker
        .parent()
        .map(|rootfs| rootfs.join(EXEC_MARKER_NAME))
        .ok_or_else(|| "KVM WaitProcess init marker has no rootfs parent".to_string())
}

pub(super) async fn signal_process_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    target: &ProcessTarget,
) -> Result<SignalProcessJournalStatus, String> {
    crate::operation_journal_evidence::process_empty_operation_journal_status(
        state_root,
        operation_id,
        "signal-process",
        target,
    )
    .await
}

pub(super) async fn process_exit_cache(
    state_root: &Path,
    target: &ProcessTarget,
) -> Result<(ProcessRecord, Option<ExitStatus>), String> {
    crate::operation_journal_evidence::process_exit_cache(state_root, target).await
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
            "first KVM owner returned an unexpected WaitProcess transport error at {}: {error}",
            stage.as_str()
        ))
    }
}

pub(super) fn identity_or_expected<T: Clone>(
    identity: Result<T, String>,
    failure: &mut Option<String>,
    expected: T,
) -> T {
    match identity {
        Ok(identity) => identity,
        Err(reason) => {
            append_failure(failure, reason);
            expected
        }
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
    use super::{waitable_exec_process, EXEC_MARKER_NAME};
    use crate::operation_reopen_replacement_report::wait_process::{
        WAIT_PROCESS_SIGNAL, WAIT_PROCESS_TIMEOUT_MS,
    };

    #[test]
    fn waitable_exec_is_nonce_bound_terminal_signal_target() {
        let (process_id, process, io) =
            waitable_exec_process("wait-123").expect("waitable Exec payload");
        assert_eq!(process_id.as_str(), "wait-worker-wait-123");
        let process = serde_json::to_value(process).expect("process JSON");
        assert_eq!(
            process.get("terminal"),
            Some(&serde_json::Value::Bool(true))
        );
        assert!(process
            .pointer("/args/2")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|command| {
                command.contains("a3s-oci-wait-process-wait-123")
                    && command.contains(EXEC_MARKER_NAME)
                    && command.contains("exec /bin/busybox sleep 3600")
            }));
        assert_eq!(WAIT_PROCESS_SIGNAL, 10);
        assert_eq!(WAIT_PROCESS_TIMEOUT_MS, 15_000);
        assert_eq!(
            io.terminal_size,
            Some(a3s_oci_sdk::TerminalSize {
                width: 80,
                height: 24,
            })
        );
        assert!(waitable_exec_process("unsafe nonce").is_err());
    }
}
