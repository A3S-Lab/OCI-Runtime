use std::path::Path;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{
    Error, ErrorCode, ExitStatus, OperationId, ProcessId, ProcessIo, ProcessRecord, ProcessTarget,
    TerminalSize,
};

use super::super::{append_failure, QualificationHvfDriver, FAULT_OPERATION};
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::OciVmOperationReopenReplacementReport;

pub(super) use crate::operation_journal_evidence::EmptyOperationJournalStatus as SignalProcessJournalStatus;

pub(super) fn waitable_exec_process(
    nonce: &str,
) -> std::result::Result<(ProcessId, Process, ProcessIo), String> {
    if nonce.is_empty()
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("WaitProcess qualification nonce contains unsafe shell characters".into());
    }
    let process_id = ProcessId::new(format!("wait-worker-{nonce}"))
        .map_err(|error| format!("failed to construct waitable Exec process ID: {error}"))?;
    let command = format!(
        "set -eu; printf 'a3s-oci-wait-process-{nonce}\\n' > /{}; exec /bin/busybox sleep 3600",
        super::super::exec::EXEC_MARKER_NAME,
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
            "first owner returned an unexpected WaitProcess transport error at {}: {error}",
            stage.as_str()
        ))
    }
}

pub(super) fn record_recovery_evidence(
    report: &mut OciVmOperationReopenReplacementReport,
    driver: &QualificationHvfDriver,
) {
    super::super::exec::support::record_recovery_evidence(report, driver);
    report.replacement_rehydrated_signal_process = driver.rehydrated_signal_process();
}

pub(super) async fn signal_process_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    target: &ProcessTarget,
) -> std::result::Result<SignalProcessJournalStatus, String> {
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
) -> std::result::Result<(ProcessRecord, Option<ExitStatus>), String> {
    crate::operation_journal_evidence::process_exit_cache(state_root, target).await
}

pub(super) fn identity_or_expected<T: Clone>(
    identity: std::result::Result<T, String>,
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

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::{ContainerId, ContainerTarget, Generation, ProcessTarget};

    use super::waitable_exec_process;

    #[test]
    fn waitable_exec_is_terminal_and_nonce_bound() {
        let (id, process, io) = waitable_exec_process("nonce-7").expect("waitable process");
        assert_eq!(id.as_str(), "wait-worker-nonce-7");
        assert_eq!(process.terminal(), Some(true));
        assert!(io.terminal_size.is_some());
        assert!(waitable_exec_process("unsafe nonce").is_err());

        let target = ProcessTarget {
            container: ContainerTarget::exact(
                ContainerId::new("wait-process").expect("container ID"),
                Generation(1),
            ),
            process_id: id,
        };
        assert!(!target.process_id.is_init());
    }
}
