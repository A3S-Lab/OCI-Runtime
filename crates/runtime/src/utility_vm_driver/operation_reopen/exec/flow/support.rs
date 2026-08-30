use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{
    ContainerTarget, DeleteRequest, Error, ErrorCode, ExecRequest, OciBundle, OperationId,
    ProcessId, ProcessIo, ProcessTarget, StartRequest, TerminalSize,
};
use tokio::time::{sleep, Instant};

pub(super) use super::super::super::workload_marker::{path_absent, reset_marker, runtime_marker};
pub(super) use crate::operation_journal_evidence::ProcessOperationJournalStatus as ExecJournalStatus;
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::{DriverExecRequest, OciVmOperationReopenReplacementReport};

use super::super::super::{QUALIFICATION_FAULT_OPERATION, QUALIFICATION_TIMEOUT};

pub(in crate::utility_vm_driver::operation_reopen) const EXEC_MARKER_NAME: &str =
    ".a3s-oci-exec-reopen-smoke";
const ORIGINAL_INIT_MARKER_WRITE: &str =
    "printf 'a3s-oci-create-start-user-time-v1\\n' > /.a3s-oci-create-start-smoke;";
const MARKER_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(25);

pub(super) type CreateIdentity = (OperationId, ContainerTarget);

pub(super) struct FirstOwnerOutcome {
    pub(super) target: ContainerTarget,
    pub(super) mount_root: PathBuf,
    pub(super) init_marker: PathBuf,
    pub(super) exec_marker: PathBuf,
    pub(super) create_identity: CreateIdentity,
    pub(super) start_identity: CreateIdentity,
    pub(super) exec_identity: DriverExecRequest,
    pub(super) start: StartRequest,
    pub(super) exec: ExecRequest,
    pub(super) delete: DeleteRequest,
    pub(super) response_delivered: bool,
}

pub(in crate::utility_vm_driver::operation_reopen) fn nonce_bound_bundle(
    bundle: OciBundle,
    nonce: &str,
) -> Result<OciBundle, String> {
    if nonce.is_empty()
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("KVM Exec qualification nonce contains unsafe shell characters".to_string());
    }
    let mut config: serde_json::Value = serde_json::from_str(bundle.config_json())
        .map_err(|error| format!("failed to decode KVM Exec qualification bundle: {error}"))?;
    let command = config
        .pointer_mut("/process/args/2")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            "KVM Exec qualification bundle must use the expected /bin/sh -c init command"
                .to_string()
        })?
        .to_string();
    if command.matches(ORIGINAL_INIT_MARKER_WRITE).count() != 1 {
        return Err(
            "KVM Exec qualification bundle does not contain the exact init marker write"
                .to_string(),
        );
    }
    let replacement =
        format!("printf 'a3s-oci-exec-init-{nonce}\\n' > /.a3s-oci-create-start-smoke;");
    config["process"]["args"][2] =
        serde_json::Value::String(command.replacen(ORIGINAL_INIT_MARKER_WRITE, &replacement, 1));
    let encoded = serde_json::to_string_pretty(&config)
        .map_err(|error| format!("failed to encode nonce-bound KVM Exec bundle: {error}"))?;
    OciBundle::from_json(bundle.directory().to_path_buf(), encoded)
        .map_err(|error| format!("failed to validate nonce-bound KVM Exec bundle: {error}"))
}

pub(in crate::utility_vm_driver::operation_reopen::exec) fn exec_process(
    nonce: &str,
) -> Result<(ProcessId, Process, ProcessIo), String> {
    let process_id = ProcessId::new(format!("worker-{nonce}"))
        .map_err(|error| format!("failed to construct KVM Exec process ID: {error}"))?;
    let command = format!(
        "set -eu; printf 'a3s-oci-exec-process-{nonce}\\n' > /{EXEC_MARKER_NAME}; while :; do /bin/busybox sleep 1; done"
    );
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": true,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", command],
        "env": ["PATH=/bin:/usr/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .map_err(|error| format!("failed to construct terminal KVM Exec process: {error}"))?;
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
        .ok_or_else(|| "KVM Exec init marker has no rootfs parent".to_string())
}

pub(in crate::utility_vm_driver::operation_reopen) async fn wait_for_exact_marker(
    marker: &Path,
    expected: &[u8],
    label: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + QUALIFICATION_TIMEOUT;
    loop {
        if !path_absent(marker).await? {
            let contents = tokio::fs::read(marker)
                .await
                .map_err(|error| format!("failed to read {label} marker: {error}"))?;
            match crate::marker::exact_marker_state(&contents, expected) {
                crate::marker::ExactMarkerState::Complete => return Ok(()),
                crate::marker::ExactMarkerState::InProgress => {}
                crate::marker::ExactMarkerState::Mismatch => {
                    return Err(format!("{label} produced unexpected marker contents"));
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{label} did not produce its marker within {} seconds",
                QUALIFICATION_TIMEOUT.as_secs()
            ));
        }
        sleep(MARKER_POLL_INTERVAL).await;
    }
}

pub(super) async fn verify_first_exec_marker(
    marker: &Path,
    expected: &[u8],
    stage: AgentTransportOperationStage,
) -> Result<(), String> {
    let marker_exists = !path_absent(marker).await?;
    if !dispatch_may_have_reached(stage) && marker_exists {
        Err(format!(
            "{} produced a KVM Exec marker before Guest dispatch",
            stage.as_str()
        ))
    } else if marker_exists {
        wait_for_exact_marker(marker, expected, "first-owner KVM Exec").await
    } else {
        Ok(())
    }
}

pub(in crate::utility_vm_driver::operation_reopen) const fn dispatch_may_have_reached(
    stage: AgentTransportOperationStage,
) -> bool {
    matches!(
        stage,
        AgentTransportOperationStage::HostAfterRequestWrite
            | AgentTransportOperationStage::HostBeforeResponseRead
            | AgentTransportOperationStage::HostAfterResponseRead
            | AgentTransportOperationStage::GuestAfterDispatch
            | AgentTransportOperationStage::GuestBeforeResponseWrite
            | AgentTransportOperationStage::GuestAfterResponseWrite
    )
}

pub(super) async fn exec_journal_status(
    state_root: &Path,
    operation_id: &OperationId,
    target: &ProcessTarget,
) -> Result<ExecJournalStatus, String> {
    crate::operation_journal_evidence::process_operation_journal_status(
        state_root,
        operation_id,
        "exec",
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

pub(in crate::utility_vm_driver::operation_reopen) fn exact_process_target(
    exec: &ExecRequest,
) -> ProcessTarget {
    ProcessTarget {
        container: exec.container.clone(),
        process_id: exec.process_id.clone(),
    }
}

pub(in crate::utility_vm_driver::operation_reopen) fn stale_target(
    container: &ContainerTarget,
) -> Result<ContainerTarget, String> {
    let generation = container
        .generation
        .ok_or_else(|| "KVM Exec qualification container target is not exact".to_string())?;
    let stale = generation
        .0
        .checked_add(1)
        .ok_or_else(|| "KVM Exec qualification generation cannot be incremented".to_string())?;
    Ok(ContainerTarget::exact(
        container.id.clone(),
        a3s_oci_sdk::Generation(stale),
    ))
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
            "first KVM owner returned an unexpected Exec transport error at {}: {error}",
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
    use std::path::PathBuf;

    use a3s_oci_sdk::OciBundle;

    use super::{exec_process, nonce_bound_bundle, EXEC_MARKER_NAME, ORIGINAL_INIT_MARKER_WRITE};

    #[test]
    fn nonce_bound_bundle_replaces_only_the_exact_init_marker_payload() {
        let bundle = OciBundle::from_json(
            PathBuf::from("/qualification-bundle"),
            include_str!("../../../../../../../fixtures/utility-vm/config.linux-kvm.json")
                .to_string(),
        )
        .expect("Linux KVM fixture bundle");
        let bound = nonce_bound_bundle(bundle, "exec-123").expect("nonce-bound bundle");
        let config: serde_json::Value =
            serde_json::from_str(bound.config_json()).expect("bound config JSON");
        let command = config
            .pointer("/process/args/2")
            .and_then(serde_json::Value::as_str)
            .expect("init shell command");
        assert!(!command.contains(ORIGINAL_INIT_MARKER_WRITE));
        assert!(command
            .contains("printf 'a3s-oci-exec-init-exec-123\\n' > /.a3s-oci-create-start-smoke;"));
        assert!(nonce_bound_bundle(bound, "unsafe nonce").is_err());
    }

    #[test]
    fn exec_process_is_a_nonce_bound_long_running_terminal_payload() {
        let (process_id, process, io) = exec_process("exec-123").expect("Exec payload");
        assert_eq!(process_id.as_str(), "worker-exec-123");
        let process = serde_json::to_value(process).expect("process JSON");
        assert_eq!(
            process.get("terminal"),
            Some(&serde_json::Value::Bool(true))
        );
        assert!(process
            .pointer("/args/2")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|command| {
                command.contains("a3s-oci-exec-process-exec-123")
                    && command.contains(EXEC_MARKER_NAME)
                    && command.contains("while :")
            }));
        assert_eq!(
            io.terminal_size,
            Some(a3s_oci_sdk::TerminalSize {
                width: 80,
                height: 24,
            })
        );
    }
}
