use std::path::Path;

use serde::Deserialize;
use tokio::process::Child;
use tonic::transport::Channel;

use super::super::{
    launch_replacement_while_containerd_suspended, stop_replacement, wait_for_pid_exit, Bootstrap,
};
use crate::faults;
use crate::support::{
    containerd_main_pid, qualification_error, restart_containerd, QualificationConfig,
    RuntimeIdentity, TestResult,
};

const DELETE_JOURNAL_FILE_NAME: &str = "a3s-oci-shim-exec-delete-v1.json";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteJournalEvidence {
    schema_version: u32,
    namespace: String,
    task_id: String,
    incarnation: Option<String>,
    container_id: String,
    generation: u64,
    bundle: std::path::PathBuf,
    receipts: Vec<DeleteReceiptEvidence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteReceiptEvidence {
    exec_id: String,
    incarnation: u64,
    pid: u32,
    exit_status: u32,
    exited_at_unix_nanos: u128,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn qualify(
    config: &QualificationConfig,
    task_id: &str,
    bundle: &Path,
    binary: &Path,
    bootstrap: &Bootstrap,
    identity: &RuntimeIdentity,
    expected: &crate::api::DeleteResponse,
    mut old_replacement: Child,
) -> TestResult<(Channel, Child)> {
    require_delete_receipt(config, task_id, bundle, identity, expected).await?;
    let old_shim_pid = old_replacement
        .id()
        .ok_or_else(|| qualification_error("DeleteProcess receipt shim has no PID"))?;
    let containerd_pid = containerd_main_pid(config).await?;
    faults::send_signal(
        containerd_pid,
        libc::SIGSTOP,
        "DeleteProcess receipt containerd",
    )?;
    let mut replacement = None;
    let relaunch = async {
        faults::send_signal(
            old_shim_pid,
            libc::SIGKILL,
            "DeleteProcess receipt original shim",
        )?;
        tokio::time::timeout(std::time::Duration::from_secs(5), old_replacement.wait())
            .await
            .map_err(|_| {
                qualification_error(
                    "DeleteProcess receipt original shim did not terminate within 5 seconds",
                )
            })?
            .map_err(|error| {
                qualification_error(format!(
                    "wait for DeleteProcess receipt original shim: {error}"
                ))
            })?;
        wait_for_pid_exit(old_shim_pid, "DeleteProcess receipt original shim").await?;
        launch_replacement_while_containerd_suspended(
            config,
            task_id,
            bundle,
            binary,
            bootstrap,
            containerd_pid,
            &mut replacement,
        )
        .await
    }
    .await;
    let _ = faults::send_signal(
        containerd_pid,
        libc::SIGCONT,
        "DeleteProcess receipt containerd",
    );
    if let Err(error) = relaunch {
        let _ = old_replacement.start_kill();
        let _ = old_replacement.wait().await;
        stop_replacement(&mut replacement).await;
        let recovery = restart_containerd(config, "failed-DeleteProcess-receipt-replay").await;
        return match recovery {
            Ok(_) => Err(error),
            Err(recovery_error) => Err(qualification_error(format!(
                "DeleteProcess receipt replacement failed: {error}; containerd recovery also failed: {recovery_error}"
            ))
            .into()),
        };
    }

    let replacement = replacement
        .ok_or_else(|| qualification_error("DeleteProcess receipt relaunch omitted its child"))?;
    let replacement_pid = replacement
        .id()
        .ok_or_else(|| qualification_error("DeleteProcess receipt replacement has no PID"))?;
    let channel = restart_containerd(config, "DeleteProcess-receipt-replay").await?;
    super::require_replacement_pid(config, task_id, replacement_pid).await?;

    let replayed = shim_delete_process(&bootstrap.address, task_id, super::EXEC_ID).await?;
    let expected_time = expected.exited_at.as_ref().ok_or_else(|| {
        qualification_error("first DeleteProcess response omitted its exit timestamp")
    })?;
    if replayed.pid() != expected.pid
        || replayed.exit_status() != expected.exit_status
        || replayed.exited_at().seconds != expected_time.seconds
        || replayed.exited_at().nanos != expected_time.nanos
    {
        return Err(qualification_error(format!(
            "replayed DeleteProcess response was pid={}, exit={}, time={}.{}; expected pid={}, exit={}, time={}.{}",
            replayed.pid(),
            replayed.exit_status(),
            replayed.exited_at().seconds,
            replayed.exited_at().nanos,
            expected.pid,
            expected.exit_status,
            expected_time.seconds,
            expected_time.nanos
        ))
        .into());
    }
    require_delete_receipt(config, task_id, bundle, identity, expected).await?;
    Ok((channel, replacement))
}

async fn require_delete_receipt(
    config: &QualificationConfig,
    task_id: &str,
    bundle: &Path,
    identity: &RuntimeIdentity,
    expected: &crate::api::DeleteResponse,
) -> TestResult<()> {
    let path = bundle.join(DELETE_JOURNAL_FILE_NAME);
    let bytes = tokio::fs::read(&path).await.map_err(|error| {
        qualification_error(format!(
            "read durable DeleteProcess receipt {}: {error}",
            path.display()
        ))
    })?;
    let evidence: DeleteJournalEvidence = serde_json::from_slice(&bytes).map_err(|error| {
        qualification_error(format!(
            "decode durable DeleteProcess receipt {}: {error}",
            path.display()
        ))
    })?;
    let timestamp = expected
        .exited_at
        .as_ref()
        .ok_or_else(|| qualification_error("DeleteProcess response omitted its exit timestamp"))?;
    let seconds = u128::try_from(timestamp.seconds).map_err(|_| {
        qualification_error("DeleteProcess response recorded a negative exit timestamp")
    })?;
    let nanos = u128::try_from(timestamp.nanos).map_err(|_| {
        qualification_error("DeleteProcess response recorded negative subsecond nanoseconds")
    })?;
    let exited_at_unix_nanos = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or_else(|| qualification_error("DeleteProcess exit timestamp overflowed u128"))?;
    let expected_bundle = bundle.to_path_buf();
    let [receipt] = evidence.receipts.as_slice() else {
        return Err(qualification_error(format!(
            "DeleteProcess journal retained {} receipts instead of one: {evidence:?}",
            evidence.receipts.len()
        ))
        .into());
    };
    if evidence.schema_version != 1
        || evidence.namespace != config.namespace
        || evidence.task_id != task_id
        || evidence.incarnation.as_deref() != Some(identity.incarnation.as_str())
        || evidence.container_id != identity.container_id.as_str()
        || evidence.generation != identity.generation
        || evidence.bundle != expected_bundle
        || receipt.exec_id != super::EXEC_ID
        || receipt.incarnation != 1
        || receipt.pid != expected.pid
        || receipt.exit_status != expected.exit_status
        || receipt.exited_at_unix_nanos != exited_at_unix_nanos
    {
        return Err(qualification_error(format!(
            "DeleteProcess journal did not retain the exact task, exec incarnation, and response: {evidence:?}"
        ))
        .into());
    }
    Ok(())
}

async fn shim_delete_process(
    address: &str,
    task_id: &str,
    exec_id: &str,
) -> TestResult<containerd_shim_protos::api::DeleteResponse> {
    let client = containerd_shim_protos::ttrpc::asynchronous::Client::connect(address)
        .await
        .map_err(|error| {
            qualification_error(format!(
                "connect DeleteProcess receipt shim at {address}: {error}"
            ))
        })?;
    let task = containerd_shim_protos::shim::shim_ttrpc_async::TaskClient::new(client);
    let mut request = containerd_shim_protos::api::DeleteRequest::new();
    request.set_id(task_id.to_string());
    request.set_exec_id(exec_id.to_string());
    task.delete(
        containerd_shim_protos::ttrpc::context::Context::default(),
        &request,
    )
    .await
    .map_err(|error| {
        qualification_error(format!(
            "replay DeleteProcess through replacement shim {address}: {error}"
        ))
        .into()
    })
}
