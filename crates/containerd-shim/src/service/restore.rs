use std::time::{Duration, SystemTime};

use a3s_oci_sdk::oci_spec::runtime::ContainerState;

use crate::metadata::ExecStage;

use super::{ErrorCode, RuntimeAdapter, RuntimeError, TaskState};

const STOPPED_EXIT_RECOVERY_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) async fn recover_stopped_init_exit(
    adapter: &RuntimeAdapter,
    task: &mut TaskState,
) -> Result<(), RuntimeError> {
    if task.exit.is_some() || *task.record.state.status() != ContainerState::Stopped {
        return Ok(());
    }

    let exit = tokio::time::timeout(
        STOPPED_EXIT_RECOVERY_TIMEOUT,
        adapter.wait(&task.identity, task.record.generation),
    )
    .await
    .map_err(|_| {
        RuntimeError::new(
            ErrorCode::DeadlineExceeded,
            format!(
                "runtime generation {} reported Stopped without returning its durable init exit within {} seconds",
                task.record.generation.0,
                STOPPED_EXIT_RECOVERY_TIMEOUT.as_secs()
            ),
        )
        .for_operation("containerd-shim-rehydrate-exit")
    })??;
    task.exit = Some(exit);
    task.exited_at = Some(SystemTime::now());
    Ok(())
}

pub(super) async fn recover_pending_exec_signal_exits(
    adapter: &RuntimeAdapter,
    task: &mut TaskState,
) -> Result<(), RuntimeError> {
    let exec_ids = task
        .execs
        .iter()
        .filter(|(_, exec)| {
            exec.stage == ExecStage::Started
                && exec.record.is_some()
                && exec.exit.is_none()
                && exec.pending_signal.is_some()
        })
        .map(|(exec_id, _)| exec_id.clone())
        .collect::<Vec<_>>();

    for exec_id in exec_ids {
        let exec_identity = task
            .execs
            .get(&exec_id)
            .ok_or_else(|| {
                RuntimeError::new(
                    ErrorCode::Internal,
                    format!("containerd exec {exec_id} disappeared during exit recovery"),
                )
                .for_operation("containerd-shim-rehydrate-exec-exit")
            })?
            .identity(&exec_id)?;
        let Some(exit) = adapter
            .poll_process_exit(&task.identity, task.record.generation, &exec_identity)
            .await?
        else {
            continue;
        };
        let exec = task.execs.get_mut(&exec_id).ok_or_else(|| {
            RuntimeError::new(
                ErrorCode::Internal,
                format!("containerd exec {exec_id} disappeared before exit recovery commit"),
            )
            .for_operation("containerd-shim-rehydrate-exec-exit")
        })?;
        exec.stage = ExecStage::Exited;
        exec.exit = Some(exit);
        exec.exited_at = Some(SystemTime::now());
    }
    Ok(())
}
