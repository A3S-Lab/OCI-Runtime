use std::time::{Duration, SystemTime};

use a3s_oci_sdk::oci_spec::runtime::ContainerState;

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
