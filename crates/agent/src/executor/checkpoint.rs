use std::path::{Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{ContainerTarget, ErrorCode, OperationContext, Result};

use super::state::ContainerKey;
use super::{executor_error, validate_deadline, LinuxExecutor};

/// Stable process and cgroup evidence used by a native checkpoint backend.
///
/// This snapshot does not transfer process ownership. It is valid only while
/// the exact source generation remains live and paused in the executor that
/// produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxExecutorCheckpointSource {
    target: ContainerTarget,
    launcher_pid: i32,
    checkpoint_root_pid: i32,
    init_pid: i32,
    cgroup_path: PathBuf,
}

impl LinuxExecutorCheckpointSource {
    /// Exact source generation represented by this snapshot.
    #[must_use]
    pub const fn target(&self) -> &ContainerTarget {
        &self.target
    }

    /// Host-visible PID of the runtime-owned launcher.
    #[must_use]
    pub const fn launcher_pid(&self) -> i32 {
        self.launcher_pid
    }

    /// Host-visible root PID of the workload process tree captured by CRIU.
    ///
    /// This is the configured OCI init payload. Runtime-owned launcher and PID
    /// namespace supervision processes are deliberately outside the portable
    /// checkpoint image.
    #[must_use]
    pub const fn checkpoint_root_pid(&self) -> i32 {
        self.checkpoint_root_pid
    }

    /// Host-visible PID of the configured OCI init payload.
    #[must_use]
    pub const fn init_pid(&self) -> i32 {
        self.init_pid
    }

    /// Exact cgroup-v2 subtree frozen for this generation.
    #[must_use]
    pub fn cgroup_path(&self) -> &Path {
        &self.cgroup_path
    }
}

impl LinuxExecutor {
    /// Resolve one already-paused exact generation for native checkpointing.
    ///
    /// The first native checkpoint format deliberately accepts only the init
    /// process tree. Live `exec` processes are rejected so a later restore
    /// cannot silently lose independently addressed process state.
    pub async fn checkpoint_source(
        &self,
        context: &OperationContext,
        target: &ContainerTarget,
        expected_config_digest: &str,
    ) -> Result<LinuxExecutorCheckpointSource> {
        validate_deadline(context)?;
        let key = ContainerKey::from_target(target)?;
        let mut state = self.state.lock().await;
        let record = state.containers.get_mut(&key).ok_or_else(|| {
            executor_error(
                ErrorCode::NotFound,
                format!(
                    "container {} generation {} does not exist",
                    key.id, key.generation
                ),
            )
        })?;
        record.refresh()?;
        if record.target != *target {
            return Err(executor_error(
                ErrorCode::Conflict,
                "checkpoint target does not match the executor generation",
            ));
        }
        if record.config_digest != expected_config_digest {
            return Err(executor_error(
                ErrorCode::Conflict,
                "checkpoint configuration digest does not match executor state",
            ));
        }
        if record.status != ContainerState::Running || !record.paused {
            return Err(executor_error(
                ErrorCode::FailedPrecondition,
                "checkpoint source must be a paused running container generation",
            ));
        }
        if !record.process.has_isolated_checkpoint_workload() {
            return Err(executor_error(
                ErrorCode::FailedPrecondition,
                "native checkpoint format v1 requires the control-workload-v1 cgroup layout",
            ));
        }
        if record.process.has_pid_namespace_supervisor() {
            return Err(executor_error(
                ErrorCode::FailedPrecondition,
                "native checkpoint format v1 does not support a private PID namespace",
            ));
        }

        // Reassert and observe the kernel freezer instead of trusting only the
        // executor's cached pause flag. This is idempotent and keeps the source
        // frozen if any later checkpoint step fails.
        record.process.set_frozen(true).await?;
        record.process.require_checkpoint_membership().await?;
        let live_processes = record.live_processes()?;
        if live_processes.len() != 1 || !live_processes[0].target.process_id.is_init() {
            return Err(executor_error(
                ErrorCode::FailedPrecondition,
                "native checkpoint format v1 requires no live exec processes",
            ));
        }

        let launcher_pid = record.process.launcher_pid()?;
        let checkpoint_root_pid = record.process.checkpoint_root_pid();
        let init_pid = record.process.pid();
        let cgroup_path = record
            .process
            .checkpoint_cgroup_path()
            .ok_or_else(|| {
                executor_error(
                    ErrorCode::FailedPrecondition,
                    "native checkpoint requires an explicit cgroup-v2 path",
                )
            })?
            .to_path_buf();
        Ok(LinuxExecutorCheckpointSource {
            target: record.target.clone(),
            launcher_pid,
            checkpoint_root_pid,
            init_pid,
            cgroup_path,
        })
    }
}
