use std::collections::{BTreeMap, BTreeSet};

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{ContainerTarget, ErrorCode, ProcessId, ProcessRecord, Result};

use crate::fault::DurableMutation;

use super::filesystem::state_error;
use super::model::{StoredOperation, StoredOperationStatus};
use super::process::{
    exact_process_target, required_operation_process_id, validate_process_response,
};
use super::{DurableStateStore, ProcessOperationPreparation};

impl DurableStateStore {
    pub(super) async fn reconcile_succeeded_exec(
        &self,
        operation: &mut StoredOperation,
        response: ProcessRecord,
    ) -> Result<ProcessOperationPreparation> {
        validate_process_response(&response, operation, "reconcile-succeeded-exec")?;
        let container = match self.load_stored_container(&operation.container_id).await {
            Ok(container) => container,
            Err(error) if error.code == ErrorCode::NotFound => {
                return Ok(ProcessOperationPreparation::Replayed(response));
            }
            Err(error) => return Err(error),
        };
        if container.record.generation != operation.generation {
            return Ok(ProcessOperationPreparation::Replayed(response));
        }
        let target = exact_process_target(
            &container,
            required_operation_process_id(operation, "reconcile-succeeded-exec")?.clone(),
        );
        let process = self.load_stored_process(&target).await?;
        if process.record == response {
            return Ok(ProcessOperationPreparation::Replayed(response));
        }
        if *container.record.state.status() != ContainerState::Running
            || process.exit_status.is_some()
            || process.record.target != response.target
            || process.record.terminal != response.terminal
            || process.record.pid.is_none()
        {
            return Err(state_error(
                ErrorCode::Conflict,
                "reconcile-succeeded-exec",
                format!(
                    "completed exec operation {} changed beyond its recovered process identity",
                    operation.operation_id
                ),
            ));
        }
        operation.outcome = StoredOperationStatus::SucceededProcess {
            response: process.record.clone(),
        };
        self.write_json(
            DurableMutation::ReconcileExecOperation,
            &self.operation_path(&operation.operation_id),
            operation,
        )
        .await?;
        Ok(ProcessOperationPreparation::Replayed(process.record))
    }

    pub(crate) async fn observe_recreated_exec_processes(
        &self,
        container_target: &ContainerTarget,
        observed: &[ProcessRecord],
    ) -> Result<()> {
        let generation = container_target.generation.ok_or_else(|| {
            state_error(
                ErrorCode::InvalidArgument,
                "observe-recreated-exec-processes",
                "replacement exec recovery requires an exact container generation",
            )
        })?;
        let _guard = self.gate.lock().await;
        let container = self
            .load_stored_exact(&container_target.id, generation)
            .await?;
        if *container.record.state.status() != ContainerState::Running
            || container.record.is_paused()
        {
            return Err(state_error(
                ErrorCode::Conflict,
                "observe-recreated-exec-processes",
                format!(
                    "container {} generation {} must be running and unpaused for exec recovery",
                    container.id, generation.0
                ),
            ));
        }
        let init_pid = container
            .record
            .state
            .pid()
            .and_then(|pid| u32::try_from(pid).ok())
            .ok_or_else(|| {
                state_error(
                    ErrorCode::Conflict,
                    "observe-recreated-exec-processes",
                    "running replacement container has no positive init PID",
                )
            })?;

        let mut observed_by_id = BTreeMap::new();
        let mut observed_pids = BTreeSet::new();
        for process in observed {
            if process.target.container != *container_target
                || process.target.process_id.is_init()
                || process.pid.is_none()
                || process.pid == Some(0)
                || process.pid == Some(init_pid)
            {
                return Err(state_error(
                    ErrorCode::Conflict,
                    "observe-recreated-exec-processes",
                    "replacement driver returned an invalid, init-aliasing, or cross-generation exec process",
                ));
            }
            let pid = process.pid.ok_or_else(|| {
                state_error(
                    ErrorCode::Conflict,
                    "observe-recreated-exec-processes",
                    "replacement driver returned an exec process without a PID",
                )
            })?;
            if !observed_pids.insert(pid)
                || observed_by_id
                    .insert(process.target.process_id.clone(), process.clone())
                    .is_some()
            {
                return Err(state_error(
                    ErrorCode::Conflict,
                    "observe-recreated-exec-processes",
                    "replacement driver returned duplicate exec process evidence",
                ));
            }
        }

        let mut durable_by_id = BTreeMap::new();
        let directory = self.process_directory(&container.id);
        if self.filesystem.path_exists(&directory).await? {
            self.filesystem
                .ensure_plain_directory(&directory, "process state directory")
                .await?;
            for file_name in self
                .filesystem
                .read_directory(&directory, "process state directory")
                .await?
            {
                let file_name = file_name.to_str().ok_or_else(|| {
                    state_error(
                        ErrorCode::FailedPrecondition,
                        "observe-recreated-exec-processes",
                        "process record filename is not valid UTF-8",
                    )
                })?;
                if let Some(process_id) = file_name
                    .strip_prefix('.')
                    .and_then(|value| value.strip_suffix(".json.next"))
                {
                    ProcessId::new(process_id.to_string()).map_err(|error| {
                        state_error(
                            ErrorCode::FailedPrecondition,
                            "observe-recreated-exec-processes",
                            format!("invalid process transaction filename {file_name}: {error}"),
                        )
                    })?;
                    self.filesystem
                        .ensure_plain_file(
                            &directory.join(file_name),
                            "process state transaction file",
                        )
                        .await?;
                    continue;
                }
                let process_id = file_name
                    .strip_suffix(".json")
                    .ok_or_else(|| {
                        state_error(
                            ErrorCode::FailedPrecondition,
                            "observe-recreated-exec-processes",
                            format!("unexpected file in process state directory: {file_name}"),
                        )
                    })
                    .and_then(|value| {
                        ProcessId::new(value.to_string()).map_err(|error| {
                            state_error(
                                ErrorCode::FailedPrecondition,
                                "observe-recreated-exec-processes",
                                format!("invalid process record filename {file_name}: {error}"),
                            )
                        })
                    })?;
                let target = exact_process_target(&container, process_id.clone());
                let process = self.load_stored_process(&target).await?;
                if process.record.pid.is_some() && process.exit_status.is_none() {
                    durable_by_id.insert(process_id, process);
                }
            }
        }

        let missing = durable_by_id
            .keys()
            .filter(|process_id| !observed_by_id.contains_key(*process_id))
            .map(ProcessId::as_str)
            .collect::<Vec<_>>();
        let unexpected = observed_by_id
            .keys()
            .filter(|process_id| !durable_by_id.contains_key(*process_id))
            .map(ProcessId::as_str)
            .collect::<Vec<_>>();
        if !missing.is_empty() || !unexpected.is_empty() {
            return Err(state_error(
                ErrorCode::Conflict,
                "observe-recreated-exec-processes",
                format!(
                    "replacement exec inventory differs from durable live processes: missing [{}], unexpected [{}]",
                    missing.join(", "),
                    unexpected.join(", ")
                ),
            ));
        }

        for (process_id, observed) in observed_by_id {
            let mut durable = durable_by_id.remove(&process_id).ok_or_else(|| {
                state_error(
                    ErrorCode::Internal,
                    "observe-recreated-exec-processes",
                    format!("durable process {process_id} disappeared during recovery"),
                )
            })?;
            if durable.record.terminal != observed.terminal {
                return Err(state_error(
                    ErrorCode::Conflict,
                    "observe-recreated-exec-processes",
                    format!(
                        "replacement process {process_id} terminal mode differs from durable state"
                    ),
                ));
            }
            if durable.record.pid != observed.pid {
                durable.record.pid = observed.pid;
                self.write_json(
                    DurableMutation::ReconcileExecProcess,
                    &self.process_path(&durable.record.target),
                    &durable,
                )
                .await?;
            }
        }
        Ok(())
    }
}
