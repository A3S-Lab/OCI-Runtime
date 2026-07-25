use a3s_oci_sdk::oci_spec::runtime::{ContainerState, Process};
use a3s_oci_sdk::{
    ContainerId, ContainerTarget, ErrorCode, ExecRequest, ExitStatus, OciSchemaValidator,
    OperationId, ProcessId, ProcessIo, ProcessRecord, ProcessTarget, Result, Signal,
    SignalProcessRequest, ValidateRequest, WaitProcessRequest,
};
use serde::Serialize;

use crate::fault::DurableMutation;

use super::filesystem::{
    create_private_directory, ensure_plain_directory, path_exists, read_json, state_error,
};
use super::model::{
    StoredContainer, StoredOperation, StoredOperationKind, StoredOperationStatus, StoredProcess,
    OPERATION_SCHEMA_VERSION, PROCESS_SCHEMA_VERSION,
};
use super::oci_state::rebuild_state;
use super::operation::{request_digest, validate_deadline, validate_retry};
use super::{
    claim_active_operation, ensure_active_operation, generation_conflict, DurableStateStore,
    ProcessOperationPreparation, ProcessWaitPreparation, SignalProcessPreparation,
    CONTAINER_RECORD_FILE,
};

#[derive(Serialize)]
struct ExecFingerprint<'a> {
    container: &'a ContainerTarget,
    process_id: &'a ProcessId,
    process: &'a Process,
    io: &'a ProcessIo,
}

#[derive(Serialize)]
struct SignalProcessFingerprint<'a> {
    process: &'a ProcessTarget,
    signal: Signal,
}

impl DurableStateStore {
    /// Resolve a caller target to the exact current generation and verify that
    /// the durable process was fully created.
    pub(crate) async fn resolve_process_target(
        &self,
        requested: &ProcessTarget,
        operation: &'static str,
    ) -> Result<ProcessTarget> {
        let _guard = self.gate.lock().await;
        let container = self.load_stored_container(&requested.container.id).await?;
        validate_requested_generation(&container, &requested.container, operation)?;
        ensure_container_unclaimed(&container, operation)?;
        let target = exact_process_target(&container, requested.process_id.clone());
        if target.process_id.is_init() {
            if *container.record.state.status() == ContainerState::Creating {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    operation,
                    format!(
                        "container {} generation {} has no prepared init process",
                        container.id, container.record.generation.0
                    ),
                ));
            }
            return Ok(target);
        }

        let process = self.load_stored_process(&target).await?;
        if process.record.pid.is_none() {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                operation,
                format!("process {} has not completed exec", target.process_id),
            ));
        }
        Ok(target)
    }

    pub(crate) async fn prepare_exec(
        &self,
        request: &ExecRequest,
    ) -> Result<ProcessOperationPreparation> {
        request.validate()?;
        let digest = request_digest(
            &ExecFingerprint {
                container: &request.container,
                process_id: &request.process_id,
                process: &request.process,
                io: &request.io,
            },
            "digest-exec-request",
        )?;
        let _guard = self.gate.lock().await;

        if let Some(mut operation) = self
            .load_operation_if_present(&request.context.operation_id)
            .await?
        {
            validate_process_retry(
                &operation,
                &request.context.operation_id,
                StoredOperationKind::Exec,
                &request.container.id,
                &request.process_id,
                &digest,
                "prepare-exec",
            )?;
            return match &operation.outcome {
                StoredOperationStatus::Prepared => {
                    let mut process = self.reconcile_prepared_exec(request, &operation).await?;
                    if process.record.pid.is_some() {
                        ensure_active_process_operation(
                            &process,
                            &request.context.operation_id,
                            "prepare-exec",
                        )?;
                        if process.active_operation.is_some() {
                            process.active_operation = None;
                            self.write_json(
                                DurableMutation::ReconcileExecProcess,
                                &self.process_path(&process.record.target),
                                &process,
                            )
                            .await?;
                        }
                        operation.outcome = StoredOperationStatus::SucceededProcess {
                            response: process.record.clone(),
                        };
                        self.write_json(
                            DurableMutation::ReconcileExecOperation,
                            &self.operation_path(&request.context.operation_id),
                            &operation,
                        )
                        .await?;
                        Ok(ProcessOperationPreparation::Replayed(process.record))
                    } else {
                        claim_active_process_operation(
                            self,
                            &mut process,
                            &request.context.operation_id,
                            DurableMutation::ClaimExecOperation,
                            "prepare-exec",
                        )
                        .await?;
                        Ok(ProcessOperationPreparation::Resume(process.record))
                    }
                }
                StoredOperationStatus::SucceededProcess { response } => {
                    validate_process_response(response, &operation, "prepare-exec")?;
                    Ok(ProcessOperationPreparation::Replayed(response.clone()))
                }
                StoredOperationStatus::Failed { error } => Err(error.clone()),
                StoredOperationStatus::Succeeded { .. } | StoredOperationStatus::SucceededEmpty => {
                    Err(state_error(
                        ErrorCode::FailedPrecondition,
                        "prepare-exec",
                        format!(
                            "exec operation {} has an invalid outcome",
                            request.context.operation_id
                        ),
                    ))
                }
            };
        }

        validate_deadline(&request.context, "prepare-exec")?;
        let container = self.load_stored_container(&request.container.id).await?;
        validate_requested_generation(&container, &request.container, "prepare-exec")?;
        ensure_container_unclaimed(&container, "prepare-exec")?;
        if *container.record.state.status() != ContainerState::Running {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "prepare-exec",
                format!(
                    "container {} generation {} cannot exec while {}",
                    container.id,
                    container.record.generation.0,
                    container.record.state.status()
                ),
            ));
        }
        if container.record.is_paused() {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "prepare-exec",
                format!(
                    "container {} generation {} cannot exec while paused",
                    container.id, container.record.generation.0
                ),
            ));
        }
        let target = exact_process_target(&container, request.process_id.clone());
        self.ensure_process_directory(&container.id).await?;
        if path_exists(&self.process_path(&target)).await? {
            return Err(state_error(
                ErrorCode::AlreadyExists,
                "prepare-exec",
                format!(
                    "process {} already exists in container {} generation {}",
                    target.process_id, target.container.id, container.record.generation.0
                ),
            ));
        }

        let operation = StoredOperation {
            schema_version: OPERATION_SCHEMA_VERSION.to_string(),
            operation_id: request.context.operation_id.clone(),
            kind: StoredOperationKind::Exec,
            container_id: container.id.clone(),
            generation: container.record.generation,
            process_id: Some(request.process_id.clone()),
            request_digest: digest,
            outcome: StoredOperationStatus::Prepared,
        };
        self.write_json(
            DurableMutation::PrepareExecOperation,
            &self.operation_path(&request.context.operation_id),
            &operation,
        )
        .await?;
        let process = self.reconcile_prepared_exec(request, &operation).await?;
        Ok(ProcessOperationPreparation::Prepared(process.record))
    }

    async fn reconcile_prepared_exec(
        &self,
        request: &ExecRequest,
        operation: &StoredOperation,
    ) -> Result<StoredProcess> {
        let container = self
            .load_stored_exact(&operation.container_id, operation.generation)
            .await?;
        ensure_container_unclaimed(&container, "reconcile-exec")?;
        let process_id = required_operation_process_id(operation, "reconcile-exec")?;
        let target = exact_process_target(&container, process_id.clone());
        self.ensure_process_directory(&container.id).await?;
        let path = self.process_path(&target);
        let terminal = request.process.terminal().unwrap_or(false);
        if path_exists(&path).await? {
            let process = self.load_stored_process(&target).await?;
            if process.record.terminal != terminal {
                return Err(state_error(
                    ErrorCode::Conflict,
                    "reconcile-exec",
                    format!(
                        "process {} terminal mode differs from its durable exec request",
                        target.process_id
                    ),
                ));
            }
            return Ok(process);
        }

        let process = StoredProcess {
            schema_version: PROCESS_SCHEMA_VERSION.to_string(),
            record: ProcessRecord {
                target,
                pid: None,
                terminal,
            },
            active_operation: Some(operation.operation_id.clone()),
            exit_status: None,
        };
        self.write_json(DurableMutation::StoreExecutingProcess, &path, &process)
            .await?;
        Ok(process)
    }

    pub(crate) async fn complete_exec(
        &self,
        operation_id: &OperationId,
        pid: i32,
        terminal: bool,
    ) -> Result<ProcessRecord> {
        let pid = u32::try_from(pid).map_err(|error| {
            state_error(
                ErrorCode::InvalidArgument,
                "complete-exec",
                format!("driver exec PID must be positive and fit u32: {error}"),
            )
        })?;
        if pid == 0 {
            return Err(state_error(
                ErrorCode::InvalidArgument,
                "complete-exec",
                "driver exec PID must be positive",
            ));
        }
        let _guard = self.gate.lock().await;
        let mut operation = self.load_operation(operation_id).await?;
        if operation.kind != StoredOperationKind::Exec {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "complete-exec",
                format!("operation {operation_id} is not an OCI exec"),
            ));
        }
        match &operation.outcome {
            StoredOperationStatus::Prepared => {}
            StoredOperationStatus::SucceededProcess { response } => return Ok(response.clone()),
            StoredOperationStatus::Failed { error } => return Err(error.clone()),
            StoredOperationStatus::Succeeded { .. } | StoredOperationStatus::SucceededEmpty => {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "complete-exec",
                    format!("exec operation {operation_id} has an invalid outcome"),
                ));
            }
        }

        let container = self
            .load_stored_exact(&operation.container_id, operation.generation)
            .await?;
        let target = exact_process_target(
            &container,
            required_operation_process_id(&operation, "complete-exec")?.clone(),
        );
        let mut process = self.load_stored_process(&target).await?;
        ensure_active_process_operation(&process, operation_id, "complete-exec")?;
        if process.record.terminal != terminal {
            return Err(state_error(
                ErrorCode::Conflict,
                "complete-exec",
                format!(
                    "driver terminal mode {terminal} differs from durable mode {} for process {}",
                    process.record.terminal, target.process_id
                ),
            ));
        }
        match process.record.pid {
            None => process.record.pid = Some(pid),
            Some(existing) if existing == pid => {}
            Some(existing) => {
                return Err(state_error(
                    ErrorCode::Conflict,
                    "complete-exec",
                    format!(
                        "process {} PID mismatch: durable {existing}, driver {pid}",
                        target.process_id
                    ),
                ));
            }
        }
        process.active_operation = None;
        self.write_json(
            DurableMutation::CompleteExecProcess,
            &self.process_path(&target),
            &process,
        )
        .await?;
        let response = process.record;
        operation.outcome = StoredOperationStatus::SucceededProcess {
            response: response.clone(),
        };
        self.write_json(
            DurableMutation::CompleteExecOperation,
            &self.operation_path(operation_id),
            &operation,
        )
        .await?;
        Ok(response)
    }

    pub(crate) async fn prepare_signal_process(
        &self,
        request: &SignalProcessRequest,
    ) -> Result<SignalProcessPreparation> {
        request.validate()?;
        let digest = request_digest(
            &SignalProcessFingerprint {
                process: &request.process,
                signal: request.signal,
            },
            "digest-signal-process-request",
        )?;
        let _guard = self.gate.lock().await;

        if let Some(operation) = self
            .load_operation_if_present(&request.context.operation_id)
            .await?
        {
            validate_process_retry(
                &operation,
                &request.context.operation_id,
                StoredOperationKind::SignalProcess,
                &request.process.container.id,
                &request.process.process_id,
                &digest,
                "prepare-signal-process",
            )?;
            return match &operation.outcome {
                StoredOperationStatus::Prepared => {
                    let target = self
                        .claim_signal_process(&operation, &request.context.operation_id)
                        .await?;
                    Ok(SignalProcessPreparation::Resume(target))
                }
                StoredOperationStatus::SucceededEmpty => Ok(SignalProcessPreparation::Replayed),
                StoredOperationStatus::Failed { error } => Err(error.clone()),
                StoredOperationStatus::Succeeded { .. }
                | StoredOperationStatus::SucceededProcess { .. } => Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "prepare-signal-process",
                    format!(
                        "signal operation {} has an invalid outcome",
                        request.context.operation_id
                    ),
                )),
            };
        }

        validate_deadline(&request.context, "prepare-signal-process")?;
        let container = self
            .load_stored_container(&request.process.container.id)
            .await?;
        validate_requested_generation(
            &container,
            &request.process.container,
            "prepare-signal-process",
        )?;
        ensure_container_unclaimed(&container, "prepare-signal-process")?;
        let target = exact_process_target(&container, request.process.process_id.clone());
        validate_signal_target(self, &container, &target).await?;

        let operation = StoredOperation {
            schema_version: OPERATION_SCHEMA_VERSION.to_string(),
            operation_id: request.context.operation_id.clone(),
            kind: StoredOperationKind::SignalProcess,
            container_id: container.id.clone(),
            generation: container.record.generation,
            process_id: Some(target.process_id.clone()),
            request_digest: digest,
            outcome: StoredOperationStatus::Prepared,
        };
        self.write_json(
            DurableMutation::PrepareSignalProcessOperation,
            &self.operation_path(&request.context.operation_id),
            &operation,
        )
        .await?;
        let target = self
            .claim_signal_process(&operation, &request.context.operation_id)
            .await?;
        Ok(SignalProcessPreparation::Prepared(target))
    }

    async fn claim_signal_process(
        &self,
        operation: &StoredOperation,
        operation_id: &OperationId,
    ) -> Result<ProcessTarget> {
        let mut container = self
            .load_stored_exact(&operation.container_id, operation.generation)
            .await?;
        let process_id = required_operation_process_id(operation, "claim-signal-process")?.clone();
        let target = exact_process_target(&container, process_id);
        if target.process_id.is_init() {
            claim_active_operation(
                self,
                &mut container,
                operation_id,
                DurableMutation::ClaimSignalProcessOperation,
                "claim-signal-process",
            )
            .await?;
        } else {
            ensure_container_unclaimed(&container, "claim-signal-process")?;
            let mut process = self.load_stored_process(&target).await?;
            claim_active_process_operation(
                self,
                &mut process,
                operation_id,
                DurableMutation::ClaimSignalProcessOperation,
                "claim-signal-process",
            )
            .await?;
        }
        Ok(target)
    }

    pub(crate) async fn complete_signal_process(&self, operation_id: &OperationId) -> Result<()> {
        let _guard = self.gate.lock().await;
        let mut operation = self.load_operation(operation_id).await?;
        if operation.kind != StoredOperationKind::SignalProcess {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "complete-signal-process",
                format!("operation {operation_id} is not a process signal"),
            ));
        }
        match &operation.outcome {
            StoredOperationStatus::Prepared => {}
            StoredOperationStatus::SucceededEmpty => return Ok(()),
            StoredOperationStatus::Failed { error } => return Err(error.clone()),
            StoredOperationStatus::Succeeded { .. }
            | StoredOperationStatus::SucceededProcess { .. } => {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "complete-signal-process",
                    format!("signal operation {operation_id} has an invalid outcome"),
                ));
            }
        }

        self.release_process_operation_claim(
            &operation,
            operation_id,
            DurableMutation::CompleteSignalProcessRecord,
            "complete-signal-process",
        )
        .await?;
        operation.outcome = StoredOperationStatus::SucceededEmpty;
        self.write_json(
            DurableMutation::CompleteSignalProcessOperation,
            &self.operation_path(operation_id),
            &operation,
        )
        .await
    }

    pub(crate) async fn prepare_wait_process(
        &self,
        request: &WaitProcessRequest,
    ) -> Result<ProcessWaitPreparation> {
        request.validate()?;
        let _guard = self.gate.lock().await;
        let container = self
            .load_stored_container(&request.process.container.id)
            .await?;
        validate_requested_generation(
            &container,
            &request.process.container,
            "prepare-wait-process",
        )?;
        let target = exact_process_target(&container, request.process.process_id.clone());
        if target.process_id.is_init() {
            if let Some(status) = container.init_exit_status {
                return Ok(ProcessWaitPreparation::Replayed(status));
            }
            if *container.record.state.status() == ContainerState::Creating {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "prepare-wait-process",
                    format!(
                        "container {} generation {} has no prepared init process",
                        container.id, container.record.generation.0
                    ),
                ));
            }
            return Ok(ProcessWaitPreparation::Prepared(target));
        }

        let process = self.load_stored_process(&target).await?;
        if let Some(status) = process.exit_status {
            return Ok(ProcessWaitPreparation::Replayed(status));
        }
        if process.record.pid.is_none() {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "prepare-wait-process",
                format!("process {} has not completed exec", target.process_id),
            ));
        }
        Ok(ProcessWaitPreparation::Prepared(target))
    }

    pub(crate) async fn complete_process_wait(
        &self,
        target: &ProcessTarget,
        status: ExitStatus,
    ) -> Result<ExitStatus> {
        status.validate()?;
        let generation = target.container.generation.ok_or_else(|| {
            state_error(
                ErrorCode::InvalidArgument,
                "complete-process-wait",
                "process wait completion requires an exact container generation",
            )
        })?;
        let _guard = self.gate.lock().await;
        let mut container = self
            .load_stored_exact(&target.container.id, generation)
            .await?;
        if target.process_id.is_init() {
            if let Some(existing) = &container.init_exit_status {
                return if existing == &status {
                    Ok(existing.clone())
                } else {
                    Err(exit_status_conflict(target, existing, &status))
                };
            }
            match *container.record.state.status() {
                ContainerState::Created | ContainerState::Running => {
                    container.record.state =
                        rebuild_state(&container.record.state, ContainerState::Stopped, None)?;
                    OciSchemaValidator::new()?.validate_state(&container.record.state)?;
                }
                ContainerState::Stopped => {}
                ContainerState::Creating => {
                    return Err(state_error(
                        ErrorCode::FailedPrecondition,
                        "complete-process-wait",
                        format!(
                            "container {} generation {} has no prepared init process",
                            container.id, generation.0
                        ),
                    ));
                }
            }
            container.init_exit_status = Some(status.clone());
            self.write_json(
                DurableMutation::CacheInitWait,
                &self
                    .container_directory(&container.id)
                    .join(CONTAINER_RECORD_FILE),
                &container,
            )
            .await?;
            return Ok(status);
        }

        let mut process = self.load_stored_process(target).await?;
        if let Some(existing) = &process.exit_status {
            return if existing == &status {
                Ok(existing.clone())
            } else {
                Err(exit_status_conflict(target, existing, &status))
            };
        }
        process.exit_status = Some(status.clone());
        self.write_json(
            DurableMutation::CacheProcessWait,
            &self.process_path(target),
            &process,
        )
        .await?;
        Ok(status)
    }

    pub(super) async fn load_stored_process(
        &self,
        target: &ProcessTarget,
    ) -> Result<StoredProcess> {
        let generation = target.container.generation.ok_or_else(|| {
            state_error(
                ErrorCode::InvalidArgument,
                "load-process-state",
                "durable process lookup requires an exact container generation",
            )
        })?;
        let directory = self.process_directory(&target.container.id);
        if !path_exists(&directory).await? {
            return Err(state_error(
                ErrorCode::NotFound,
                "load-process-state",
                format!(
                    "process {} does not exist in container {} generation {}",
                    target.process_id, target.container.id, generation.0
                ),
            ));
        }
        ensure_plain_directory(&directory, "process state directory").await?;
        let path = self.process_path(target);
        if !path_exists(&path).await? {
            return Err(state_error(
                ErrorCode::NotFound,
                "load-process-state",
                format!(
                    "process {} does not exist in container {} generation {}",
                    target.process_id, target.container.id, generation.0
                ),
            ));
        }
        let process: StoredProcess = read_json(&path).await?;
        if process.schema_version != PROCESS_SCHEMA_VERSION
            || process.record.target != *target
            || process.record.target.container.generation != Some(generation)
            || process.record.pid == Some(0)
        {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "load-process-state",
                format!(
                    "invalid durable process record for {} in container {} generation {}",
                    target.process_id, target.container.id, generation.0
                ),
            ));
        }
        if let Some(exit) = &process.exit_status {
            exit.validate()?;
        }
        Ok(process)
    }

    pub(super) async fn release_failed_process_operation(
        &self,
        operation: &StoredOperation,
        mutation: DurableMutation,
    ) -> Result<()> {
        self.release_process_operation_claim(
            operation,
            &operation.operation_id,
            mutation,
            "fail-process-operation",
        )
        .await
    }

    pub(super) async fn release_process_operation_claim(
        &self,
        operation: &StoredOperation,
        operation_id: &OperationId,
        mutation: DurableMutation,
        operation_name: &'static str,
    ) -> Result<()> {
        let mut container = self
            .load_stored_exact(&operation.container_id, operation.generation)
            .await?;
        let process_id = required_operation_process_id(operation, operation_name)?.clone();
        let target = exact_process_target(&container, process_id);
        if target.process_id.is_init() {
            ensure_active_operation(&container, operation_id, operation_name)?;
            if container.active_operation.is_some() {
                container.active_operation = None;
                self.write_json(
                    mutation,
                    &self
                        .container_directory(&container.id)
                        .join(CONTAINER_RECORD_FILE),
                    &container,
                )
                .await?;
            }
            return Ok(());
        }

        let mut process = self.load_stored_process(&target).await?;
        ensure_active_process_operation(&process, operation_id, operation_name)?;
        if process.active_operation.is_some() {
            process.active_operation = None;
            self.write_json(mutation, &self.process_path(&target), &process)
                .await?;
        }
        Ok(())
    }

    pub(super) async fn ensure_no_active_process_operations(
        &self,
        container: &StoredContainer,
        operation: &'static str,
    ) -> Result<()> {
        let directory = self.process_directory(&container.id);
        if !path_exists(&directory).await? {
            return Ok(());
        }
        ensure_plain_directory(&directory, "process state directory").await?;
        let mut entries = tokio::fs::read_dir(&directory).await.map_err(|error| {
            state_error(
                ErrorCode::Internal,
                operation,
                format!(
                    "failed to inspect process records for container {}: {error}",
                    container.id
                ),
            )
        })?;
        while let Some(entry) = entries.next_entry().await.map_err(|error| {
            state_error(
                ErrorCode::Internal,
                operation,
                format!(
                    "failed to enumerate process records for container {}: {error}",
                    container.id
                ),
            )
        })? {
            let file_name = entry.file_name();
            let file_name = file_name.to_str().ok_or_else(|| {
                state_error(
                    ErrorCode::FailedPrecondition,
                    operation,
                    "process record filename is not valid UTF-8",
                )
            })?;
            let process_id = file_name
                .strip_suffix(".json")
                .ok_or_else(|| {
                    state_error(
                        ErrorCode::FailedPrecondition,
                        operation,
                        format!("unexpected file in process state directory: {file_name}"),
                    )
                })
                .and_then(|value| {
                    ProcessId::new(value.to_string()).map_err(|error| {
                        state_error(
                            ErrorCode::FailedPrecondition,
                            operation,
                            format!("invalid process record filename {file_name}: {error}"),
                        )
                    })
                })?;
            let target = exact_process_target(container, process_id);
            let process = self.load_stored_process(&target).await?;
            if let Some(active) = process.active_operation {
                return Err(state_error(
                    ErrorCode::Conflict,
                    operation,
                    format!(
                        "container {} process {} is owned by active operation {active}",
                        container.id, target.process_id
                    ),
                )
                .retryable(true));
            }
        }
        Ok(())
    }

    async fn ensure_process_directory(&self, id: &ContainerId) -> Result<()> {
        let directory = self.process_directory(id);
        if path_exists(&directory).await? {
            ensure_plain_directory(&directory, "process state directory").await
        } else {
            create_private_directory(&directory).await
        }
    }
}

async fn validate_signal_target(
    store: &DurableStateStore,
    container: &StoredContainer,
    target: &ProcessTarget,
) -> Result<()> {
    if !matches!(
        *container.record.state.status(),
        ContainerState::Created | ContainerState::Running
    ) {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "prepare-signal-process",
            format!(
                "container {} generation {} cannot signal process {} while {}",
                container.id,
                container.record.generation.0,
                target.process_id,
                container.record.state.status()
            ),
        ));
    }
    if target.process_id.is_init() {
        return Ok(());
    }
    let process = store.load_stored_process(target).await?;
    if process.record.pid.is_none() {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "prepare-signal-process",
            format!("process {} has not completed exec", target.process_id),
        ));
    }
    if process.exit_status.is_some() {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "prepare-signal-process",
            format!("process {} has already exited", target.process_id),
        ));
    }
    Ok(())
}

pub(super) fn exact_process_target(
    container: &StoredContainer,
    process_id: ProcessId,
) -> ProcessTarget {
    ProcessTarget {
        container: ContainerTarget::exact(container.id.clone(), container.record.generation),
        process_id,
    }
}

pub(super) fn validate_requested_generation(
    container: &StoredContainer,
    target: &ContainerTarget,
    operation: &'static str,
) -> Result<()> {
    if let Some(expected) = target.generation {
        if container.record.generation != expected {
            return Err(generation_conflict(
                &target.id,
                expected,
                container.record.generation,
                operation,
            ));
        }
    }
    Ok(())
}

pub(super) fn ensure_container_unclaimed(
    container: &StoredContainer,
    operation: &'static str,
) -> Result<()> {
    if let Some(active) = &container.active_operation {
        return Err(state_error(
            ErrorCode::Conflict,
            operation,
            format!(
                "container {} is owned by active operation {active}",
                container.id
            ),
        )
        .retryable(true));
    }
    Ok(())
}

pub(super) fn validate_process_retry(
    stored: &StoredOperation,
    operation_id: &OperationId,
    kind: StoredOperationKind,
    container_id: &ContainerId,
    process_id: &ProcessId,
    digest: &str,
    operation: &'static str,
) -> Result<()> {
    validate_retry(stored, operation_id, kind, container_id, digest, operation)?;
    if stored.process_id.as_ref() != Some(process_id) {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            operation,
            format!("operation ID {operation_id} was already used for a different process"),
        ));
    }
    Ok(())
}

pub(super) fn required_operation_process_id<'a>(
    operation: &'a StoredOperation,
    operation_name: &'static str,
) -> Result<&'a ProcessId> {
    operation.process_id.as_ref().ok_or_else(|| {
        state_error(
            ErrorCode::FailedPrecondition,
            operation_name,
            format!(
                "process operation {} has no durable process ID",
                operation.operation_id
            ),
        )
    })
}

fn validate_process_response(
    response: &ProcessRecord,
    operation: &StoredOperation,
    operation_name: &'static str,
) -> Result<()> {
    let process_id = required_operation_process_id(operation, operation_name)?;
    if response.target.container
        != ContainerTarget::exact(operation.container_id.clone(), operation.generation)
        || response.target.process_id != *process_id
        || response.pid.is_none()
        || response.pid == Some(0)
    {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            operation_name,
            format!(
                "operation {} contains an invalid process response",
                operation.operation_id
            ),
        ));
    }
    Ok(())
}

fn ensure_active_process_operation(
    process: &StoredProcess,
    operation_id: &OperationId,
    operation: &'static str,
) -> Result<()> {
    match process.active_operation.as_ref() {
        Some(active) if active == operation_id => Ok(()),
        Some(active) => Err(state_error(
            ErrorCode::Conflict,
            operation,
            format!(
                "process {} is owned by active operation {active}, not {operation_id}",
                process.record.target.process_id
            ),
        )),
        None => Ok(()),
    }
}

pub(super) async fn claim_active_process_operation(
    store: &DurableStateStore,
    process: &mut StoredProcess,
    operation_id: &OperationId,
    mutation: DurableMutation,
    operation: &'static str,
) -> Result<()> {
    match process.active_operation.as_ref() {
        Some(active) if active == operation_id => return Ok(()),
        Some(active) => {
            return Err(state_error(
                ErrorCode::Conflict,
                operation,
                format!(
                    "process {} already has active operation {active}",
                    process.record.target.process_id
                ),
            ));
        }
        None => process.active_operation = Some(operation_id.clone()),
    }
    store
        .write_json(
            mutation,
            &store.process_path(&process.record.target),
            process,
        )
        .await
}

fn exit_status_conflict(
    target: &ProcessTarget,
    durable: &ExitStatus,
    observed: &ExitStatus,
) -> a3s_oci_sdk::Error {
    state_error(
        ErrorCode::Conflict,
        "complete-process-wait",
        format!(
            "process {} terminal result mismatch: durable {durable:?}, driver {observed:?}",
            target.process_id
        ),
    )
}
