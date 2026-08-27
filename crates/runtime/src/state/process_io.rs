use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    CloseStdinRequest, OperationContext, OperationId, ProcessTarget, ResizeRequest, Result,
    TerminalSize, ValidateRequest, WriteStdinRequest,
};
use serde::Serialize;

use crate::fault::DurableMutation;

use super::filesystem::state_error;
use super::model::{
    StoredOperation, StoredOperationKind, StoredOperationStatus, OPERATION_SCHEMA_VERSION,
};
use super::operation::{request_digest, validate_deadline, RequestDigests};
use super::process::{
    exact_process_target, required_operation_process_id, validate_process_retry,
    validate_requested_generation,
};
use super::{DurableStateStore, ErrorCode, ProcessIoPreparation};

#[derive(Serialize)]
struct WriteStdinFingerprint<'a> {
    process: &'a ProcessTarget,
    data: &'a [u8],
}

#[derive(Serialize)]
struct ProcessTargetFingerprint<'a> {
    process: &'a ProcessTarget,
}

#[derive(Serialize)]
struct ResizeFingerprint<'a> {
    process: &'a ProcessTarget,
    size: TerminalSize,
}

#[derive(Debug, Clone, Copy)]
struct ProcessIoOperation {
    kind: StoredOperationKind,
    name: &'static str,
    prepare: DurableMutation,
    claim: DurableMutation,
    complete_record: DurableMutation,
    complete_operation: DurableMutation,
}

const WRITE_STDIN: ProcessIoOperation = ProcessIoOperation {
    kind: StoredOperationKind::WriteStdin,
    name: "write-stdin",
    prepare: DurableMutation::PrepareWriteStdinOperation,
    claim: DurableMutation::ClaimWriteStdinOperation,
    complete_record: DurableMutation::CompleteWriteStdinRecord,
    complete_operation: DurableMutation::CompleteWriteStdinOperation,
};

const CLOSE_STDIN: ProcessIoOperation = ProcessIoOperation {
    kind: StoredOperationKind::CloseStdin,
    name: "close-stdin",
    prepare: DurableMutation::PrepareCloseStdinOperation,
    claim: DurableMutation::ClaimCloseStdinOperation,
    complete_record: DurableMutation::CompleteCloseStdinRecord,
    complete_operation: DurableMutation::CompleteCloseStdinOperation,
};

const RESIZE: ProcessIoOperation = ProcessIoOperation {
    kind: StoredOperationKind::Resize,
    name: "resize",
    prepare: DurableMutation::PrepareResizeOperation,
    claim: DurableMutation::ClaimResizeOperation,
    complete_record: DurableMutation::CompleteResizeRecord,
    complete_operation: DurableMutation::CompleteResizeOperation,
};

impl DurableStateStore {
    pub(crate) async fn prepare_write_stdin(
        &self,
        request: &WriteStdinRequest,
    ) -> Result<ProcessIoPreparation> {
        request.validate()?;
        let digest = request_digest(
            &WriteStdinFingerprint {
                process: &request.process,
                data: &request.data,
            },
            "digest-write-stdin-request",
        )?;
        self.prepare_process_io_operation(&request.context, &request.process, digest, WRITE_STDIN)
            .await
    }

    pub(crate) async fn prepare_close_stdin(
        &self,
        request: &CloseStdinRequest,
    ) -> Result<ProcessIoPreparation> {
        request.validate()?;
        let digest = request_digest(
            &ProcessTargetFingerprint {
                process: &request.process,
            },
            "digest-close-stdin-request",
        )?;
        self.prepare_process_io_operation(&request.context, &request.process, digest, CLOSE_STDIN)
            .await
    }

    pub(crate) async fn prepare_resize(
        &self,
        request: &ResizeRequest,
    ) -> Result<ProcessIoPreparation> {
        request.validate()?;
        let digest = request_digest(
            &ResizeFingerprint {
                process: &request.process,
                size: request.size,
            },
            "digest-resize-request",
        )?;
        self.prepare_process_io_operation(&request.context, &request.process, digest, RESIZE)
            .await
    }

    pub(crate) async fn complete_write_stdin(&self, operation_id: &OperationId) -> Result<()> {
        self.complete_process_io_operation(operation_id, WRITE_STDIN)
            .await
    }

    pub(crate) async fn complete_close_stdin(&self, operation_id: &OperationId) -> Result<()> {
        self.complete_process_io_operation(operation_id, CLOSE_STDIN)
            .await
    }

    pub(crate) async fn complete_resize(&self, operation_id: &OperationId) -> Result<()> {
        self.complete_process_io_operation(operation_id, RESIZE)
            .await
    }

    async fn prepare_process_io_operation(
        &self,
        context: &OperationContext,
        requested: &ProcessTarget,
        digest: RequestDigests,
        profile: ProcessIoOperation,
    ) -> Result<ProcessIoPreparation> {
        let operation_name = profile.name;
        let _guard = self.gate.lock().await;
        if let Some(operation) = self
            .load_operation_if_present(&context.operation_id)
            .await?
        {
            validate_process_retry(
                &operation,
                &context.operation_id,
                profile.kind,
                &requested.container.id,
                &requested.process_id,
                &digest,
                operation_name,
            )?;
            return match &operation.outcome {
                StoredOperationStatus::Prepared => {
                    let target = self.claim_process_io_operation(&operation, profile).await?;
                    Ok(ProcessIoPreparation::Resume(target))
                }
                StoredOperationStatus::SucceededEmpty => Ok(ProcessIoPreparation::Replayed),
                StoredOperationStatus::Failed { error } => Err(error.clone()),
                StoredOperationStatus::Succeeded { .. }
                | StoredOperationStatus::SucceededProcess { .. }
                | StoredOperationStatus::SucceededFilesystem { .. }
                | StoredOperationStatus::SucceededCheckpoint { .. } => Err(state_error(
                    ErrorCode::FailedPrecondition,
                    operation_name,
                    format!(
                        "{} operation {} has an invalid outcome",
                        profile.name, context.operation_id
                    ),
                )),
            };
        }

        validate_deadline(context, operation_name)?;
        let container = self.load_stored_container(&requested.container.id).await?;
        validate_requested_generation(&container, &requested.container, operation_name)?;
        let target = exact_process_target(&container, requested.process_id.clone());
        if target.process_id.is_init() {
            self.ensure_init_io_lifecycle_compatible(&container, operation_name)
                .await?;
        } else {
            self.ensure_process_io_lifecycle_compatible(&container, operation_name)
                .await?;
        }
        self.validate_process_io_target(&container, &target, operation_name)
            .await?;

        let operation = StoredOperation {
            schema_version: OPERATION_SCHEMA_VERSION.to_string(),
            operation_id: context.operation_id.clone(),
            kind: profile.kind,
            container_id: container.id.clone(),
            generation: container.record.generation,
            process_id: Some(target.process_id.clone()),
            request: None,
            request_digest: digest.current().to_string(),
            outcome: StoredOperationStatus::Prepared,
        };
        self.write_json(
            profile.prepare,
            &self.operation_path(&context.operation_id),
            &operation,
        )
        .await?;
        let target = self.claim_process_io_operation(&operation, profile).await?;
        Ok(ProcessIoPreparation::Prepared(target))
    }

    async fn validate_process_io_target(
        &self,
        container: &super::model::StoredContainer,
        target: &ProcessTarget,
        operation: &'static str,
    ) -> Result<()> {
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
            return Ok(());
        }
        let process = self.load_stored_process(target).await?;
        if process.record.pid.is_none() {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                operation,
                format!("process {} has not completed exec", target.process_id),
            ));
        }
        Ok(())
    }

    async fn claim_process_io_operation(
        &self,
        operation: &StoredOperation,
        profile: ProcessIoOperation,
    ) -> Result<ProcessTarget> {
        let mut container = self
            .load_stored_exact(&operation.container_id, operation.generation)
            .await?;
        let process_id = required_operation_process_id(operation, profile.name)?.clone();
        let target = exact_process_target(&container, process_id);
        if target.process_id.is_init() {
            self.ensure_init_io_lifecycle_compatible(&container, profile.name)
                .await?;
            claim_init_io_operation(self, &mut container, operation, profile).await?;
        } else {
            self.ensure_process_io_lifecycle_compatible(&container, profile.name)
                .await?;
            let mut process = self.load_stored_process(&target).await?;
            claim_process_io_operation(self, &mut process, operation, profile).await?;
        }
        Ok(target)
    }

    async fn ensure_init_io_lifecycle_compatible(
        &self,
        container: &super::model::StoredContainer,
        operation_name: &'static str,
    ) -> Result<()> {
        let Some(active_id) = container.active_operation.as_ref() else {
            return Ok(());
        };
        let active = self.load_operation(active_id).await?;
        if matches!(
            active.kind,
            StoredOperationKind::Delete | StoredOperationKind::Checkpoint
        ) {
            return Err(state_error(
                ErrorCode::Conflict,
                operation_name,
                format!(
                    "container {} is fenced by active {:?} operation {active_id}",
                    container.id, active.kind
                ),
            )
            .retryable(true));
        }
        Ok(())
    }

    async fn ensure_process_io_lifecycle_compatible(
        &self,
        container: &super::model::StoredContainer,
        operation_name: &'static str,
    ) -> Result<()> {
        self.ensure_init_io_lifecycle_compatible(container, operation_name)
            .await
    }

    async fn complete_process_io_operation(
        &self,
        operation_id: &OperationId,
        profile: ProcessIoOperation,
    ) -> Result<()> {
        let _guard = self.gate.lock().await;
        let mut operation = self.load_operation(operation_id).await?;
        if operation.kind != profile.kind {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                profile.name,
                format!(
                    "operation {operation_id} is not a {} operation",
                    profile.name
                ),
            ));
        }
        match &operation.outcome {
            StoredOperationStatus::Prepared => {}
            StoredOperationStatus::SucceededEmpty => return Ok(()),
            StoredOperationStatus::Failed { error } => return Err(error.clone()),
            StoredOperationStatus::Succeeded { .. }
            | StoredOperationStatus::SucceededProcess { .. }
            | StoredOperationStatus::SucceededFilesystem { .. }
            | StoredOperationStatus::SucceededCheckpoint { .. } => {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    profile.name,
                    format!(
                        "{} operation {operation_id} has an invalid outcome",
                        profile.name
                    ),
                ));
            }
        }

        self.release_process_operation_claim(
            &operation,
            operation_id,
            profile.complete_record,
            profile.name,
        )
        .await?;
        operation.outcome = StoredOperationStatus::SucceededEmpty;
        self.write_json(
            profile.complete_operation,
            &self.operation_path(operation_id),
            &operation,
        )
        .await
    }
}

async fn claim_init_io_operation(
    store: &DurableStateStore,
    container: &mut super::model::StoredContainer,
    operation: &StoredOperation,
    profile: ProcessIoOperation,
) -> Result<()> {
    if container
        .init_io_operations
        .contains(&operation.operation_id)
    {
        return Ok(());
    }

    if container.active_operation.as_ref() == Some(&operation.operation_id) {
        // A previous release used the lifecycle slot for init I/O. Move the
        // exact prepared claim instead of leaving start permanently blocked.
        container.active_operation = None;
    }
    container
        .init_io_operations
        .insert(operation.operation_id.clone());
    store
        .write_json(
            profile.claim,
            &store
                .container_directory(&container.id)
                .join(super::CONTAINER_RECORD_FILE),
            container,
        )
        .await
}

async fn claim_process_io_operation(
    store: &DurableStateStore,
    process: &mut super::model::StoredProcess,
    operation: &StoredOperation,
    profile: ProcessIoOperation,
) -> Result<()> {
    if process
        .active_io_operations
        .contains(&operation.operation_id)
    {
        return Ok(());
    }
    if process.active_operation.as_ref() == Some(&operation.operation_id) {
        // Migrate a prepared exec-I/O claim written by an older release.
        process.active_operation = None;
    }
    process
        .active_io_operations
        .insert(operation.operation_id.clone());
    store
        .write_json(
            profile.claim,
            &store.process_path(&process.record.target),
            process,
        )
        .await
}

pub(super) async fn migrate_legacy_init_io_claim(
    store: &DurableStateStore,
    container: &mut super::model::StoredContainer,
) -> Result<Option<OperationId>> {
    let Some(operation_id) = container.active_operation.clone() else {
        return Ok(None);
    };
    let operation = store.load_operation(&operation_id).await?;
    if !is_process_io_kind(operation.kind) {
        return Ok(None);
    }
    validate_legacy_io_operation(&operation, &container.id, container.record.generation, true)?;
    container.active_operation = None;
    container.init_io_operations.insert(operation_id.clone());
    Ok(Some(operation_id))
}

pub(super) async fn migrate_legacy_process_io_claim(
    store: &DurableStateStore,
    process: &mut super::model::StoredProcess,
) -> Result<Option<OperationId>> {
    let Some(operation_id) = process.active_operation.clone() else {
        return Ok(None);
    };
    let operation = store.load_operation(&operation_id).await?;
    if !is_process_io_kind(operation.kind) {
        return Ok(None);
    }
    let generation = process.record.target.container.generation.ok_or_else(|| {
        state_error(
            ErrorCode::FailedPrecondition,
            "migrate-process-io-claim",
            "legacy process I/O claim does not have an exact container generation",
        )
    })?;
    validate_legacy_io_operation(
        &operation,
        &process.record.target.container.id,
        generation,
        process.record.target.process_id.is_init(),
    )?;
    if operation.process_id.as_ref() != Some(&process.record.target.process_id) {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "migrate-process-io-claim",
            format!("legacy process I/O operation {operation_id} targets a different process"),
        ));
    }
    process.active_operation = None;
    process.active_io_operations.insert(operation_id.clone());
    Ok(Some(operation_id))
}

fn validate_legacy_io_operation(
    operation: &StoredOperation,
    container_id: &a3s_oci_sdk::ContainerId,
    generation: a3s_oci_sdk::Generation,
    init: bool,
) -> Result<()> {
    let process_matches = operation
        .process_id
        .as_ref()
        .is_some_and(|process_id| process_id.is_init() == init);
    if operation.container_id != *container_id
        || operation.generation != generation
        || !process_matches
        || !matches!(operation.outcome, StoredOperationStatus::Prepared)
    {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "migrate-process-io-claim",
            format!(
                "legacy process I/O operation {} does not match its active durable claim",
                operation.operation_id
            ),
        ));
    }
    Ok(())
}

const fn is_process_io_kind(kind: StoredOperationKind) -> bool {
    matches!(
        kind,
        StoredOperationKind::WriteStdin
            | StoredOperationKind::CloseStdin
            | StoredOperationKind::Resize
    )
}
