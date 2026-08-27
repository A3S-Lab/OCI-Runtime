use std::collections::BTreeMap;

use a3s_oci_core::DriverKind;
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    CheckpointArtifactPath, CheckpointReference, ContainerId, ContainerRecord, ContainerTarget,
    CreateAttachments, ErrorCode, IsolationRequest, OciBundle, OciSchemaValidator, OperationId,
    RestoreRequest, RestoreResponse, Result, RuntimeEventKind, ValidateRequest,
};
use serde::Serialize;

use crate::fault::DurableMutation;

use super::creation::CreationProfile;
use super::filesystem::state_error;
use super::model::{
    StoredOperation, StoredOperationKind, StoredOperationRequest, StoredOperationStatus,
    OPERATION_SCHEMA_VERSION,
};
use super::oci_state::{is_paused, rebuild_paused_state, rebuild_state};
use super::operation::{request_digest, validate_deadline, validate_retry, RequestDigests};
use super::{
    claim_active_operation, DurableStateStore, RestoreOperationLookup, RestoreOperationPreparation,
    CONTAINER_RECORD_FILE,
};

#[derive(Serialize)]
struct RestoreFingerprint<'a> {
    id: &'a ContainerId,
    bundle: &'a OciBundle,
    artifact_path: &'a CheckpointArtifactPath,
    isolation: &'a IsolationRequest,
    attachments: &'a CreateAttachments,
    reference: &'a CheckpointReference,
}

impl DurableStateStore {
    /// Check durable restore replay before touching the caller-owned artifact.
    pub(crate) async fn lookup_restore(
        &self,
        request: &RestoreRequest,
    ) -> Result<RestoreOperationLookup> {
        request.validate()?;
        let digest = restore_request_digest(request)?;
        let _guard = self.gate.lock().await;
        let Some(operation) = self
            .load_operation_if_present(&request.context().operation_id)
            .await?
        else {
            return Ok(RestoreOperationLookup::Pending);
        };
        validate_restore_retry(&operation, request, &digest)?;
        match operation.outcome.clone() {
            StoredOperationStatus::Prepared => Ok(RestoreOperationLookup::Pending),
            StoredOperationStatus::SucceededRestore { response } => {
                let response = self
                    .reconcile_succeeded_restore(operation, response)
                    .await?;
                Ok(RestoreOperationLookup::Replayed(response))
            }
            StoredOperationStatus::Failed { error } => {
                self.reconcile_failed_restore(&operation).await?;
                Err(error)
            }
            StoredOperationStatus::Succeeded { .. }
            | StoredOperationStatus::SucceededProcess { .. }
            | StoredOperationStatus::SucceededFilesystem { .. }
            | StoredOperationStatus::SucceededCheckpoint { .. }
            | StoredOperationStatus::SucceededAttestation { .. }
            | StoredOperationStatus::SucceededEmpty => {
                Err(invalid_restore_outcome(&operation.operation_id))
            }
        }
    }

    /// Reserve a new restoring generation after read-only artifact validation.
    pub(crate) async fn prepare_restore(
        &self,
        request: &RestoreRequest,
        driver: DriverKind,
    ) -> Result<RestoreOperationPreparation> {
        request.validate()?;
        let digest = restore_request_digest(request)?;
        let operation_id = &request.context().operation_id;
        let _guard = self.gate.lock().await;

        if let Some(operation) = self.load_operation_if_present(operation_id).await? {
            validate_restore_retry(&operation, request, &digest)?;
            return match operation.outcome.clone() {
                StoredOperationStatus::Prepared => {
                    let mut stored = self
                        .reconcile_prepared_restore(request, driver, operation.generation)
                        .await?;
                    claim_active_operation(
                        self,
                        &mut stored,
                        operation_id,
                        DurableMutation::ClaimRestoreOperation,
                        "restore",
                    )
                    .await?;
                    self.append_restore_creating_event(operation_id, &stored.record)
                        .await?;
                    Ok(RestoreOperationPreparation::Resume(stored.record))
                }
                StoredOperationStatus::SucceededRestore { response } => {
                    let response = self
                        .reconcile_succeeded_restore(operation, response)
                        .await?;
                    Ok(RestoreOperationPreparation::Replayed(response))
                }
                StoredOperationStatus::Failed { error } => {
                    self.reconcile_failed_restore(&operation).await?;
                    Err(error)
                }
                StoredOperationStatus::Succeeded { .. }
                | StoredOperationStatus::SucceededProcess { .. }
                | StoredOperationStatus::SucceededFilesystem { .. }
                | StoredOperationStatus::SucceededCheckpoint { .. }
                | StoredOperationStatus::SucceededAttestation { .. }
                | StoredOperationStatus::SucceededEmpty => {
                    Err(invalid_restore_outcome(operation_id))
                }
            };
        }

        validate_deadline(request.context(), "restore")?;
        let container_directory = self.container_directory(request.id());
        if self.filesystem.path_exists(&container_directory).await? {
            return Err(state_error(
                ErrorCode::AlreadyExists,
                "restore",
                format!("container {} already exists", request.id()),
            ));
        }
        let generation = self.next_generation(request.id()).await?;
        let operation = StoredOperation {
            schema_version: OPERATION_SCHEMA_VERSION.to_string(),
            operation_id: operation_id.clone(),
            kind: StoredOperationKind::Restore,
            container_id: request.id().clone(),
            generation,
            process_id: None,
            request: Some(StoredOperationRequest::Restore(Box::new(request.clone()))),
            request_digest: digest.current().to_string(),
            outcome: StoredOperationStatus::Prepared,
        };
        self.write_json(
            DurableMutation::PrepareRestoreOperation,
            &self.operation_path(operation_id),
            &operation,
        )
        .await?;
        let stored = self
            .reconcile_prepared_restore(request, driver, generation)
            .await?;
        self.append_restore_creating_event(operation_id, &stored.record)
            .await?;
        Ok(RestoreOperationPreparation::Prepared(stored.record))
    }

    /// Commit an exact paused-running restore response.
    pub(crate) async fn complete_restore(
        &self,
        operation_id: &OperationId,
        pid: i32,
    ) -> Result<RestoreResponse> {
        if pid <= 0 {
            return Err(state_error(
                ErrorCode::InvalidArgument,
                "complete-restore",
                format!("restored container PID must be positive; received {pid}"),
            ));
        }
        let _guard = self.gate.lock().await;
        let mut operation = self.load_operation(operation_id).await?;
        if operation.kind != StoredOperationKind::Restore {
            return Err(invalid_restore_outcome(operation_id));
        }
        match &operation.outcome {
            StoredOperationStatus::Prepared => {}
            StoredOperationStatus::SucceededRestore { response } => {
                return Ok(response.as_ref().clone());
            }
            StoredOperationStatus::Failed { error } => return Err(error.clone()),
            StoredOperationStatus::Succeeded { .. }
            | StoredOperationStatus::SucceededProcess { .. }
            | StoredOperationStatus::SucceededFilesystem { .. }
            | StoredOperationStatus::SucceededCheckpoint { .. }
            | StoredOperationStatus::SucceededAttestation { .. }
            | StoredOperationStatus::SucceededEmpty => {
                return Err(invalid_restore_outcome(operation_id));
            }
        }
        let request = retained_restore_request(&operation)?;
        let mut stored = self
            .load_stored_exact(&operation.container_id, operation.generation)
            .await?;
        match *stored.record.state.status() {
            ContainerState::Creating => {
                if stored.active_operation.as_ref() != Some(operation_id) {
                    return Err(state_error(
                        ErrorCode::Conflict,
                        "complete-restore",
                        format!(
                            "restoring container {} is not owned by operation {operation_id}",
                            operation.container_id
                        ),
                    ));
                }
                stored.record.state =
                    rebuild_state(&stored.record.state, ContainerState::Running, Some(pid))?;
                stored.record.state = rebuild_paused_state(&stored.record.state, true)?;
                OciSchemaValidator::new()?.validate_state(&stored.record.state)?;
            }
            ContainerState::Running
                if *stored.record.state.pid() == Some(pid) && is_paused(&stored.record.state) => {}
            status => {
                return Err(state_error(
                    ErrorCode::Conflict,
                    "complete-restore",
                    format!(
                        "container {} cannot complete restore as PID {pid} while {status} with PID {:?} and paused={}",
                        operation.container_id,
                        stored.record.state.pid(),
                        is_paused(&stored.record.state)
                    ),
                ));
            }
        }
        if stored
            .active_operation
            .as_ref()
            .is_some_and(|active| active != operation_id)
        {
            return Err(state_error(
                ErrorCode::Conflict,
                "complete-restore",
                format!(
                    "container {} is owned by another active operation",
                    operation.container_id
                ),
            ));
        }
        stored.active_operation = None;
        self.write_json(
            DurableMutation::CompleteRestoreContainer,
            &self
                .container_directory(&operation.container_id)
                .join(CONTAINER_RECORD_FILE),
            &stored,
        )
        .await?;

        let target = ContainerTarget::exact(operation.container_id.clone(), operation.generation);
        let attributes = BTreeMap::from([(
            "operation-id".to_string(),
            operation_id.as_str().to_string(),
        )]);
        self.append_operation_event(
            operation_id,
            "restore-created",
            &target,
            None,
            RuntimeEventKind::ContainerCreated,
            attributes.clone(),
        )
        .await?;
        self.append_operation_event(
            operation_id,
            "restore-started",
            &target,
            None,
            RuntimeEventKind::ContainerStarted,
            attributes.clone(),
        )
        .await?;
        self.append_operation_event(
            operation_id,
            "restore-paused",
            &target,
            None,
            RuntimeEventKind::ContainerPaused,
            attributes,
        )
        .await?;

        let response = RestoreResponse::new(stored.record.clone(), request.reference()?.clone())?;
        response.validate_for_request(request)?;
        operation.outcome = StoredOperationStatus::SucceededRestore {
            response: Box::new(response.clone()),
        };
        self.write_json(
            DurableMutation::CompleteRestoreOperation,
            &self.operation_path(operation_id),
            &operation,
        )
        .await?;
        Ok(response)
    }

    async fn reconcile_prepared_restore(
        &self,
        request: &RestoreRequest,
        driver: DriverKind,
        generation: a3s_oci_sdk::Generation,
    ) -> Result<super::model::StoredContainer> {
        if request.reference()?.compatibility().driver() != driver {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "reconcile-restore",
                "selected restore driver does not match the immutable checkpoint reference",
            ));
        }
        self.reconcile_prepared_container(
            request.id(),
            request.bundle(),
            request.isolation().class(),
            request.attachments(),
            driver,
            generation,
            &request.context().operation_id,
            CreationProfile {
                operation: "reconcile-restore",
                store_config: DurableMutation::StoreRestoreConfig,
                store_container: DurableMutation::StoreRestoringContainer,
            },
        )
        .await
    }

    async fn reconcile_succeeded_restore(
        &self,
        mut operation: StoredOperation,
        response: Box<RestoreResponse>,
    ) -> Result<Box<RestoreResponse>> {
        let stored = match self.load_stored_container(&operation.container_id).await {
            Ok(stored) => stored,
            Err(error) if error.code == ErrorCode::NotFound => {
                return Ok(response);
            }
            Err(error) => return Err(error),
        };
        if stored.record.generation != operation.generation || response.restored() == &stored.record
        {
            return Ok(response);
        }
        if *stored.record.state.status() != ContainerState::Running
            || !is_paused(&stored.record.state)
            || *response.restored().state.status() != ContainerState::Running
            || !response.restored().is_paused()
        {
            return Ok(response);
        }
        let active_allows_rebind = match stored.active_operation.as_ref() {
            Some(operation_id) => {
                let active = self.load_operation(operation_id).await?;
                matches!(
                    active.kind,
                    StoredOperationKind::Kill
                        | StoredOperationKind::Pause
                        | StoredOperationKind::Resume
                        | StoredOperationKind::Update
                        | StoredOperationKind::File
                        | StoredOperationKind::Filesystem
                        | StoredOperationKind::Checkpoint
                ) && active.container_id == stored.id
                    && active.generation == stored.record.generation
                    && matches!(active.outcome, StoredOperationStatus::Prepared)
            }
            None => true,
        };
        let mut expected_state = rebuild_state(
            &response.restored().state,
            ContainerState::Running,
            *stored.record.state.pid(),
        )?;
        expected_state = rebuild_paused_state(&expected_state, true)?;
        let expected_durable = ContainerRecord {
            state: expected_state,
            ..response.restored().clone()
        };
        if !active_allows_rebind || expected_durable != stored.record {
            return Err(state_error(
                ErrorCode::Conflict,
                "reconcile-succeeded-restore",
                format!(
                    "completed restore operation {} changed beyond its recovered process identity",
                    operation.operation_id
                ),
            ));
        }
        let rebound = RestoreResponse::new(stored.record, response.reference().clone())?;
        rebound.validate_for_request(retained_restore_request(&operation)?)?;
        operation.outcome = StoredOperationStatus::SucceededRestore {
            response: Box::new(rebound.clone()),
        };
        self.write_json(
            DurableMutation::CompleteRestoreOperation,
            &self.operation_path(&operation.operation_id),
            &operation,
        )
        .await?;
        Ok(Box::new(rebound))
    }

    async fn append_restore_creating_event(
        &self,
        operation_id: &OperationId,
        record: &ContainerRecord,
    ) -> Result<()> {
        self.append_operation_event(
            operation_id,
            "restoring",
            &ContainerTarget::exact(
                ContainerId::new(record.state.id().to_string())?,
                record.generation,
            ),
            None,
            RuntimeEventKind::ContainerCreating,
            BTreeMap::from([(
                "operation-id".to_string(),
                operation_id.as_str().to_string(),
            )]),
        )
        .await?;
        Ok(())
    }
}

pub(super) fn restore_request_digest(request: &RestoreRequest) -> Result<RequestDigests> {
    request_digest(
        &RestoreFingerprint {
            id: request.id(),
            bundle: request.bundle(),
            artifact_path: request.artifact_path(),
            isolation: request.isolation(),
            attachments: request.attachments(),
            reference: request.reference()?,
        },
        "restore",
    )
}

fn validate_restore_retry(
    operation: &StoredOperation,
    request: &RestoreRequest,
    digest: &RequestDigests,
) -> Result<()> {
    validate_retry(
        operation,
        &request.context().operation_id,
        StoredOperationKind::Restore,
        request.id(),
        digest,
        "restore",
    )?;
    if operation.request.as_ref()
        != Some(&StoredOperationRequest::Restore(Box::new(request.clone())))
    {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "restore",
            format!(
                "operation ID {} was already used for a different restore request",
                request.context().operation_id
            ),
        ));
    }
    Ok(())
}

fn retained_restore_request(operation: &StoredOperation) -> Result<&RestoreRequest> {
    let Some(StoredOperationRequest::Restore(request)) = operation.request.as_ref() else {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "restore",
            format!(
                "restore operation {} has no retained request",
                operation.operation_id
            ),
        ));
    };
    Ok(request)
}

fn invalid_restore_outcome(operation_id: &OperationId) -> a3s_oci_sdk::Error {
    state_error(
        ErrorCode::FailedPrecondition,
        "restore",
        format!("restore operation {operation_id} has an invalid durable outcome"),
    )
}
