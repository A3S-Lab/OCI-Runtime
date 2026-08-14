use std::collections::BTreeMap;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerOperationRequest, ContainerRecord, ContainerTarget, ErrorCode, OciSchemaValidator,
    OperationId, Result, RuntimeEventKind, ValidateRequest,
};
use serde::Serialize;

use crate::fault::DurableMutation;

use super::filesystem::state_error;
use super::model::{
    StoredOperation, StoredOperationKind, StoredOperationStatus, OPERATION_SCHEMA_VERSION,
};
use super::oci_state::{is_paused, rebuild_paused_state, rebuild_state};
use super::operation::{request_digest, validate_deadline, validate_retry};
use super::{
    claim_active_operation, ensure_active_operation, generation_conflict, DurableStateStore,
    RecordOperationPreparation,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FreezerAction {
    Pause,
    Resume,
}

impl FreezerAction {
    const fn kind(self) -> StoredOperationKind {
        match self {
            Self::Pause => StoredOperationKind::Pause,
            Self::Resume => StoredOperationKind::Resume,
        }
    }

    const fn desired(self) -> bool {
        matches!(self, Self::Pause)
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Pause => "pause",
            Self::Resume => "resume",
        }
    }

    const fn prepare_mutation(self) -> DurableMutation {
        match self {
            Self::Pause => DurableMutation::PreparePauseOperation,
            Self::Resume => DurableMutation::PrepareResumeOperation,
        }
    }

    const fn claim_mutation(self) -> DurableMutation {
        match self {
            Self::Pause => DurableMutation::ClaimPauseOperation,
            Self::Resume => DurableMutation::ClaimResumeOperation,
        }
    }

    const fn reconcile_container_mutation(self) -> DurableMutation {
        match self {
            Self::Pause => DurableMutation::ReconcilePauseContainer,
            Self::Resume => DurableMutation::ReconcileResumeContainer,
        }
    }

    const fn reconcile_operation_mutation(self) -> DurableMutation {
        match self {
            Self::Pause => DurableMutation::ReconcilePauseOperation,
            Self::Resume => DurableMutation::ReconcileResumeOperation,
        }
    }

    const fn complete_container_mutation(self) -> DurableMutation {
        match self {
            Self::Pause => DurableMutation::CompletePauseContainer,
            Self::Resume => DurableMutation::CompleteResumeContainer,
        }
    }

    const fn complete_operation_mutation(self) -> DurableMutation {
        match self {
            Self::Pause => DurableMutation::CompletePauseOperation,
            Self::Resume => DurableMutation::CompleteResumeOperation,
        }
    }
}

#[derive(Serialize)]
struct FreezerFingerprint<'a> {
    target: &'a ContainerTarget,
}

impl DurableStateStore {
    pub(crate) async fn prepare_pause(
        &self,
        request: &ContainerOperationRequest,
    ) -> Result<RecordOperationPreparation> {
        self.prepare_freezer(request, FreezerAction::Pause).await
    }

    pub(crate) async fn prepare_resume(
        &self,
        request: &ContainerOperationRequest,
    ) -> Result<RecordOperationPreparation> {
        self.prepare_freezer(request, FreezerAction::Resume).await
    }

    async fn prepare_freezer(
        &self,
        request: &ContainerOperationRequest,
        action: FreezerAction,
    ) -> Result<RecordOperationPreparation> {
        request.validate()?;
        let operation_name = action.name();
        let digest = request_digest(
            &FreezerFingerprint {
                target: &request.target,
            },
            operation_name,
        )?;
        let _guard = self.gate.lock().await;

        if let Some(mut operation) = self
            .load_operation_if_present(&request.context.operation_id)
            .await?
        {
            validate_retry(
                &operation,
                &request.context.operation_id,
                action.kind(),
                &request.target.id,
                &digest,
                operation_name,
            )?;
            return match operation.outcome.clone() {
                StoredOperationStatus::Prepared => {
                    let mut stored = self
                        .load_stored_exact(&operation.container_id, operation.generation)
                        .await?;
                    if is_paused(&stored.record.state) == action.desired() {
                        ensure_active_operation(
                            &stored,
                            &request.context.operation_id,
                            operation_name,
                        )?;
                        if stored.active_operation.is_some() {
                            stored.active_operation = None;
                            self.write_json(
                                action.reconcile_container_mutation(),
                                &self
                                    .container_directory(&operation.container_id)
                                    .join(super::CONTAINER_RECORD_FILE),
                                &stored,
                            )
                            .await?;
                        }
                        self.append_operation_event(
                            &operation.operation_id,
                            operation_name,
                            &ContainerTarget::exact(
                                operation.container_id.clone(),
                                operation.generation,
                            ),
                            None,
                            match action {
                                FreezerAction::Pause => RuntimeEventKind::ContainerPaused,
                                FreezerAction::Resume => RuntimeEventKind::ContainerResumed,
                            },
                            BTreeMap::from([(
                                "operation-id".to_string(),
                                operation.operation_id.as_str().to_string(),
                            )]),
                        )
                        .await?;
                        operation.outcome = StoredOperationStatus::Succeeded {
                            response: stored.record.clone(),
                        };
                        self.write_json(
                            action.reconcile_operation_mutation(),
                            &self.operation_path(&request.context.operation_id),
                            &operation,
                        )
                        .await?;
                        return Ok(RecordOperationPreparation::Replayed(stored.record));
                    }
                    claim_active_operation(
                        self,
                        &mut stored,
                        &request.context.operation_id,
                        action.claim_mutation(),
                        operation_name,
                    )
                    .await?;
                    Ok(RecordOperationPreparation::Resume(stored.record))
                }
                StoredOperationStatus::Succeeded { response } => {
                    self.reconcile_succeeded_freezer(operation, response, action)
                        .await
                }
                StoredOperationStatus::Failed { error } => Err(error),
                StoredOperationStatus::SucceededProcess { .. }
                | StoredOperationStatus::SucceededFilesystem { .. }
                | StoredOperationStatus::SucceededEmpty => Err(state_error(
                    ErrorCode::FailedPrecondition,
                    operation_name,
                    format!(
                        "{operation_name} operation {} has an invalid outcome",
                        request.context.operation_id
                    ),
                )),
            };
        }

        validate_deadline(&request.context, operation_name)?;
        let mut stored = self.load_stored_container(&request.target.id).await?;
        if let Some(expected) = request.target.generation {
            if stored.record.generation != expected {
                return Err(generation_conflict(
                    &request.target.id,
                    expected,
                    stored.record.generation,
                    operation_name,
                ));
            }
        }
        if *stored.record.state.status() != ContainerState::Running {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                operation_name,
                format!(
                    "container {} generation {} cannot {operation_name} while {}",
                    stored.id,
                    stored.record.generation.0,
                    stored.record.state.status()
                ),
            ));
        }

        let operation = StoredOperation {
            schema_version: OPERATION_SCHEMA_VERSION.to_string(),
            operation_id: request.context.operation_id.clone(),
            kind: action.kind(),
            container_id: request.target.id.clone(),
            generation: stored.record.generation,
            process_id: None,
            request: None,
            request_digest: digest.current().to_string(),
            outcome: StoredOperationStatus::Prepared,
        };
        self.write_json(
            action.prepare_mutation(),
            &self.operation_path(&request.context.operation_id),
            &operation,
        )
        .await?;
        claim_active_operation(
            self,
            &mut stored,
            &request.context.operation_id,
            action.claim_mutation(),
            operation_name,
        )
        .await?;
        Ok(RecordOperationPreparation::Prepared(stored.record))
    }

    async fn reconcile_succeeded_freezer(
        &self,
        mut operation: StoredOperation,
        response: ContainerRecord,
        action: FreezerAction,
    ) -> Result<RecordOperationPreparation> {
        let stored = match self.load_stored_container(&operation.container_id).await {
            Ok(stored) => stored,
            Err(error) if error.code == ErrorCode::NotFound => {
                return Ok(RecordOperationPreparation::Replayed(response));
            }
            Err(error) => return Err(error),
        };
        if stored.record.generation != operation.generation || stored.record == response {
            return Ok(RecordOperationPreparation::Replayed(response));
        }
        if *stored.record.state.status() != ContainerState::Running
            || *response.state.status() != ContainerState::Running
            || is_paused(&response.state) != action.desired()
            || stored.record.state.pid() == response.state.pid()
        {
            return Ok(RecordOperationPreparation::Replayed(response));
        }
        let rebound_state = rebuild_state(
            &response.state,
            ContainerState::Running,
            *stored.record.state.pid(),
        )?;
        let rebound_state = rebuild_paused_state(&rebound_state, action.desired())?;
        let rebound_response = ContainerRecord {
            state: rebound_state,
            ..response
        };
        let expected_state =
            rebuild_paused_state(&rebound_response.state, is_paused(&stored.record.state))?;
        let expected_durable = ContainerRecord {
            state: expected_state,
            ..rebound_response.clone()
        };
        if expected_durable != stored.record {
            return Err(state_error(
                ErrorCode::Conflict,
                action.name(),
                format!(
                    "completed {} operation {} changed beyond its recovered process identity",
                    action.name(),
                    operation.operation_id
                ),
            ));
        }
        operation.outcome = StoredOperationStatus::Succeeded {
            response: rebound_response.clone(),
        };
        self.write_json(
            action.reconcile_operation_mutation(),
            &self.operation_path(&operation.operation_id),
            &operation,
        )
        .await?;
        Ok(RecordOperationPreparation::Replayed(rebound_response))
    }

    pub(crate) async fn complete_pause(
        &self,
        operation_id: &OperationId,
        status: ContainerState,
        pid: Option<i32>,
        paused: bool,
    ) -> Result<ContainerRecord> {
        self.complete_freezer(operation_id, status, pid, paused, FreezerAction::Pause)
            .await
    }

    pub(crate) async fn complete_resume(
        &self,
        operation_id: &OperationId,
        status: ContainerState,
        pid: Option<i32>,
        paused: bool,
    ) -> Result<ContainerRecord> {
        self.complete_freezer(operation_id, status, pid, paused, FreezerAction::Resume)
            .await
    }

    async fn complete_freezer(
        &self,
        operation_id: &OperationId,
        status: ContainerState,
        pid: Option<i32>,
        paused: bool,
        action: FreezerAction,
    ) -> Result<ContainerRecord> {
        let operation_name = action.name();
        if status != ContainerState::Running || pid.is_none_or(|pid| pid <= 0) {
            return Err(state_error(
                ErrorCode::InvalidArgument,
                operation_name,
                format!("driver returned invalid freezer state {status} with PID {pid:?}"),
            ));
        }
        if paused != action.desired() {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                operation_name,
                format!(
                    "driver {operation_name} returned paused={paused}, expected {}",
                    action.desired()
                ),
            ));
        }

        let _guard = self.gate.lock().await;
        let mut operation = self.load_operation(operation_id).await?;
        if operation.kind != action.kind() {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                operation_name,
                format!("operation {operation_id} is not an OCI {operation_name}"),
            ));
        }
        match &operation.outcome {
            StoredOperationStatus::Prepared => {}
            StoredOperationStatus::Succeeded { response } => return Ok(response.clone()),
            StoredOperationStatus::Failed { error } => return Err(error.clone()),
            StoredOperationStatus::SucceededProcess { .. }
            | StoredOperationStatus::SucceededFilesystem { .. }
            | StoredOperationStatus::SucceededEmpty => {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    operation_name,
                    format!("{operation_name} operation {operation_id} has an invalid outcome"),
                ));
            }
        }

        let mut stored = self.load_stored_container(&operation.container_id).await?;
        if stored.record.generation != operation.generation {
            return Err(generation_conflict(
                &operation.container_id,
                operation.generation,
                stored.record.generation,
                operation_name,
            ));
        }
        if *stored.record.state.status() != ContainerState::Running
            || *stored.record.state.pid() != pid
        {
            return Err(state_error(
                ErrorCode::Conflict,
                operation_name,
                format!(
                    "container {} durable state does not match driver freezer response",
                    operation.container_id
                ),
            ));
        }

        stored.record.state = rebuild_paused_state(&stored.record.state, paused)?;
        OciSchemaValidator::new()?.validate_state(&stored.record.state)?;
        ensure_active_operation(&stored, operation_id, operation_name)?;
        stored.active_operation = None;
        self.write_json(
            action.complete_container_mutation(),
            &self
                .container_directory(&operation.container_id)
                .join(super::CONTAINER_RECORD_FILE),
            &stored,
        )
        .await?;
        let response = stored.record.clone();
        self.append_operation_event(
            operation_id,
            operation_name,
            &ContainerTarget::exact(operation.container_id.clone(), operation.generation),
            None,
            match action {
                FreezerAction::Pause => RuntimeEventKind::ContainerPaused,
                FreezerAction::Resume => RuntimeEventKind::ContainerResumed,
            },
            BTreeMap::from([(
                "operation-id".to_string(),
                operation_id.as_str().to_string(),
            )]),
        )
        .await?;
        operation.outcome = StoredOperationStatus::Succeeded {
            response: response.clone(),
        };
        self.write_json(
            action.complete_operation_mutation(),
            &self.operation_path(operation_id),
            &operation,
        )
        .await?;
        Ok(response)
    }
}
