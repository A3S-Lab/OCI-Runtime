use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, ErrorCode, FileOp, FileRequest, FileResponse, FilesystemOp, FilesystemRequest,
    FilesystemResponse, OperationContext, OperationId, Result, ValidateRequest,
};
use serde::Serialize;

use crate::fault::DurableMutation;

use super::filesystem::state_error;
use super::model::{
    StoredFilesystemMutationResponse, StoredOperation, StoredOperationKind, StoredOperationRequest,
    StoredOperationStatus, OPERATION_SCHEMA_VERSION,
};
use super::operation::{request_digest, validate_deadline, validate_retry, RequestDigests};
use super::{
    claim_active_operation, ensure_active_operation, generation_conflict, DurableStateStore,
    FilesystemMutationPreparation,
};

#[derive(Serialize)]
struct FileFingerprint<'a> {
    target: &'a ContainerTarget,
    op: FileOp,
    path: &'a str,
    data: &'a Option<String>,
    user: &'a Option<String>,
}

#[derive(Serialize)]
struct FilesystemFingerprint<'a> {
    target: &'a ContainerTarget,
    op: FilesystemOp,
    path: &'a str,
    destination: &'a Option<String>,
    depth: u32,
    user: &'a Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct FilesystemMutationProfile {
    kind: StoredOperationKind,
    name: &'static str,
    prepare: DurableMutation,
    claim: DurableMutation,
    complete_container: DurableMutation,
    complete_operation: DurableMutation,
}

const FILE: FilesystemMutationProfile = FilesystemMutationProfile {
    kind: StoredOperationKind::File,
    name: "file",
    prepare: DurableMutation::PrepareFileOperation,
    claim: DurableMutation::ClaimFileOperation,
    complete_container: DurableMutation::CompleteFileContainer,
    complete_operation: DurableMutation::CompleteFileOperation,
};

const FILESYSTEM: FilesystemMutationProfile = FilesystemMutationProfile {
    kind: StoredOperationKind::Filesystem,
    name: "filesystem",
    prepare: DurableMutation::PrepareFilesystemOperation,
    claim: DurableMutation::ClaimFilesystemOperation,
    complete_container: DurableMutation::CompleteFilesystemContainer,
    complete_operation: DurableMutation::CompleteFilesystemOperation,
};

enum StoredPreparation {
    Prepared(ContainerTarget),
    Resume(ContainerTarget),
    Replayed(Box<StoredFilesystemMutationResponse>),
}

impl DurableStateStore {
    pub(crate) async fn prepare_file_mutation(
        &self,
        request: &FileRequest,
    ) -> Result<FilesystemMutationPreparation<FileResponse>> {
        request.validate()?;
        if request.op != FileOp::Upload {
            return Err(state_error(
                ErrorCode::InvalidArgument,
                "file",
                "only File uploads are durable mutations",
            ));
        }
        let context = request.context.as_ref().ok_or_else(|| {
            state_error(
                ErrorCode::InvalidArgument,
                "file",
                "File upload has no operation context",
            )
        })?;
        let digest = request_digest(
            &FileFingerprint {
                target: &request.target,
                op: request.op,
                path: &request.path,
                data: &request.data,
                user: &request.user,
            },
            "file",
        )?;
        match self
            .prepare_filesystem_mutation_operation(
                context,
                &request.target,
                digest,
                StoredOperationRequest::File(request.clone()),
                FILE,
            )
            .await?
        {
            StoredPreparation::Prepared(target) => {
                Ok(FilesystemMutationPreparation::Prepared(target))
            }
            StoredPreparation::Resume(target) => Ok(FilesystemMutationPreparation::Resume(target)),
            StoredPreparation::Replayed(response) => match *response {
                StoredFilesystemMutationResponse::File(response) => {
                    Ok(FilesystemMutationPreparation::Replayed(response))
                }
                StoredFilesystemMutationResponse::Filesystem(_) => {
                    Err(invalid_outcome(context, FILE))
                }
            },
        }
    }

    pub(crate) async fn prepare_filesystem_mutation(
        &self,
        request: &FilesystemRequest,
    ) -> Result<FilesystemMutationPreparation<FilesystemResponse>> {
        request.validate()?;
        if !request.op.is_mutating() {
            return Err(state_error(
                ErrorCode::InvalidArgument,
                "filesystem",
                "only mutating Filesystem operations use the durable journal",
            ));
        }
        let context = request.context.as_ref().ok_or_else(|| {
            state_error(
                ErrorCode::InvalidArgument,
                "filesystem",
                "Filesystem mutation has no operation context",
            )
        })?;
        let digest = request_digest(
            &FilesystemFingerprint {
                target: &request.target,
                op: request.op,
                path: &request.path,
                destination: &request.destination,
                depth: request.depth,
                user: &request.user,
            },
            "filesystem",
        )?;
        match self
            .prepare_filesystem_mutation_operation(
                context,
                &request.target,
                digest,
                StoredOperationRequest::Filesystem(request.clone()),
                FILESYSTEM,
            )
            .await?
        {
            StoredPreparation::Prepared(target) => {
                Ok(FilesystemMutationPreparation::Prepared(target))
            }
            StoredPreparation::Resume(target) => Ok(FilesystemMutationPreparation::Resume(target)),
            StoredPreparation::Replayed(response) => match *response {
                StoredFilesystemMutationResponse::Filesystem(response) => {
                    Ok(FilesystemMutationPreparation::Replayed(response))
                }
                StoredFilesystemMutationResponse::File(_) => {
                    Err(invalid_outcome(context, FILESYSTEM))
                }
            },
        }
    }

    async fn prepare_filesystem_mutation_operation(
        &self,
        context: &OperationContext,
        requested: &ContainerTarget,
        digest: RequestDigests,
        retained_request: StoredOperationRequest,
        profile: FilesystemMutationProfile,
    ) -> Result<StoredPreparation> {
        let _guard = self.gate.lock().await;
        if let Some(operation) = self
            .load_operation_if_present(&context.operation_id)
            .await?
        {
            validate_retry(
                &operation,
                &context.operation_id,
                profile.kind,
                &requested.id,
                &digest,
                profile.name,
            )?;
            return match operation.outcome.clone() {
                StoredOperationStatus::Prepared => {
                    let mut stored = self
                        .load_stored_exact(&operation.container_id, operation.generation)
                        .await?;
                    ensure_live_filesystem(&stored, profile.name)?;
                    claim_active_operation(
                        self,
                        &mut stored,
                        &context.operation_id,
                        profile.claim,
                        profile.name,
                    )
                    .await?;
                    Ok(StoredPreparation::Resume(ContainerTarget::exact(
                        stored.id,
                        stored.record.generation,
                    )))
                }
                StoredOperationStatus::SucceededFilesystem { response } => {
                    Ok(StoredPreparation::Replayed(Box::new(response)))
                }
                StoredOperationStatus::Failed { error } => Err(error),
                StoredOperationStatus::Succeeded { .. }
                | StoredOperationStatus::SucceededProcess { .. }
                | StoredOperationStatus::SucceededCheckpoint { .. }
                | StoredOperationStatus::SucceededRestore { .. }
                | StoredOperationStatus::SucceededAttestation { .. }
                | StoredOperationStatus::SucceededEmpty => Err(invalid_outcome(context, profile)),
            };
        }

        validate_deadline(context, profile.name)?;
        let mut stored = self.load_stored_container(&requested.id).await?;
        if let Some(expected) = requested.generation {
            if stored.record.generation != expected {
                return Err(generation_conflict(
                    &requested.id,
                    expected,
                    stored.record.generation,
                    profile.name,
                ));
            }
        }
        ensure_live_filesystem(&stored, profile.name)?;
        let target = ContainerTarget::exact(stored.id.clone(), stored.record.generation);
        let operation = StoredOperation {
            schema_version: OPERATION_SCHEMA_VERSION.to_string(),
            operation_id: context.operation_id.clone(),
            kind: profile.kind,
            container_id: stored.id.clone(),
            generation: stored.record.generation,
            process_id: None,
            request: Some(retained_request),
            request_digest: digest.current().to_string(),
            outcome: StoredOperationStatus::Prepared,
        };
        self.write_json(
            profile.prepare,
            &self.operation_path(&context.operation_id),
            &operation,
        )
        .await?;
        claim_active_operation(
            self,
            &mut stored,
            &context.operation_id,
            profile.claim,
            profile.name,
        )
        .await?;
        Ok(StoredPreparation::Prepared(target))
    }

    pub(crate) async fn complete_file_mutation(
        &self,
        operation_id: &OperationId,
        response: FileResponse,
    ) -> Result<FileResponse> {
        match self
            .complete_filesystem_mutation_operation(
                operation_id,
                StoredFilesystemMutationResponse::File(response),
                FILE,
            )
            .await?
        {
            StoredFilesystemMutationResponse::File(response) => Ok(response),
            StoredFilesystemMutationResponse::Filesystem(_) => {
                Err(invalid_operation_outcome(operation_id, FILE))
            }
        }
    }

    pub(crate) async fn complete_filesystem_mutation(
        &self,
        operation_id: &OperationId,
        response: FilesystemResponse,
    ) -> Result<FilesystemResponse> {
        match self
            .complete_filesystem_mutation_operation(
                operation_id,
                StoredFilesystemMutationResponse::Filesystem(response),
                FILESYSTEM,
            )
            .await?
        {
            StoredFilesystemMutationResponse::Filesystem(response) => Ok(response),
            StoredFilesystemMutationResponse::File(_) => {
                Err(invalid_operation_outcome(operation_id, FILESYSTEM))
            }
        }
    }

    async fn complete_filesystem_mutation_operation(
        &self,
        operation_id: &OperationId,
        response: StoredFilesystemMutationResponse,
        profile: FilesystemMutationProfile,
    ) -> Result<StoredFilesystemMutationResponse> {
        let _guard = self.gate.lock().await;
        let mut operation = self.load_operation(operation_id).await?;
        if operation.kind != profile.kind {
            return Err(invalid_operation_outcome(operation_id, profile));
        }
        match &operation.outcome {
            StoredOperationStatus::Prepared => {}
            StoredOperationStatus::SucceededFilesystem { response } => {
                return Ok(response.clone());
            }
            StoredOperationStatus::Failed { error } => return Err(error.clone()),
            StoredOperationStatus::Succeeded { .. }
            | StoredOperationStatus::SucceededProcess { .. }
            | StoredOperationStatus::SucceededCheckpoint { .. }
            | StoredOperationStatus::SucceededRestore { .. }
            | StoredOperationStatus::SucceededAttestation { .. }
            | StoredOperationStatus::SucceededEmpty => {
                return Err(invalid_operation_outcome(operation_id, profile));
            }
        }
        let response_target = match &response {
            StoredFilesystemMutationResponse::File(response) => &response.target,
            StoredFilesystemMutationResponse::Filesystem(response) => &response.target,
        };
        if response_target.id != operation.container_id
            || response_target.generation != Some(operation.generation)
        {
            return Err(state_error(
                ErrorCode::Conflict,
                profile.name,
                format!(
                    "driver response for operation {operation_id} targets a different container generation"
                ),
            ));
        }

        let mut stored = self
            .load_stored_exact(&operation.container_id, operation.generation)
            .await?;
        ensure_live_filesystem(&stored, profile.name)?;
        ensure_active_operation(&stored, operation_id, profile.name)?;
        stored.active_operation = None;
        self.write_json(
            profile.complete_container,
            &self
                .container_directory(&operation.container_id)
                .join(super::CONTAINER_RECORD_FILE),
            &stored,
        )
        .await?;
        operation.outcome = StoredOperationStatus::SucceededFilesystem {
            response: response.clone(),
        };
        self.write_json(
            profile.complete_operation,
            &self.operation_path(operation_id),
            &operation,
        )
        .await?;
        Ok(response)
    }
}

fn ensure_live_filesystem(
    stored: &super::model::StoredContainer,
    operation: &'static str,
) -> Result<()> {
    if matches!(
        stored.record.state.status(),
        ContainerState::Created | ContainerState::Running
    ) {
        Ok(())
    } else {
        Err(state_error(
            ErrorCode::FailedPrecondition,
            operation,
            format!(
                "container {} generation {} cannot mutate its filesystem while {}",
                stored.id,
                stored.record.generation.0,
                stored.record.state.status()
            ),
        ))
    }
}

fn invalid_outcome(
    context: &OperationContext,
    profile: FilesystemMutationProfile,
) -> a3s_oci_sdk::Error {
    invalid_operation_outcome(&context.operation_id, profile)
}

fn invalid_operation_outcome(
    operation_id: &OperationId,
    profile: FilesystemMutationProfile,
) -> a3s_oci_sdk::Error {
    state_error(
        ErrorCode::FailedPrecondition,
        profile.name,
        format!(
            "{} operation {operation_id} has an invalid durable outcome",
            profile.name
        ),
    )
}
